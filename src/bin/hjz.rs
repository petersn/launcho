use anyhow::{bail, Error};
use clap::Parser;
use hujingzhi::{get_config_path, guarantee_hjz_directory, ClientResponse, GetAuthConfigMode};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  #[clap(subcommand)]
  action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
  Version,
  PrintAuth,
  Server {
    #[clap(short, long, value_parser)]
    config: Option<String>,
  },
  Ping,
  GetTarget,
  SetTarget {
    #[clap(short, long, value_parser, default_value = "hjz-target.yaml")]
    target: String,
  },
  Status {
    #[clap(long, action)]
    ipvs: bool,
  },
  Logs {
    process: String,
  },
  Restart {
    process: String,
  },
  Upload {
    path: String,
    #[clap(short, long)]
    name: Option<String>,
  },
  Download {
    id: String,
    path: String,
  },
  DeleteResources {
    ids: Vec<String>,
  },
  ListResources,
}

fn handle_error_response(response: ClientResponse) -> ClientResponse {
  match response {
    ClientResponse::Error { message } => {
      eprintln!("Error: {}", message);
      std::process::exit(1);
    }
    _ => response,
  }
}

async fn main_result() -> Result<(), Error> {
  dotenv::dotenv().ok();
  let args: Args = Args::parse();

  Ok(match args.action {
    Action::Version => {
      println!("hujingzhi {}", env!("CARGO_PKG_VERSION"));
    }
    Action::PrintAuth => {
      let mut auth_config = hujingzhi::get_auth_config(GetAuthConfigMode::ServerFailIfNotExists)?;
      auth_config.host = Some("change-me-to-point-to-the-server.example.com:12888".to_string());
      auth_config.private = None;
      println!("# Paste this into ~/.hjz/hjz-client-auth.yaml on the client machine");
      print!("{}", serde_yaml::to_string(&auth_config)?);
    }
    Action::Server {
      config: maybe_config_path,
    } => {
      // Check if we're on Linux.
      #[cfg(not(target_os = "linux"))]
      {
        std::mem::drop(maybe_config_path); // Suppress warning.
        eprintln!("hjz server only works on Linux");
        std::process::exit(1);
      }
      #[cfg(target_os = "linux")]
      {
        let using_default_config_path = maybe_config_path.is_none();
        // Parse the config file.
        let config_path = match maybe_config_path {
          Some(config_path) => config_path,
          None => get_config_path()?,
        };
        let config_string_result = std::fs::read_to_string(&config_path);
        let config_string = match (using_default_config_path, config_string_result) {
          (_, Ok(config_string)) => config_string,
          (true, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            hujingzhi::server::log_event(hujingzhi::LogEvent::Warning {
              msg: format!("Config file not found at {} -- writing default config", config_path),
            });
            guarantee_hjz_directory()?;
            let default_config = include_str!("../default-config.yaml");
            std::fs::write(&config_path, &default_config)?;
            default_config.to_string()
          }
          (_, Err(e)) => bail!("Failed to read config file at {}: {}", config_path, e),
        };
        let server_config = serde_yaml::from_str(&config_string)?;
        hujingzhi::server::server_main(server_config).await?
      }
    }
    Action::Ping => {
      let pong = hujingzhi::send_request(hujingzhi::ClientRequest::Ping).await?;
      println!("{:#?}", pong);
    }
    Action::GetTarget => {
      let response =
        handle_error_response(hujingzhi::send_request(hujingzhi::ClientRequest::GetTarget).await?);
      match response {
        ClientResponse::Target { target } => print!("{}", target),
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::SetTarget { target } => {
      let target_text = std::fs::read_to_string(&target)?;
      let response = handle_error_response(
        hujingzhi::send_request(hujingzhi::ClientRequest::SetTarget {
          target: target_text,
        })
        .await?,
      );
      match response {
        ClientResponse::Success { message: None } => println!("Success"),
        ClientResponse::Success {
          message: Some(message),
        } => println!("{}", message),
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Status { ipvs } => {
      println!("Events:");
      let response =
        handle_error_response(hujingzhi::send_request(hujingzhi::ClientRequest::Status).await?);
      match response {
        ClientResponse::Status {
          status,
          events,
          ipvs_state,
        } => {
          for event in events {
            println!("  {:?}", event);
          }
          if ipvs {
            println!("IPVS:");
            println!("{:#?}", ipvs_state);
          }
          println!("{}", status)
        }
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Logs { process } => {
      let response = handle_error_response(
        hujingzhi::send_request(hujingzhi::ClientRequest::GetLogs { name: process }).await?,
      );
      match response {
        ClientResponse::Logs { name, output } => {
          println!("Process: {}", name);
          println!("{}", output);
        }
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Restart { process } => {
      let response = handle_error_response(
        hujingzhi::send_request(hujingzhi::ClientRequest::Restart { name: process }).await?,
      );
      match response {
        ClientResponse::Success { message: None } => println!("Success"),
        ClientResponse::Success {
          message: Some(message),
        } => println!("Success: {}", message),
        ClientResponse::Error { message } => println!("Error: {}", message),
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Upload { name, path } => {
      let data = std::fs::read(&path)?;
      let response = handle_error_response(
        hujingzhi::send_request(hujingzhi::ClientRequest::UploadResource {
          name: name.unwrap_or(path),
          data,
        })
        .await?,
      );
      match response {
        ClientResponse::Success { message: None } => println!("Success"),
        ClientResponse::Success {
          message: Some(message),
        } => println!("Success: {}", message),
        ClientResponse::Error { message } => println!("Error: {}", message),
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Download { id, path } => {
      let response = handle_error_response(
        hujingzhi::send_request(hujingzhi::ClientRequest::DownloadResource { id }).await?,
      );
      match response {
        ClientResponse::Resource { id: _, data } => {
          std::fs::write(&path, data)?;
          println!("Success");
        }
        ClientResponse::Error { message } => println!("Error: {}", message),
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::DeleteResources { ids } => {
      let response = handle_error_response(
        hujingzhi::send_request(hujingzhi::ClientRequest::DeleteResources { ids }).await?,
      );
      match response {
        ClientResponse::Success { message: None } => println!("Success"),
        ClientResponse::Success {
          message: Some(message),
        } => println!("Success: {}", message),
        ClientResponse::Error { message } => println!("Error: {}", message),
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::ListResources => {
      let response =
        handle_error_response(hujingzhi::send_request(hujingzhi::ClientRequest::ListResources).await?);
      match response {
        ClientResponse::ResourceList { resources } => {
          println!("Found {} resources", resources.len());
          for resource in resources {
            println!("{} [{:9} bytes] {}", resource.id, resource.size, resource.name);
          }
        }
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
  })
}

#[tokio::main]
async fn main() {
  match main_result().await {
    Ok(()) => {}
    Err(e) => {
      eprintln!("Error: {}", e);
      std::process::exit(1);
    }
  }
}
