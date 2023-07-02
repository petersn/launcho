use anyhow::{bail, Context, Error};
use clap::Parser;
use hujingzhi::{
  get_config_path, guarantee_hjz_directory, make_authenticated_client, ClientResponse,
  GetAuthConfigMode,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  #[clap(subcommand)]
  action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
  Server {
    #[clap(short, long, value_parser)]
    config: Option<String>,
  },
  PrintAuth,
  #[clap(subcommand, alias = "t")]
  Target(TargetAction),
  #[clap(subcommand, aliases = &["r", "resources"])]
  Resource(ResourceAction),
  Status {
    #[clap(long, action)]
    ipvs: bool,
  },
  Logs {
    process: String,
  },
  RestartProcess {
    process: String,
  },
  #[clap(subcommand)]
  Uncommon(UncommonAction),
  Version,
}

#[derive(Debug, clap::Subcommand)]
enum TargetAction {
  Get,
  Set { file: String },
  Edit,
}

#[derive(Debug, clap::Subcommand)]
enum ResourceAction {
  Up {
    file: String,
    #[clap(short, long)]
    name: Option<String>,
  },
  Down {
    id:   String,
    file: String,
  },
  Rm {
    ids: Vec<String>,
  },
  Ls,
}

#[derive(Debug, clap::Subcommand)]
enum UncommonAction {
  ClearLaunchRateLimits,
  Ping,
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

fn handle_success_or_error(response: ClientResponse) {
  let response = handle_error_response(response);
  match &response {
    ClientResponse::Success { message: None } => println!("Success"),
    ClientResponse::Success {
      message: Some(message),
    } => println!("Success: {}", message),
    _ => panic!("Unexpected response: {:?}", response),
  }
}

fn progress_bar(prefix: &str, bytes: f64, full_size: f64) {
  print!(
    "\r{} {:.2}% ({:.2} / {:.2} MiB)",
    prefix,
    100.0 * bytes / full_size,
    bytes / (1024.0 * 1024.0),
    full_size / (1024.0 * 1024.0)
  );
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
    Action::Target(TargetAction::Get) => {
      let response =
        handle_error_response(hujingzhi::send_request(hujingzhi::ClientRequest::GetTarget).await?);
      match response {
        ClientResponse::Target { target } => print!("{}", target),
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Target(TargetAction::Set { file }) => {
      handle_success_or_error(
        hujingzhi::send_request(hujingzhi::ClientRequest::SetTarget {
          target: std::fs::read_to_string(&file)?,
        })
        .await?,
      );
    }
    Action::Target(TargetAction::Edit) => {
      let response =
        handle_error_response(hujingzhi::send_request(hujingzhi::ClientRequest::GetTarget).await?);
      let target = match response {
        ClientResponse::Target { target } => target,
        _ => panic!("Unexpected response: {:?}", response),
      };
      let new_target = edit::edit(&target)?;
      if new_target == target {
        println!("No changes -- not updating");
      } else {
        handle_success_or_error(
          hujingzhi::send_request(hujingzhi::ClientRequest::SetTarget { target: new_target })
            .await?,
        );
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
    Action::RestartProcess { process } => {
      handle_success_or_error(
        hujingzhi::send_request(hujingzhi::ClientRequest::Restart { name: process }).await?,
      );
    }
    Action::Resource(ResourceAction::Up { name, file }) => {
      use futures::TryStreamExt;
      let full_size = std::fs::metadata(&file)?.len();
      let mut bytes_written = 0;
      let reader =
        tokio_util::io::ReaderStream::new(tokio::fs::File::open(&file).await?).map_ok(move |x| {
          bytes_written += x.len();
          progress_bar("Uploading:", bytes_written as f64, full_size as f64);
          x
        });
      let (client, host, port) = make_authenticated_client()?;
      let response = client
        .post(format!("https://hujingzhi:{}/upload", port))
        .body(reqwest::Body::wrap_stream(reader))
        .query(&[("name", name.unwrap_or(file))])
        .header("Content-Length", full_size as u64)
        .send()
        .await
        .with_context(|| format!("Upload to {} failed", host))?
        .text()
        .await?;
      println!(" Done.");
      handle_success_or_error(serde_json::from_str(&response)?);
    }
    Action::Resource(ResourceAction::Down { id, file }) => {
      use std::io::Write;

      use futures::TryStreamExt;
      let (client, host, port) = make_authenticated_client()?;
      let response = client
        .get(format!("https://hujingzhi:{}/download", port))
        .query(&[("id", id)])
        .send()
        .await
        .with_context(|| format!("Download from {} failed", host))?;
      if !response.status().is_success() {
        bail!("Download failed: {}", response.text().await?);
      }
      let full_size = response
        .headers()
        .get("content-length")
        .and_then(|x| x.to_str().ok())
        .and_then(|x| x.parse::<u64>().ok())
        .unwrap_or(1);
      let mut stream = response.bytes_stream();
      let mut file = std::fs::File::create(file)?;
      let mut bytes_written = 0;
      while let Some(chunk) = stream.try_next().await? {
        bytes_written += chunk.len();
        progress_bar("Downloading:", bytes_written as f64, full_size as f64);
        file.write_all(&chunk)?;
      }
      println!(" Done.");
    }
    Action::Resource(ResourceAction::Rm { ids }) => {
      handle_success_or_error(
        hujingzhi::send_request(hujingzhi::ClientRequest::DeleteResources { ids }).await?,
      );
    }
    Action::Resource(ResourceAction::Ls) => {
      let response = handle_error_response(
        hujingzhi::send_request(hujingzhi::ClientRequest::ListResources).await?,
      );
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
    Action::Uncommon(UncommonAction::ClearLaunchRateLimits) => {
      handle_success_or_error(
        hujingzhi::send_request(hujingzhi::ClientRequest::ClearLaunchRateLimits).await?,
      );
    }
    Action::Uncommon(UncommonAction::Ping) => {
      let pong = hujingzhi::send_request(hujingzhi::ClientRequest::Ping).await?;
      println!("{:#?}", pong);
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
