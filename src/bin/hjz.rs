use anyhow::Error;
use clap::Parser;
use hujingzhi::{ClientResponse, GetAuthConfigMode, get_config_path};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  // #[clap(short, long, value_parser, default_value = "hjz-config.yaml")]
  // config: String,

  #[clap(short, long, value_parser)]
  auth: Option<String>,

  // #[clap(short, long)]
  // debug_mode: bool,
  #[clap(subcommand)]
  action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
  Version,
  PrintAuth,
  Server {
    #[clap(short, long, value_parser, default_value = "hjz-config.yaml")]
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
      auth_config.private = None;
      println!("{}", serde_yaml::to_string(&auth_config)?);
    }
    Action::Server { config } => {
      // Check if we're on Linux.
      #[cfg(not(target_os = "linux"))]
      {
        std::mem::drop(config); // Suppress warning.
        eprintln!("hjz server only works on Linux");
        std::process::exit(1);
      }
      #[cfg(target_os = "linux")]
      {
        // Parse the config file.
        let config = match config {
          Some(config) => config,
          None => get_config_path()?,
        };
        let config_string = std::fs::read_to_string(config)?;
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
