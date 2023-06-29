use anyhow::Error;
use clap::Parser;
use hujingzhi::{ipvs, ClientResponse};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  // #[clap(short, long, value_parser, default_value = "hjz-config.yaml")]
  // config: String,

  // #[clap(short, long)]
  // debug_mode: bool,
  #[clap(subcommand)]
  action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
  #[clap(about = "Print the version")]
  Version,
  #[clap(about = "Print the default config file")]
  PrintDefaultConfig,
  PrintAuth,
  Server {
    #[clap(short, long, value_parser, default_value = "hjz-config.yaml")]
    config: String,
  },
  Ipvs,
  Ping,
  GetTarget,
  SetTarget {
    #[clap(short, long, value_parser, default_value = "hjz-target.yaml")]
    path: String,
  },
  Status,
  Logs {
    #[clap(short, long)]
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
    Action::PrintDefaultConfig => {
      println!("{}", include_str!("../default-config.yaml"));
    }
    Action::PrintAuth => {
      let mut auth_config = hujingzhi::get_auth_config()?;
      auth_config.private = None;
      println!("{}", serde_yaml::to_string(&auth_config)?);
    }
    Action::Server { config } => {
      // Parse the config file.
      let config_string = std::fs::read_to_string(&config)?;
      let server_config = serde_yaml::from_str(&config_string)?;
      hujingzhi::server_main(server_config).await?
    }
    Action::Ipvs => {
      let state = ipvs::get_ipvs_state()?;
      println!("{:#?}", state);
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
    Action::SetTarget { path } => {
      let target_text = std::fs::read_to_string(&path)?;
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
    Action::Status => {
      println!("Status:");
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
          println!("{:#?}", ipvs_state);
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
        ClientResponse::Logs { name, stdout, stderr } => {
          println!("Process: {}", name);
          println!("stdout:");
          println!("{}", stdout);
          println!("stderr:");
          println!("{}", stderr);
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
