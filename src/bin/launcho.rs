use std::{io::Write, path::PathBuf};

use anyhow::{bail, Context, Error};
use clap::Parser;
use futures::TryStreamExt;
use launcho::{
  get_config_path, guarantee_launcho_directory, make_authenticated_client, ClientResponse,
  GetAuthConfigMode,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  /// Pick which configuration file to load
  #[clap(long, short)]
  which: Option<String>,

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
  #[clap(subcommand, aliases = &["s", "secrets"])]
  Secret(SecretAction),
  Status {
    #[clap(long, action)]
    ipvs: bool,

    #[clap(long, short)]
    all: bool,
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
enum SecretAction {
  Get { names: Vec<String> },
  Set { name: String, value: String },
  Rm { names: Vec<String> },
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
  eprint!(
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
      println!("launcho {}", env!("CARGO_PKG_VERSION"));
    }
    Action::PrintAuth => {
      let mut auth_config = launcho::get_auth_config(args.which, GetAuthConfigMode::ServerFailIfNotExists)?;
      auth_config.host = Some("change-me-to-point-to-the-server.example.com:12888".to_string());
      auth_config.private = None;
      println!("# Paste this into ~/.launcho/launcho-client-auth.yaml on the client machine");
      print!("{}", serde_yaml::to_string(&auth_config)?);
    }
    Action::Server {
      config: maybe_config_path,
    } => {
      // Check if we're on Linux.
      #[cfg(not(target_os = "linux"))]
      {
        std::mem::drop(maybe_config_path); // Suppress warning.
        eprintln!("launcho server only works on Linux");
        std::process::exit(1);
      }
      #[cfg(target_os = "linux")]
      {
        let using_default_config_path = maybe_config_path.is_none();
        // Parse the config file.
        let config_path = match maybe_config_path {
          Some(config_path) => PathBuf::from(config_path),
          None => get_config_path()?,
        };
        let config_string_result = std::fs::read_to_string(&config_path);
        let config_string = match (using_default_config_path, config_string_result) {
          (_, Ok(config_string)) => config_string,
          (true, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            launcho::server::log_event(launcho::LogEvent::Warning {
              msg: format!("Config file not found at {:?} -- writing default config", config_path),
            });
            guarantee_launcho_directory()?;
            let default_config = include_str!("../default-config.yaml");
            std::fs::write(&config_path, &default_config)?;
            default_config.to_string()
          }
          (_, Err(e)) => bail!("Failed to read config file at {:?}: {}", config_path, e),
        };
        let server_config = serde_yaml::from_str(&config_string)?;
        launcho::server::server_main(server_config).await?
      }
    }
    Action::Target(TargetAction::Get) => {
      let response =
        handle_error_response(launcho::send_request(args.which, launcho::ClientRequest::GetTarget).await?);
      match response {
        ClientResponse::Target { target } => print!("{}", target),
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Target(TargetAction::Set { file }) => {
      handle_success_or_error(
        launcho::send_request(args.which, launcho::ClientRequest::SetTarget {
          target: std::fs::read_to_string(&file)?,
        })
        .await?,
      );
    }
    Action::Target(TargetAction::Edit) => {
      let response =
        handle_error_response(launcho::send_request(args.which.clone(), launcho::ClientRequest::GetTarget).await?);
      let target = match response {
        ClientResponse::Target { target } => target,
        _ => panic!("Unexpected response: {:?}", response),
      };
      let new_target = edit::edit(&target)?;
      if new_target == target {
        println!("No changes -- not updating");
      } else {
        handle_success_or_error(
          launcho::send_request(args.which, launcho::ClientRequest::SetTarget { target: new_target })
            .await?,
        );
      }
    }
    Action::Secret(SecretAction::Get { names }) => {
      let response = handle_error_response(
        launcho::send_request(args.which, launcho::ClientRequest::GetSecrets { names }).await?,
      );
      match response {
        ClientResponse::Secrets { secrets } =>
          for (name, secret) in secrets {
            print!("{}: ", name);
            match secret {
              Some(secret) => println!("{:?}", secret),
              None => println!("(not found)"),
            }
          },
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Secret(SecretAction::Set { name, value }) => {
      handle_success_or_error(
        launcho::send_request(args.which, launcho::ClientRequest::SetSecret { name, value }).await?,
      );
    }
    Action::Secret(SecretAction::Rm { names }) => {
      let response = handle_error_response(
        launcho::send_request(args.which, launcho::ClientRequest::DeleteSecrets { names }).await?,
      );
      match response {
        ClientResponse::Success {
          message: Some(message),
        } => println!("{}", message.trim()),
        ClientResponse::Success { message: None } =>
          println!("Unexpected lack of message from server, but operation succeeded"),
        _ => panic!("Unexpected response"),
      }
    }
    Action::Secret(SecretAction::Ls) => {
      let response = handle_error_response(
        launcho::send_request(args.which, launcho::ClientRequest::ListSecrets).await?,
      );
      match response {
        ClientResponse::SecretList { secrets } =>
          for name in secrets {
            println!("{}", name);
          },
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Status { ipvs, all } => {
      println!("Events:");
      let response =
        handle_error_response(launcho::send_request(args.which, launcho::ClientRequest::Status { all }).await?);
      match response {
        ClientResponse::Status {
          status,
          events,
          ipvs_state,
        } => {
          println!("\x1b[93m=== Events:\x1b[0m");
          let events_subslice = match all {
            true => &events[..],
            false => &events[events.len().saturating_sub(5)..],
          };
          if events_subslice.len() != events.len() {
            println!("  ... {} omitted (--all to show)", events.len() - events_subslice.len());
          }
          for event in events_subslice {
            println!("  {:?}", event);
          }
          if ipvs {
            println!("\x1b[93m=== IPVS state:\x1b[0m");
            println!("{:#?}", ipvs_state);
          }
          println!("\x1b[93m=== Processes:\x1b[0m");
          println!("{}", status)
        }
        _ => panic!("Unexpected response: {:?}", response),
      }
    }
    Action::Logs { process } => {
      let response = handle_error_response(
        launcho::send_request(args.which, launcho::ClientRequest::GetLogs { name: process }).await?,
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
        launcho::send_request(args.which, launcho::ClientRequest::Restart { name: process }).await?,
      );
    }
    Action::Resource(ResourceAction::Up { name, file }) => {
      let full_size = std::fs::metadata(&file)?.len();
      let mut bytes_written = 0;
      let reader =
        tokio_util::io::ReaderStream::new(tokio::fs::File::open(&file).await?).map_ok(move |x| {
          bytes_written += x.len();
          progress_bar("Uploading:", bytes_written as f64, full_size as f64);
          x
        });
      let (client, host, port) = make_authenticated_client(args.which)?;
      let response = client
        .post(format!("https://launcho:{}/upload", port))
        .body(reqwest::Body::wrap_stream(reader))
        .query(&[("name", name.unwrap_or(file))])
        .header("Content-Length", full_size as u64)
        .send()
        .await
        .with_context(|| format!("Upload to {} failed", host))?
        .text()
        .await?;
      eprintln!(" Done.");
      match serde_json::from_str(&response)? {
        ClientResponse::Success { message: None } =>
          eprintln!("Success, but no resource ID returned, for some reason"),
        ClientResponse::Success {
          message: Some(message),
        } => println!("{}", message),
        _ => panic!("Unexpected response: {:?}", response),
      }
      ()
    }
    Action::Resource(ResourceAction::Down { id, file }) => {
      let (client, host, port) = make_authenticated_client(args.which)?;
      let response = client
        .get(format!("https://launcho:{}/download", port))
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
      eprintln!(" Done.");
    }
    Action::Resource(ResourceAction::Rm { ids }) => {
      handle_success_or_error(
        launcho::send_request(args.which, launcho::ClientRequest::DeleteResources { ids }).await?,
      );
    }
    Action::Resource(ResourceAction::Ls) => {
      let response = handle_error_response(
        launcho::send_request(args.which, launcho::ClientRequest::ListResources).await?,
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
        launcho::send_request(args.which, launcho::ClientRequest::ClearLaunchRateLimits).await?,
      );
    }
    Action::Uncommon(UncommonAction::Ping) => {
      let pong = launcho::send_request(args.which, launcho::ClientRequest::Ping).await?;
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
