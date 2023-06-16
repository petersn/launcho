use anyhow::Error;
use clap::Parser;

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
  Ping,
  Get {
    #[clap(short, long)]
    stream: String,
  },
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
    Action::Ping => hujingzhi::send_request(hujingzhi::RestRequest::Ping).await?,
    Action::Get { stream } => hujingzhi::send_request(hujingzhi::RestRequest::Get { stream }).await?,
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
