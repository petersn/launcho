pub mod config;

use std::{sync::Arc, net::{SocketAddr, IpAddr, Ipv4Addr}};

use anyhow::{bail, Error};
use reqwest::dns::Resolve;
use serde::{Deserialize, Serialize};
use serde_json::json;
use warp::Filter;

use crate::config::{AuthConfig, HujingzhiConfig};

static DEFAULT_AUTH_CONFIG_PATH: &str = ".hjz-auth.yaml";

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
  use subtle::ConstantTimeEq;
  a.ct_eq(b).into()
}

fn make_cryptographic_token() -> String {
  use rand::RngCore;
  let mut token = [0u8; 32];
  rand::rngs::OsRng.fill_bytes(&mut token);
  token.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RestRequest {
  Get { stream: String },
  Ping,
}

struct GlobalState {}

impl GlobalState {
  async fn housekeeping(&self) -> Result<(), Error> {
    Ok(())
  }

  async fn handle_rest_request(&self, request: RestRequest) -> Result<Result<serde_json::Value, &'static str>, Error> {
    Ok(match request {
      RestRequest::Get { stream } => {
        Err("Not implemented")
      },
      RestRequest::Ping => Ok(json!("pong")),
    })
  }
}

pub fn get_auth_config() -> Result<AuthConfig, Error> {
  if let Ok(auth_config_string) = std::fs::read_to_string(DEFAULT_AUTH_CONFIG_PATH) {
    let auth_config: AuthConfig = serde_yaml::from_str(&auth_config_string)?;
    return Ok(auth_config);
  }
  println!("No auth config found, generating one...");
  use rcgen::generate_simple_self_signed;
  let subject_alt_names = vec!["hujingzhi".to_string()];
  let cert = generate_simple_self_signed(subject_alt_names)?;
  let auth_config = AuthConfig {
    host:    Some("example.com".to_string()),
    cert:    cert.serialize_pem()?,
    private: Some(cert.serialize_private_key_pem()),
    token:   make_cryptographic_token(),
  };
  let auth_config_yaml = serde_yaml::to_string(&auth_config)?;
  std::fs::write(DEFAULT_AUTH_CONFIG_PATH, &auth_config_yaml)?;
  Ok(auth_config)
}

pub async fn server_main(server_config: HujingzhiConfig) -> Result<(), Error> {
  // Load the secrets.
  let secrets: &'static _ = Box::leak(Box::new(server_config.secrets.load()?));

  let cors = warp::cors()
    .allow_any_origin()
    .allow_methods(&[warp::http::Method::GET, warp::http::Method::POST])
    .allow_headers(vec![
      "User-Agent",
      "Sec-Fetch-Mode",
      "Referer",
      "Origin",
      "Access-Control-Request-Method",
      "Access-Control-Request-Headers",
      "Content-Type",
      "X-Requested-With",
    ]);

  let global_state: &'static _ = Box::leak(Box::new(GlobalState {}));

  // Run housekeeping every minute.
  tokio::spawn(async move {
    loop {
      match global_state.housekeeping().await {
        Ok(()) => {}
        Err(err) => eprintln!("Housekeeping error: {}", err),
      }
      tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
  });

  // // For each stream that might need polling we spawn a task.
  // for stream_spec in server_config.streams.values() {
  //   match stream_spec.stream_type
  // }

  let warp_global_state = warp::any().map(move || global_state);

  let auth_config: &'static AuthConfig = Box::leak(Box::new(get_auth_config()?));

  #[derive(Debug)]
  struct MessageAndStatus(&'static str, warp::http::StatusCode);
  impl warp::reject::Reject for MessageAndStatus {}

  let check_basic_auth = |basic: &str| -> Result<(), &'static str> {
    use base64::{engine::general_purpose, Engine};
    let decoded =
      general_purpose::STANDARD.decode(basic.as_bytes()).map_err(|_| "Invalid base64")?;
    let decoded = String::from_utf8(decoded).map_err(|_| "Invalid UTF-8 inside base64")?;
    let mut split = decoded.splitn(2, ':');
    // Ignore the username.
    let _ = split.next().ok_or_else(|| "No username")?;
    let token = split.next().ok_or_else(|| "No token")?;
    match constant_time_eq(token.as_bytes(), auth_config.token.as_bytes()) {
      true => Ok(()),
      false => Err("Wrong token"),
    }
  };

  // let ws_endpoint = warp::path!("ws")
  //   // Check for authorization.
  //   .and(warp::header::optional::<String>("authorization"))
  //   .and_then(move |auth_header: Option<String>| async move {
  //     check_auth_header(&auth_header.unwrap_or_default())
  //   })
  //   .and(warp_global_state.clone())
  //   // Upgrade to a websocket, and handle the session.
  //   .and(warp::ws())
  //   .map(|auth_data, global_state, ws: ws::Ws| {
  //     println!("auth_data: {:?}", auth_data);
  //     ws.on_upgrade(move |socket| {
  //       async fn f(global_state: &'static GlobalState, socket: ws::WebSocket) {
  //         let (tx, rx) = socket.split();
  //         let mut session_state = SessionState::new(global_state, rx, tx);
  //         session_state.handle_session().await;
  //       }
  //       f(global_state, socket)
  //     })
  //   });

  let api_endpoint = warp::path!("api")
    .and(warp::header::optional::<String>("authorization"))
    .and_then(move |auth_header: Option<String>| async move {
      match auth_header.unwrap_or_default().strip_prefix("Basic ") {
        Some(basic) => match check_basic_auth(basic) {
          Ok(()) => Ok(()),
          Err(err) =>
            Err(warp::reject::custom(MessageAndStatus(err, warp::http::StatusCode::UNAUTHORIZED))),
        },
        None => Err(warp::reject::custom(MessageAndStatus(
          r#"Authorization header is required, like:

  Authorization: Basic <base64 of "any username:server token">
"#,
          warp::http::StatusCode::UNAUTHORIZED,
        ))),
      }
    })
    .and(warp_global_state.clone())
    // Handle the REST request.
    .and(warp::body::json())
    .and_then(|(), global_state: &'static GlobalState, request: RestRequest| async move {
      match global_state.handle_rest_request(request).await {
        Ok(Ok(result)) => Ok(warp::reply::json(&result)),
        Ok(Err(message)) => Err(warp::reject::custom(MessageAndStatus(
          message,
          warp::http::StatusCode::BAD_REQUEST,
        ))),
        Err(err) => {
          eprintln!("REST request error: {}", err);
          Err(warp::reject::custom(MessageAndStatus(
            "Internal server error",
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
          )))
        }
      }
    });

  let all_endpoints = api_endpoint
    // Map rejections to a response.
    .recover(|err: warp::Rejection| async move {
      if let Some(MessageAndStatus(msg, status)) = err.find() {
        Ok(warp::http::Response::builder().status(status).body(*msg).unwrap())
      } else {
        Err(err)
      }
    })
    .with(cors);

  // Create a server, optionally enable TLS, and run it.
  use std::str::FromStr;
  let host = std::net::IpAddr::from_str(&server_config.server.host)?;

  println!("\x1b[94m--- Starting TLS server on port {} ---\x1b[0m", server_config.server.port);
  Ok(
    warp::serve(all_endpoints)
      .tls()
      .cert(&auth_config.cert)
      .key(auth_config.private.as_ref().unwrap())
      .run((host, server_config.server.port))
      .await,
  )
}

pub async fn send_request(request: RestRequest) -> Result<(), Error> {
  use std::net::ToSocketAddrs;
  use base64::{Engine, engine::general_purpose};
  use reqwest::header;

  let auth_config = get_auth_config()?;
  let host = auth_config.host.unwrap();
  // FIXME: Parse this more robustly.
  let mut split = host.splitn(2, ':');
  split.next().unwrap();
  let port = split.next().unwrap();
  // println!("domain: {}, port: {}", domain, port);
  let addrs: Vec<_> = host.to_socket_addrs()?.collect();
  // println!("addrs: {:?}", addrs);
  let auth_header = format!("Basic {}", general_purpose::STANDARD.encode(format!(":{}", auth_config.token).as_bytes()));
  let mut auth_value = header::HeaderValue::from_str(&auth_header)?;
  auth_value.set_sensitive(true);
  let mut headers = header::HeaderMap::new();
  headers.insert(header::AUTHORIZATION, auth_value);
  let client = reqwest::Client::builder()
    .https_only(true)
    .add_root_certificate(reqwest::Certificate::from_pem(auth_config.cert.as_bytes())?)
    .resolve_to_addrs("hujingzhi", &addrs)
    .default_headers(headers)
    .build()?;
  let response = client.post(format!("https://hujingzhi:{}/api", port)).json(&request).send().await?;
  let response = response.text().await?;
  println!("Response: {}", response);
  Ok(())
}
