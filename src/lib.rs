pub mod config;
pub mod ipvs;
#[cfg(target_os = "linux")]
pub mod server;

use std::collections::HashMap;

use anyhow::Error;
use serde::{Deserialize, Serialize};

use crate::config::{AuthConfig, HujingzhiTarget, ServiceSpec};
use crate::ipvs::IpvsState;

static DEFAULT_AUTH_CONFIG_PATH: &str = ".hjz-auth.yaml";
static DEFAULT_TARGET_PATH: &str = "hjz-target.yaml";
#[allow(unused)] // Only used on Linux
static SERVICE_IP_PREFIX: &str = "127.0.0.";

fn make_cryptographic_token() -> String {
  use rand::RngCore;
  let mut token = [0u8; 32];
  rand::rngs::OsRng.fill_bytes(&mut token);
  token.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessStatus {
  Starting,
  Running,
  Unhealthy,
  Sunsetting,
  Exited { exit_status: i32, approx_time: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LogEvent {
  Warning {
    msg: String,
  },
  Error {
    msg: String,
  },
  CreateIpvsService {
    spec: ServiceSpec,
  },
  LaunchProcess {
    name:             String,
    process_name:     String,
    port_allocations: HashMap<String, u16>,
  },
  StatusChange {
    name:   String,
    status: ProcessStatus,
  },
  WeightChange {
    service: String,
    port:    u16,
    weight:  i32,
  },
  ForceRestart {
    name: String,
  },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientRequest {
  Ping,
  GetTarget,
  SetTarget { target: String },
  Status,
  GetLogs { name: String },
  Restart { name: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientResponse {
  Pong,
  Success {
    message: Option<String>,
  },
  Target {
    target: String,
  },
  Error {
    message: String,
  },
  Status {
    events:     Vec<LogEvent>,
    status:     String,
    ipvs_state: Option<IpvsState>,
  },
  Logs {
    name:   String,
    output: String,
  },
}

pub fn get_auth_config() -> Result<AuthConfig, Error> {
  if let Ok(auth_config_string) = std::fs::read_to_string(DEFAULT_AUTH_CONFIG_PATH) {
    let auth_config: AuthConfig = serde_yaml::from_str(&auth_config_string)?;
    return Ok(auth_config);
  }
  #[cfg(target_os = "linux")]
  server::log_event(LogEvent::Warning {
    msg: "No auth config found, generating one...".to_string(),
  });
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

pub fn get_target() -> Result<(String, HujingzhiTarget), Error> {
  let target_text = match std::fs::read_to_string(DEFAULT_TARGET_PATH) {
    Ok(target_text) => target_text,
    // Check just for file-not-found errors.
    Err(err) if err.kind() == std::io::ErrorKind::NotFound =>
      "# No orchestration target set\nprocesses: []\nservices: []\n".to_string(),
    Err(err) => return Err(err.into()),
  };
  let target = serde_yaml::from_str(&target_text)?;
  Ok((target_text, target))
}

pub async fn send_request(request: ClientRequest) -> Result<ClientResponse, Error> {
  use std::net::ToSocketAddrs;

  use base64::{engine::general_purpose, Engine};
  use reqwest::header;

  let auth_config = get_auth_config()?;
  let host = auth_config.host.as_ref().unwrap();
  let (_, port) = ipvs::parse_host_and_port(host)?;
  let addrs: Vec<_> = host.to_socket_addrs()?.collect();
  let auth_header = format!(
    "Basic {}",
    general_purpose::STANDARD.encode(format!(":{}", auth_config.token).as_bytes())
  );
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
  let response =
    client.post(format!("https://hujingzhi:{}/api", port)).json(&request).send().await?;
  let response = response.text().await?;
  Ok(serde_json::from_str(&response)?)
}
