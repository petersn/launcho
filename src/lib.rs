pub mod config;
pub mod ipvs;
#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod storage;

use std::collections::HashMap;

use anyhow::{bail, Context, Error};
use serde::{Deserialize, Serialize};

use crate::config::{AuthConfig, HujingzhiTarget, ServiceSpec};
use crate::ipvs::IpvsState;

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
  DeleteIpvsService {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TarballListEntry {
  pub id:   String,
  pub name: String,
  pub size: u64,
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
  UploadTarball { name: String, data: Vec<u8> },
  DownloadTarball { id: String },
  DeleteTarballs { ids: Vec<String> },
  ListTarballs,
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
  Tarball {
    id:   String,
    data: Vec<u8>,
  },
  TarballList {
    tarballs: Vec<TarballListEntry>,
  },
}

#[derive(PartialEq, Eq)]
pub enum GetAuthConfigMode {
  ServerCreateIfNotExists,
  ServerFailIfNotExists,
  Client,
}

pub fn get_hjz_directory() -> Result<String, Error> {
  Ok(format!("{}/.hjz", std::env::var("HOME")?))
}

pub fn guarantee_hjz_directory() -> Result<(), Error> {
  fn already_exists_ok(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
      Ok(()) => Ok(()),
      Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
      Err(e) => Err(e),
    }
  }
  let hjz_dir = get_hjz_directory()?;
  already_exists_ok(std::fs::create_dir(&hjz_dir))?;
  already_exists_ok(std::fs::create_dir(format!("{}/{}", hjz_dir, "storage")))?;
  Ok(())
}

pub fn get_auth_config(mode: GetAuthConfigMode) -> Result<AuthConfig, Error> {
  let config_path_suffix = match mode {
    GetAuthConfigMode::ServerCreateIfNotExists | GetAuthConfigMode::ServerFailIfNotExists =>
      "hjz-server-auth.yaml",
    GetAuthConfigMode::Client => "hjz-client-auth.yaml",
  };
  let hjz_dir = get_hjz_directory()?;
  let config_path = format!("{}/{}", hjz_dir, config_path_suffix);
  if let Ok(auth_config_string) = std::fs::read_to_string(&config_path) {
    let auth_config: AuthConfig = serde_yaml::from_str(&auth_config_string)?;
    return Ok(auth_config);
  }
  match mode {
    GetAuthConfigMode::ServerFailIfNotExists =>
      bail!("Auth info not found at {}\nStart the server to create the auth.", config_path),
    GetAuthConfigMode::Client =>
      bail!("Auth info not found at {}\nOn the server run `hjz print-auth`, and paste the result into a file at {}", config_path, config_path),
    GetAuthConfigMode::ServerCreateIfNotExists => {},
  }
  #[cfg(target_os = "linux")]
  server::log_event(LogEvent::Warning {
    msg: format!("Auth file not found at {} -- generating a new one", config_path),
  });
  let subject_alt_names = vec!["hujingzhi".to_string()];
  let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
  let auth_config = AuthConfig {
    host:    None,
    cert:    cert.serialize_pem()?,
    private: Some(cert.serialize_private_key_pem()),
    token:   make_cryptographic_token(),
  };
  let auth_config_yaml = serde_yaml::to_string(&auth_config)?;
  guarantee_hjz_directory()?;
  std::fs::write(config_path, &auth_config_yaml)?;
  Ok(auth_config)
}

pub fn get_config_path() -> Result<String, Error> {
  Ok(format!("{}/hjz-config.yaml", get_hjz_directory()?))
}

pub fn get_target_path() -> Result<String, Error> {
  Ok(format!("{}/hjz-target.yaml", get_hjz_directory()?))
}

pub fn get_target() -> Result<(String, HujingzhiTarget), Error> {
  let target_text = match std::fs::read_to_string(get_target_path()?) {
    Ok(target_text) => target_text,
    // Check just for file-not-found errors.
    Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
      include_str!("default-target.yaml").to_string(),
    Err(e) => return Err(e.into()),
  };
  let target = serde_yaml::from_str(&target_text)?;
  Ok((target_text, target))
}

pub async fn send_request(request: ClientRequest) -> Result<ClientResponse, Error> {
  use std::net::ToSocketAddrs;

  use base64::{engine::general_purpose, Engine};
  use reqwest::header;

  let auth_config = get_auth_config(GetAuthConfigMode::Client)?;
  let host = auth_config.host.as_ref().unwrap();
  let (_, port) = ipvs::parse_host_and_port(host)?;
  let addrs: Vec<_> = host
    .to_socket_addrs()
    .with_context(|| format!("DNS lookup for {} failed", host))?
    .collect();
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
  let response = client
    .post(format!("https://hujingzhi:{}/api", port))
    .json(&request)
    .send()
    .await
    .with_context(|| format!("Request to {} failed", host))?;
  let response = response.text().await?;
  Ok(serde_json::from_str(&response)?)
}
