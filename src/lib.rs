pub mod config;
pub mod ipvs;

use std::{
  collections::{HashMap, HashSet, VecDeque},
  process::ExitStatus,
  sync::atomic,
};

use anyhow::{anyhow, bail, Error};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TokioMutex;
use warp::Filter;

use crate::config::{
  AuthConfig, HujingzhiConfig, HujingzhiTarget, ProcessSpec, Secrets, ServiceSpec,
};

static DEFAULT_AUTH_CONFIG_PATH: &str = ".hjz-auth.yaml";
static DEFAULT_TARGET_PATH: &str = "hjz-target.yaml";

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

fn make_random_word() -> String {
  static ADJECTIVES: &str = include_str!("english-adjectives.txt");
  static NOUNS: &str = include_str!("english-nouns.txt");
  use rand::Rng;
  let mut rng = rand::thread_rng();
  let adjectives = ADJECTIVES.lines().collect::<Vec<_>>();
  let nouns = NOUNS.lines().collect::<Vec<_>>();
  format!(
    "{}-{}",
    adjectives[rng.gen_range(0..adjectives.len())],
    nouns[rng.gen_range(0..nouns.len())]
  )
}

fn get_counter() -> usize {
  static COUNTER: atomic::AtomicUsize = atomic::AtomicUsize::new(0);
  COUNTER.fetch_add(1, atomic::Ordering::Relaxed)
}

fn test_port(port: u16) -> Result<bool, Error> {
  // FIXME: Actually bind to the socket with SO_REUSEADDR to test it.
  Ok(true)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientRequest {
  Ping,
  GetTarget,
  SetTarget { target: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientResponse {
  Pong,
  Success { message: Option<String> },
  Target { target: String },
  Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessStatus {
  Starting,
  Running,
  Sunsetting,
  Exited {
    exit_status: ExitStatus,
    approx_time: std::time::Instant,
  },
}

struct RunningProcessEntry {
  status:           ProcessStatus,
  process:          tokio::process::Child,
  name:             String,
  /// Maps service name to port number.
  port_allocations: HashMap<String, u16>,
}

impl RunningProcessEntry {
  fn new(process: tokio::process::Child, port_allocations: HashMap<String, u16>) -> Self {
    let pid = process.id().unwrap_or(u32::MAX);
    let name = format!("{}-{}-{}", make_random_word(), get_counter(), pid);
    Self {
      status: ProcessStatus::Starting,
      process,
      name,
      port_allocations,
    }
  }
}

struct ProcessSet {
  pub running_versions: Vec<(ProcessSpec, RunningProcessEntry)>,
}

impl ProcessSet {
  fn new() -> Self {
    Self {
      running_versions: Vec::new(),
    }
  }
}

struct SyncedGlobalState {
  target_text:         String,
  target:              HujingzhiTarget,
  processes_by_name:   HashMap<String, ProcessSet>,
  free_loopback_ports: VecDeque<u16>,
}

fn allocate_port(
  free_loopback_ports: &mut VecDeque<u16>,
  service_name: &str,
) -> Result<u16, Error> {
  loop {
    let port =
      free_loopback_ports.pop_front().ok_or_else(|| anyhow!("No more free loopback ports"))?;
    if !test_port(port)? {
      free_loopback_ports.push_back(port);
      continue;
    }
    return Ok(port);
  }
}

fn release_port(free_loopback_ports: &mut VecDeque<u16>, port: u16) {
  free_loopback_ports.push_front(port);
}

struct GlobalState {
  config:  HujingzhiConfig,
  secrets: Secrets,
  synced:  TokioMutex<SyncedGlobalState>,
}

impl GlobalState {
  fn new(
    config: HujingzhiConfig,
    target_text: String,
    target: HujingzhiTarget,
    secrets: Secrets,
  ) -> Self {
    let mut free_loopback_ports = VecDeque::new();
    for i in config.server.loopback_ports.0..config.server.loopback_ports.1 {
      if i == config.server.admin_port {
        println!(
          "\x1b[93m[W]\x1b[0m Loopback port range includes the admin port {}, skipping it",
          i
        );
        continue;
      }
      free_loopback_ports.push_back(i);
    }
    let this = Self {
      config,
      secrets,
      synced: TokioMutex::new(SyncedGlobalState {
        target_text,
        target,
        processes_by_name: HashMap::new(),
        free_loopback_ports,
      }),
    };
    this
  }

  fn launch_process(
    &self,
    free_loopback_ports: &mut VecDeque<u16>,
    process_spec: &ProcessSpec,
  ) -> Result<RunningProcessEntry, Error> {
    println!("\x1b[92m[I]\x1b[0m Launching process {:?}", process_spec.name);

    // Allocate ports for the services.
    let mut port_allocations = HashMap::new();
    for service_name in &process_spec.receives {
      let port = match allocate_port(free_loopback_ports, &service_name) {
        Ok(port) => port,
        Err(e) => {
          // Avoid leaking ports.
          for port in port_allocations.values() {
            release_port(free_loopback_ports, *port);
          }
          return Err(e);
        }
      };
      println!("\x1b[92m[I]\x1b[0m Allocated port {} for service {}", port, service_name);
      port_allocations.insert(service_name.clone(), port);
    }

    //let executable_path = std::fs::canonicalize(&process_spec.command[0])?;
    let mut process = tokio::process::Command::new(&process_spec.command[0]);
    if let Some(cwd) = &process_spec.cwd {
      process.current_dir(cwd);
    }
    if let Some(uid) = &process_spec.uid {
      process.uid(uid.to_uid()?);
    }
    if let Some(gid) = &process_spec.gid {
      process.gid(gid.to_uid()?);
    }
    process.args(&process_spec.command[1..]);
    for (key, value) in &process_spec.env {
      process.env(key, value);
    }
    for (service_name, port) in &port_allocations {
      process.env(&format!("SERVICE_PORT_{}", service_name.to_uppercase()), port.to_string());
    }
    let process = process.spawn()?;
    Ok(RunningProcessEntry::new(process, port_allocations))
  }

  async fn health_check(
    &self,
    process_spec: &ProcessSpec,
    entry: &RunningProcessEntry,
  ) -> Result<bool, Error> {
    let Some(health_check_spec) = &process_spec.health else {
      // If there's no health check, then the process is always considered healthy.
      return Ok(true);
    };
    println!("\x1b[92m[I]\x1b[0m Checking health of process {:?}", process_spec.name);
    let service_port = *entry
      .port_allocations
      .get(&health_check_spec.service)
      .ok_or_else(|| anyhow!("BUG: No port allocated for service {}", health_check_spec.service))?;
    let maybe_slash = if health_check_spec.path.starts_with("/") {
      ""
    } else {
      "/"
    };
    Ok(
      match reqwest::get(format!(
        "http://localhost:{}{}{}",
        service_port, maybe_slash, health_check_spec.path
      ))
      .await
      {
        Ok(response) => response.status().is_success(),
        Err(e) if e.is_connect() => false,
        Err(e) => return Err(e.into()),
      },
    )
  }

  async fn housekeeping(&self) -> Result<(), Error> {
    let mut synced = self.synced.lock().await;
    let SyncedGlobalState {
      target,
      processes_by_name,
      free_loopback_ports,
      ..
    } = &mut *synced;

    // Make sure we have all relevant process sets.
    for process in &target.processes {
      if !processes_by_name.contains_key(&process.name) {
        processes_by_name.insert(process.name.clone(), ProcessSet::new());
      }
    }

    // Get the ipvs state.
    let ipvs_state = ipvs::get_ipvs_state()?;
    //println!("\x1b[92m[I]\x1b[0m Got ipvs state: {:#?}", ipvs_state);

    // Create IPVS services for every service in the target.
    for service in &target.services {
      let (host, port) = ipvs::parse_host_and_port(&service.on)?;
      if !ipvs_state.services.contains_key(&(host.to_string(), port)) {
        println!("\x1b[92m[I]\x1b[0m Creating IPVS service for {}:{}", host, port);
        ipvs::create_service(&service)?;
      }
    }

    // Map process names to specs.
    let mut specs = HashMap::<&str, &ProcessSpec>::new();
    for process_spec in &target.processes {
      assert!(!specs.contains_key(process_spec.name.as_str()));
      specs.insert(&process_spec.name, process_spec);
    }

    // Do upkeep on every process set.
    for (process_name, process_set) in processes_by_name.iter_mut() {
      let target_spec = specs.get(process_name.as_str());
      let most_recent_version = process_set.running_versions.last();
      match (target_spec, most_recent_version) {
        // If we have no target spec then we won't launch anything.
        (None, _) => {}
        // If we have an up-to-date running version then we won't launch anything.
        (Some(target_spec), Some((running_version, _))) if *target_spec == running_version => {}
        // Otherwise, launch a new version.
        (Some(target_spec), _) => {
          let process_entry = match self.launch_process(free_loopback_ports, target_spec) {
            Ok(process_entry) => process_entry,
            Err(e) => {
              println!("\x1b[91m[E]\x1b[0m Failed to launch process {}: {}", process_name, e);
              continue;
            }
          };
          process_set.running_versions.push((ProcessSpec::clone(target_spec), process_entry));
        }
      };
    }

    let mut connection_count_by_loopback_port = HashMap::<u16, i32>::new();
    for service in ipvs_state.services.values() {
      for server in &service.servers {
        if server.address == "127.0.0.1" {
          connection_count_by_loopback_port
            .entry(server.port)
            .and_modify(|count| *count += server.active_conn)
            .or_insert(0);
        }
      }
    }
    println!("\x1b[92m[I]\x1b[0m Connection counts: {:#?}", connection_count_by_loopback_port);

    // Update statuses on processes.
    for process_set in processes_by_name.values_mut() {
      // Perform health checks.
      if let Some((spec, entry)) = process_set.running_versions.last_mut() {
        if entry.status == ProcessStatus::Starting && self.health_check(spec, entry).await? {
          entry.status = ProcessStatus::Running;
        }
      }
      // If a process is running, isn't the last version, and has no connections on any services, then set it to sunsetting.
      for i in 0..process_set.running_versions.len() - 1 {
        let (_, entry) = &mut process_set.running_versions[i];
        let total_connection_count: i32 = entry.port_allocations.values().map(|port| {
          connection_count_by_loopback_port
            .get(port)
            .copied()
            .unwrap_or(0)
        }).sum();
        if entry.status == ProcessStatus::Running && total_connection_count == 0 {
          entry.status = ProcessStatus::Sunsetting;
          // When doing so, send a SIGINT to the process.
          println!("\x1b[92m[I]\x1b[0m Sunsetting {}", entry.name);
          entry.process.id().map(|pid| unsafe { libc::kill(pid as i32, libc::SIGINT) });
        }
      }
      // If a process has exited, then set it to exited.
      for (_, entry) in &mut process_set.running_versions {
        if let Some(exit_status) = entry.process.try_wait()? {
          entry.status = ProcessStatus::Exited {
            exit_status,
            approx_time: std::time::Instant::now(),
          };
        }
      }
    }

    // Adjust IPVS weights based on health of process sets.
    for process_set in processes_by_name.values() {
      for i in 0..process_set.running_versions.len() {
        let is_last = i == process_set.running_versions.len() - 1;
        let (_, entry) = &process_set.running_versions[i];
        match (is_last, entry.status, ipvs_state) {}
      }
    }

    Ok(())
  }

  fn validate_target(&self, target: &HujingzhiTarget) -> Result<(), Error> {
    // Make sure all process and service names are unique.
    macro_rules! check_unique {
      ($field_name:literal, $name:expr) => {{
        let mut names = HashSet::<&str>::new();
        for value in &$name {
          if !names.insert(&value.name) {
            bail!("Duplicate name {} in {}", value.name, $field_name);
          }
        }
      }};
    }
    check_unique!("processes", target.processes);
    check_unique!("services", target.services);
    // Make sure service ports are valid.
    for service in &target.services {
      ipvs::parse_host_and_port(&service.on)?;
    }
    Ok(())
  }

  async fn handle_rest_request(&self, request: ClientRequest) -> Result<ClientResponse, Error> {
    Ok(match request {
      ClientRequest::Ping => ClientResponse::Pong,
      ClientRequest::GetTarget => {
        let target_text = self.synced.lock().await.target_text.clone();
        ClientResponse::Target {
          target: target_text,
        }
      }
      ClientRequest::SetTarget {
        target: target_text,
      } => {
        let mut target: HujingzhiTarget = serde_yaml::from_str(&target_text)?;
        target.apply_secrets(&self.secrets)?;
        self.validate_target(&target)?;
        std::fs::write(DEFAULT_TARGET_PATH, &target_text)?;
        let mut synced = self.synced.lock().await;
        let changed = synced.target != target;
        synced.target_text = target_text;
        synced.target = target;
        ClientResponse::Success {
          message: Some(
            match changed {
              true => "Target updated",
              false => "(no changes made)",
            }
            .to_string(),
          ),
        }
      }
    })
  }
}

pub fn get_auth_config() -> Result<AuthConfig, Error> {
  if let Ok(auth_config_string) = std::fs::read_to_string(DEFAULT_AUTH_CONFIG_PATH) {
    let auth_config: AuthConfig = serde_yaml::from_str(&auth_config_string)?;
    return Ok(auth_config);
  }
  println!("\x1b[93m[W]\x1b[0m No auth config found, generating one...");
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
      "# No orchestration target set\nprocesses: []\n".to_string(),
    Err(err) => return Err(err.into()),
  };
  let target = serde_yaml::from_str(&target_text)?;
  Ok((target_text, target))
}

pub async fn server_main(mut config: HujingzhiConfig) -> Result<(), Error> {
  let secrets = config.secrets.load()?;
  config.apply_secrets(&secrets)?;
  let (target_text, mut target) = get_target()?;
  target.apply_secrets(&secrets)?;
  let global_state: &'static _ =
    Box::leak(Box::new(GlobalState::new(config.clone(), target_text, target, secrets)));

  // Run housekeeping every second.
  tokio::spawn(async move {
    loop {
      match global_state.housekeeping().await {
        Ok(()) => {}
        Err(err) => eprintln!("Housekeeping error: {}", err),
      }
      tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
  });

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
    .then(|(), global_state: &'static GlobalState, request: ClientRequest| async move {
      match global_state.handle_rest_request(request).await {
        Ok(response) => warp::reply::json(&response),
        Err(err) => warp::reply::json(&ClientResponse::Error {
          message: format!("{}", err),
        }),
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
    .with(
      warp::cors()
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
        ]),
    );

  use std::str::FromStr;
  let host = std::net::IpAddr::from_str(&config.server.admin_host)?;

  println!("\x1b[92m[I]\x1b[0m Starting TLS server on port {}", config.server.admin_port);
  Ok(
    warp::serve(all_endpoints)
      .tls()
      .cert(&auth_config.cert)
      .key(auth_config.private.as_ref().unwrap())
      .run((host, config.server.admin_port))
      .await,
  )
}

pub async fn send_request(request: ClientRequest) -> Result<ClientResponse, Error> {
  use std::net::ToSocketAddrs;

  use base64::{engine::general_purpose, Engine};
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
