use std::{
  collections::{HashMap, HashSet, VecDeque},
  process::Stdio,
  sync::{atomic, Arc, Mutex},
};

use anyhow::{anyhow, bail, Error};
use tokio::{
  io::AsyncRead,
  process::{ChildStderr, ChildStdout},
  sync::Mutex as TokioMutex,
};
use warp::Filter;

use crate::ipvs;
use crate::{
  config::{AuthConfig, HujingzhiConfig, HujingzhiTarget, ProcessSpec, Secrets},
  constant_time_eq, get_auth_config, get_target, ClientRequest, ClientResponse, LogEvent,
  ProcessStatus, DEFAULT_TARGET_PATH, SERVICE_IP_PREFIX,
};

static HOUSEKEEPING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
// FIXME: These two intervals can only be evaluated in increments of the housekeeping interval.
static START_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
static HEALTH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
static CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
  // We now use libc to bind the port with SO_REUSEADDR.
  let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
  if socket < 0 {
    bail!("Failed to create socket: {}", std::io::Error::last_os_error());
  }
  let mut addr = libc::sockaddr_in {
    sin_family: libc::AF_INET as u16,
    sin_port:   port.to_be(),
    sin_addr:   libc::in_addr {
      s_addr: libc::INADDR_ANY.to_be(),
    },
    sin_zero:   [0; 8],
  };
  let addr_ptr = &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr;
  let reuse_addr = 1;
  let setsockopt_result = unsafe {
    libc::setsockopt(
      socket,
      libc::SOL_SOCKET,
      libc::SO_REUSEADDR,
      &reuse_addr as *const _ as *const libc::c_void,
      std::mem::size_of::<i32>() as u32,
    )
  };
  if setsockopt_result != 0 {
    bail!("Failed to set SO_REUSEADDR on socket: {}", std::io::Error::last_os_error());
  }
  let bind_result =
    unsafe { libc::bind(socket, addr_ptr, std::mem::size_of::<libc::sockaddr_in>() as u32) };
  if bind_result == 0 {
    unsafe { libc::close(socket) };
    Ok(true)
  } else {
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::AddrInUse {
      Ok(false)
    } else {
      Err(anyhow!("Failed to bind socket: {}", err))
    }
  }
}

const LOG_MAX_SIZE: usize = 1000;
static LOG_EVENTS: Mutex<VecDeque<LogEvent>> = Mutex::new(VecDeque::new());

pub fn log_event(event: LogEvent) {
  eprintln!("\x1b[93m[Event]\x1b[0m {:?}", event);
  let mut events = LOG_EVENTS.lock().unwrap();
  events.push_back(event);
  while events.len() > LOG_MAX_SIZE {
    events.pop_front();
  }
}

pub fn get_entire_log() -> Vec<LogEvent> {
  LOG_EVENTS.lock().unwrap().iter().cloned().collect()
}

static RATE_LIMITING: Mutex<Option<HashMap<String, std::time::Instant>>> = Mutex::new(None);

pub fn rate_limit(key: String, duration: std::time::Duration) -> bool {
  let mut map_guard = RATE_LIMITING.lock().unwrap();
  let map = match map_guard.as_mut() {
    Some(map) => map,
    None => {
      *map_guard = Some(HashMap::new());
      map_guard.as_mut().unwrap()
    }
  };
  let now = std::time::Instant::now();
  let last = map.entry(key).or_insert(now);
  if now.duration_since(*last) > duration {
    *last = now;
    true
  } else {
    false
  }
}

struct SpooledOutput {
  buffer: Mutex<Vec<u8>>,
}

impl SpooledOutput {
  fn new(stdout: ChildStdout, stderr: ChildStderr) -> Arc<Self> {
    let this = Arc::new(Self {
      buffer: Mutex::new(Vec::new()),
    });

    fn launch<T>(this: Arc<SpooledOutput>, mut reader: T)
    where
      T: AsyncRead + Unpin + Send + Sync + 'static,
    {
      use tokio::io::AsyncReadExt;
      tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
          let n = reader.read(&mut buf).await.unwrap();
          if n == 0 {
            break;
          }
          let mut guard = this.buffer.lock().unwrap();
          guard.extend_from_slice(&buf[..n]);
          std::mem::drop(guard);
        }
      });
    }
    launch(this.clone(), stdout);
    launch(this.clone(), stderr);

    this
  }

  fn get(&self) -> String {
    let guard = self.buffer.lock().unwrap();
    String::from_utf8_lossy(&guard).to_string()
  }
}

struct RunningProcessEntry {
  status:            ProcessStatus,
  approx_start:      std::time::Instant,
  approx_conn_count: i32,
  process:           tokio::process::Child,
  name:              String,
  /// Maps service name to port number.
  port_allocations:  HashMap<String, u16>,
  output:            Arc<SpooledOutput>,
}

impl RunningProcessEntry {
  fn new(mut process: tokio::process::Child, port_allocations: HashMap<String, u16>) -> Self {
    let pid = process.id().unwrap_or(u32::MAX);
    let name = format!("{}-{}-{}", make_random_word(), get_counter(), pid);
    let stdout = process.stdout.take().unwrap();
    let stderr = process.stderr.take().unwrap();
    Self {
      status: ProcessStatus::Starting,
      approx_start: std::time::Instant::now(),
      approx_conn_count: 0,
      process,
      name,
      port_allocations,
      output: SpooledOutput::new(stdout, stderr),
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
  processed_services:  HashSet<String>,
  processes_by_name:   HashMap<String, ProcessSet>,
  free_loopback_ports: VecDeque<u16>,
  allocated_ports:     HashSet<u16>,
  last_ipvs_state:     Option<ipvs::IpvsState>,
}

fn allocate_port(
  free_loopback_ports: &mut VecDeque<u16>,
  allocated_ports: &mut HashSet<u16>,
) -> Result<u16, Error> {
  loop {
    let port =
      free_loopback_ports.pop_front().ok_or_else(|| anyhow!("No more free loopback ports"))?;
    if !test_port(port)? {
      log_event(LogEvent::Warning {
        msg: format!("Port {} is in use, skipping", port),
      });
      free_loopback_ports.push_back(port);
      continue;
    }
    assert!(!allocated_ports.contains(&port));
    allocated_ports.insert(port);
    return Ok(port);
  }
}

fn release_port(
  free_loopback_ports: &mut VecDeque<u16>,
  allocated_ports: &mut HashSet<u16>,
  port: u16,
) {
  assert!(allocated_ports.contains(&port));
  allocated_ports.remove(&port);
  free_loopback_ports.push_front(port);
}

struct GlobalState {
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
        log_event(LogEvent::Warning {
          msg: format!("Loopback port range includes the admin port {}, skipping it", i),
        });
        continue;
      }
      free_loopback_ports.push_back(i);
    }
    let target = match Self::validate_target(&target) {
      Ok(()) => target,
      Err(e) => {
        log_event(LogEvent::Warning {
          msg: format!("Ignoring stored target, as it is invalid: {}", e),
        });
        HujingzhiTarget::default()
      }
    };
    let this = Self {
      secrets,
      synced: TokioMutex::new(SyncedGlobalState {
        target_text,
        target,
        processed_services: HashSet::new(),
        processes_by_name: HashMap::new(),
        free_loopback_ports,
        allocated_ports: HashSet::new(),
        last_ipvs_state: None,
      }),
    };
    this
  }

  fn launch_process(
    &self,
    free_loopback_ports: &mut VecDeque<u16>,
    allocated_ports: &mut HashSet<u16>,
    process_spec: &ProcessSpec,
  ) -> Result<RunningProcessEntry, Error> {
    // Allocate ports for the services.
    let mut port_allocations = HashMap::new();
    for service_name in &process_spec.receives {
      let port = match allocate_port(free_loopback_ports, allocated_ports) {
        Ok(port) => port,
        Err(e) => {
          log_event(LogEvent::Error {
            msg: format!("Failed to allocate ports when launching process: {}", e),
          });
          // Avoid leaking ports.
          for port in port_allocations.values() {
            release_port(free_loopback_ports, allocated_ports, *port);
          }
          return Err(e);
        }
      };
      //println!("\x1b[92m[I]\x1b[0m Allocated port {} for service {}", port, service_name);
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
    process.stdin(Stdio::null());
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());
    let process = process.spawn()?;
    let entry = RunningProcessEntry::new(process, port_allocations.clone());
    log_event(LogEvent::LaunchProcess {
      name: entry.name.clone(),
      process_name: process_spec.name.clone(),
      port_allocations,
    });
    Ok(entry)
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
    //println!("\x1b[92m[I]\x1b[0m Checking health of process {:?}", process_spec.name);
    let service_port = *entry
      .port_allocations
      .get(&health_check_spec.service)
      .ok_or_else(|| anyhow!("BUG: No port allocated for service {}", health_check_spec.service))?;
    let maybe_slash = if health_check_spec.path.starts_with("/") {
      ""
    } else {
      "/"
    };
    let client = reqwest::Client::builder().timeout(CHECK_TIMEOUT).build()?;
    Ok(
      match client
        .get(format!("http://localhost:{}{}{}", service_port, maybe_slash, health_check_spec.path))
        .send()
        .await
      {
        Ok(response) => response.status().is_success(),
        Err(e) if e.is_connect() || e.is_timeout() => false,
        Err(e) => return Err(e.into()),
      },
    )
  }

  async fn housekeeping(&self) -> Result<(), Error> {
    let mut synced = self.synced.lock().await;
    let SyncedGlobalState {
      target,
      processed_services,
      processes_by_name,
      free_loopback_ports,
      allocated_ports,
      last_ipvs_state,
      ..
    } = &mut *synced;

    // Make sure we have all relevant process sets.
    for process in &target.processes {
      if !processes_by_name.contains_key(&process.name) {
        processes_by_name.insert(process.name.clone(), ProcessSet::new());
      }
    }

    // Get the ipvs state.
    *last_ipvs_state = Some(ipvs::get_ipvs_state()?);
    let ipvs_state = last_ipvs_state.as_ref().unwrap();
    //println!("\x1b[92m[I]\x1b[0m Got ipvs state: {:#?}", ipvs_state);

    // Create IPVS services for every service in the target.
    for service in &target.services {
      // FIXME: Again, I have to think about migrations more carefully.
      if !processed_services.contains(&service.name) {
        //println!("\x1b[92m[I]\x1b[0m Creating IPVS service {} on {}", service.name, service.on);
        log_event(LogEvent::CreateIpvsService {
          spec: service.clone(),
        });
        ipvs::delete_service(&service).ok();
        ipvs::create_service(&service)?;
        processed_services.insert(service.name.clone());
      }

      // let (host, port) = ipvs::parse_host_and_port(&service.on)?;
      // if !ipvs_state.services.contains_key(&(host.to_string(), port)) {
      //   println!("\x1b[92m[I]\x1b[0m Creating IPVS service for {}:{}", host, port);
      //   ipvs::create_service(&service)?;
      // }
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
        // If we have an up-to-date version that's either starting or running then we won't launch anything.
        (
          Some(target_spec),
          Some((
            running_version,
            RunningProcessEntry {
              status: ProcessStatus::Starting | ProcessStatus::Running,
              ..
            },
          )),
        ) if *target_spec == running_version => {}
        // Otherwise, launch a new version.
        (Some(target_spec), _) => {
          let process_entry =
            match self.launch_process(free_loopback_ports, allocated_ports, target_spec) {
              Ok(process_entry) => process_entry,
              Err(e) => {
                log_event(LogEvent::Error {
                  msg: format!("Failed to launch process {}: {}", process_name, e),
                });
                continue;
              }
            };
          process_set.running_versions.push((ProcessSpec::clone(target_spec), process_entry));
        }
      };
    }

    #[derive(Debug)]
    struct LoopbackInfo {
      connections: i32,
      weight:      i32,
    }
    let mut loopback_info = HashMap::<u16, LoopbackInfo>::new();
    for service in ipvs_state.services.values() {
      if !service.local_address.starts_with(SERVICE_IP_PREFIX) {
        continue;
      }
      for server in &service.servers {
        if server.address == "127.0.0.1" {
          assert!(!loopback_info.contains_key(&server.port));
          loopback_info.insert(server.port, LoopbackInfo {
            connections: server.active_conn,
            weight:      server.weight,
          });
        }
      }
    }

    // Update statuses on processes.
    for process_set in processes_by_name.values_mut() {
      macro_rules! update_status {
        ($entry:ident, $status:expr) => {{
          let status = $status;
          log_event(LogEvent::StatusChange {
            name: $entry.name.clone(),
            status,
          });
          $entry.status = status;
        }};
      }
      // Update connection counts.
      for (_, entry) in &mut process_set.running_versions {
        entry.approx_conn_count = entry
          .port_allocations
          .values()
          .map(|port| loopback_info.get(port).map(|info| info.connections).unwrap_or(0))
          .sum();
      }
      // Perform health checks on running processes.
      for (spec, entry) in &mut process_set.running_versions {
        if entry.status == ProcessStatus::Running
          && rate_limit(format!("health:{}", entry.name), HEALTH_INTERVAL)
        {
          // FIXME: Blocking on this potentially slow health check is bad.
          if !self.health_check(spec, entry).await? {
            update_status!(entry, ProcessStatus::Unhealthy);
          }
        }
      }
      // Perform start-up checks on starting processes.
      if let Some((spec, entry)) = process_set.running_versions.last_mut() {
        if entry.status == ProcessStatus::Starting
          && rate_limit(format!("start:{}", entry.name), START_INTERVAL)
        {
          // FIXME: Blocking on this potentially slow health check is bad.
          if self.health_check(spec, entry).await? {
            update_status!(entry, ProcessStatus::Running);
          }
        }
      }
      // If there's a newer running version, then sunset the older running versions.
      let mut have_newer_running_version = false;
      for i in (0..process_set.running_versions.len()).rev() {
        let (_, entry) = &mut process_set.running_versions[i];
        if matches!(
          entry.status,
          ProcessStatus::Starting | ProcessStatus::Running | ProcessStatus::Unhealthy
        ) {
          if have_newer_running_version {
            update_status!(entry, ProcessStatus::Sunsetting);
            // When doing so, send a SIGINT to the process.
            match entry.process.id() {
              Some(pid) => unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
              },
              None => log_event(LogEvent::Error {
                msg: format!("Failed to send SIGTERM to {}: no PID available", entry.name),
              }),
            }
          }
          have_newer_running_version = true;
        }
      }
      // If a process has exited, then set it to exited.
      for (_, entry) in &mut process_set.running_versions {
        if matches!(entry.status, ProcessStatus::Exited { .. }) {
          continue;
        }
        if let Some(exit_status) = entry.process.try_wait()? {
          update_status!(entry, ProcessStatus::Exited {
            exit_status: exit_status.code().unwrap_or(-1),
            approx_time: std::time::SystemTime::now()
              .duration_since(std::time::UNIX_EPOCH)?
              .as_secs(),
          });
        }
      }
    }

    // Release ports of exited processes.
    for process_set in processes_by_name.values_mut() {
      for (_, entry) in &mut process_set.running_versions {
        if matches!(entry.status, ProcessStatus::Exited { .. }) {
          for port in std::mem::take(&mut entry.port_allocations).values() {
            release_port(free_loopback_ports, allocated_ports, *port);
          }
        }
      }
    }

    // // Drop entries that have exited.
    // for process_set in processes_by_name.values_mut() {
    //   process_set
    //     .running_versions
    //     .retain(|(_, entry)| !matches!(entry.status, ProcessStatus::Exited { .. }));
    // }

    // Adjust IPVS weights based on health of process sets.
    for process_set in processes_by_name.values() {
      for (_, entry) in &process_set.running_versions {
        let target_weight = match entry.status {
          ProcessStatus::Running => 1,
          _ => 0,
        };
        for (service_name, port) in &entry.port_allocations {
          // FIXME: There are bugs here relating to changing the port a service is on.
          let service = target
            .services
            .iter()
            .find(|service| service.name == *service_name)
            .ok_or_else(|| anyhow!("BUG: Service {} not found", service_name))?;
          let current_weight = loopback_info.get(port).map(|info| info.weight).unwrap_or(0);
          if current_weight != target_weight {
            log_event(LogEvent::WeightChange {
              service: service.name.clone(),
              port:    *port,
              weight:  target_weight,
            });
            ipvs::set_loopback_weight(service, *port, target_weight)?;
          }
        }
      }
    }

    Ok(())
  }

  fn find_matching_process<'a>(
    name: &str,
    processes_by_name: &'a mut HashMap<String, ProcessSet>,
  ) -> Result<&'a mut RunningProcessEntry, String> {
    let mut result = Err(format!("no process matching {:?} found", name));
    for process_set in processes_by_name.values_mut() {
      for (_, entry) in &mut process_set.running_versions {
        if entry.name.starts_with(&name) {
          if result.is_ok() {
            return Err(format!("multiple processes matching {:?} found", name));
          }
          result = Ok(entry);
        }
      }
    }
    result
  }

  fn validate_target(target: &HujingzhiTarget) -> Result<(), Error> {
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
    // Make sure service ports and IPs are valid.
    for service in &target.services {
      let (host, _) = ipvs::parse_host_and_port(&service.on)?;
      if !host.starts_with(SERVICE_IP_PREFIX) {
        bail!(
          "Service {} has invalid IP {:?} -- must start with {:?}",
          service.name,
          host,
          SERVICE_IP_PREFIX
        );
      }
    }
    Ok(())
  }

  async fn handle_request(&self, request: ClientRequest) -> Result<ClientResponse, Error> {
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
        Self::validate_target(&target)?;
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
      ClientRequest::Status => {
        let synced = self.synced.lock().await;
        let mut formatted_status = String::new();
        for (process_name, process_set) in &synced.processes_by_name {
          formatted_status.push_str(&format!("{}:\n", process_name));
          for (_, entry) in &process_set.running_versions {
            let duration = entry.approx_start.elapsed();
            formatted_status.push_str(&format!(
              "  {}: {:?} (run-time: {:?})\n",
              entry.name, entry.status, duration
            ));
            formatted_status.push_str("    ports:");
            for (service_name, port) in &entry.port_allocations {
              formatted_status.push_str(&format!(" {}:{}", service_name, port));
            }
            formatted_status.push_str("\n");
          }
        }
        ClientResponse::Status {
          events:     get_entire_log(),
          status:     formatted_status,
          ipvs_state: synced.last_ipvs_state.clone(),
        }
      }
      ClientRequest::GetLogs { name } => {
        let mut synced = self.synced.lock().await;
        match Self::find_matching_process(&name, &mut synced.processes_by_name) {
          Ok(entry) => ClientResponse::Logs {
            name:   entry.name.clone(),
            output: entry.output.get(),
          },
          Err(message) => ClientResponse::Error { message },
        }
      }
      ClientRequest::Restart { name } => {
        let mut synced = self.synced.lock().await;
        match Self::find_matching_process(&name, &mut synced.processes_by_name) {
          Ok(entry) => match entry.status {
            ProcessStatus::Starting | ProcessStatus::Running => {
              log_event(LogEvent::ForceRestart {
                name: entry.name.clone(),
              });
              entry.status = ProcessStatus::Unhealthy;
              ClientResponse::Success {
                message: Some(format!("Marked {} for restarting", entry.name)),
              }
            }
            status => ClientResponse::Error {
              message: format!("{} has the inapplicable status {:?}", entry.name, status),
            },
          },
          Err(message) => ClientResponse::Error { message },
        }
      }
    })
  }
}

pub async fn server_main(mut config: HujingzhiConfig) -> Result<(), Error> {
  let secrets = config.secrets.load()?;
  config.apply_secrets(&secrets)?;
  let (target_text, mut target) = get_target()?;
  target.apply_secrets(&secrets)?;
  let global_state: &'static _ =
    Box::leak(Box::new(GlobalState::new(config.clone(), target_text, target, secrets)));

  tokio::spawn(async move {
    loop {
      if let Err(e) = global_state.housekeeping().await {
        log_event(LogEvent::Error {
          msg: format!("Housekeeping error: {}", e),
        });
      }
      tokio::time::sleep(HOUSEKEEPING_INTERVAL).await;
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
    .and(warp::body::json())
    .then(|(), global_state: &'static GlobalState, request: ClientRequest| async move {
      match global_state.handle_request(request).await {
        Ok(response) => warp::reply::json(&response),
        Err(err) => {
          eprintln!("Error: {}", err);
          warp::reply::json(&ClientResponse::Error {
            message: format!("{}", err),
          })
        }
      }
    });

  let all_endpoints = api_endpoint
    // Map rejections to a response.
    .recover(|err: warp::Rejection| async move {
      if let Some(MessageAndStatus(msg, status)) = err.find() {
        Ok(warp::http::Response::builder().status(status).body(*msg).unwrap())
      } else {
        eprintln!("unhandled rejection: {:?}", err);
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

  //println!("\x1b[92m[I]\x1b[0m Starting TLS server on port {}", config.server.admin_port);
  Ok(
    warp::serve(all_endpoints)
      .tls()
      .cert(&auth_config.cert)
      .key(auth_config.private.as_ref().unwrap())
      .run((host, config.server.admin_port))
      .await,
  )
}
