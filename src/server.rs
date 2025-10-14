use std::{
  collections::{HashMap, HashSet, VecDeque},
  path::PathBuf,
  process::Stdio,
  sync::{atomic, Arc, Mutex},
};

use anyhow::{anyhow, bail, Context, Error};
use tokio::{
  io::AsyncRead,
  process::{ChildStderr, ChildStdout},
  sync::{Mutex as TokioMutex, MutexGuard as TokioMutexGuard},
};
use warp::Filter;

use crate::{
  config::{
    delete_extra_secrets, insert_and_save_secret, AuthConfig, LaunchoConfig, LaunchoTarget,
    ProcessSpec, Secrets, ServiceSpec,
  },
  get_auth_config, get_target, get_target_path, guarantee_launcho_directory, storage, ClientRequest,
  ClientResponse, LogEvent, ProcessStatus,
};
use crate::{ipvs, GetAuthConfigMode};

static SERVICE_IP_PREFIX: &str = "127.0.0.";
static HOUSEKEEPING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
static CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

// FIXME: These rate limits can only be evaluated in increments of the housekeeping interval.
static START_RATE_LIMIT: &RateLimit = &RateLimit {
  prefix:           "start",
  duration:         std::time::Duration::from_secs(2),
  backoff_duration: std::time::Duration::from_secs(5),
  max_attempts:     2,
};
static HEALTH_CHECK_RATE_LIMIT: &RateLimit = &RateLimit {
  prefix:           "health_check",
  duration:         std::time::Duration::from_secs(60),
  backoff_duration: std::time::Duration::from_secs(60),
  max_attempts:     1,
};
static LAUNCH_RATE_LIMIT: &RateLimit = &RateLimit {
  prefix:           "launch",
  duration:         std::time::Duration::from_secs(30),
  backoff_duration: std::time::Duration::from_secs(1200),
  max_attempts:     3,
};

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
  use subtle::ConstantTimeEq;
  a.ct_eq(b).into()
}

fn get_unix_time() -> u64 {
  std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
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
    unsafe { libc::close(socket) };
    bail!("Failed to set SO_REUSEADDR on socket: {}", std::io::Error::last_os_error());
  }
  let bind_result =
    unsafe { libc::bind(socket, addr_ptr, std::mem::size_of::<libc::sockaddr_in>() as u32) };
  if bind_result == 0 {
    unsafe { libc::close(socket) };
    Ok(true)
  } else {
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::AddrInUse {
      Ok(false)
    } else {
      Err(anyhow!("Failed to bind socket: {}", e))
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

#[derive(PartialEq, Eq)]
pub enum RateLimitResult {
  Success,
  RateLimited,
  Backoff,
}

impl RateLimitResult {
  pub fn is_success(&self) -> bool {
    match self {
      RateLimitResult::Success => true,
      _ => false,
    }
  }
}

pub struct RateLimit {
  prefix:           &'static str,
  duration:         std::time::Duration,
  backoff_duration: std::time::Duration,
  max_attempts:     usize,
}

static RATE_LIMITING: Mutex<Option<HashMap<String, Vec<std::time::Instant>>>> = Mutex::new(None);

macro_rules! get_rate_limiting {
  ($map:ident) => {
    let mut map_guard = RATE_LIMITING.lock().unwrap();
    let $map = match map_guard.as_mut() {
      Some(map) => map,
      None => {
        *map_guard = Some(HashMap::new());
        map_guard.as_mut().unwrap()
      }
    };
  };
}

// NB: count must always have the same value for a particular key.
pub fn check_rate_limit(key: &str, rate_limit: &RateLimit) -> RateLimitResult {
  let key = format!("{}:{}", rate_limit.prefix, key);
  get_rate_limiting!(map);
  let occurrences = map.entry(key).or_insert(Vec::new());
  let now = std::time::Instant::now();
  if let Some(last) = occurrences.last() {
    if now.duration_since(*last) < rate_limit.duration {
      return RateLimitResult::RateLimited;
    }
  }
  if let Some(first) = occurrences.first() {
    if occurrences.len() >= rate_limit.max_attempts
      && now.duration_since(*first) < rate_limit.backoff_duration
    {
      return RateLimitResult::Backoff;
    }
  }
  RateLimitResult::Success
}

pub fn rate_limit_event(key: &str, rate_limit: &RateLimit) {
  let key = format!("{}:{}", rate_limit.prefix, key);
  get_rate_limiting!(map);
  let occurrences = map.entry(key).or_insert(Vec::new());
  let now = std::time::Instant::now();
  occurrences.push(now);
  while occurrences.len() > rate_limit.max_attempts {
    occurrences.remove(0);
  }
}

fn clear_launch_rate_limits() {
  get_rate_limiting!(map);
  map.retain(|k, _| !k.starts_with("launch:"));
}

pub const MAX_LOG_SPOOL_LENGTH: usize = 64 * 1024 * 1024;

struct SpooledOutput {
  buffer: Mutex<VecDeque<u8>>,
}

impl SpooledOutput {
  fn new(stdout: ChildStdout, stderr: ChildStderr) -> Arc<Self> {
    let this = Arc::new(Self {
      buffer: Mutex::new(VecDeque::new()),
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
          guard.extend(&buf[..n]);
          guard.truncate_front(MAX_LOG_SPOOL_LENGTH);
          std::mem::drop(guard);
        }
      });
    }
    launch(this.clone(), stdout);
    launch(this.clone(), stderr);

    this
  }

  fn get(&self) -> String {
    let mut guard = self.buffer.lock().unwrap();
    String::from_utf8_lossy(guard.make_contiguous()).to_string()
  }
}

struct RunningProcessEntry {
  status:            ProcessStatus,
  approx_start:      std::time::Instant,
  approx_conn_count: i32,
  process:           tokio::process::Child,
  name:              String,
  _cwd:              PathBuf,
  /// Maps service name to port number.
  port_allocations:  HashMap<String, u16>,
  output:            Arc<SpooledOutput>,
}

impl RunningProcessEntry {
  fn new(
    mut process: tokio::process::Child,
    cwd: PathBuf,
    port_allocations: HashMap<String, u16>,
  ) -> Self {
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
      _cwd: cwd,
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

#[derive(Debug, PartialEq, Eq, Hash)]
struct AppliedIpvsService {
  name: String,
  host: String,
  port: u16,
}

struct SyncedGlobalState {
  secrets:             Secrets,
  target_text:         String,
  target:              LaunchoTarget,
  clean_services:      HashSet<AppliedIpvsService>,
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
  // Whoops, I no longer have any unsynced state. Should I remove this extra type?
  synced: TokioMutex<SyncedGlobalState>,
}

impl GlobalState {
  fn new(
    config: LaunchoConfig,
    target_text: String,
    target: LaunchoTarget,
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
        LaunchoTarget::default()
      }
    };
    let this = Self {
      synced: TokioMutex::new(SyncedGlobalState {
        secrets,
        target_text,
        target,
        clean_services: HashSet::new(),
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
          // FIXME: There are many other paths along which I leak ports, not just this one!
          // I should avoid leaking ports in all of them.
          for port in port_allocations.values() {
            release_port(free_loopback_ports, allocated_ports, *port);
          }
          return Err(e);
        }
      };
      port_allocations.insert(service_name.clone(), port);
    }

    let mut command = tokio::process::Command::new(&process_spec.command[0]);
    let cwd = match &process_spec.cwd {
      Some(cwd) => PathBuf::from(cwd),
      None => {
        // FIXME: Clean this stuff up.
        crate::already_exists_ok(std::fs::create_dir(&"/tmp/launcho-procs"))?;
        let nonce: u64 = rand::random();
        let path = format!("/tmp/launcho-procs/tmp-{:016x}", nonce);
        crate::already_exists_ok(std::fs::create_dir(&path))?;
        command.current_dir(&path);
        PathBuf::from(path)
      }
    };
    command.current_dir(&cwd);
    // Unpack requested resources.
    for resource_request in &process_spec.resources {
      let target = cwd.join(&resource_request.file);
      storage::copy_resource(&resource_request.id, &target)?;
    }
    // Perform the optional before command.
    if let Some(before) = &process_spec.before {
      let mut before_command = std::process::Command::new("sh");
      before_command.arg("-c").arg(before).current_dir(&cwd);
      if let Some(uid) = &process_spec.uid {
        command.uid(uid.to_uid()?);
      }
      if let Some(gid) = &process_spec.gid {
        command.gid(gid.to_uid()?);
      }
      for (key, value) in &process_spec.env {
        command.env(key, value);
      }
      for (service_name, port) in &port_allocations {
        command.env(&format!("SERVICE_PORT_{}", service_name.to_uppercase()), port.to_string());
      }
      match before_command.output() {
        Ok(output) =>
          if !output.status.success() {
            log_event(LogEvent::Error {
              msg: format!("Before command failed: {}", String::from_utf8_lossy(&output.stderr)),
            });
            return Err(anyhow!("Before command failed"));
          },
        Err(e) => {
          log_event(LogEvent::Error {
            msg: format!("Failed to run before command: {}", e),
          });
          return Err(anyhow!("Failed to run before command"));
        }
      }
    }
    // FIXME: Maybe deduplicate this against the above.
    if let Some(uid) = &process_spec.uid {
      command.uid(uid.to_uid()?);
    }
    if let Some(gid) = &process_spec.gid {
      command.gid(gid.to_uid()?);
    }
    command.args(&process_spec.command[1..]);
    for (key, value) in &process_spec.env {
      command.env(key, value);
    }
    for (service_name, port) in &port_allocations {
      command.env(&format!("SERVICE_PORT_{}", service_name.to_uppercase()), port.to_string());
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // FIXME: I should try to find a way to distinguish between the binary and cwd not being found.
    let process = command
      .spawn()
      .with_context(|| format!("Failed to launch process {:?}", process_spec.command))?;
    let entry = RunningProcessEntry::new(process, cwd, port_allocations.clone());
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
      clean_services,
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

    // Create IPVS services for every service in the target.
    for service in &target.services {
      let (host, port) = ipvs::parse_host_and_port(&service.on)?;
      let key = AppliedIpvsService {
        name: service.name.clone(),
        host: host.to_string(),
        port,
      };
      if !clean_services.contains(&key) {
        log_event(LogEvent::CreateIpvsService {
          spec: service.clone(),
        });
        ipvs::delete_service(&service).ok();
        ipvs::create_service(&service)?;
        clean_services.insert(key);
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
        // If we have no target spec then we should kill all running versions.
        (None, _) =>
          for (_, version) in &mut process_set.running_versions {
            if !matches!(version.status, ProcessStatus::Exited { .. }) {
              log_event(LogEvent::Kill {
                name: version.name.clone(),
              });
              version.process.kill().await.ok();
            }
          },
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
          if check_rate_limit(&process_name, LAUNCH_RATE_LIMIT).is_success() {
            rate_limit_event(&process_name, LAUNCH_RATE_LIMIT);
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
        }
      };
    }

    // Get the ipvs state.
    *last_ipvs_state = Some(ipvs::get_ipvs_state()?);
    let ipvs_state = last_ipvs_state.as_ref().unwrap();

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
          && check_rate_limit(&entry.name, HEALTH_CHECK_RATE_LIMIT).is_success()
        {
          rate_limit_event(&entry.name, HEALTH_CHECK_RATE_LIMIT);
          // FIXME: Blocking on this potentially slow health check is bad.
          if !self.health_check(spec, entry).await? {
            update_status!(entry, ProcessStatus::Unhealthy);
          }
        }
      }
      // Perform start-up checks on starting processes.
      if let Some((spec, entry)) = process_set.running_versions.last_mut() {
        if entry.status == ProcessStatus::Starting
          && check_rate_limit(&entry.name, START_RATE_LIMIT).is_success()
        {
          rate_limit_event(&entry.name, START_RATE_LIMIT);
          // FIXME: Blocking on this potentially slow health check is bad.
          if self.health_check(spec, entry).await? {
            update_status!(entry, ProcessStatus::Running);
          }
        }
      }
      // If there's a newer version that's at a strictly higher level
      // of functionality, then sunset the older running versions.
      let mut best_goodness = 0;
      for i in (0..process_set.running_versions.len()).rev() {
        let (_, entry) = &mut process_set.running_versions[i];
        let goodness = match entry.status {
          // I'm not sure, which value is better, unheathy, or starting?
          ProcessStatus::Unhealthy => 1,
          ProcessStatus::Starting => 2,
          ProcessStatus::Running => 3,
          _ => continue,
        };
        if goodness <= best_goodness {
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
        best_goodness = best_goodness.max(goodness);
      }
      // If a process has exited, then set it to exited.
      for (_, entry) in &mut process_set.running_versions {
        if matches!(entry.status, ProcessStatus::Exited { .. }) {
          continue;
        }
        if let Some(exit_status) = entry.process.try_wait()? {
          update_status!(entry, ProcessStatus::Exited {
            exit_status: exit_status.code().unwrap_or(-1),
            approx_time: get_unix_time(),
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

  fn validate_target(target: &LaunchoTarget) -> Result<(), Error> {
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
    // Make sure service ports and IPs are valid, and each service is on a unique IP+port pair.
    let mut services_on = HashSet::new();
    for service in &target.services {
      let (host, port) = ipvs::parse_host_and_port(&service.on)?;
      if !services_on.insert((host, port)) {
        bail!("Duplicated service address+port: {}", service.on);
      }
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

  fn change_target(
    &self,
    synced: &mut TokioMutexGuard<'_, SyncedGlobalState>,
    new_target_text: String,
    new_target: LaunchoTarget,
  ) -> Result<(), Error> {
    // We delete every service that no longer exists.
    // The above code will take care of creating new ones.
    let mut new_services: HashSet<AppliedIpvsService> = HashSet::new();
    for service in &new_target.services {
      let (host, port) = ipvs::parse_host_and_port(&service.on)?;
      new_services.insert(AppliedIpvsService {
        name: service.name.clone(),
        host: host.to_owned(),
        port,
      });
    }
    synced.clean_services.retain(|applied_service| {
      if new_services.contains(&applied_service) {
        true
      } else {
        // NB: This is a little weird to reconstitute.
        // I should probably just parse my inputs better, and get rid of this distinction.
        let spec = ServiceSpec {
          name: applied_service.name.clone(),
          on:   format!("{}:{}", applied_service.host, applied_service.port),
        };
        log_event(LogEvent::DeleteIpvsService { spec: spec.clone() });
        if let Err(e) = ipvs::delete_service(&spec) {
          log_event(LogEvent::Warning {
            msg: format!("Failed to delete service: {}", e),
          });
        }
        false
      }
    });

    // Clear all launch-related rate limits.
    clear_launch_rate_limits();

    synced.target_text = new_target_text;
    synced.target = new_target;
    Ok(())
  }

  pub fn rebuild_target_after_secrets_change(
    &self,
    synced: &mut TokioMutexGuard<'_, SyncedGlobalState>,
  ) -> Result<bool, Error> {
    let mut new_target: LaunchoTarget = serde_yaml::from_str(&synced.target_text)?;
    new_target.apply_secrets(&synced.secrets)?;
    Self::validate_target(&new_target)?;
    if new_target != synced.target {
      self.change_target(synced, synced.target_text.clone(), new_target)?;
      Ok(true)
    } else {
      Ok(false)
    }
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
        let mut synced = self.synced.lock().await;
        let mut target: LaunchoTarget = serde_yaml::from_str(&target_text)?;
        target.apply_secrets(&synced.secrets)?;
        Self::validate_target(&target)?;
        std::fs::write(get_target_path()?, &target_text)?;
        let changed = synced.target != target;
        if changed {
          self.change_target(&mut synced, target_text, target)?;
        }
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
      ClientRequest::GetSecrets { names } => {
        let synced = self.synced.lock().await;
        ClientResponse::Secrets {
          secrets: names
            .into_iter()
            .map(|name| {
              let secret = synced.secrets.0.get(&name).cloned();
              (name, secret)
            })
            .collect(),
        }
      }
      ClientRequest::SetSecret { name, value } => {
        let mut synced = self.synced.lock().await;
        insert_and_save_secret(&mut synced.secrets, &name, &value)?;
        let changed = self.rebuild_target_after_secrets_change(&mut synced)?;
        ClientResponse::Success {
          message: Some(
            match changed {
              true => "Secret updated, target changed",
              false => "Secret updated, target unchanged",
            }
            .to_string(),
          ),
        }
      }
      ClientRequest::DeleteSecrets { names } => {
        let mut synced = self.synced.lock().await;
        let mut message = delete_extra_secrets(&mut synced.secrets, &names)?;
        let changed = self.rebuild_target_after_secrets_change(&mut synced)?;
        if changed {
          message.push_str("(target changed)\n");
        }
        ClientResponse::Success {
          message: Some(message),
        }
      }
      ClientRequest::ListSecrets => {
        let synced = self.synced.lock().await;
        ClientResponse::SecretList {
          secrets: synced.secrets.0.keys().cloned().collect(),
        }
      }
      ClientRequest::Status { all } => {
        let synced = self.synced.lock().await;
        let mut formatted_status = String::new();
        for (process_name, process_set) in &synced.processes_by_name {
          formatted_status.push_str(&format!("{}:\n", process_name));
          let rv = &process_set.running_versions;
          let subslice = match all {
            true => &rv[..],
            false => &rv[rv.len().saturating_sub(5)..],
          };
          if subslice.len() != rv.len() {
            println!("  ... {} omitted (--all to show)", rv.len() - subslice.len());
          }
          for (_, entry) in subslice {
            let duration = match entry.status {
              ProcessStatus::Exited { approx_time, .. } =>
                std::time::Duration::from_secs(get_unix_time() - approx_time),
              _ => entry.approx_start.elapsed(),
            };
            formatted_status.push_str(&format!(
              "  {}: {:?} (run-time: {:.0?})",
              entry.name, entry.status, duration,
            ));
            // FIXME: This bit doesn't even make sense, as a process
            // can't be starting if it's failing to launch.
            // TODO: Figure out what I want here.
            // if entry.status == ProcessStatus::Starting
            //   && check_rate_limit(&process_name, LAUNCH_RATE_LIMIT)
            //     == RateLimitResult::Backoff
            // {
            //   formatted_status.push_str(" (too many crashes -- backing off)");
            // }
            formatted_status.push_str("\n");
            if !entry.port_allocations.is_empty() {
              formatted_status.push_str("    ports:");
              for (service_name, port) in &entry.port_allocations {
                formatted_status.push_str(&format!(" {}:{}", service_name, port));
              }
              formatted_status.push_str("\n");
            }
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
      ClientRequest::DeleteResources { ids } => {
        let errors =
          ids.iter().filter_map(|id| storage::delete_resource(id).err()).collect::<Vec<_>>();
        if errors.is_empty() {
          ClientResponse::Success { message: None }
        } else {
          ClientResponse::Error {
            message: format!("Failed to delete resources: {:?}", errors),
          }
        }
      }
      ClientRequest::ListResources => ClientResponse::ResourceList {
        resources: storage::list_resources()?,
      },
      ClientRequest::ClearLaunchRateLimits => {
        clear_launch_rate_limits();
        ClientResponse::Success { message: None }
      }
    })
  }
}

pub async fn server_main(mut config: LaunchoConfig) -> Result<(), Error> {
  guarantee_launcho_directory()?;

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

  let auth_config: &'static AuthConfig =
    Box::leak(Box::new(get_auth_config(None, GetAuthConfigMode::ServerCreateIfNotExists)?));

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
  let validate_auth = move |auth_header: Option<String>| async move {
    match auth_header.unwrap_or_default().strip_prefix("Basic ") {
      Some(basic) => match check_basic_auth(basic) {
        Ok(()) => Ok(()),
        Err(e) =>
          Err(warp::reject::custom(MessageAndStatus(e, warp::http::StatusCode::UNAUTHORIZED))),
      },
      None => Err(warp::reject::custom(MessageAndStatus(
        r#"Authorization header is required, like:

Authorization: Basic <base64 of "any username:server token">
"#,
        warp::http::StatusCode::UNAUTHORIZED,
      ))),
    }
  };

  fn make_response(r: Result<ClientResponse, Error>) -> impl warp::Reply {
    match r {
      Ok(response) => warp::reply::json(&response),
      Err(e) => {
        eprintln!("Error: {}", e);
        warp::reply::json(&ClientResponse::Error {
          message: format!("{}", e),
        })
      }
    }
  }

  let check_auth = warp::header::optional::<String>("authorization")
    .and_then(validate_auth)
    .and(warp_global_state.clone());

  let api_endpoint = check_auth.and(warp::path!("api")).and(warp::body::json()).then(
    |(), global_state: &'static GlobalState, request: ClientRequest| async move {
      make_response(global_state.handle_request(request).await)
    },
  );

  // FIXME: Don't spool the file, stream to disk.
  let upload_endpoint = check_auth
    .and(warp::path!("upload"))
    .and(warp::body::content_length_limit(1024 * 1024 * 1024))
    .and(warp::body::bytes())
    .and(warp::query::<HashMap<String, String>>())
    .then(|(), _: &'static GlobalState, bytes: bytes::Bytes, query: HashMap<String, String>| async move {
      fn handle_upload(bytes: bytes::Bytes, query: HashMap<String, String>) -> Result<ClientResponse, Error> {
        let name = query.get("name").ok_or_else(|| anyhow!("Missing name query parameter"))?;
        let id = storage::write_resource(name.clone(), &bytes)?;
        Ok(ClientResponse::Success { message: Some(id) })
      }
      make_response(handle_upload(bytes, query))
    });

  // FIXME: Don't slurp the file, stream from disk.
  let download_endpoint = check_auth
    .and(warp::path!("download"))
    .and(warp::query::<HashMap<String, String>>())
    .then(|(), _: &'static GlobalState, query: HashMap<String, String>| async move {
      fn handle_download(query: HashMap<String, String>) -> Result<Vec<u8>, Error> {
        let id = query.get("id").ok_or_else(|| anyhow!("Missing id query parameter"))?;
        Ok(storage::read_resource(id)?)
      }
      let builder = warp::http::Response::builder();
      match handle_download(query) {
        Ok(data) => builder
          .header("Content-Type", "application/octet-stream")
          .header("Content-Length", data.len())
          .body(data),
        Err(e) =>
          builder.status(warp::http::StatusCode::BAD_REQUEST).body(format!("{}", e).into_bytes()),
      }
      .unwrap()
    });

  let all_endpoints = api_endpoint
    .or(upload_endpoint)
    .or(download_endpoint)
    // Map rejections to a response.
    .recover(|e: warp::Rejection| async move {
      if let Some(MessageAndStatus(msg, status)) = e.find() {
        Ok(warp::http::Response::builder().status(status).body(*msg).unwrap())
      } else {
        eprintln!("unhandled rejection: {:?}", e);
        Err(e)
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
  println!("Starting server at {}:{}", host, config.server.admin_port);
  Ok(
    warp::serve(all_endpoints)
      .tls()
      .cert(&auth_config.cert)
      .key(auth_config.private.as_ref().unwrap())
      .run((host, config.server.admin_port))
      .await,
  )
}
