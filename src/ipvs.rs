use std::collections::HashMap;

use anyhow::{anyhow, bail, Error};

use crate::config::ServiceSpec;

#[derive(Debug)]
pub struct IpvsServer {
  pub address:       String,
  pub port:          u16,
  pub forward:       String,
  pub weight:        i32,
  pub active_conn:   i32,
  pub inactive_conn: i32,
}

#[derive(Debug)]
pub struct IpvsService {
  pub proto:         String,
  pub local_address: String,
  pub local_port:    u16,
  pub scheduler:     String,
  pub servers:       Vec<IpvsServer>,
}

#[derive(Debug)]
pub struct IpvsState {
  pub services: HashMap<(String, u16), IpvsService>,
}

pub fn parse_host_and_port(host_and_port: &str) -> Result<(&str, u16), Error> {
  let mut iter = host_and_port.split(':');
  let host = iter.next().ok_or_else(|| anyhow!("missing host"))?;
  let port = iter.next().ok_or_else(|| anyhow!("missing port"))?.parse::<u16>()?;
  if iter.next().is_some() {
    bail!("unexpected extra components in {}", host_and_port);
  }
  Ok((host, port))
}

pub fn get_ipvs_state() -> Result<IpvsState, Error> {
  fn short_output() -> Error {
    anyhow!("short output from ipvsadm")
  }

  let output = std::process::Command::new("ipvsadm")
    .arg("--list")
    .arg("--numeric")
    .arg("--exact")
    .output()?;
  if !output.status.success() {
    bail!("Failed to run ipvsadm: {:?}", output);
  }
  let output = String::from_utf8(output.stdout)?;
  let mut services = HashMap::new();
  let mut lines = output.lines();
  // Try to parse the first three lines.
  for expected_prefix in [
    "IP Virtual Server",
    "Prot LocalAddress:Port Scheduler",
    "  -> RemoteAddress:Port",
  ] {
    let line = lines.next().ok_or_else(short_output)?;
    if !line.starts_with(expected_prefix) {
      bail!("Unexpected output from ipvsadm: {}", line);
    }
  }
  let mut current_service = None;
  while let Some(line) = lines.next() {
    // Split the line into components.
    let mut components = line.split_whitespace();
    let first = components.next().ok_or_else(short_output)?;
    if first == "->" {
      let current_service: &mut IpvsService =
        current_service.as_mut().ok_or_else(|| anyhow!("unexpected server line"))?;
      let (host, port) = parse_host_and_port(components.next().ok_or_else(short_output)?)?;
      let forward = components.next().ok_or_else(short_output)?;
      let mut get_num =
        || -> Result<i32, Error> { Ok(components.next().ok_or_else(short_output)?.parse()?) };
      let weight = get_num()?;
      let active_conn = get_num()?;
      let inactive_conn = get_num()?;
      current_service.servers.push(IpvsServer {
        address: host.to_string(),
        port,
        forward: forward.to_string(),
        weight,
        active_conn,
        inactive_conn,
      });
    } else {
      let proto = first;
      let (host, port) = parse_host_and_port(components.next().ok_or_else(short_output)?)?;
      let scheduler = components.next().ok_or_else(short_output)?;
      if let Some(service) = current_service {
        services.insert((service.local_address.clone(), service.local_port), service);
      }
      current_service = Some(IpvsService {
        proto:         proto.to_string(),
        local_address: host.to_string(),
        local_port:    port,
        scheduler:     scheduler.to_string(),
        servers:       Vec::new(),
      });
    }
  }
  if let Some(service) = current_service {
    services.insert((service.local_address.clone(), service.local_port), service);
  }
  Ok(IpvsState { services })
}

pub fn create_service(service: &ServiceSpec) -> Result<(), Error> {
  let output = std::process::Command::new("ipvsadm")
    .arg("--add-service")
    .arg("--tcp-service")
    .arg(&service.on)
    .arg("--persistent")
    .arg("--scheduler")
    .arg("wrr")
    .output()?;
  if !output.status.success() {
    bail!("Failed to run ipvsadm: {:?}", output);
  }
  Ok(())
}
