use std::collections::HashMap;

use anyhow::{anyhow, bail, Error};
use serde::{Deserialize, Serialize};

use crate::config::ServiceSpec;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpvsServer {
  pub address:       String,
  pub port:          u16,
  pub forward:       String,
  pub weight:        i32,
  pub active_conn:   i32,
  pub inactive_conn: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpvsService {
  pub proto:         String,
  pub local_address: String,
  pub local_port:    u16,
  pub scheduler:     String,
  pub servers:       Vec<IpvsServer>,
}

#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpvsState {
  #[serde_as(as = "Vec<(_, _)>")]
  pub services: HashMap<(String, u16), IpvsService>,
}

fn get_output(cmd: &mut std::process::Command) -> Result<String, Error> {
  let output = cmd.output()?;
  if !output.status.success() {
    bail!("Failed to run {:?}: {:?}", cmd, output);
  }
  Ok(String::from_utf8(output.stdout)?)
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

  let output = get_output(
    std::process::Command::new("ipvsadm").arg("--list").arg("--numeric").arg("--exact"),
  )?;
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

pub fn delete_service(service: &ServiceSpec) -> Result<(), Error> {
  get_output(
    std::process::Command::new("ipvsadm")
      .arg("--delete-service")
      .arg("--tcp-service")
      .arg(&service.on),
  )?;
  Ok(())
}

pub fn create_service(service: &ServiceSpec) -> Result<(), Error> {
  get_output(
    std::process::Command::new("ipvsadm")
      .arg("--add-service")
      .arg("--tcp-service")
      .arg(&service.on)
      //.arg("--persistent")
      .arg("--scheduler")
      .arg("wrr"),
  )?;
  Ok(())
}

pub fn set_loopback_weight(service: &ServiceSpec, port: u16, weight: i32) -> Result<(), Error> {
  // If the new weight is zero, simply delete it.
  if weight == 0 {
    let mut cmd = std::process::Command::new("ipvsadm");
    cmd
      .arg("--delete-server")
      .arg("--tcp-service")
      .arg(&service.on)
      .arg("--real-server")
      .arg(&format!("localhost:{}", port));
    let output = cmd.output()?;
    if !output.status.success() {
      if std::str::from_utf8(&output.stderr)?.contains("No such destination") {
        return Ok(());
      }
      bail!("Failed to run {:?}: {:?}", cmd, output);
    }
    return Ok(());
  }

  for (mode, tolerate_failure) in [("--add-server", true), ("--edit-server", false)] {
    match get_output(
      std::process::Command::new("ipvsadm")
        .arg(mode)
        .arg("--tcp-service")
        .arg(&service.on)
        .arg("--real-server")
        .arg(&format!("localhost:{}", port))
        .arg("--weight")
        .arg(&format!("{}", weight))
        .arg("--masquerading"),
    ) {
      Ok(_) => break,
      Err(_) if tolerate_failure => continue,
      Err(e) => return Err(e),
    }
  }
  Ok(())
}
