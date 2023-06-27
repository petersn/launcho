use std::collections::{BTreeMap, HashMap};

use anyhow::{bail, Context, Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSpec {
  pub admin_host:     String,
  pub admin_port:     u16,
  pub loopback_ports: (u16, u16),
}

impl ServerSpec {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    self.admin_host = secrets.substitute(&self.admin_host)?;
    Ok(())
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets(pub HashMap<String, String>);

impl Secrets {
  pub fn substitute(&self, input: &str) -> Result<String, Error> {
    let mut output = input.to_string();
    // FIXME: Replace simultaneously.
    for (key, value) in &self.0 {
      output = output.replace(&format!("${{{}}}", key), value);
    }
    if output.contains("${") {
      bail!("Failed to substitute secrets in {}", input);
    }
    Ok(output)
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsSpec {
  pub file:   Option<String>,
  pub env:    Option<Vec<String>>,
  pub values: Option<HashMap<String, String>>,
}

impl Default for SecretsSpec {
  fn default() -> Self {
    Self {
      file:   None,
      env:    None,
      values: None,
    }
  }
}

impl SecretsSpec {
  pub fn load(&self) -> Result<Secrets, Error> {
    let mut secrets = HashMap::new();

    if let Some(file) = &self.file {
      let file_contents = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read secrets file {}", file))?;
      let file_secrets: HashMap<String, String> = serde_yaml::from_str(&file_contents)
        .with_context(|| format!("Failed to parse secrets file {}", file))?;
      secrets.extend(file_secrets);
    }

    if let Some(env) = &self.env {
      for key in env {
        secrets.insert(
          key.to_string(),
          std::env::var(key).with_context(|| format!("Missing env var {}", key))?,
        );
      }
    }

    if let Some(values) = &self.values {
      secrets.extend(values.clone());
    }

    Ok(Secrets(secrets))
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HujingzhiConfig {
  pub server:  ServerSpec,
  pub secrets: SecretsSpec,
}

impl HujingzhiConfig {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    self.server.apply_secrets(secrets)?;
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckSpec {
  pub service: String,
  pub path:    String,
}

impl HealthCheckSpec {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    self.service = secrets.substitute(&self.service)?;
    self.path = secrets.substitute(&self.path)?;
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpec {
  pub name:    String,
  pub command: Vec<String>,
  #[serde(default)]
  pub env:     BTreeMap<String, String>,
  pub receives: Vec<String>,
  pub health:  Option<HealthCheckSpec>,
}

impl ProcessSpec {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    for command in &mut self.command {
      *command = secrets.substitute(command)?;
    }
    for (key, value) in &mut self.env {
      *value = secrets.substitute(value)?;
    }
    for receive in &mut self.receives {
      *receive = secrets.substitute(receive)?;
    }
    if let Some(health) = &mut self.health {
      health.apply_secrets(secrets)?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
  pub name: String,
  pub on:   String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HujingzhiTarget {
  pub processes: Vec<ProcessSpec>,
  pub services:  Vec<ServiceSpec>,
}

impl HujingzhiTarget {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    for process in &mut self.processes {
      process.apply_secrets(secrets)?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
  pub host:    Option<String>,
  pub cert:    String,
  pub private: Option<String>,
  pub token:   String,
}
