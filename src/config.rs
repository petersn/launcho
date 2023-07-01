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
#[serde(untagged)]
pub enum UidOrUsername {
  Uid(u32),
  Username(String),
}

impl UidOrUsername {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    Ok(match self {
      UidOrUsername::Uid(_) => {}
      UidOrUsername::Username(s) => *s = secrets.substitute(s)?,
    })
  }

  pub fn to_uid(&self) -> Result<u32, Error> {
    Ok(match self {
      UidOrUsername::Uid(uid) => *uid,
      UidOrUsername::Username(username) => {
        let user = users::get_user_by_name(username)
          .with_context(|| format!("Failed to find user {}", username))?;
        user.uid()
      }
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
  pub id:  String,
  pub file: String,
}

impl ResourceRequest {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    self.id = secrets.substitute(&self.id)?;
    self.file = secrets.substitute(&self.file)?;
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpec {
  pub name:      String,
  pub cwd:       Option<String>,
  pub resources: Vec<ResourceRequest>,
  pub before:    Option<String>,
  pub command:   Vec<String>,
  #[serde(default)]
  pub env:       BTreeMap<String, String>,
  pub receives:  Vec<String>,
  pub health:    Option<HealthCheckSpec>,
  pub uid:       Option<UidOrUsername>,
  pub gid:       Option<UidOrUsername>,
}

impl ProcessSpec {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    self.name = secrets.substitute(&self.name)?;
    if let Some(cwd) = &mut self.cwd {
      *cwd = secrets.substitute(cwd)?;
    }
    for resource in &mut self.resources {
      resource.apply_secrets(secrets)?;
    }
    if let Some(before) = &mut self.before {
      *before = secrets.substitute(before)?;
    }
    for command in &mut self.command {
      *command = secrets.substitute(command)?;
    }
    for env in self.env.values_mut() {
      *env = secrets.substitute(env)?;
    }
    for receive in &mut self.receives {
      *receive = secrets.substitute(receive)?;
    }
    if let Some(health) = &mut self.health {
      health.apply_secrets(secrets)?;
    }
    if let Some(uid) = &mut self.uid {
      uid.apply_secrets(secrets)?;
    }
    if let Some(gid) = &mut self.gid {
      gid.apply_secrets(secrets)?;
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

impl ServiceSpec {
  pub fn apply_secrets(&mut self, secrets: &Secrets) -> Result<(), Error> {
    self.name = secrets.substitute(&self.name)?;
    self.on = secrets.substitute(&self.on)?;
    Ok(())
  }
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
    for service in &mut self.services {
      service.apply_secrets(secrets)?;
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
