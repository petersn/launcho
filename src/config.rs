use std::collections::HashMap;

use anyhow::{Context, Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSpec {
  pub host:       String,
  pub port:       u16,
  pub debug_mode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets(pub HashMap<String, String>);

impl Secrets {
  pub fn substitute(&self, input: &str) -> String {
    let mut output = input.to_string();
    // FIXME: Replace simultaneously.
    for (key, value) in &self.0 {
      output = output.replace(&format!("${{{}}}", key), value);
    }
    output
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
pub struct ProcessSpec {
  pub name:    String,
  pub command: String,
  pub args:    Vec<String>,
  pub env:     Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HujingzhiConfig {
  pub server:  ServerSpec,
  pub secrets: SecretsSpec,
  pub processes: Vec<ProcessSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
  pub host:    Option<String>,
  pub cert:    String,
  pub private: Option<String>,
  pub token:   String,
}
