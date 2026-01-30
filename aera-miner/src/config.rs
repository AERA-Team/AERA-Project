use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
  pub data_dir: String,
  pub node_url: String,
  pub mining_address: String,
}

impl Default for AppConfig {
  fn default() -> Self {
    Self {
      data_dir: "./data".to_string(),
      node_url: "http://127.0.0.1:3030".to_string(),
      mining_address: "".to_string(),
    }
  }
}

pub fn load_or_create(path: &Path) -> Result<AppConfig> {
  if path.exists() {
    let raw = fs::read_to_string(path)
      .with_context(|| format!("Failed to read config at {}", path.display()))?;
    let config = toml::from_str(&raw)
      .with_context(|| format!("Invalid config TOML at {}", path.display()))?;
    Ok(config)
  } else {
    let config = AppConfig::default();
    save(path, &config)?;
    Ok(config)
  }
}

pub fn save(path: &Path, config: &AppConfig) -> Result<()> {
  let raw = toml::to_string_pretty(config).context("Failed to serialize config")?;
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent)
      .with_context(|| format!("Failed to create {}", parent.display()))?;
  }
  fs::write(path, raw)
    .with_context(|| format!("Failed to write config at {}", path.display()))?;
  Ok(())
}

pub fn resolve_data_dir(config_path: &Path, data_dir: &str) -> PathBuf {
  let path = PathBuf::from(data_dir);
  if path.is_absolute() {
    path
  } else {
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    base.join(path)
  }
}
