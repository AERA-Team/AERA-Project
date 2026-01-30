use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerState {
  pub running: bool,
  pub address: String,
  pub hashrate: f64,
  pub blocks_mined: u64,
  pub total_rewards: u64,
  pub started_at: Option<u64>,
}

impl Default for MinerState {
  fn default() -> Self {
    Self {
      running: false,
      address: "".to_string(),
      hashrate: 0.0,
      blocks_mined: 0,
      total_rewards: 0,
      started_at: None,
    }
  }
}

pub fn load_or_default(path: &Path) -> Result<MinerState> {
  if path.exists() {
    let raw = fs::read_to_string(path)
      .with_context(|| format!("Failed to read status at {}", path.display()))?;
    let state = serde_json::from_str(&raw)
      .with_context(|| format!("Invalid status JSON at {}", path.display()))?;
    Ok(state)
  } else {
    Ok(MinerState::default())
  }
}

pub fn save(path: &Path, state: &MinerState) -> Result<()> {
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent)
      .with_context(|| format!("Failed to create {}", parent.display()))?;
  }
  let raw = serde_json::to_string_pretty(state).context("Failed to serialize status")?;
  fs::write(path, raw)
    .with_context(|| format!("Failed to write status at {}", path.display()))?;
  Ok(())
}
