use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::state::{load_or_default, save as save_state};

const HASH_BATCH: u64 = 50_000;
const REPORT_INTERVAL: Duration = Duration::from_secs(1);
const REWARD_PER_BLOCK: u64 = 2;
const DIFFICULTY_ZERO_BYTES: usize = 1;

pub fn run_miner(data_dir: &Path, address: &str) -> Result<()> {
  let status_path = data_dir.join("miner_status.json");
  let mut state = load_or_default(&status_path)?;

  if state.running {
    return Err(anyhow!("Miner already running"));
  }

  state.running = true;
  state.address = address.to_string();
  state.started_at = Some(crate::now_unix());
  save_state(&status_path, &state)?;

  let mut nonce: u64 = 0;
  let mut hashes: u64 = 0;
  let mut last_report = Instant::now();

  loop {
    for _ in 0..HASH_BATCH {
      let mut hasher = Sha256::new();
      hasher.update(address.as_bytes());
      hasher.update(nonce.to_le_bytes());
      let digest = hasher.finalize();
      hashes += 1;
      nonce = nonce.wrapping_add(1);

      if meets_difficulty(&digest) {
        state.blocks_mined += 1;
        state.total_rewards += REWARD_PER_BLOCK;
      }
    }

    if last_report.elapsed() >= REPORT_INTERVAL {
      let elapsed = last_report.elapsed().as_secs_f64();
      state.hashrate = if elapsed > 0.0 {
        hashes as f64 / elapsed
      } else {
        0.0
      };
      hashes = 0;
      last_report = Instant::now();

      save_state(&status_path, &state)?;

      if should_stop(&status_path)? {
        break;
      }
    }
  }

  state.running = false;
  save_state(&status_path, &state)?;
  Ok(())
}

fn meets_difficulty(digest: &[u8]) -> bool {
  digest.len() >= DIFFICULTY_ZERO_BYTES && digest[..DIFFICULTY_ZERO_BYTES].iter().all(|b| *b == 0)
}

fn should_stop(status_path: &Path) -> Result<bool> {
  let on_disk = load_or_default(status_path).context("Failed to read miner status")?;
  Ok(!on_disk.running)
}
