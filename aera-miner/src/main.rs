use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod config;
mod miner;
mod state;
mod wallet;

use config::{load_or_create, resolve_data_dir, save, AppConfig};
use state::{load_or_default, save as save_state};
use wallet::KeyVault;

#[derive(Parser)]
#[command(name = "aera-miner", version, about = "AERA Mining Utility")]
struct Cli {
  #[arg(long, default_value = "config.toml")]
  config: String,
  #[command(subcommand)]
  command: Commands,
}

#[derive(Subcommand)]
enum Commands {
  Init {
    #[arg(long)]
    data_dir: Option<String>,
    #[arg(long, default_value_t = false)]
    show_mnemonic: bool,
  },
  Import {
    #[arg(long)]
    mnemonic: String,
    #[arg(long)]
    data_dir: Option<String>,
  },
  Export {
    #[arg(long)]
    address: String,
    #[arg(long)]
    out: String,
    #[arg(long)]
    data_dir: Option<String>,
  },
  Start {
    #[arg(long)]
    address: Option<String>,
    #[arg(long)]
    data_dir: Option<String>,
  },
  Stop {
    #[arg(long)]
    data_dir: Option<String>,
  },
  Status {
    #[arg(long)]
    data_dir: Option<String>,
  },
}

fn main() -> Result<()> {
  let cli = Cli::parse();
  let config_path = PathBuf::from(cli.config);
  let mut config = load_or_create(&config_path)?;

  match cli.command {
    Commands::Init { data_dir, show_mnemonic } => {
      let data_dir = apply_data_dir(&mut config, &config_path, data_dir)?;
      let password = prompt_password("Create wallet password: ")?;
      let (address, mnemonic) = init_wallet(&data_dir, &password)?;
      config.mining_address = address.clone();
      save(&config_path, &config)?;
      println!("Address: {}", address);
      if show_mnemonic {
        eprintln!("Mnemonic: {}", mnemonic);
      } else {
        eprintln!("Mnemonic hidden. Re-run with --show-mnemonic to display once.");
      }
    }
    Commands::Import {
      mnemonic,
      data_dir,
    } => {
      let data_dir = apply_data_dir(&mut config, &config_path, data_dir)?;
      let password = prompt_password("Wallet password: ")?;
      let address = import_wallet(&data_dir, &mnemonic, &password)?;
      config.mining_address = address.clone();
      save(&config_path, &config)?;
      println!("Address: {}", address);
    }
    Commands::Export {
      address,
      out,
      data_dir,
    } => {
      let data_dir = apply_data_dir(&mut config, &config_path, data_dir)?;
      export_keystore(&data_dir, &address, Path::new(&out))?;
      println!("Exported: {}", out);
    }
    Commands::Start { address, data_dir } => {
      let data_dir = apply_data_dir(&mut config, &config_path, data_dir)?;
      let address = resolve_address(&config, address)?;
      start_mining(&data_dir, &address)?;
      config.mining_address = address;
      save(&config_path, &config)?;
      println!("Mining started. Use Ctrl+C to stop or run `aera-miner stop` in another terminal.");
    }
    Commands::Stop { data_dir } => {
      let data_dir = apply_data_dir(&mut config, &config_path, data_dir)?;
      stop_mining(&data_dir)?;
      println!("Mining stopped");
    }
    Commands::Status { data_dir } => {
      let data_dir = apply_data_dir(&mut config, &config_path, data_dir)?;
      show_status(&data_dir)?;
    }
  }

  Ok(())
}

fn apply_data_dir(
  config: &mut AppConfig,
  config_path: &Path,
  override_dir: Option<String>,
) -> Result<PathBuf> {
  if let Some(dir) = override_dir {
    config.data_dir = dir;
  }
  let data_dir = resolve_data_dir(config_path, &config.data_dir);
  fs::create_dir_all(&data_dir)
    .with_context(|| format!("Failed to create {}", data_dir.display()))?;
  Ok(data_dir)
}

fn keystore_dir(data_dir: &Path) -> PathBuf {
  data_dir.join("keystore")
}

fn status_path(data_dir: &Path) -> PathBuf {
  data_dir.join("miner_status.json")
}

fn init_wallet(data_dir: &Path, password: &str) -> Result<(String, String)> {
  let keystore_path = keystore_dir(data_dir);
  let mut vault = KeyVault::open(&keystore_path).context("Failed to open keystore")?;
  let (address, mnemonic) = vault
    .create_mnemonic_wallet(password)
    .context("Failed to create wallet")?;
  Ok((address, mnemonic))
}

fn import_wallet(data_dir: &Path, mnemonic: &str, password: &str) -> Result<String> {
  let keystore_path = keystore_dir(data_dir);
  let mut vault = KeyVault::open(&keystore_path).context("Failed to open keystore")?;
  let address = vault
    .import_mnemonic_wallet(mnemonic, password)
    .context("Failed to import wallet")?;
  Ok(address)
}

fn export_keystore(data_dir: &Path, address: &str, out: &Path) -> Result<()> {
  let file_name = format!("wallet_{}.json", address.to_lowercase());
  let source = keystore_dir(data_dir).join(file_name);
  if !source.exists() {
    return Err(anyhow!("Keystore not found for {}", address));
  }
  if let Some(parent) = out.parent() {
    fs::create_dir_all(parent)
      .with_context(|| format!("Failed to create {}", parent.display()))?;
  }
  fs::copy(&source, out).context("Failed to export keystore")?;
  Ok(())
}

fn resolve_address(config: &AppConfig, override_address: Option<String>) -> Result<String> {
  if let Some(address) = override_address {
    return Ok(address);
  }
  if config.mining_address.is_empty() {
    return Err(anyhow!("Mining address missing. Use --address or init/import wallet."));
  }
  Ok(config.mining_address.clone())
}

fn start_mining(data_dir: &Path, address: &str) -> Result<()> {
  miner::run_miner(data_dir, address)
}

fn stop_mining(data_dir: &Path) -> Result<()> {
  let mut state = load_or_default(&status_path(data_dir))?;
  state.running = false;
  save_state(&status_path(data_dir), &state)?;
  Ok(())
}

fn show_status(data_dir: &Path) -> Result<()> {
  let state = load_or_default(&status_path(data_dir))?;
  println!("running: {}", state.running);
  println!("address: {}", state.address);
  println!("hashrate: {}", state.hashrate);
  println!("blocks_mined: {}", state.blocks_mined);
  println!("total_rewards: {}", state.total_rewards);
  if let Some(started_at) = state.started_at {
    println!("started_at: {}", started_at);
  }
  Ok(())
}

fn prompt_password(prompt: &str) -> Result<String> {
  let password = rpassword::prompt_password(prompt)?;
  if password.len() < 8 {
    return Err(anyhow!("Password must be at least 8 characters"));
  }
  Ok(password)
}

pub fn now_unix() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
}
