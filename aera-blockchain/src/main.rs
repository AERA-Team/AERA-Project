//! AERA Blockchain Node
//!
//! Main entry point - starts the AeraManager

use aera_blockchain::manager::{AeraManager, ManagerConfig};
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, warn, Level};

/// AERA Node CLI
#[derive(Parser, Debug)]
#[command(name = "aera-node")]
#[command(about = "AERA L1 Blockchain Node", long_about = None)]
struct Args {
    /// Data directory
    #[arg(short, long)]
    data_dir: Option<String>,

    /// P2P listen address
    #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/30333")]
    listen: String,

    /// Chain ID
    #[arg(long, default_value = "1")]
    chain_id: u32,

    /// Bootstrap nodes (comma-separated)
    #[arg(long)]
    bootnodes: Option<String>,

    /// Ethereum RPC URL
    #[arg(long)]
    eth_rpc: Option<String>,

    /// Bridge vault address on ETH
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
    eth_vault: String,

    /// Enable validator mode
    #[arg(long)]
    validator: bool,

    /// RPC server port
    #[arg(long, default_value = "8545")]
    rpc_port: u16,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = match args.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Resolve Data Directory (Sync with Tauri AppData)
    let data_dir = if let Some(dir) = args.data_dir {
        PathBuf::from(dir)
    } else if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata).join("aera-wallet")
    } else {
        PathBuf::from("./aera-data")
    };

    // Build config from CLI args (with load from config.toml)
    let mut config = ManagerConfig::default();
    config.data_dir = data_dir.to_string_lossy().to_string();
    config.chain_id = args.chain_id;
    config.p2p_listen = args.listen;
    config.validator = args.validator;
    config.rpc_port = args.rpc_port;

    if let Some(nodes) = args.bootnodes {
        config.bootnodes = nodes
            .split(',')
            .map(str::trim)
            .filter(|node| !node.is_empty())
            .map(String::from)
            .collect();
    }

    // Load from config.toml (Sync with UI)
    let config_path = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("config.toml")))
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match content.parse::<toml::Value>() {
                Ok(value) => {
                    if let Some(bridge) = value.get("bridge") {
                        let non_empty = |field: &str| -> Option<String> {
                            bridge
                                .get(field)
                                .and_then(|v| v.as_str())
                                .map(str::trim)
                                .filter(|v| !v.is_empty())
                                .map(String::from)
                                .or_else(|| {
                                    if bridge.get(field).is_some() {
                                        warn!("config.toml bridge.{} is empty; ignoring", field);
                                    }
                                    None
                                })
                        };

                        if let Some(key) = non_empty("INFURA_API_KEY") {
                            config.bridge_config.infura_api_key = key;
                        }
                        if let Some(url) = non_empty("ETH_RPC_URL") {
                            config.bridge_config.eth_rpc_url = url;
                        }
                        if let Some(c) = non_empty("ETH_USDT_CONTRACT") {
                            config.bridge_config.eth_usdt_contract = c;
                        }
                        if let Some(url) = non_empty("TRON_API_URL") {
                            if !url.starts_with("http://") && !url.starts_with("https://") {
                                warn!("config.toml bridge.TRON_API_URL does not look like a URL");
                            }
                            config.bridge_config.tron_api_url = url;
                        }
                        if let Some(key) = non_empty("TRON_API_KEY") {
                            config.bridge_config.tron_api_key = key;
                        }
                        if let Some(c) = non_empty("TRON_USDT_CONTRACT") {
                            config.bridge_config.tron_usdt_contract = c;
                        }
                    }
                }
                Err(err) => {
                    warn!("Failed to parse config.toml at {}: {}", config_path.display(), err);
                }
            },
            Err(err) => {
                error!("Failed to read config.toml at {}: {}", config_path.display(), err);
            }
        }
    }

    // Override with direct CLI if provided (eth_rpc is full URL; infura_api_key stays in config.toml)
    if let Some(eth_rpc) = args.eth_rpc {
        let eth_rpc = eth_rpc.trim();
        if eth_rpc.is_empty() {
            warn!("--eth_rpc provided but empty; ignoring");
        } else {
            config.bridge_config.eth_rpc_url = eth_rpc.to_string();
        }
    }
    if args.eth_vault != "0x0000000000000000000000000000000000000000" {
        config.bridge_config.eth_vault_address = args.eth_vault;
    }

    // Print banner
    println!(r#"
    AERA Blockchain Node - Standalone Mode
    Data Dir: {}
    P2P Listen: {}
    RPC Port: {}
    "#, config.data_dir, config.p2p_listen, config.rpc_port);

    // Start AERA Manager
    AeraManager::start(config).await
}
