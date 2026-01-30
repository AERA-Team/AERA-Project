pub mod eth_listener;
pub mod deposit_store;
pub mod tron_client;

use crate::types::Address;
use serde::{Deserialize, Serialize};

pub use eth_listener::EthListener;
pub use deposit_store::DepositStore;
pub use tron_client::TronClient;

// ============================================================================
// Bridge Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalChain {
    Ethereum,
    Tron,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    AERA,
    USDT,
    TRX,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStatus {
    Pending,
    Confirmed,
    Minted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deposit {
    pub id: [u8; 32],
    pub chain: ExternalChain,
    pub source_tx_hash: Vec<u8>,
    pub source_block: u64,
    pub sender: String,
    pub recipient: Address,
    pub token: TokenType,
    pub amount: u128,
    pub confirmations: u32,
    pub status: DepositStatus,
    pub detected_at: u64,
}

impl Deposit {
    pub fn generate_id(tx_hash: &[u8], index: u32) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(tx_hash);
        hasher.update(&index.to_be_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    pub infura_api_key: String,
    pub eth_rpc_url: String,
    pub tron_api_url: String,
    pub tron_api_key: String,
    pub eth_vault_address: String,
    pub tron_vault_address: String,
    pub tron_usdt_contract: String,
    pub confirmations: u32,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            infura_api_key: "".to_string(),
            eth_rpc_url: "".to_string(),
            tron_api_url: "https://api.trongrid.io".to_string(),
            tron_api_key: "".to_string(),
            eth_vault_address: "".to_string(),
            tron_vault_address: "".to_string(),
            tron_usdt_contract: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".to_string(),
            confirmations: 3,
        }
    }
}

pub enum BridgeEvent {
    DepositDetected(Deposit),
    DepositConfirmed(Deposit),
    SyncStatus {
        chain: ExternalChain,
        current_block: u64,
        latest_block: u64,
    },
    Error {
        chain: ExternalChain,
        message: String,
    },
}

pub struct BridgeService {
    config: BridgeConfig,
    event_tx: tokio::sync::mpsc::Sender<BridgeEvent>,
    deposit_store: DepositStore,
}

impl BridgeService {
    pub fn new(config: BridgeConfig, event_tx: tokio::sync::mpsc::Sender<BridgeEvent>, store: DepositStore) -> Self {
        Self {
            config,
            event_tx,
            deposit_store: store,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let config = &self.config;
        let eth_rpc_url = if !config.eth_rpc_url.is_empty() {
            Some(config.eth_rpc_url.clone())
        } else if !config.infura_api_key.is_empty() {
            Some(format!("https://mainnet.infura.io/v3/{}", config.infura_api_key))
        } else {
            None
        };
        
        // Start ETH Listener
        if !config.eth_vault_address.is_empty() {
            // USDT Contract Address (Mainnet)
            // In a real scenario, this should also be configurable or determined by chain_id
            let usdt_contract = "0xdac17f958d2ee523a2206206994597c13d831ec7"; 

            if let Some(rpc_url) = eth_rpc_url {
                let mut eth_listener = EthListener::new(
                    &rpc_url,
                    usdt_contract,
                    &config.eth_vault_address,
                    config.confirmations,
                    15, // poll interval (seconds)
                    self.event_tx.clone(),
                    self.deposit_store.clone(),
                )
                .await?;

                tokio::spawn(async move {
                    if let Err(e) = eth_listener.run().await {
                        tracing::error!("ETH Listener failed: {}", e);
                    }
                });
                tracing::info!("   ✓ ETH Listener started");
            } else {
                tracing::info!("   ⚠️ Skipping ETH listener (missing RPC config)");
            }
        } else {
             tracing::info!("   ⚠️ Skipping ETH listener (missing config)");
        }

        Ok(())
    }
}
