//! Ethereum USDT Listener
//!
//! Monitors the USDT (ERC-20) contract for Transfer events
//! to the bridge vault address using ethers.rs

use super::{BridgeEvent, Deposit, DepositStatus, DepositStore, ExternalChain, TokenType};
use crate::types::Address;
use anyhow::{Context, Result};
use ethers::prelude::*;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// ERC-20 Transfer event signature
/// keccak256("Transfer(address,address,uint256)")
const TRANSFER_EVENT_SIGNATURE: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// Ethereum/USDT Listener
pub struct EthListener {
    /// Ethereum RPC provider
    provider: Arc<Provider<Http>>,
    /// USDT contract address
    usdt_contract: H160,
    /// Bridge vault address (receives deposits)
    vault_address: H160,
    /// Required confirmations
    confirmations: u32,
    /// Polling interval in seconds
    poll_interval: u64,
    /// Last processed block
    last_block: u64,
    /// Channel to send events to main loop
    event_tx: mpsc::Sender<BridgeEvent>,
    /// Deposit store for persistence
    deposit_store: DepositStore,
}

impl EthListener {
    /// Create a new ETH listener
    pub async fn new(
        rpc_url: &str,
        usdt_contract: &str,
        vault_address: &str,
        confirmations: u32,
        poll_interval: u64,
        event_tx: mpsc::Sender<BridgeEvent>,
        deposit_store: DepositStore,
    ) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create ETH provider")?;

        let usdt_contract = usdt_contract
            .parse::<H160>()
            .context("Invalid USDT contract address")?;

        let vault_address = vault_address
            .parse::<H160>()
            .context("Invalid vault address")?;

        // Get current block as starting point
        let current_block = provider.get_block_number().await?.as_u64();
        
        // Resume from last processed block if available
        let last_block = deposit_store
            .get_last_eth_block()?
            .unwrap_or(current_block.saturating_sub(100)); // Start 100 blocks back

        info!(
            "🔗 ETH Listener initialized: USDT={:?}, vault={:?}, from_block={}",
            usdt_contract, vault_address, last_block
        );

        Ok(Self {
            provider: Arc::new(provider),
            usdt_contract,
            vault_address,
            confirmations,
            poll_interval,
            last_block,
            event_tx,
            deposit_store,
        })
    }

    /// Run the listener loop
    pub async fn run(&mut self) -> Result<()> {
        info!("🚀 Starting ETH/USDT listener...");

        loop {
            match self.poll_deposits().await {
                Ok(()) => {}
                Err(e) => {
                    warn!("ETH polling error: {}", e);
                    let _ = self.event_tx.send(BridgeEvent::Error {
                        chain: ExternalChain::Ethereum,
                        message: e.to_string(),
                    }).await;
                }
            }

            // Update pending deposits with new confirmations
            if let Err(e) = self.update_confirmations().await {
                warn!("Failed to update confirmations: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(self.poll_interval)).await;
        }
    }

    /// Poll for new Transfer events
    async fn poll_deposits(&mut self) -> Result<()> {
        let current_block = self.provider.get_block_number().await?.as_u64();

        if current_block <= self.last_block {
            return Ok(());
        }

        // Query blocks in batches to avoid RPC limits
        let batch_size = 1000u64;
        let from_block = self.last_block + 1;
        let to_block = std::cmp::min(current_block, from_block + batch_size);

        debug!(
            "Scanning ETH blocks {} to {} for USDT transfers",
            from_block, to_block
        );

        // Build filter for Transfer events TO our vault
        let filter = Filter::new()
            .address(self.usdt_contract)
            .topic0(TRANSFER_EVENT_SIGNATURE.parse::<H256>()?)
            .topic2(H256::from(self.vault_address)) // `to` is indexed as topic2
            .from_block(from_block)
            .to_block(to_block);

        let logs = self.provider.get_logs(&filter).await?;

        for log in logs {
            if let Some(deposit) = self.parse_transfer_log(&log, current_block).await? {
                // Check if already processed
                if self.deposit_store.is_processed(&deposit.id)? {
                    debug!("Skipping already processed deposit: {:?}", hex::encode(&deposit.id[..8]));
                    continue;
                }

                info!(
                    "💰 USDT deposit detected: {} USDT from {} (tx: {})",
                    deposit.amount / 1_000_000, // USDT has 6 decimals
                    deposit.sender,
                    hex::encode(&deposit.source_tx_hash)
                );

                // Store deposit
                self.deposit_store.store_deposit(&deposit)?;

                // Send event to main loop
                self.event_tx.send(BridgeEvent::DepositDetected(deposit)).await?;
            }
        }

        // Update last processed block
        self.last_block = to_block;
        self.deposit_store.set_last_eth_block(to_block)?;

        // Send sync status
        let _ = self.event_tx.send(BridgeEvent::SyncStatus {
            chain: ExternalChain::Ethereum,
            current_block: to_block,
            latest_block: current_block,
        }).await;

        Ok(())
    }

    /// Parse a Transfer event log into a Deposit
    async fn parse_transfer_log(
        &self,
        log: &Log,
        current_block: u64,
    ) -> Result<Option<Deposit>> {
        // Topics: [Transfer sig, from, to]
        if log.topics.len() < 3 {
            return Ok(None);
        }

        let from = H160::from(log.topics[1]);
        let to = H160::from(log.topics[2]);

        // Verify destination is our vault
        if to != self.vault_address {
            return Ok(None);
        }

        // Parse amount from data (uint256)
        let amount = U256::from_big_endian(&log.data);

        let tx_hash = log.transaction_hash.unwrap_or_default();
        let block_number = log.block_number.unwrap_or_default().as_u64();
        let log_index = log.log_index.unwrap_or_default().as_u32();

        let confirmations = current_block.saturating_sub(block_number) as u32;

        // Generate unique deposit ID
        let deposit_id = Deposit::generate_id(tx_hash.as_bytes(), log_index);

        // Extract AERA recipient from transaction input (memo)
        // For now, derive from sender address
        let recipient = self.derive_aera_address(from);

        let deposit = Deposit {
            id: deposit_id,
            chain: ExternalChain::Ethereum,
            source_tx_hash: tx_hash.as_bytes().to_vec(),
            source_block: block_number,
            sender: format!("{:?}", from),
            recipient,
            token: TokenType::USDT,
            amount: amount.as_u128(),
            confirmations,
            status: if confirmations >= self.confirmations {
                DepositStatus::Confirmed
            } else {
                DepositStatus::Pending
            },
            detected_at: chrono::Utc::now().timestamp() as u64,
        };

        Ok(Some(deposit))
    }

    /// Update confirmations for pending deposits
    async fn update_confirmations(&mut self) -> Result<()> {
        let current_block = self.provider.get_block_number().await?.as_u64();
        let pending = self.deposit_store.get_pending_deposits(ExternalChain::Ethereum)?;

        for mut deposit in pending {
            let new_confirmations = current_block.saturating_sub(deposit.source_block) as u32;
            
            if new_confirmations != deposit.confirmations {
                deposit.confirmations = new_confirmations;

                // Check if newly confirmed
                if deposit.confirmations >= self.confirmations 
                    && deposit.status == DepositStatus::Pending 
                {
                    deposit.status = DepositStatus::Confirmed;
                    info!(
                        "✅ Deposit confirmed: {} USDT ({})",
                        deposit.amount / 1_000_000,
                        hex::encode(&deposit.id[..8])
                    );
                    
                    // Emit confirmed event
                    self.event_tx.send(BridgeEvent::DepositConfirmed(deposit.clone())).await?;
                }

                self.deposit_store.store_deposit(&deposit)?;
            }
        }

        Ok(())
    }

    /// Derive AERA address from ETH address
    /// In production, this would use a mapping or memo field
    fn derive_aera_address(&self, eth_addr: H160) -> Address {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"AERA_FROM_ETH:");
        hasher.update(eth_addr.as_bytes());
        hasher.finalize().into()
    }
}

/// Call an Ethereum contract (read-only)
pub async fn eth_call(
    rpc_url: &str,
    contract: &str,
    data: Vec<u8>,
) -> Result<Vec<u8>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let contract_addr = contract.parse::<H160>()?;

    let tx = TransactionRequest::new()
        .to(contract_addr)
        .data(data);

    let result = provider.call(&tx.into(), None).await?;
    Ok(result.to_vec())
}

/// Encode a function call with ABI
pub fn encode_function_call(signature: &str, params: &[ethers::abi::Token]) -> Vec<u8> {
    // use ethers::abi::{Function, ParamType};
    
    // Parse function signature and encode
    let selector = ethers::utils::keccak256(signature.as_bytes());
    let mut data = selector[..4].to_vec();
    
    // Encode parameters (simplified - in production use full ABI)
    for param in params {
        match param {
            ethers::abi::Token::Address(addr) => {
                let mut padded = [0u8; 32];
                padded[12..].copy_from_slice(addr.as_bytes());
                data.extend_from_slice(&padded);
            }
            ethers::abi::Token::Uint(val) => {
                let mut bytes = [0u8; 32];
                val.to_big_endian(&mut bytes);
                data.extend_from_slice(&bytes);
            }
            _ => {}
        }
    }
    
    data
}
