//! AERA Manager - Central Coordinator
//!
//! Connects all components:
//! - NetworkService (P2P)
//! - BridgeService (Cross-chain)
//! - KeyVault (Wallets)
//! - StateDB (Storage)

use crate::bridge::{BridgeEvent, BridgeConfig, DepositStore, TronClient};
use crate::mining::MiningManager;
use crate::network::{NetworkEvent, NetworkService};
use crate::state::StateDB;
use crate::wallet::keystore::{KeyVault, KeyPurpose};
use crate::state::{TransactionRecord, TransactionStatus};
use crate::types::{Address, Amount};

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

// ============================================================================
// Configuration
// ============================================================================

/// AERA Manager configuration
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Data directory
    pub data_dir: String,
    /// Chain ID
    pub chain_id: u32,
    /// P2P listen address
    pub p2p_listen: String,
    /// Bootstrap nodes
    pub bootnodes: Vec<String>,
    /// Bridge configuration
    pub bridge_config: BridgeConfig,
    /// Enable validator mode
    pub validator: bool,
    /// RPC server port
    pub rpc_port: u16,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            data_dir: "./aera-data".to_string(),
            chain_id: 1,
            p2p_listen: "/ip4/0.0.0.0/tcp/30333".to_string(),
            bootnodes: vec![],
            bridge_config: BridgeConfig::default(),
            validator: false,
            rpc_port: 8545,
        }
    }
}

// ============================================================================
// Cross-Chain Transfer
// ============================================================================

#[derive(Debug, Clone)]
pub struct CrossChainTransfer {
    pub from_key: String,
    pub to_address: String,
    pub amount: Amount,
    pub target_chain: TargetChain,
}

#[derive(Debug, Clone, Copy)]
pub enum TargetChain {
    Ethereum,
    EthereumUsdt,
    Tron,
    TronNative,
    Aera,
}

// ============================================================================
// AERA Manager
// ============================================================================

pub struct AeraManager {
    config: ManagerConfig,
    state: Arc<StateDB>,
    network: NetworkService,
    key_vault: Arc<RwLock<KeyVault>>,
    mining: Arc<RwLock<MiningManager>>,
    bridge_rx: mpsc::Receiver<BridgeEvent>,
    deposit_store: DepositStore,
    tron_client: TronClient,
}

impl AeraManager {
    pub async fn new(config: ManagerConfig) -> Result<Self> {
        info!("🚀 Initializing AERA Manager...");

        // Create data directories
        let data_dir = PathBuf::from(&config.data_dir);
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("Failed to create data dir {}", data_dir.display()))?;

        let state_path = data_dir.join("state");
        let state = Arc::new(StateDB::open(&state_path)
            .with_context(|| format!("Failed to open state DB at {}", state_path.display()))?);
        info!("   ✓ State database initialized");

        // Initialize genesis if state is empty
        if state.is_empty()? {
            crate::state::genesis::initialize_genesis_state(&state, &crate::state::genesis::GenesisConfig::default())?;
            info!("   ✓ Genesis state applied");
        }

        let listen_addr = config.p2p_listen.parse()
            .context("Invalid P2P listen address")?;
        let network = NetworkService::start(listen_addr).await?;
        info!("   ✓ P2P network started ({})", network.local_peer_id);

        let key_vault = Arc::new(RwLock::new(
            KeyVault::open(&data_dir)
                .map_err(|e| anyhow!("Failed to open keystore at {}: {}", data_dir.display(), e))?,
        ));
        info!("   ✓ KeyVault loaded");

        let (bridge_tx, bridge_rx) = mpsc::channel::<BridgeEvent>(256);

        // Initialize Bridge Service
        let deposit_store_path = data_dir.join("bridge_deposits");
        let deposit_store = DepositStore::open(&deposit_store_path)
            .with_context(|| format!("Failed to open deposit store at {}", deposit_store_path.display()))?;
        let bridge_service = crate::bridge::BridgeService::new(
            config.bridge_config.clone(),
            bridge_tx,
            deposit_store.clone(),
        );
        bridge_service.start().await?;
        info!("   ✓ Bridge Service started");
        // info!("   ! Bridge Service disabled (development mode)");

        let tron_client = TronClient::new(
            if config.bridge_config.tron_api_key.is_empty() { None } else { Some(config.bridge_config.tron_api_key.clone()) },
            config.bridge_config.tron_api_url.clone(),
            config.bridge_config.tron_usdt_contract.clone(),
        );
        let mining = Arc::new(RwLock::new(MiningManager::new()));

        Ok(Self {
            config,
            state,
            network,
            key_vault,
            mining,
            bridge_rx,
            deposit_store,
            tron_client,
        })
    }

    pub async fn start(config: ManagerConfig) -> Result<()> {
        let mut manager = Self::new(config).await?;
        manager.run().await
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("🌐 AERA Manager running. Press Ctrl+C to stop.");

        for bootnode in &self.config.bootnodes {
            if let Ok(addr) = bootnode.parse() {
                self.network.dial(addr).await?;
            }
        }

        loop {
            tokio::select! {
                Some(event) = self.network.recv_event() => {
                    self.handle_network_event(event).await;
                }
                Some(event) = self.bridge_rx.recv() => {
                    self.handle_bridge_event(event).await;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("⏹️  Shutdown signal received");
                    break;
                }
            }
        }

        self.shutdown().await
    }

    async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerConnected(peer) => info!("🔗 Peer connected: {}", peer),
            NetworkEvent::PeerDisconnected(peer) => info!("🔌 Peer disconnected: {}", peer),
            NetworkEvent::NewBlock(block) => {
                info!("📦 New block #{}: {}", block.header.height, hex::encode(&block.hash()[..8]));
            }
            NetworkEvent::NewTransaction(tx) => debug!("📨 New transaction: {}", hex::encode(&tx.hash()[..8])),
            _ => {}
        }
    }

    async fn handle_bridge_event(&mut self, event: BridgeEvent) {
        match event {
            BridgeEvent::DepositDetected(deposit) => {
                info!(
                    "💰 Deposit detected: {} {:?} from {} ({} confirmations)",
                    deposit.amount, deposit.token, deposit.sender, deposit.confirmations
                );
            }
            BridgeEvent::DepositConfirmed(deposit) => {
                info!("✅ Deposit CONFIRMED: {} {:?} from {}", deposit.amount, deposit.token, deposit.sender);
                self.credit_user_balance(&deposit.recipient, deposit.amount).await;
                if let Err(e) = self.deposit_store.mark_processed(&deposit.id) {
                    error!("Failed to mark deposit processed: {}", e);
                }
            }
            BridgeEvent::SyncStatus { chain, current_block, latest_block } => {
                debug!("Sync status [{:?}]: {}/{}", chain, current_block, latest_block);
            }
            BridgeEvent::Error { chain, message } => warn!("Bridge error [{:?}]: {}", chain, message),
        }
    }

    async fn credit_user_balance(&self, address: &Address, amount: Amount) {
        match self.state.get_balance(address) {
            Ok(current_balance) => {
                let new_balance = current_balance + amount;
                if let Err(e) = self.state.set_balance(address, new_balance) {
                    error!("Failed to credit balance: {}", e);
                } else {
                    info!("💵 Credited {} to {}", amount, hex::encode(&address[..8]));
                }
            }
            Err(e) => error!("Failed to get balance: {}", e),
        }
    }

    /// Credit mining reward to wallet; deduct from MINING_REWARDS pool (no inflation).
    pub async fn credit_mining_reward(&self, address_str: String, reward_aera: f64) {
        let decimals = 10u128.pow(18);
        let reward_amount = (reward_aera * decimals as f64) as u128;
        let pool_addr: crate::types::Address = [0u8; 32]; // MINING_REWARDS_ADDRESS

        let miner_bytes = match {
            let n = address_str.to_lowercase();
            let h = n.replace("aera1", "");
            hex::decode(&h)
        } {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => {
                error!("Invalid address format for mining reward: {}", address_str);
                return;
            }
        };

        let pool_balance = match self.state.get_balance(&pool_addr) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to get mining pool balance: {}", e);
                return;
            }
        };
        if pool_balance < reward_amount {
            error!(
                "Mining pool exhausted: need {} base units, have {}",
                reward_amount, pool_balance
            );
            return;
        }

        if let Err(e) = self.state.set_balance(&pool_addr, pool_balance - reward_amount) {
            error!("Failed to deduct from mining pool: {}", e);
            return;
        }
        let miner_balance = self.state.get_balance(&miner_bytes).unwrap_or(0);
        if let Err(e) = self.state.set_balance(&miner_bytes, miner_balance + reward_amount) {
            error!("Failed to credit mining reward: {}", e);
            let _ = self.state.set_balance(&pool_addr, pool_balance);
            return;
        }
        if let Err(e) = self.state.flush() {
            error!("Failed to flush state after mining reward: {}", e);
        }
        info!("⛏️ Mining reward: {} AERA to {}", reward_aera, &address_str[..address_str.len().min(12)]);
    }

    /// Send a native AERA transaction locally (for simulation/fallback)
    pub async fn send_native_transaction(
        &self,
        from_address: String,
        to_address: String,
        amount: u128,
        password: &str,
    ) -> Result<String> {
        info!("📲 Processing native transaction locally (Simulation Fallback)");
        
        let from_bytes = self.address_to_bytes(&from_address.to_lowercase())
            .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
        let to_bytes = self.address_to_bytes(&to_address.to_lowercase())
            .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?;

        let fee = crate::state::genesis::calculate_fee(amount);
        let total = amount + fee;
        let balance = self.state.get_balance(&from_bytes)?;
        if balance < total {
            return Err(anyhow::anyhow!("Insufficient balance: {} available, {} needed (incl. fee)", balance, total));
        }

        let vault = self.key_vault.read().await;
        let tx_data = format!("SIM_TX:{}:{}:{}", from_address, to_address, amount);
        let signature = vault.sign_transaction(&from_address, password, tx_data.as_bytes())?;
        let tx_hash = hex::encode(&signature[..32]);

        self.state.set_balance(&from_bytes, balance - total)?;
        let to_balance = self.state.get_balance(&to_bytes)?;
        self.state.set_balance(&to_bytes, to_balance + amount)?;

        // 5. Record History
        let record = TransactionRecord {
            hash: tx_hash.clone(),
            from: from_address,
            to: to_address,
            amount: amount,
            timestamp: Self::unix_timestamp(),
            chain: "Aera (Local)".to_string(),
            status: TransactionStatus::Confirmed,
        };
        self.state.put_transaction(&record)?;
        self.state.flush()?;

        info!("✅ Local transaction processed: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Simple address validation
    fn validate_address(&self, address: &str, chain: TargetChain) -> Result<()> {
        match chain {
            TargetChain::Aera => {
                let address = address.to_lowercase();
                if !address.starts_with("aera1") || address.len() != 69 {
                    return Err(anyhow::anyhow!("Invalid AERA address length (expected 69 chars)"));
                }
            }
            TargetChain::Ethereum | TargetChain::EthereumUsdt => {
                let address = address.to_lowercase();
                if !address.starts_with("0x") || address.len() != 42 {
                    return Err(anyhow::anyhow!("Invalid Ethereum address format"));
                }
            }
            TargetChain::Tron | TargetChain::TronNative => {
                if !(address.starts_with('T') || address.starts_with('t')) || address.len() < 30 {
                    return Err(anyhow::anyhow!("Invalid TRON address format"));
                }
            }
        }
        Ok(())
    }

    fn unix_timestamp() -> u64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(err) => {
                warn!("System time is before UNIX_EPOCH: {}", err);
                0
            }
        }
    }

    fn eth_rpc_url(&self) -> Result<String> {
        if !self.config.bridge_config.eth_rpc_url.is_empty() {
            Ok(self.config.bridge_config.eth_rpc_url.clone())
        } else if !self.config.bridge_config.infura_api_key.is_empty() {
            Ok(format!(
                "https://mainnet.infura.io/v3/{}",
                self.config.bridge_config.infura_api_key
            ))
        } else {
            Err(anyhow!("Ethereum RPC is not configured"))
        }
    }

    pub async fn send_cross_chain_transfer(
        &self,
        transfer: CrossChainTransfer,
        password: &str,
    ) -> Result<String> {
        // 1. Validate Address
        self.validate_address(&transfer.to_address, transfer.target_chain)?;
        match transfer.target_chain {
            TargetChain::Aera => {
                // 2. Check Balance & Fees (0.001%)
                let fee = transfer.amount / 100_000;
                let total_needed = transfer.amount + fee;

                let from_bytes = self.address_to_bytes(&transfer.from_key.to_lowercase())
                    .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;

                let balance = self.state.get_balance(&from_bytes)?;
                if balance < total_needed {
                    return Err(anyhow::anyhow!(
                        "Insufficient balance. Required: {}, Available: {}",
                        total_needed, balance
                    ));
                }

                // Sign (for local audit record)
                let vault = self.key_vault.read().await;
                let tx_data = self.build_aera_transfer(&transfer.to_address, transfer.amount)?;
                let signature = vault.sign_transaction(&transfer.from_key, password, &tx_data)?;
                let tx_hash = hex::encode(&signature[..32]);

                // Update balances
                self.state.set_balance(&from_bytes, balance - total_needed)?;
                let to_bytes = self.address_to_bytes(&transfer.to_address.to_lowercase())
                    .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?;
                let to_balance = self.state.get_balance(&to_bytes)?;
                self.state.set_balance(&to_bytes, to_balance + transfer.amount)?;

                let record = TransactionRecord {
                    hash: tx_hash.clone(),
                    from: transfer.from_key.clone(),
                    to: transfer.to_address.clone(),
                    amount: transfer.amount,
                    timestamp: Self::unix_timestamp(),
                    chain: "Aera".to_string(),
                    status: TransactionStatus::Confirmed,
                };
                let _ = self.state.put_transaction(&record);
                Ok(tx_hash)
            }
            TargetChain::Ethereum => {
                let vault = self.key_vault.read().await;
                let priv_key = vault.get_eth_private_key_from_session()
                    .map_err(|_| anyhow::anyhow!("ETH private key not available. Unlock wallet with mnemonic."))?;
                let tx_hash = self.send_eth_transaction(&transfer.to_address, transfer.amount, &priv_key).await?;

                let record = TransactionRecord {
                    hash: tx_hash.clone(),
                    from: transfer.from_key.clone(),
                    to: transfer.to_address.clone(),
                    amount: transfer.amount,
                    timestamp: Self::unix_timestamp(),
                    chain: "Ethereum".to_string(),
                    status: TransactionStatus::Confirmed,
                };
                let _ = self.state.put_transaction(&record);
                Ok(tx_hash)
            }
            TargetChain::EthereumUsdt => {
                let vault = self.key_vault.read().await;
                let priv_key = vault.get_eth_private_key_from_session()
                    .map_err(|_| anyhow::anyhow!("ETH private key not available. Unlock wallet with mnemonic."))?;

                let usdt_amount = transfer.amount / 1_000_000_000_000;
                if usdt_amount == 0 {
                    return Err(anyhow::anyhow!("Amount too small: minimum 0.000001 USDT"));
                }

                let tx_hash = self.send_eth_usdt_transfer(&transfer.to_address, usdt_amount, &priv_key).await?;
                let record = TransactionRecord {
                    hash: tx_hash.clone(),
                    from: transfer.from_key.clone(),
                    to: transfer.to_address.clone(),
                    amount: transfer.amount,
                    timestamp: Self::unix_timestamp(),
                    chain: "EthereumUSDT".to_string(),
                    status: TransactionStatus::Confirmed,
                };
                let _ = self.state.put_transaction(&record);
                Ok(tx_hash)
            }
            TargetChain::Tron => {
                let vault = self.key_vault.read().await;
                let priv_key = vault.get_tron_private_key_from_session()
                    .map_err(|_| anyhow::anyhow!("TRON private key not available. Unlock wallet with mnemonic."))?;
                let tron_from = vault.get_address_by_purpose(KeyPurpose::Tron)
                    .ok_or_else(|| anyhow::anyhow!("TRON address not available. Unlock wallet first."))?;

                let usdt_amount = transfer.amount / 1_000_000_000_000;
                if usdt_amount == 0 {
                    return Err(anyhow::anyhow!("Amount too small: minimum 0.000001 USDT"));
                }

                let tx_hash = self.tron_client.send_usdt(&tron_from, &transfer.to_address, usdt_amount, &priv_key)
                    .await
                    .map_err(|e| anyhow::anyhow!("TRON transfer failed: {}", e))?;

                let record = TransactionRecord {
                    hash: tx_hash.clone(),
                    from: transfer.from_key.clone(),
                    to: transfer.to_address.clone(),
                    amount: transfer.amount,
                    timestamp: Self::unix_timestamp(),
                    chain: "TronUSDT".to_string(),
                    status: TransactionStatus::Confirmed,
                };
                let _ = self.state.put_transaction(&record);
                Ok(tx_hash)
            }
            TargetChain::TronNative => {
                let vault = self.key_vault.read().await;
                let priv_key = vault.get_tron_private_key_from_session()
                    .map_err(|_| anyhow::anyhow!("TRON private key not available. Unlock wallet with mnemonic."))?;
                let tron_from = vault.get_address_by_purpose(KeyPurpose::Tron)
                    .ok_or_else(|| anyhow::anyhow!("TRON address not available. Unlock wallet first."))?;

                if transfer.amount == 0 {
                    return Err(anyhow::anyhow!("Amount must be greater than zero"));
                }

                let tx_hash = self.tron_client.send_trx(&tron_from, &transfer.to_address, transfer.amount, &priv_key)
                    .await
                    .map_err(|e| anyhow::anyhow!("TRON transfer failed: {}", e))?;

                let record = TransactionRecord {
                    hash: tx_hash.clone(),
                    from: transfer.from_key.clone(),
                    to: transfer.to_address.clone(),
                    amount: transfer.amount,
                    timestamp: Self::unix_timestamp(),
                    chain: "Tron".to_string(),
                    status: TransactionStatus::Confirmed,
                };
                let _ = self.state.put_transaction(&record);
                Ok(tx_hash)
            }
        }
    }

    /// Helper to convert bech32-style aera1... address to 32-byte hash
    pub fn address_to_bytes(&self, address: &str) -> Result<[u8; 32]> {
        let hex_part = address.replace("aera1", "");
        let bytes = hex::decode(&hex_part).map_err(|_| anyhow::anyhow!("Invalid hex in address"))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid address length: expected 32 bytes"));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }

    fn build_aera_transfer(&self, to: &str, amount: Amount) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(to.as_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        Ok(data)
    }

    async fn shutdown(&self) -> Result<()> {
        info!("🔄 Shutting down...");
        self.state.flush()?;
        Ok(())
    }

    pub fn state(&self) -> &Arc<StateDB> { &self.state }
    pub fn config(&self) -> &ManagerConfig { &self.config }
    pub fn key_vault(&self) -> &Arc<RwLock<KeyVault>> { &self.key_vault }

    pub async fn peer_count(&self) -> usize {
        self.network.peer_count().await
    }

    /// Generate a new TRON address
    pub async fn generate_tron_address(&self, password: &str) -> Result<String> {
        let mut vault = self.key_vault.write().await;
        vault.generate_tron_key(password).map_err(|e| anyhow::anyhow!("Keystore error: {}", e))
    }

    /// Generate a new Ethereum address
    pub async fn generate_eth_address(&self, password: &str) -> Result<String> {
        let mut vault = self.key_vault.write().await;
        vault.generate_ethereum_key(password).map_err(|e| anyhow::anyhow!("Keystore error: {}", e))
    }

    /// Get TRON balance
    pub async fn get_tron_balance(&self, address: &str) -> Result<f64> {
        self.tron_client.get_usdt_balance(address).await
            .map_err(|e| {
                if self.config.bridge_config.tron_api_key.is_empty() {
                    anyhow::anyhow!("Rate limit reached, please add API key (TRON)")
                } else {
                    anyhow::anyhow!("TRON API error: {}", e)
                }
            })
    }

    /// Get TRX balance
    pub async fn get_trx_balance(&self, address: &str) -> Result<f64> {
        self.tron_client.get_trx_balance(address).await
            .map_err(|e| anyhow::anyhow!("TRON API error: {}", e))
    }

    /// Get Ethereum balance using Infura
    pub async fn get_eth_balance(&self, address: &str) -> Result<f64> {
        use ethers::providers::{Provider, Http, Middleware};
        use ethers::types::Address as EthAddress;
        use std::str::FromStr;

        let rpc_url = self.eth_rpc_url()?;
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create Ethereum provider")?;
            
        let addr = EthAddress::from_str(address)
            .map_err(|e| anyhow::anyhow!("Invalid Ethereum address: {}", e))?;
            
        let balance = provider.get_balance(addr, None).await
            .map_err(|e| anyhow::anyhow!("Failed to fetch ETH balance: {}", e))?;
            
        // Convert wei to eth
        Ok(ethers::utils::format_units(balance, "ether")?
            .parse::<f64>()
            .unwrap_or(0.0))
    }

    /// Send native ETH transaction
    pub async fn send_eth_transaction(
        &self,
        to_address: &str,
        amount_wei: u128,
        private_key: &[u8; 32],
    ) -> Result<String> {
        use ethers::middleware::{Middleware, SignerMiddleware};
        use ethers::providers::{Http, Provider};
        use ethers::signers::{LocalWallet, Signer};
        use ethers::types::{Address as EthAddress, TransactionRequest, U256};
        use std::str::FromStr;

        let rpc_url = self.eth_rpc_url()?;
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create Ethereum provider")?;
        let chain_id = provider.get_chainid().await?.as_u64();

        let wallet = LocalWallet::from_bytes(private_key)
            .map_err(|e| anyhow::anyhow!("Invalid ETH private key: {}", e))?
            .with_chain_id(chain_id);

        let client = SignerMiddleware::new(provider, wallet);
        let to = EthAddress::from_str(to_address)
            .map_err(|e| anyhow::anyhow!("Invalid Ethereum address: {}", e))?;

        let tx = TransactionRequest::new()
            .to(to)
            .value(U256::from(amount_wei));

        let pending = client.send_transaction(tx, None).await
            .map_err(|e| anyhow::anyhow!("ETH send failed: {}", e))?;
        Ok(format!("{:#x}", pending.tx_hash()))
    }

    /// Get USDT (ERC-20) balance using Infura
    pub async fn get_eth_usdt_balance(&self, address: &str) -> Result<f64> {
        use ethers::abi::Token;
        use ethers::types::{Address as EthAddress, U256};
        use std::str::FromStr;

        const USDT_CONTRACT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        let rpc_url = self.eth_rpc_url()?;

        let addr = EthAddress::from_str(address)
            .map_err(|e| anyhow::anyhow!("Invalid Ethereum address: {}", e))?;

        let data = crate::bridge::eth_listener::encode_function_call(
            "balanceOf(address)",
            &[Token::Address(addr)],
        );

        let raw = crate::bridge::eth_listener::eth_call(&rpc_url, USDT_CONTRACT, data)
            .await
            .map_err(|e| anyhow::anyhow!("ETH USDT call failed: {}", e))?;

        if raw.len() < 32 {
            return Err(anyhow::anyhow!("Invalid USDT balance response"));
        }

        let value = U256::from_big_endian(&raw[raw.len() - 32..]);
        // USDT has 6 decimals
        Ok(value.as_u128() as f64 / 1_000_000.0)
    }

    /// Send USDT (ERC-20) transfer using Infura
    pub async fn send_eth_usdt_transfer(
        &self,
        to_address: &str,
        amount_usdt: u128,
        private_key: &[u8; 32],
    ) -> Result<String> {
        use ethers::abi::Token;
        use ethers::middleware::{Middleware, SignerMiddleware};
        use ethers::providers::{Http, Provider};
        use ethers::signers::{LocalWallet, Signer};
        use ethers::types::{Address as EthAddress, TransactionRequest, U256};
        use std::str::FromStr;

        const USDT_CONTRACT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        let rpc_url = self.eth_rpc_url()?;

        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create Ethereum provider")?;
        let chain_id = provider.get_chainid().await?.as_u64();

        let wallet = LocalWallet::from_bytes(private_key)
            .map_err(|e| anyhow::anyhow!("Invalid ETH private key: {}", e))?
            .with_chain_id(chain_id);

        let client = SignerMiddleware::new(provider, wallet);
        let to = EthAddress::from_str(to_address)
            .map_err(|e| anyhow::anyhow!("Invalid Ethereum address: {}", e))?;
        let contract = EthAddress::from_str(USDT_CONTRACT)
            .map_err(|e| anyhow::anyhow!("Invalid USDT contract: {}", e))?;

        let data = crate::bridge::eth_listener::encode_function_call(
            "transfer(address,uint256)",
            &[Token::Address(to), Token::Uint(U256::from(amount_usdt))],
        );

        let tx = TransactionRequest::new()
            .to(contract)
            .data(data)
            .value(U256::zero());

        let pending = client.send_transaction(tx, None).await
            .map_err(|e| anyhow::anyhow!("ERC-20 send failed: {}", e))?;
        Ok(format!("{:#x}", pending.tx_hash()))
    }

    pub fn mining(&self) -> &Arc<RwLock<MiningManager>> {
        &self.mining
    }

    /// Explicitly reload all wallets from the data directory
    pub async fn refresh_keystore(&self) -> Result<(), crate::wallet::keystore::KeystoreError> {
        let mut vault = self.key_vault.write().await;
        vault.reload_from_disk()?;
        info!("   ✓ Keystore refreshed ({} keys loaded)", vault.list_keys().len());
        Ok(())
    }

}
