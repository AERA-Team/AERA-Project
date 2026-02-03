//! Tauri Integration Module
//!
//! Provides commands for Tauri frontend (TypeScript) to interact with AeraManager.
//! This file would be imported by the Tauri app's main.rs

use crate::manager::{AeraManager, ManagerConfig, CrossChainTransfer, TargetChain};
use crate::mining::MiningStats;
use crate::state::genesis::{BLOCK_REWARD, TOTAL_SUPPLY, DECIMALS};
use crate::wallet::keystore::KeyPurpose;
use crate::state::TransactionRecord;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};
use std::sync::Arc;
use tokio::sync::RwLock;
use tauri::{Manager, State};
use tracing::debug;

// ============================================================================
// Tauri State
// ============================================================================

/// Global app state accessible from Tauri commands
pub struct TauriState {
    pub manager: Arc<RwLock<Option<AeraManager>>>,
    pub config: ManagerConfig,
}

// ============================================================================
// Response Types (JSON-serializable for TypeScript)
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub balance: String,
    pub balance_formatted: String,
    pub mnemonic: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub peer_count: usize,
    pub block_height: u64,
    pub chain_id: u32,
    pub synced: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResult {
    pub success: bool,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenomicsInfo {
    pub total_supply: String,
    pub circulating: String,
    pub block_reward: String,
    pub decimals: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeResponse {
    hash: Option<String>,
    error: Option<String>,
}

/// Get the system's default app data directory
#[tauri::command]
pub async fn get_default_data_dir(app_handle: tauri::AppHandle) -> Result<String, String> {
    use tauri::Manager;
    app_handle.path().app_data_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

// ============================================================================
// Tauri Commands (called from TypeScript)
// ============================================================================

/// Initialize AERA node
/// Called: await invoke('init_node', { dataDir: '...' })
#[tauri::command]
pub async fn init_node(
    state: State<'_, TauriState>,
    app_handle: tauri::AppHandle,
    data_dir: String,
) -> Result<String, String> {
    let data_dir = sanitize_data_dir(&app_handle, &data_dir)?;
    let mut config = ManagerConfig {
        data_dir: data_dir.clone(),
        ..state.config.clone()
    };

    // Attempt to load bridge config from config.toml in the same directory as the app or project
    let config_path = Path::new(&data_dir).join("config.toml");
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(value) = content.parse::<toml::Value>() {
                if let Some(bridge) = value.get("bridge") {
                    if let Some(key) = bridge.get("INFURA_API_KEY").and_then(|k| k.as_str()) {
                         if !key.is_empty() { config.bridge_config.infura_api_key = key.to_string(); }
                    }
                    if let Some(c) = bridge.get("ETH_USDT_CONTRACT").and_then(|c| c.as_str()) {
                        if !c.is_empty() { config.bridge_config.eth_usdt_contract = c.to_string(); }
                    }
                    if let Some(url) = bridge.get("TRON_API_URL").and_then(|u| u.as_str()) {
                        if !url.is_empty() { config.bridge_config.tron_api_url = url.to_string(); }
                    }
                    if let Some(key) = bridge.get("TRON_API_KEY").and_then(|k| k.as_str()) {
                        if !key.is_empty() { config.bridge_config.tron_api_key = key.to_string(); }
                    }
                    if let Some(c) = bridge.get("TRON_USDT_CONTRACT").and_then(|c| c.as_str()) {
                        if !c.is_empty() { config.bridge_config.tron_usdt_contract = c.to_string(); }
                    }
                }
            }
        }
    }

    match AeraManager::new(config).await {
        Ok(manager) => {
            *state.manager.write().await = Some(manager);
            Ok("Node initialized".to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Create new wallet
/// Called: await invoke('create_wallet', { password: 'secret' })
#[tauri::command]
pub async fn create_wallet(
    state: State<'_, TauriState>,
    password: String,
) -> Result<WalletInfo, String> {
    validate_password(&password)?;
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;

    let mut vault = manager.key_vault().write().await;
    let address = vault.generate_aera_key(&password).map_err(|e| e.to_string())?;
    let balance = 0u128; // New wallets always start with 0

    Ok(WalletInfo {
        address,
        balance: balance.to_string(),
        balance_formatted: format_aera(balance),
        mnemonic: None,
    })
}

/// Create a new mnemonic wallet
/// Called: await invoke('create_mnemonic_wallet', { password: 'secret' })
#[tauri::command]
pub async fn create_mnemonic_wallet(
    state: State<'_, TauriState>,
    password: String,
) -> Result<WalletInfo, String> {
    validate_password(&password)?;
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;

    let mut vault = manager.key_vault().write().await;
    let (address, mnemonic) = vault.create_mnemonic_wallet(&password).map_err(|e| e.to_string())?;
    
    // Step 2: Force manager refresh after write
    vault.reload_from_disk().map_err(|e| e.to_string())?;

    Ok(WalletInfo {
        address,
        balance: "0".to_string(),
        balance_formatted: "0.00 AERA".to_string(),
        mnemonic: Some(mnemonic),
    })
}

/// Import wallet from mnemonic
/// Called: await invoke('import_mnemonic_wallet', { phrase: '...', password: 'secret' })
#[tauri::command]
pub async fn import_mnemonic_wallet(
    state: State<'_, TauriState>,
    phrase: String,
    password: String,
) -> Result<WalletInfo, String> {
    validate_password(&password)?;
    validate_len(&phrase, "Mnemonic")?;
    validate_mnemonic(&phrase)?;
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;

    let mut vault = manager.key_vault().write().await;
    let address = vault.import_mnemonic_wallet(&phrase, &password).map_err(|e| e.to_string())?;
    
    // Step 2: Force manager refresh after write
    vault.reload_from_disk().map_err(|e| e.to_string())?;

    Ok(WalletInfo {
        address,
        balance: "0".to_string(),
        balance_formatted: "0.00 AERA".to_string(),
        mnemonic: None,
    })
}

/// Check if a wallet already exists on disk
#[tauri::command]
pub async fn has_wallet(state: State<'_, TauriState>) -> Result<bool, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    let vault = manager.key_vault().read().await;
    Ok(!vault.list_keys().is_empty())
}
/// Get the public address of the current wallet (no password needed)
#[tauri::command]
pub async fn get_address(state: State<'_, TauriState>) -> Result<String, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    let vault = manager.key_vault().read().await;
    
    match vault.get_first_address() {
        Some(address) => {
            Ok(address)
        }
        None => Err("No wallet found. Please create or import a wallet first.".to_string())
    }
}

/// Get TRON address
#[tauri::command]
pub async fn get_tron_address(state: State<'_, TauriState>) -> Result<String, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    let vault = manager.key_vault().read().await;
    
    Ok(vault.get_address_by_purpose(KeyPurpose::Tron)
        .ok_or_else(|| "Address not generated".to_string())?)
}

/// Get ETH address
#[tauri::command]
pub async fn get_eth_address(state: State<'_, TauriState>) -> Result<String, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    let vault = manager.key_vault().read().await;
    
    Ok(vault.get_address_by_purpose(KeyPurpose::Ethereum)
        .ok_or_else(|| "Address not generated".to_string())?)
}

/// Get USDT (ERC-20) receive address (same as ETH address)
#[tauri::command]
pub async fn get_eth_usdt_address(state: State<'_, TauriState>) -> Result<String, String> {
    get_eth_address(state).await
}


/// Unlock existing wallet with password
#[tauri::command]
pub async fn unlock_wallet(
    state: State<'_, TauriState>,
    address: String,
    password: String,
) -> Result<WalletInfo, String> {
    validate_password(&password)?;
    validate_len(&address, "Address")?;
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;

    let mut vault = manager.key_vault().write().await;
    
    // Trim and lowercase address from input
    let address = address.trim().to_lowercase();
    
    // Verify key exists
    if !vault.has_key(&address) {
        return Err("Address not found in keystore".to_string());
    }

    // Verify password and unlock session
    vault.unlock_session(&password, Some(&address)).map_err(|e| e.to_string())?;
    
    // Fetch actual balance from state
    let address_bytes = parse_aera_address(&address)?;
    let balance = manager.state().get_balance(&address_bytes).unwrap_or(0);

    Ok(WalletInfo {
        address: address.clone(),
        balance: balance.to_string(),
        balance_formatted: format_aera(balance),
        mnemonic: None,
    })
}

/// Logout and lock wallet session (Zeroize keys in memory)
#[tauri::command]
pub async fn lock_session(state: State<'_, TauriState>) -> Result<bool, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    
    let mut vault = manager.key_vault().write().await;
    vault.lock_session(); // Clear session and sensitive data

    // Also trigger a refresh to make sure we see any manual file changes on the login screen
    if let Err(e) = vault.reload_from_disk() {
        tracing::warn!("Keystore reload after lock failed: {}", e);
    }

    Ok(true)
}

/// Refresh the list of wallets from disk and return all available addresses
#[tauri::command]
pub async fn refresh_wallets(state: State<'_, TauriState>) -> Result<Vec<String>, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    
    manager.refresh_keystore().await.map_err(|e| e.to_string())?;
    
    let vault = manager.key_vault().read().await;
    // Step 3: Clean list - only AERA addresses (starts with aera1)
    Ok(vault.list_keys()
        .into_iter()
        .filter(|k| k.starts_with("aera1"))
        .cloned()
        .collect())
}

/// List all available wallet addresses from memory
#[tauri::command]
pub async fn list_wallets(state: State<'_, TauriState>) -> Result<Vec<String>, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    
    let vault = manager.key_vault().read().await;
    // Step 3: Clean list - only AERA addresses (starts with aera1)
    Ok(vault.list_keys()
        .into_iter()
        .filter(|k| k.starts_with("aera1"))
        .cloned()
        .collect())
}

// reset_wallet command removed for security.

/// Get wallet balance
/// Called: await invoke('get_balance', { address: 'aera1...' })
#[tauri::command]
pub async fn get_balance(
    state: State<'_, TauriState>,
    address: String,
) -> Result<WalletInfo, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;

    validate_len(&address, "Address")?;
    let addr_bytes = parse_aera_address(&address)?;

    // Get balance from state DB
    let balance = manager.state().get_balance(&addr_bytes).map_err(|e| e.to_string())?;

    Ok(WalletInfo {
        address: address.to_lowercase(),
        balance: balance.to_string(),
        balance_formatted: format_aera(balance),
        mnemonic: None,
    })
}

/// Get TRON balance
#[tauri::command]
pub async fn get_tron_balance(state: State<'_, TauriState>, address: String) -> Result<String, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    validate_len(&address, "Address")?;
    validate_tron_address(&address)?;
    let balance = manager.get_tron_balance(&address).await.map_err(|e| e.to_string())?;
    Ok(format!("{:.6} USDT", balance))
}

/// Get TRX balance
#[tauri::command]
pub async fn get_trx_balance(state: State<'_, TauriState>, address: String) -> Result<String, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    validate_len(&address, "Address")?;
    validate_tron_address(&address)?;
    let balance = manager.get_trx_balance(&address).await.map_err(|e| e.to_string())?;
    Ok(format!("{:.6} TRX", balance))
}

/// Get ETH balance
#[tauri::command]
pub async fn get_eth_balance(state: State<'_, TauriState>, address: String) -> Result<String, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    validate_len(&address, "Address")?;
    validate_eth_address(&address)?;
    let balance = manager.get_eth_balance(&address).await.map_err(|e| e.to_string())?;
    Ok(format!("{:.4} ETH", balance))
}

/// Get USDT (ERC-20) balance
#[tauri::command]
pub async fn get_eth_usdt_balance(state: State<'_, TauriState>, address: String) -> Result<String, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    validate_len(&address, "Address")?;
    validate_eth_address(&address)?;
    let balance = manager.get_eth_usdt_balance(&address).await.map_err(|e| e.to_string())?;
    Ok(format!("{:.6} USDT", balance))
}

/// Start mining with specified address
#[tauri::command]
pub async fn start_mining(
    state: State<'_, TauriState>, 
    app_handle: tauri::AppHandle,
    address: String
) -> Result<(), String> {
    validate_len(&address, "Address")?;
    parse_aera_address(&address)?;
    // 1. Get access to mining manager
    let manager_arc = state.manager.clone();
    let guard = manager_arc.read().await;
    let manager_ref = guard.as_ref().ok_or("Node not initialized")?;
    
    // Configure mining inside the mining manager lock
    {
        let mut mining = manager_ref.mining().write().await;
        mining.set_miner_address(address);
        
        // Setup reward callback
        let m_handle = manager_arc.clone();
        mining.set_block_found_callback(move |addr, reward| {
            let m_ptr = m_handle.clone();
            // Rewards are credited asynchronously
            tauri::async_runtime::spawn(async move {
                let guard = m_ptr.read().await;
                if let Some(m) = guard.as_ref() {
                    m.credit_mining_reward(addr, reward).await;
                }
            });
        });
        
        mining.start();
    }

    // 2. Start event emission task (pushes hashrate/difficulty to UI every second)
    let m_handle_emitter = manager_arc.clone();
    tauri::async_runtime::spawn(async move {
        use tauri::Emitter;
        
        debug!("📡 Mining event emitter task started.");
        loop {
            // Check if mining is still active
            let stats = {
                let guard = m_handle_emitter.read().await;
                if let Some(m) = guard.as_ref() {
                    let mining_guard = m.mining().read().await;
                    let s = mining_guard.get_status();
                    if !s.is_active {
                        break;
                    }
                    Some(s)
                } else {
                    break;
                }
            };

            if let Some(s) = stats {
                // Emit mining-tick event to frontend
                if let Err(e) = app_handle.emit("mining-tick", &s) {
                    tracing::error!("Failed to emit mining-tick: {}", e);
                    break;
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        debug!("📡 Mining event emitter task stopped.");
    });

    Ok(())
}

/// Stop mining
#[tauri::command]
pub async fn stop_mining(state: State<'_, TauriState>) -> Result<(), String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    let mut mining = manager.mining().write().await;
    mining.stop();
    Ok(())
}

/// Get mining status
#[tauri::command]
pub async fn get_mining_status(state: State<'_, TauriState>) -> Result<MiningStats, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    let mining = manager.mining().read().await;
    Ok(mining.get_status())
}

/// Get network info (real peer count and mining blocks). Defaults when node not initialized.
#[tauri::command]
pub async fn get_network_info(state: State<'_, TauriState>) -> Result<NetworkInfo, String> {
    let guard = state.manager.read().await;
    let (peer_count, block_height, chain_id, synced) = match guard.as_ref() {
        Some(m) => {
            let pc = m.peer_count().await;
            let bh = m.mining().read().await.get_status().blocks_mined;
            (pc, bh, m.config().chain_id, pc > 0)
        }
        None => (0, 0, 1, false),
    };
    Ok(NetworkInfo { peer_count, block_height, chain_id, synced })
}

/// Get transaction history for an address
#[tauri::command]
pub async fn get_activity(
    state: State<'_, TauriState>,
    address: String,
) -> Result<Vec<TransactionRecord>, String> {
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    validate_len(&address, "Address")?;
    
    manager.state().get_activity(&address).map_err(|e| e.to_string())
}

/// Get tokenomics info
/// Called: await invoke('get_tokenomics')
#[tauri::command]
pub async fn get_tokenomics() -> Result<TokenomicsInfo, String> {
    Ok(TokenomicsInfo {
        total_supply: format_aera(TOTAL_SUPPLY),
        circulating: "0".to_string(), // Would calculate from state
        block_reward: format_aera(BLOCK_REWARD),
        decimals: DECIMALS,
    })
}

/// Send native AERA or USDT transaction to node API
/// Called: await invoke('send_aera_transaction', { recipient, amount, asset, password })
#[tauri::command]
pub async fn send_aera_transaction(
    state: State<'_, TauriState>,
    from: String,
    recipient: String,
    amount: String,
    asset: String,
    password: String,
) -> Result<TransactionResult, String> {
    validate_password(&password)?;
    validate_len(&from, "From")?;
    validate_len(&recipient, "Recipient")?;
    validate_len(&amount, "Amount")?;
    validate_len(&asset, "Asset")?;

    // 1. Get Manager & Vault
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    let vault = manager.key_vault().read().await;

    // 2. Identify sender (use explicit from address)
    let sender = from.to_lowercase();
    parse_aera_address(&sender)?;
    parse_aera_address(&recipient)?;
    let amount_u128 = amount.parse::<u128>().map_err(|_| "Invalid amount format")?;
    if amount_u128 == 0 {
        return Err("Amount must be greater than zero".to_string());
    }
    let asset_norm = asset.to_lowercase();
    if asset_norm != "aera" && asset_norm != "usdt" {
        return Err("Unsupported asset".to_string());
    }
    if !vault.has_key(&sender) {
        return Err("Sender address not found in keystore".to_string());
    }

    // 3. Formulate Transaction Data & Sign
    let mut payload = serde_json::json!({
        "recipient": recipient,
        "amount": amount,
        "asset": asset_norm,
        "sender": sender,
        "timestamp": current_unix_ts()?
    });

    let data_to_sign = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    
    // sign_transaction handles hybrid key extraction and zeroization internally
    let signature = vault.sign_transaction(&sender, &password, &data_to_sign)
        .map_err(|e| {
            if e.to_string().contains("System storage") {
                "Security access denied: Please check OS Credential Manager permissions".to_string()
            } else {
                format!("Signing failed: {}", e)
            }
        })?;

    // 4. Update payload with hex-encoded signature
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "signature".to_string(),
            serde_json::Value::String(hex::encode(signature)),
        );
    } else {
        return Err("Failed to build transaction payload".to_string());
    }

    // 5. POST request to AERA Node API (Simulation Fallback if connection fails)
    let client = reqwest::Client::new();
    let response_result = client
        .post("https://api.aera.network/tx/send")
        .json(&payload)
        .send()
        .await;

    match response_result {
        Ok(response) if response.status().is_success() => {
            let node_res: NodeResponse = response.json().await.map_err(|e| format!("API Response Error: {}", e))?;
            Ok(TransactionResult {
                success: true,
                tx_hash: node_res.hash,
                error: None,
            })
        }
        _ => {
            // Fallback: If it's a native AERA/USDT transaction and remote fails, process locally if possible
            if asset_norm == "aera" {
                match manager.send_native_transaction(sender, recipient, amount_u128, &password).await {
                    Ok(tx_hash) => {
                        Ok(TransactionResult {
                            success: true,
                            tx_hash: Some(tx_hash),
                            error: None,
                        })
                    }
                    Err(e) => {
                        Ok(TransactionResult {
                            success: false,
                            tx_hash: None,
                            error: Some(format!("Local processing failed: {}", e)),
                        })
                    }
                }
            } else {
                // If not native AERA, we can't process it locally
                Ok(TransactionResult {
                    success: false,
                    tx_hash: None,
                    error: Some("Node connection failed and local processing not available for this asset".to_string()),
                })
            }
        }
    }
}

/// Cross-chain transfer (ETH/TRON)
/// Called: await invoke('cross_chain_transfer', { from, to, amount, chain, password })
#[tauri::command]
pub async fn cross_chain_transfer(
    state: State<'_, TauriState>,
    from: String,
    to: String,
    amount: String,
    chain: String,
    password: String,
) -> Result<TransactionResult, String> {
    validate_password(&password)?;
    validate_len(&from, "From")?;
    validate_len(&to, "To")?;
    validate_len(&amount, "Amount")?;
    validate_len(&chain, "Chain")?;
    let guard = state.manager.read().await;
    let manager = guard.as_ref().ok_or("Node not initialized")?;
    let vault = manager.key_vault().read().await;
    let from_key = from.to_lowercase();
    if !vault.has_key(&from_key) {
        return Err("From address not found in keystore".to_string());
    }

    let amount: u128 = amount.parse().map_err(|_| "Invalid amount")?;
    if amount == 0 {
        return Err("Amount must be greater than zero".to_string());
    }
    
    let target = match chain.to_lowercase().as_str() {
        "ethereum" | "eth" => TargetChain::Ethereum,
        "bridge_eth" | "erc20" | "usdt" => TargetChain::EthereumUsdt,
        "tron_native" | "trx_native" => TargetChain::TronNative,
        "tron" | "trx" => TargetChain::Tron,
        _ => TargetChain::Aera,
    };

    match target {
        TargetChain::Aera => {
            parse_aera_address(&to)?;
        }
        TargetChain::Ethereum | TargetChain::EthereumUsdt => {
            validate_eth_address(&to)?;
        }
        TargetChain::Tron | TargetChain::TronNative => {
            validate_tron_address(&to)?;
        }
    }

    let transfer = CrossChainTransfer {
        from_key: from_key,
        to_address: to,
        amount,
        target_chain: target,
    };

    match manager.send_cross_chain_transfer(transfer, &password).await {
        Ok(tx_hash) => Ok(TransactionResult {
            success: true,
            tx_hash: Some(tx_hash),
            error: None,
        }),
        Err(e) => Ok(TransactionResult {
            success: false,
            tx_hash: None,
            error: Some(e.to_string()),
        }),
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Format amount with AERA decimals
fn format_aera(amount: u128) -> String {
    let decimals = 10u128.pow(DECIMALS);
    let whole = amount / decimals;
    let frac = amount % decimals;
    if frac == 0 {
        format!("{} AERA", whole)
    } else {
        // Pad with leading zeros to match DECIMALS length
        let frac_str = format!("{:0width$}", frac, width = DECIMALS as usize);
        // Trim trailing zeros for cleaner display, but keep at least 4 digits
        let trimmed_frac = frac_str.trim_end_matches('0');
        let displayed_frac = if trimmed_frac.len() < 4 {
            &frac_str[..4]
        } else {
            trimmed_frac
        };
        format!("{}.{} AERA", whole, displayed_frac)
    }
}

// ============================================================================
// Input validation helpers
// ============================================================================

const MIN_PASSWORD_LEN: usize = 8;
const MAX_INPUT_LEN: usize = 512;

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(format!("Password must be at least {} characters", MIN_PASSWORD_LEN));
    }
    Ok(())
}

fn validate_mnemonic(phrase: &str) -> Result<(), String> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 12 && words.len() != 24 {
        return Err("Mnemonic must be 12 or 24 words".to_string());
    }
    Ok(())
}

fn validate_len(value: &str, field: &str) -> Result<(), String> {
    if value.len() > MAX_INPUT_LEN {
        return Err(format!("{} is too long", field));
    }
    Ok(())
}

fn parse_aera_address(address: &str) -> Result<[u8; 32], String> {
    let address = address.trim().to_lowercase();
    if !address.starts_with("aera1") || address.len() != 69 {
        return Err("Invalid AERA address format".to_string());
    }
    let hex_part = address.replace("aera1", "");
    let bytes = hex::decode(&hex_part).map_err(|_| "Invalid AERA address hex")?;
    if bytes.len() != 32 {
        return Err("Invalid AERA address length".to_string());
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn validate_eth_address(address: &str) -> Result<(), String> {
    let address = address.trim().to_lowercase();
    if !address.starts_with("0x") || address.len() != 42 {
        return Err("Invalid Ethereum address format".to_string());
    }
    Ok(())
}

fn validate_tron_address(address: &str) -> Result<(), String> {
    let address = address.trim();
    if !(address.starts_with('T') || address.starts_with('t')) || address.len() < 30 {
        return Err("Invalid TRON address format".to_string());
    }
    Ok(())
}

fn current_unix_ts() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "Invalid system time".to_string())
}

fn sanitize_data_dir(app_handle: &tauri::AppHandle, data_dir: &str) -> Result<String, String> {
    if data_dir.trim().is_empty() {
        return Err("Data directory is required".to_string());
    }
    let data_dir = data_dir.trim();
    validate_len(data_dir, "Data directory")?;
    let path = Path::new(data_dir);

    // Reject parent traversal
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("Invalid data directory path".to_string());
    }

    // Allow relative paths, or absolute paths under app data dir
    if path.is_absolute() {
        let base = app_handle.path().app_data_dir().map_err(|e| e.to_string())?;
        let base = base.to_string_lossy().to_string();
        let normalized = path.to_string_lossy().to_string();
        if !normalized.starts_with(&base) {
            return Err("Data directory must be under app data directory".to_string());
        }
    }

    Ok(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aera_address_accepts_valid() {
        let addr = format!("aera1{}", "00".repeat(32));
        let parsed = parse_aera_address(&addr).expect("valid");
        assert_eq!(parsed, [0u8; 32]);
    }

    #[test]
    fn validate_mnemonic_requires_word_count() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(validate_mnemonic(phrase).is_ok());
        assert!(validate_mnemonic("one two three").is_err());
    }
}
