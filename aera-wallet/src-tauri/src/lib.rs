use aera_blockchain::tauri_bridge::TauriState;
use aera_blockchain::manager::ManagerConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = TauriState {
        manager: Arc::new(RwLock::new(None)),
        config: ManagerConfig::default(),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            aera_blockchain::tauri_bridge::get_default_data_dir,
            aera_blockchain::tauri_bridge::init_node,
            aera_blockchain::tauri_bridge::create_wallet,
            aera_blockchain::tauri_bridge::create_mnemonic_wallet,
            aera_blockchain::tauri_bridge::import_mnemonic_wallet,
            aera_blockchain::tauri_bridge::has_wallet,
            aera_blockchain::tauri_bridge::get_address,
            aera_blockchain::tauri_bridge::unlock_wallet,
            aera_blockchain::tauri_bridge::lock_session,
            aera_blockchain::tauri_bridge::get_balance,
            aera_blockchain::tauri_bridge::get_activity,
            aera_blockchain::tauri_bridge::get_network_info,
            aera_blockchain::tauri_bridge::get_tokenomics,
            aera_blockchain::tauri_bridge::send_aera_transaction,
            aera_blockchain::tauri_bridge::cross_chain_transfer,
            aera_blockchain::tauri_bridge::get_tron_address,
            aera_blockchain::tauri_bridge::get_tron_balance,
            aera_blockchain::tauri_bridge::get_trx_balance,
            aera_blockchain::tauri_bridge::get_eth_address,
            aera_blockchain::tauri_bridge::get_eth_balance,
            aera_blockchain::tauri_bridge::get_eth_usdt_address,
            aera_blockchain::tauri_bridge::get_eth_usdt_balance,
            aera_blockchain::tauri_bridge::start_mining,
            aera_blockchain::tauri_bridge::stop_mining,
            aera_blockchain::tauri_bridge::get_mining_status,
            aera_blockchain::tauri_bridge::refresh_wallets,
            aera_blockchain::tauri_bridge::list_wallets,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
