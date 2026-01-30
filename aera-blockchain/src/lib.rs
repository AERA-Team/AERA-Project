//! AERA Blockchain - L1 with EVM compatibility and cross-chain integration
//!
//! # Modules
//! - `consensus` - Hybrid PoS consensus engine
//! - `network` - libp2p-based P2P networking
//! - `state` - Account-based state management
//! - `bridge` - Cross-chain integration (ETH, TRON)
//! - `api` - JSON-RPC API server
//! - `wallet` - Key management and security
//! - `manager` - Central coordinator

pub mod consensus;
pub mod network;
pub mod state;
pub mod bridge;
pub mod api;
pub mod wallet;
pub mod types;
pub mod mining;
pub mod manager;
pub mod tauri_bridge;
