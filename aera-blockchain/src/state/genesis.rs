//! Genesis Block Configuration
//!
//! Defines initial state of the AERA blockchain:
//! - Total supply: 4,600,000,000 AERA
//! - Developer allocation: 600,000,000 AERA
//! - Mining reserve: 4,000,000,000 AERA
//! - Block reward: 1 AERA per block

use crate::state::{Account, StateDB, Validator};
use crate::types::{Address, Amount, Block, BlockHeader, Hash};
use anyhow::{anyhow, Result};
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
// use std::sync::Arc;
use tracing::info;

// ============================================================================
// Token Economics Constants
// ============================================================================

/// Total token supply: 4,600,000,000 AERA (18 decimals)
pub const TOTAL_SUPPLY: Amount = 4_600_000_000_000_000_000_000_000_000;

/// Developer allocation: 600,000,000 AERA
pub const DEVELOPER_ALLOCATION: Amount = 600_000_000_000_000_000_000_000_000;

/// Mining rewards pool: 4,000,000,000 AERA
pub const MINING_REWARDS_POOL: Amount = 4_000_000_000_000_000_000_000_000_000;

/// Block reward: 1 AERA per block
pub const BLOCK_REWARD: Amount = 1_000_000_000_000_000_000;

/// Transaction fee: 0.001% of amount (in basis points: 1 = 0.001%)
pub const TX_FEE_BASIS_POINTS: u64 = 1;

/// AERA token decimals
pub const DECIMALS: u32 = 18;

/// Target block time: 60 seconds
pub const TARGET_BLOCK_TIME_SECS: u64 = 60;

/// Difficulty adjustment interval: every 100 blocks
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 100;

// ============================================================================
// Genesis Addresses
// ============================================================================

/// Developer address (receives initial allocation)
pub const DEVELOPER_ADDRESS: &str = "aera1a01b2ebe0c1965b443d53291f597ba2b210e8fe055e6ec9d3eca4d132d22fd5f";

/// Mining rewards address
pub const MINING_REWARDS_ADDRESS: &str = "aera10000000000000000000000000000000000000000000000000000000000000000";

/// Genesis validator address (trusted for chain fork protection)
pub const GENESIS_VALIDATOR_ADDRESS: &str = "aera1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

// ============================================================================
// Genesis Configuration
// ============================================================================

/// Genesis configuration structure
#[derive(Debug, Clone)]
pub struct GenesisConfig {
    pub chain_id: u32,
    pub timestamp: u64,
    pub initial_difficulty: u64,
    pub genesis_validator_pubkey: [u8; 32],
    pub allocations: Vec<GenesisAllocation>,
    pub validators: Vec<GenesisValidator>,
}

/// Initial token allocation
#[derive(Debug, Clone)]
pub struct GenesisAllocation {
    pub address: Address,
    pub balance: Amount,
    pub label: String,
}

/// Initial validator
#[derive(Debug, Clone)]
pub struct GenesisValidator {
    pub address: Address,
    pub stake: Amount,
    pub pubkey: [u8; 32],
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            timestamp: 1705750800000, // 2024-01-20 12:00:00 UTC
            initial_difficulty: 1000,
            genesis_validator_pubkey: [0u8; 32],
            allocations: vec![
                GenesisAllocation {
                    address: address_from_string(DEVELOPER_ADDRESS),
                    balance: DEVELOPER_ALLOCATION,
                    label: "Developer Fund".to_string(),
                },
                GenesisAllocation {
                    address: address_from_string(MINING_REWARDS_ADDRESS),
                    balance: MINING_REWARDS_POOL,
                    label: "Mining Rewards".to_string(),
                },
            ],
            validators: vec![],
        }
    }
}

// ============================================================================
// Genesis Block Creation
// ============================================================================

/// Create the genesis block
pub fn create_genesis_block(config: &GenesisConfig) -> Block {
    let header = BlockHeader {
        version: 1,
        prev_hash: [0u8; 32],
        tx_root: compute_empty_merkle_root(),
        state_root: [0u8; 32],
        timestamp: config.timestamp,
        height: 0,
        validator: address_from_string(GENESIS_VALIDATOR_ADDRESS),
        validator_pubkey: [0u8; 32],
        signature: Signature::from_bytes(&[0u8; 64]),
    };

    Block {
        header,
        transactions: vec![],
    }
}

/// Initialize state with genesis allocations
pub fn initialize_genesis_state(state: &StateDB, config: &GenesisConfig) -> Result<Hash> {
    info!("🌍 Initializing genesis state...");
    info!("   Total supply: {} AERA", TOTAL_SUPPLY / 10u128.pow(DECIMALS));

    let total_allocated: Amount = config.allocations.iter().map(|a| a.balance).sum();
    if total_allocated != TOTAL_SUPPLY {
        return Err(anyhow!(
            "Genesis allocations must equal total supply (allocated: {}, total: {})",
            total_allocated,
            TOTAL_SUPPLY
        ));
    }

    for allocation in &config.allocations {
        let account = Account {
            address: allocation.address,
            balance: allocation.balance,
            nonce: 0,
            code_hash: None,
            storage_root: None,
        };
        state.put_account(&account)?;
        info!(
            "   ✓ {} : {} AERA",
            allocation.label,
            allocation.balance / 10u128.pow(DECIMALS)
        );
    }

    for validator in &config.validators {
        let v = Validator::new(validator.address, validator.stake);
        state.put_validator(&v)?;
    }

    let state_root = compute_state_root(state)?;
    Ok(state_root)
}

// ============================================================================
// Fee Calculation
// ============================================================================

/// Calculate transaction fee (0.001% of amount)
pub fn calculate_tx_fee(amount: Amount) -> Amount {
    amount * TX_FEE_BASIS_POINTS as u128 / 100_000
}

/// Minimum transaction fee
pub const MIN_TX_FEE: Amount = 1_000_000_000_000_000; // 0.001 AERA

pub fn calculate_fee(amount: Amount) -> Amount {
    std::cmp::max(calculate_tx_fee(amount), MIN_TX_FEE)
}

// ============================================================================
// Helpers
// ============================================================================

fn address_from_string(addr: &str) -> Address {
    let hex_part = addr.replace("aera1", "");
    let bytes = hex::decode(hex_part).unwrap_or_else(|_| [0u8; 32].to_vec());
    let mut address = [0u8; 32];
    if bytes.len() == 32 {
        address.copy_from_slice(&bytes);
    }
    address
}

fn compute_empty_merkle_root() -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"AERA_EMPTY_MERKLE_ROOT");
    hasher.finalize().into()
}

fn compute_state_root(_state: &StateDB) -> Result<Hash> {
    let mut hasher = Sha256::new();
    hasher.update(b"AERA_STATE_ROOT_V1");
    Ok(hasher.finalize().into())
}

pub fn is_valid_genesis(block: &Block, config: &GenesisConfig) -> bool {
    block.header.height == 0
        && block.header.prev_hash == [0u8; 32]
        && block.header.timestamp == config.timestamp
        && block.transactions.is_empty()
}

pub fn genesis_hash(config: &GenesisConfig) -> Hash {
    let block = create_genesis_block(config);
    block.hash()
}
