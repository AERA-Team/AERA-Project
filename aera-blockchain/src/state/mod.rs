//! State management module
//!
//! Account-based state model (like Ethereum) with persistent storage

mod storage;
pub mod genesis;

pub use storage::StateDB;
pub use genesis::*;

use crate::types::{Address, Amount, Hash, Nonce};
use serde::{Deserialize, Serialize};

/// Account structure in AERA blockchain
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Account {
    /// Account address (derived from public key)
    pub address: Address,
    /// Native token balance
    pub balance: Amount,
    /// Transaction nonce
    pub nonce: Nonce,
    /// Code hash for smart contracts (None for EOA)
    pub code_hash: Option<Hash>,
    /// Storage root for smart contracts
    pub storage_root: Option<Hash>,
}

impl Account {
    /// Create a new externally owned account (EOA)
    pub fn new_eoa(address: Address) -> Self {
        Self {
            address,
            balance: 0,
            nonce: 0,
            code_hash: None,
            storage_root: None,
        }
    }

    /// Create a new contract account
    pub fn new_contract(address: Address, code_hash: Hash) -> Self {
        Self {
            address,
            balance: 0,
            nonce: 0,
            code_hash: Some(code_hash),
            storage_root: Some([0u8; 32]),
        }
    }

    /// Check if this is a contract account
    pub fn is_contract(&self) -> bool {
        self.code_hash.is_some()
    }

    /// Credit balance to account
    pub fn credit(&mut self, amount: Amount) {
        self.balance = self.balance.saturating_add(amount);
    }

    /// Debit balance from account (returns false if insufficient)
    pub fn debit(&mut self, amount: Amount) -> bool {
        if self.balance >= amount {
            self.balance -= amount;
            true
        } else {
            false
        }
    }

    /// Increment nonce after transaction
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }
}

/// Transaction record for history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u128,
    pub timestamp: u64,
    pub chain: String,
    pub status: TransactionStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

/// Validator information for PoS consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Validator address
    pub address: Address,
    /// Staked amount
    pub stake: Amount,
    /// Commission rate (basis points, e.g., 500 = 5%)
    pub commission: u16,
    /// Is active validator
    pub active: bool,
    /// Total blocks produced
    pub blocks_produced: u64,
}

impl Validator {
    /// Create a new validator
    pub fn new(address: Address, stake: Amount) -> Self {
        Self {
            address,
            stake,
            commission: 500, // Default 5%
            active: true,
            blocks_produced: 0,
        }
    }
}
