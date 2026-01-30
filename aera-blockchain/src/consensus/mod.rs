//! Hybrid PoS Consensus module
//!
//! Implements:
//! - Stake-weighted validator selection
//! - Block reward: 1 AERA per block
//! - Transaction fee: 0.001% rewarded to miner
//! - Difficulty adjustment for 60-second blocks
//! - Double-spend protection
//! - Fork protection via genesis key weight

mod pos;

pub use pos::*;

use crate::state::{StateDB, Validator, genesis};
use crate::types::{Address, Amount, Block, BlockHeader, Hash, Transaction};
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::info;

// ============================================================================
// Constants
// ============================================================================

/// Minimum stake required to become a validator: 100 AERA
pub const MIN_STAKE: Amount = 100_000_000_000_000_000_000;

/// Block reward: 1 AERA per block (18 decimals)
pub const BLOCK_REWARD: Amount = 1_000_000_000_000_000_000;

/// Target block time: 60 seconds (in milliseconds)
pub const TARGET_BLOCK_TIME_MS: u64 = 60_000;

/// Difficulty adjustment interval: every 100 blocks
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 100;

/// Maximum difficulty adjustment factor (4x)
pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;

/// Number of validators required for finality (2/3 + 1)
pub const FINALITY_THRESHOLD: f64 = 0.67;

/// Genesis validator weight multiplier for fork protection
pub const GENESIS_VALIDATOR_WEIGHT: u64 = 10;

// ============================================================================
// Difficulty Controller
// ============================================================================

/// Manages difficulty adjustment
#[derive(Debug, Clone)]
pub struct DifficultyController {
    pub current_difficulty: u64,
    block_timestamps: Vec<u64>,
}

impl DifficultyController {
    pub fn new(initial_difficulty: u64) -> Self {
        Self {
            current_difficulty: initial_difficulty,
            block_timestamps: Vec::new(),
        }
    }

    pub fn record_block(&mut self, timestamp: u64) {
        self.block_timestamps.push(timestamp);
        if self.block_timestamps.len() > DIFFICULTY_ADJUSTMENT_INTERVAL as usize {
            self.block_timestamps.remove(0);
        }
    }

    pub fn adjust_difficulty(&mut self, height: u64) -> u64 {
        if height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 || self.block_timestamps.len() < 2 {
            return self.current_difficulty;
        }

        let first_time = self.block_timestamps.first().copied().unwrap_or(0);
        let last_time = self.block_timestamps.last().copied().unwrap_or(0);
        
        let actual_time = last_time.saturating_sub(first_time);
        let expected_time = TARGET_BLOCK_TIME_MS * (self.block_timestamps.len() as u64 - 1);

        if actual_time == 0 {
            return self.current_difficulty;
        }

        let new_difficulty = if actual_time < expected_time {
            let ratio = expected_time / actual_time;
            let capped_ratio = std::cmp::min(ratio, MAX_ADJUSTMENT_FACTOR);
            self.current_difficulty.saturating_mul(capped_ratio)
        } else {
            let ratio = actual_time / expected_time;
            let capped_ratio = std::cmp::min(ratio, MAX_ADJUSTMENT_FACTOR);
            self.current_difficulty / capped_ratio
        };

        self.current_difficulty = std::cmp::max(new_difficulty, 1);
        
        info!(
            "⚙️ Difficulty adjusted at height {}: {} (actual: {}ms, expected: {}ms)",
            height, self.current_difficulty, actual_time, expected_time
        );

        self.current_difficulty
    }
}

// ============================================================================
// Double-Spend Tracker
// ============================================================================

pub struct DoubleSpendTracker {
    spent_in_block: HashSet<Hash>,
    spent_in_mempool: HashSet<Hash>,
}

impl DoubleSpendTracker {
    pub fn new() -> Self {
        Self {
            spent_in_block: HashSet::new(),
            spent_in_mempool: HashSet::new(),
        }
    }

    pub fn is_double_spend(&self, tx: &Transaction) -> bool {
        let tx_hash = tx.hash();
        self.spent_in_block.contains(&tx_hash) || self.spent_in_mempool.contains(&tx_hash)
    }

    pub fn mark_spent_in_block(&mut self, tx: &Transaction) {
        self.spent_in_block.insert(tx.hash());
    }

    pub fn mark_spent_in_mempool(&mut self, tx: &Transaction) {
        self.spent_in_mempool.insert(tx.hash());
    }

    pub fn clear_block(&mut self) {
        self.spent_in_block.clear();
    }

    pub fn remove_from_mempool(&mut self, tx: &Transaction) {
        self.spent_in_mempool.remove(&tx.hash());
    }
}

// ============================================================================
// Consensus Engine
// ============================================================================

pub struct ConsensusEngine {
    pub chain_id: u32,
    state: Arc<StateDB>,
    validators: Vec<Validator>,
    genesis_validator: Option<Address>,
    current_height: u64,
    difficulty: DifficultyController,
    double_spend: DoubleSpendTracker,
}

impl ConsensusEngine {
    pub fn new(chain_id: u32, state: Arc<StateDB>) -> Result<Self> {
        let validators = state.get_active_validators()?;

        Ok(Self {
            chain_id,
            state,
            validators,
            genesis_validator: None,
            current_height: 0,
            difficulty: DifficultyController::new(1000),
            double_spend: DoubleSpendTracker::new(),
        })
    }

    pub fn set_genesis_validator(&mut self, address: Address) {
        self.genesis_validator = Some(address);
    }

    // ========================================================================
    // Rewards and Fees
    // ========================================================================

    /// Apply block reward (1 AERA) and total fees to the miner
    pub fn apply_miner_rewards(&self, validator: &Address, total_fees: Amount) -> Result<()> {
        let mut account = self.state.get_or_create_account(validator)?;
        
        // Miner gets 1 AERA + all transaction fees
        let total_reward = BLOCK_REWARD + total_fees;
        account.credit(total_reward);
        
        self.state.put_account(&account)?;

        info!(
            "💰 Miner Reward: 1 AERA + {} fees paid to {}",
            total_fees, hex::encode(&validator[..8])
        );

        Ok(())
    }

    pub fn on_block_imported(&mut self, block: &Block) -> Result<()> {
        self.difficulty.record_block(block.header.timestamp);
        self.difficulty.adjust_difficulty(block.header.height);
        self.current_height = block.header.height;
        
        // Sum fees from transactions
        let mut total_fees: Amount = 0;
        for tx in &block.transactions {
            total_fees += genesis::calculate_fee(tx.value);
            self.double_spend.mark_spent_in_block(tx);
        }

        // Reward the miner
        self.apply_miner_rewards(&block.header.validator, total_fees)?;
        
        self.double_spend.clear_block();

        Ok(())
    }

    // ========================================================================
    // Validator Selection
    // ========================================================================

    pub fn select_validator(&self, height: u64) -> Option<Address> {
        if self.validators.is_empty() {
            return None;
        }

        let total_stake: Amount = self.validators.iter().map(|v| v.stake).sum();
        if total_stake == 0 {
            return None;
        }

        let seed = Self::compute_selection_seed(height);
        let selection_point = seed % total_stake;

        let mut accumulated = 0u128;
        for validator in &self.validators {
            accumulated += validator.stake;
            if accumulated > selection_point {
                return Some(validator.address);
            }
        }

        Some(self.validators[0].address)
    }

    fn compute_selection_seed(height: u64) -> Amount {
        let mut hasher = Sha256::new();
        hasher.update(b"AERA_VALIDATOR_SELECTION");
        hasher.update(height.to_le_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        u128::from_le_bytes(bytes)
    }

    pub fn verify_validator(&self, height: u64, validator: &Address) -> bool {
        match self.select_validator(height) {
            Some(expected) => expected == *validator,
            None => false,
        }
    }

    // ========================================================================
    // Block Validation
    // ========================================================================

    pub fn verify_block_header(&self, header: &BlockHeader) -> Result<()> {
        if header.height == 0 {
            // Genesis block: signature/pubkey may be unset
            return Ok(());
        }

        if !self.verify_validator(header.height, &header.validator) {
            return Err(anyhow!("Invalid validator for height {}", header.height));
        }

        let now = chrono::Utc::now().timestamp_millis() as u64;
        if header.timestamp > now + 30_000 {
            return Err(anyhow!("Block timestamp too far in future"));
        }
        let min_timestamp = now.saturating_sub(10 * 60_000);
        if header.timestamp < min_timestamp {
            return Err(anyhow!("Block timestamp too far in past"));
        }

        let verifier = VerifyingKey::from_bytes(&header.validator_pubkey)
            .map_err(|e| anyhow!("Invalid validator public key: {}", e))?;
        let expected_addr = Self::address_from_key(&verifier);
        if expected_addr != header.validator {
            return Err(anyhow!("Validator address does not match public key"));
        }

        let header_bytes = self.header_signing_bytes(header);
        verifier
            .verify_strict(&header_bytes, &header.signature)
            .map_err(|e| anyhow!("Invalid block signature: {}", e))?;

        Ok(())
    }

    pub fn verify_transaction(&self, tx: &Transaction) -> Result<()> {
        if self.double_spend.is_double_spend(tx) {
            return Err(anyhow!("Double-spend detected"));
        }

        if tx.chain_id != self.chain_id {
            return Err(anyhow!("Invalid chain_id"));
        }

        let verifier = VerifyingKey::from_bytes(&tx.public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;
        let expected_addr = Self::address_from_key(&verifier);
        if expected_addr != tx.from {
            return Err(anyhow!("Sender address does not match public key"));
        }
        let sign_bytes = tx.signing_bytes();
        verifier
            .verify_strict(&sign_bytes, &tx.signature)
            .map_err(|e| anyhow!("Invalid transaction signature: {}", e))?;

        let fee = genesis::calculate_fee(tx.value);
        let total_cost = tx.value + fee;
        
        let balance = self.state.get_balance(&tx.from)?;
        if balance < total_cost {
            return Err(anyhow!("Insufficient balance (need {} for value+fee)", total_cost));
        }

        let account = self.state.get_or_create_account(&tx.from)?;
        if tx.nonce != account.nonce {
            return Err(anyhow!("Invalid nonce: expected {}, got {}", account.nonce, tx.nonce));
        }

        Ok(())
    }

    // ========================================================================
    // Fork Protection
    // ========================================================================

    pub fn calculate_chain_weight(&self, blocks: &[Block]) -> u128 {
        let mut weight: u128 = 0;
        for block in blocks {
            weight += self.difficulty.current_difficulty as u128;
            if let Some(ref genesis) = self.genesis_validator {
                if block.header.validator == *genesis {
                    weight += (self.difficulty.current_difficulty as u128) * (GENESIS_VALIDATOR_WEIGHT as u128);
                }
            }
        }
        weight
    }

    pub fn choose_chain(&self, chain_a: &[Block], chain_b: &[Block]) -> ChainChoice {
        let weight_a = self.calculate_chain_weight(chain_a);
        let weight_b = self.calculate_chain_weight(chain_b);

        if weight_a > weight_b {
            ChainChoice::ChainA
        } else if weight_b > weight_a {
            ChainChoice::ChainB
        } else {
            let time_a = chain_a.last().map(|b| b.header.timestamp).unwrap_or(u64::MAX);
            let time_b = chain_b.last().map(|b| b.header.timestamp).unwrap_or(u64::MAX);
            if time_a <= time_b { ChainChoice::ChainA } else { ChainChoice::ChainB }
        }
    }

    // ========================================================================
    // Block Creation
    // ========================================================================

    pub fn create_block_header(
        &self,
        prev_hash: Hash,
        tx_root: Hash,
        state_root: Hash,
        validator_key: &SigningKey,
    ) -> Result<BlockHeader> {
        let validator_pubkey = validator_key.verifying_key().to_bytes();
        let validator_address = Self::address_from_key(&validator_key.verifying_key());
        let height = self.current_height + 1;
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;

        let mut header = BlockHeader {
            version: 1,
            prev_hash,
            tx_root,
            state_root,
            timestamp,
            height,
            validator: validator_address,
            validator_pubkey,
            signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
        };

        let header_bytes = self.header_signing_bytes(&header);
        header.signature = validator_key.sign(&header_bytes);

        Ok(header)
    }

    fn header_signing_bytes(&self, header: &BlockHeader) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header.version.to_le_bytes());
        bytes.extend_from_slice(&header.prev_hash);
        bytes.extend_from_slice(&header.tx_root);
        bytes.extend_from_slice(&header.state_root);
        bytes.extend_from_slice(&header.timestamp.to_le_bytes());
        bytes.extend_from_slice(&header.height.to_le_bytes());
        bytes.extend_from_slice(&header.validator);
        bytes.extend_from_slice(&header.validator_pubkey);
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes
    }

    pub fn address_from_key(key: &VerifyingKey) -> Address {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hasher.finalize().into()
    }

    pub fn register_validator(&mut self, address: Address, stake: Amount) -> Result<()> {
        if stake < MIN_STAKE {
            return Err(anyhow!("Stake below minimum"));
        }
        let validator = Validator::new(address, stake);
        self.state.put_validator(&validator)?;
        self.validators.push(validator);
        Ok(())
    }

    pub fn validators(&self) -> &[Validator] { &self.validators }
    pub fn current_height(&self) -> u64 { self.current_height }
    pub fn set_height(&mut self, height: u64) { self.current_height = height; }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainChoice {
    ChainA,
    ChainB,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Account, StateDB};
    use crate::types::TransactionType;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn verify_transaction_checks_signature_and_chain_id() {
        let state = Arc::new(StateDB::in_memory().expect("state"));
        let engine = ConsensusEngine::new(1, Arc::clone(&state)).expect("engine");

        let mut rng = OsRng;
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifier = signing_key.verifying_key();
        let from = ConsensusEngine::address_from_key(&verifier);
        let to = [1u8; 32];

        let account = Account {
            address: from,
            balance: crate::state::genesis::MIN_TX_FEE + 2,
            nonce: 0,
            code_hash: None,
            storage_root: None,
        };
        state.put_account(&account).expect("account");

        let mut tx = Transaction {
            tx_type: TransactionType::Transfer,
            from,
            to,
            value: 1,
            data: vec![],
            gas_limit: 0,
            gas_price: 0,
            nonce: 0,
            chain_id: 1,
            public_key: verifier.to_bytes(),
            signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
        };
        let sign_bytes = tx.signing_bytes();
        tx.signature = signing_key.sign(&sign_bytes);

        engine.verify_transaction(&tx).expect("valid tx");

        tx.chain_id = 2;
        assert!(engine.verify_transaction(&tx).is_err());
    }
}
