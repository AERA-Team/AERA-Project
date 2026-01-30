//! Core types used across the AERA blockchain

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

/// 32-byte hash type used for block hashes, merkle roots, etc.
pub type Hash = [u8; 32];

/// 32-byte address derived from public key
pub type Address = [u8; 32];

/// Block height (number)
pub type BlockHeight = u64;

/// Token amount (supports up to 10^38 units)
pub type Amount = u128;

/// Unix timestamp in milliseconds
pub type Timestamp = u64;

/// Nonce for transaction replay protection
pub type Nonce = u64;

/// Block header containing metadata and validator signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Protocol version
    pub version: u32,
    /// Hash of the previous block
    pub prev_hash: Hash,
    /// Merkle root of transactions
    pub tx_root: Hash,
    /// Merkle root of state after block execution
    pub state_root: Hash,
    /// Block creation timestamp (ms since epoch)
    pub timestamp: Timestamp,
    /// Block height
    pub height: BlockHeight,
    /// Validator who produced this block
    pub validator: Address,
    /// Validator's signature over block header
    #[serde(with = "signature_serde")]
    pub signature: Signature,
}

/// Full block with header and transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// List of transactions
    pub transactions: Vec<Transaction>,
}

/// Transaction types supported by AERA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    /// Native token transfer
    Transfer,
    /// Smart contract deployment
    Deploy,
    /// Smart contract call
    Call,
    /// Staking operation
    Stake,
    /// Unstaking operation
    Unstake,
    /// Cross-chain bridge operation
    Bridge,
}

/// Signed transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type
    pub tx_type: TransactionType,
    /// Sender address
    pub from: Address,
    /// Recipient address (or contract address)
    pub to: Address,
    /// Amount of native tokens to transfer
    pub value: Amount,
    /// Transaction data (contract bytecode or call data)
    pub data: Vec<u8>,
    /// Gas limit for execution
    pub gas_limit: u64,
    /// Gas price in native tokens
    pub gas_price: u64,
    /// Sender's nonce
    pub nonce: Nonce,
    /// Chain ID for replay protection
    pub chain_id: u32,
    /// Transaction signature
    #[serde(with = "signature_serde")]
    pub signature: Signature,
}

impl Transaction {
    /// Calculate transaction hash
    pub fn hash(&self) -> Hash {
        use sha2::{Sha256, Digest};
        let encoded = bincode::serialize(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().into()
    }
}

impl Block {
    /// Calculate block hash (hash of header)
    pub fn hash(&self) -> Hash {
        use sha2::{Sha256, Digest};
        let encoded = bincode::serialize(&self.header).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().into()
    }
}

/// Serde support for ed25519 Signature
mod signature_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserializer, Serialize, Serializer};

    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        sig.to_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        let array: [u8; 64] = bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid signature length"))?;
        Ok(Signature::from_bytes(&array))
    }
}
