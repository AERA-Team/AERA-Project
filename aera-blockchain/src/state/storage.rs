//! Persistent state storage using sled embedded database

use super::{Account, Validator, TransactionRecord};
use crate::types::{Address, Amount, Hash};
use anyhow::{anyhow, Context, Result};
use std::path::Path;
use tracing::{debug, info};
use sha2::{Digest, Sha256};

/// State database for persistent account storage
pub struct StateDB {
    /// Sled database instance
    db: sled::Db,
    /// Accounts tree
    accounts: sled::Tree,
    /// Validators tree
    validators: sled::Tree,
    /// Contract code tree
    code: sled::Tree,
    /// Contract storage tree
    storage: sled::Tree,
    /// Transaction history tree
    history: sled::Tree,
}

impl StateDB {
    /// Open or create a state database at the specified path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let db = sled::open(path_ref)
            .with_context(|| format!("Failed to open state database at {}", path_ref.display()))?;
        
        let accounts = db.open_tree("accounts")?;
        let validators = db.open_tree("validators")?;
        let code = db.open_tree("code")?;
        let storage = db.open_tree("storage")?;
        let history = db.open_tree("history")?;

        info!("State database opened at {:?}", path.as_ref());

        Ok(Self {
            db,
            accounts,
            validators,
            code,
            storage,
            history,
        })
    }

    /// Create an in-memory state database (for testing)
    pub fn in_memory() -> Result<Self> {
        let config = sled::Config::new().temporary(true);
        let db = config.open()?;
        
        let accounts = db.open_tree("accounts")?;
        let validators = db.open_tree("validators")?;
        let code = db.open_tree("code")?;
        let storage = db.open_tree("storage")?;
        let history = db.open_tree("history")?;

        Ok(Self {
            db,
            accounts,
            validators,
            code,
            storage,
            history,
        })
    }

    /// Get account by address
    pub fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        match self.accounts.get(address)? {
            Some(data) => {
                let account: Account = bincode::deserialize(&data)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Get account or create a new one if not exists
    pub fn get_or_create_account(&self, address: &Address) -> Result<Account> {
        match self.get_account(address)? {
            Some(account) => Ok(account),
            None => {
                let account = Account::new_eoa(*address);
                self.put_account(&account)?;
                Ok(account)
            }
        }
    }

    /// Store account
    pub fn put_account(&self, account: &Account) -> Result<()> {
        let data = bincode::serialize(account)?;
        self.accounts.insert(&account.address, data)?;
        debug!("Stored account {:?}", hex::encode(&account.address[..8]));
        Ok(())
    }

    /// Get account balance
    pub fn get_balance(&self, address: &Address) -> Result<Amount> {
        match self.get_account(address)? {
            Some(account) => Ok(account.balance),
            None => Ok(0),
        }
    }

    /// Set account balance
    pub fn set_balance(&self, address: &Address, balance: Amount) -> Result<()> {
        let mut account = self.get_or_create_account(address)?;
        account.balance = balance;
        self.put_account(&account)
    }

    /// Check if the state database is empty (no accounts)
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.accounts.is_empty())
    }

    /// Transfer between accounts
    pub fn transfer(&self, from: &Address, to: &Address, amount: Amount) -> Result<bool> {
        let mut from_account = self.get_or_create_account(from)?;
        
        if !from_account.debit(amount) {
            return Ok(false);
        }
        
        let mut to_account = self.get_or_create_account(to)?;
        to_account.credit(amount);
        
        from_account.increment_nonce();
        
        self.put_account(&from_account)?;
        self.put_account(&to_account)?;
        
        info!(
            "Transfer: {} -> {} amount: {}",
            hex::encode(&from[..8]),
            hex::encode(&to[..8]),
            amount
        );
        
        Ok(true)
    }

    /// Get validator by address
    pub fn get_validator(&self, address: &Address) -> Result<Option<Validator>> {
        match self.validators.get(address)? {
            Some(data) => {
                let validator: Validator = bincode::deserialize(&data)?;
                Ok(Some(validator))
            }
            None => Ok(None),
        }
    }

    /// Store validator
    pub fn put_validator(&self, validator: &Validator) -> Result<()> {
        let data = bincode::serialize(validator)?;
        self.validators.insert(&validator.address, data)?;
        Ok(())
    }

    /// Get all active validators
    pub fn get_active_validators(&self) -> Result<Vec<Validator>> {
        let mut validators = Vec::new();
        for entry in self.validators.iter() {
            let (_, data) = entry?;
            let validator: Validator = bincode::deserialize(&data)?;
            if validator.active {
                validators.push(validator);
            }
        }
        Ok(validators)
    }

    /// Store contract code
    pub fn put_code(&self, code_hash: &Hash, code: &[u8]) -> Result<()> {
        self.code.insert(code_hash, code)?;
        Ok(())
    }

    /// Get contract code
    pub fn get_code(&self, code_hash: &Hash) -> Result<Option<Vec<u8>>> {
        match self.code.get(code_hash)? {
            Some(data) => Ok(Some(data.to_vec())),
            None => Ok(None),
        }
    }

    /// Store contract storage slot
    pub fn put_storage(&self, address: &Address, key: &Hash, value: &Hash) -> Result<()> {
        let mut storage_key = Vec::with_capacity(64);
        storage_key.extend_from_slice(address);
        storage_key.extend_from_slice(key);
        self.storage.insert(storage_key, value.as_slice())?;
        Ok(())
    }

    /// Get contract storage slot
    pub fn get_storage(&self, address: &Address, key: &Hash) -> Result<Option<Hash>> {
        let mut storage_key = Vec::with_capacity(64);
        storage_key.extend_from_slice(address);
        storage_key.extend_from_slice(key);
        
        match self.storage.get(storage_key)? {
            Some(data) => {
                if data.len() < 32 {
                    return Err(anyhow!(
                        "Invalid storage value length: expected 32 bytes, got {}",
                        data.len()
                    ));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[..32]);
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }

    // ========================================================================
    // Transaction History (Encrypted)
    // ========================================================================

    /// Store a transaction record (unencrypted locally for multi-wallet sync)
    pub fn put_transaction(&self, tx: &TransactionRecord) -> Result<()> {
        let data = bincode::serialize(tx)?;
        
        // Store the transaction itself (keyed by hash)
        self.history.insert(tx.hash.as_bytes(), data)?;

        // Update indices for both sender and receiver
        self.update_address_index(&tx.from, &tx.hash)?;
        self.update_address_index(&tx.to, &tx.hash)?;

        Ok(())
    }

    /// Get all transactions for a specific address
    pub fn get_activity(&self, address: &str) -> Result<Vec<TransactionRecord>> {
        let index_key = self.derive_index_key(address);
        
        let tx_hashes: Vec<String> = match self.history.get(&index_key)? {
            Some(data) => bincode::deserialize(&data)?,
            None => return Ok(Vec::new()),
        };

        let mut txs = Vec::new();
        for hash in tx_hashes {
            if let Some(data) = self.history.get(hash.as_bytes())? {
                let tx: TransactionRecord = bincode::deserialize(&data)?;
                txs.push(tx);
            }
        }

        // Sort by timestamp descending
        txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(txs)
    }

    fn update_address_index(&self, address: &str, tx_hash: &str) -> Result<()> {
        let index_key = self.derive_index_key(address);
        
        let mut tx_hashes: Vec<String> = match self.history.get(&index_key)? {
            Some(data) => bincode::deserialize(&data)?,
            None => Vec::new(),
        };

        if !tx_hashes.contains(&tx_hash.to_string()) {
            tx_hashes.push(tx_hash.to_string());
            let data = bincode::serialize(&tx_hashes)?;
            self.history.insert(index_key, data)?;
        }

        Ok(())
    }

    pub fn derive_index_key(&self, address: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(address.as_bytes());
        let hash = hasher.finalize();
        let mut key = b"idx_".to_vec();
        key.extend_from_slice(&hash);
        key
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_operations() {
        let db = StateDB::in_memory().unwrap();
        let tx = TransactionRecord {
            hash: "test_hash".to_string(),
            from: "addr1".to_string(),
            to: "addr2".to_string(),
            amount: 100,
            timestamp: 12345,
            chain: "Aera".to_string(),
            status: crate::state::TransactionStatus::Confirmed,
        };
        db.put_transaction(&tx).unwrap();
        let activity = db.get_activity("addr1").unwrap();
        assert_eq!(activity.len(), 1);
        assert_eq!(activity[0].hash, "test_hash");
    }
}
