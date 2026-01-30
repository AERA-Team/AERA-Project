//! Deposit Store
//!
//! Persistent storage for cross-chain deposits using sled DB.
//! Ensures deposits are not processed twice after node restart.

use super::{Deposit, DepositStatus, ExternalChain};
use anyhow::{Context, Result};
use std::path::Path;
use tracing::{debug, info};

/// Persistent store for bridge deposits
#[derive(Clone)]
pub struct DepositStore {
    /// Sled database
    db: sled::Db,
    /// Deposits tree
    deposits: sled::Tree,
    /// Processed deposit IDs tree
    processed: sled::Tree,
    /// Metadata tree (last processed blocks, etc.)
    metadata: sled::Tree,
}

impl DepositStore {
    /// Open or create a deposit store
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path.as_ref()).context("Failed to open deposit store")?;
        
        let deposits = db.open_tree("deposits")?;
        let processed = db.open_tree("processed")?;
        let metadata = db.open_tree("metadata")?;

        info!("📦 Deposit store opened at {:?}", path.as_ref());

        Ok(Self {
            db,
            deposits,
            processed,
            metadata,
        })
    }

    /// Create an in-memory store (for testing)
    pub fn in_memory() -> Result<Self> {
        let config = sled::Config::new().temporary(true);
        let db = config.open()?;
        
        let deposits = db.open_tree("deposits")?;
        let processed = db.open_tree("processed")?;
        let metadata = db.open_tree("metadata")?;

        Ok(Self {
            db,
            deposits,
            processed,
            metadata,
        })
    }

    /// Store a deposit
    pub fn store_deposit(&self, deposit: &Deposit) -> Result<()> {
        let key = &deposit.id;
        let value = bincode::serialize(deposit)?;
        self.deposits.insert(key, value)?;
        debug!("Stored deposit: {:?}", hex::encode(&deposit.id[..8]));
        Ok(())
    }

    /// Get deposit by ID
    pub fn get_deposit(&self, id: &[u8; 32]) -> Result<Option<Deposit>> {
        match self.deposits.get(id)? {
            Some(data) => {
                let deposit: Deposit = bincode::deserialize(&data)?;
                Ok(Some(deposit))
            }
            None => Ok(None),
        }
    }

    /// Check if a deposit has been processed (minted)
    pub fn is_processed(&self, id: &[u8; 32]) -> Result<bool> {
        Ok(self.processed.contains_key(id)?)
    }

    /// Mark a deposit as processed
    pub fn mark_processed(&self, id: &[u8; 32]) -> Result<()> {
        self.processed.insert(id, &[1u8])?;
        
        // Update deposit status
        if let Some(mut deposit) = self.get_deposit(id)? {
            deposit.status = DepositStatus::Minted;
            self.store_deposit(&deposit)?;
        }
        
        info!("Marked deposit as processed: {:?}", hex::encode(&id[..8]));
        Ok(())
    }

    /// Get all pending deposits for a chain
    pub fn get_pending_deposits(&self, chain: ExternalChain) -> Result<Vec<Deposit>> {
        let mut pending = Vec::new();
        
        for entry in self.deposits.iter() {
            let (_, data) = entry?;
            let deposit: Deposit = bincode::deserialize(&data)?;
            
            if deposit.chain == chain && deposit.status == DepositStatus::Pending {
                pending.push(deposit);
            }
        }
        
        Ok(pending)
    }

    /// Get all confirmed deposits ready for minting
    pub fn get_confirmed_deposits(&self) -> Result<Vec<Deposit>> {
        let mut confirmed = Vec::new();
        
        for entry in self.deposits.iter() {
            let (_, data) = entry?;
            let deposit: Deposit = bincode::deserialize(&data)?;
            
            if deposit.status == DepositStatus::Confirmed {
                confirmed.push(deposit);
            }
        }
        
        Ok(confirmed)
    }

    /// Get last processed ETH block
    pub fn get_last_eth_block(&self) -> Result<Option<u64>> {
        match self.metadata.get(b"last_eth_block")? {
            Some(data) => {
                let bytes: [u8; 8] = data.as_ref().try_into()?;
                Ok(Some(u64::from_le_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Set last processed ETH block
    pub fn set_last_eth_block(&self, block: u64) -> Result<()> {
        self.metadata.insert(b"last_eth_block", &block.to_le_bytes())?;
        Ok(())
    }

    /// Get deposit statistics
    pub fn get_stats(&self) -> Result<DepositStats> {
        let mut stats = DepositStats::default();
        
        for entry in self.deposits.iter() {
            let (_, data) = entry?;
            let deposit: Deposit = bincode::deserialize(&data)?;
            
            stats.total_count += 1;
            
            match deposit.status {
                DepositStatus::Pending => stats.pending_count += 1,
                DepositStatus::Confirmed => stats.confirmed_count += 1,
                DepositStatus::Minted => stats.minted_count += 1,
                DepositStatus::Failed => stats.failed_count += 1,
            }
            
            match deposit.chain {
                ExternalChain::Ethereum => stats.eth_count += 1,
                ExternalChain::Tron => stats.tron_count += 1,
            }
        }
        
        Ok(stats)
    }

    /// Flush all pending writes
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

/// Deposit statistics
#[derive(Debug, Default)]
pub struct DepositStats {
    pub total_count: u64,
    pub pending_count: u64,
    pub confirmed_count: u64,
    pub minted_count: u64,
    pub failed_count: u64,
    pub eth_count: u64,
    pub tron_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_deposit(id: u8) -> Deposit {
        Deposit {
            id: [id; 32],
            chain: ExternalChain::Ethereum,
            source_tx_hash: vec![id; 32],
            source_block: 12345,
            sender: "0x1234".to_string(),
            recipient: [0u8; 32],
            token: super::super::TokenType::USDT,
            amount: 1000000,
            confirmations: 12,
            status: DepositStatus::Pending,
            detected_at: 0,
        }
    }

    #[test]
    fn test_store_and_retrieve() {
        let store = DepositStore::in_memory().unwrap();
        let deposit = create_test_deposit(1);
        
        store.store_deposit(&deposit).unwrap();
        
        let retrieved = store.get_deposit(&deposit.id).unwrap().unwrap();
        assert_eq!(retrieved.id, deposit.id);
        assert_eq!(retrieved.amount, deposit.amount);
    }

    #[test]
    fn test_mark_processed() {
        let store = DepositStore::in_memory().unwrap();
        let deposit = create_test_deposit(2);
        
        store.store_deposit(&deposit).unwrap();
        assert!(!store.is_processed(&deposit.id).unwrap());
        
        store.mark_processed(&deposit.id).unwrap();
        assert!(store.is_processed(&deposit.id).unwrap());
        
        let updated = store.get_deposit(&deposit.id).unwrap().unwrap();
        assert_eq!(updated.status, DepositStatus::Minted);
    }

    #[test]
    fn test_pending_deposits() {
        let store = DepositStore::in_memory().unwrap();
        
        let mut d1 = create_test_deposit(1);
        d1.status = DepositStatus::Pending;
        
        let mut d2 = create_test_deposit(2);
        d2.status = DepositStatus::Confirmed;
        
        store.store_deposit(&d1).unwrap();
        store.store_deposit(&d2).unwrap();
        
        let pending = store.get_pending_deposits(ExternalChain::Ethereum).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, d1.id);
    }
}
