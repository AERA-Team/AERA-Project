//! PoS staking operations

use crate::state::StateDB;
use crate::types::{Address, Amount};
use anyhow::{anyhow, Result};
use std::sync::Arc;

/// Staking operations
pub struct StakingManager {
    state: Arc<StateDB>,
}

impl StakingManager {
    /// Create new staking manager
    pub fn new(state: Arc<StateDB>) -> Self {
        Self { state }
    }

    /// Stake tokens from an account
    pub fn stake(&self, address: &Address, amount: Amount) -> Result<()> {
        // Get current balance
        let balance = self.state.get_balance(address)?;
        if balance < amount {
            return Err(anyhow!("Insufficient balance for staking"));
        }

        // Deduct from balance
        self.state.set_balance(address, balance - amount)?;

        // Update or create validator
        match self.state.get_validator(address)? {
            Some(mut validator) => {
                validator.stake += amount;
                self.state.put_validator(&validator)?;
            }
            None => {
                let validator = crate::state::Validator::new(*address, amount);
                self.state.put_validator(&validator)?;
            }
        }

        Ok(())
    }

    /// Unstake tokens (with unbonding period - simplified)
    pub fn unstake(&self, address: &Address, amount: Amount) -> Result<()> {
        let mut validator = self.state
            .get_validator(address)?
            .ok_or_else(|| anyhow!("Not a validator"))?;

        if validator.stake < amount {
            return Err(anyhow!("Insufficient stake"));
        }

        validator.stake -= amount;
        
        // Deactivate if stake too low
        if validator.stake < super::MIN_STAKE {
            validator.active = false;
        }

        self.state.put_validator(&validator)?;

        // Return funds to account
        let balance = self.state.get_balance(address)?;
        self.state.set_balance(address, balance + amount)?;

        Ok(())
    }

    /// Slash validator for misbehavior
    pub fn slash(&self, address: &Address, percentage: u8) -> Result<Amount> {
        let mut validator = self.state
            .get_validator(address)?
            .ok_or_else(|| anyhow!("Not a validator"))?;

        let slash_amount = validator.stake * (percentage as u128) / 100;
        validator.stake -= slash_amount;
        validator.active = false;

        self.state.put_validator(&validator)?;

        Ok(slash_amount)
    }
}
