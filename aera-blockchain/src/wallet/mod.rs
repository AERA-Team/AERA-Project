//! Wallet and key management module
//!
//! Secure storage of private keys with encryption

pub mod keystore;

pub use keystore::*;

use crate::types::Address;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Derive address from public key
pub fn address_from_pubkey(pubkey: &VerifyingKey) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    hasher.finalize().into()
}

/// Derive address from private key
pub fn address_from_privkey(privkey: &SigningKey) -> Address {
    address_from_pubkey(&privkey.verifying_key())
}
