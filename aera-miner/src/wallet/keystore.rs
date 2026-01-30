//! KeyVault - Secure Storage for Private Keys
//!
//! Features:
//! - Argon2id for password-based key derivation
//! - AES-256-GCM encryption for keystore files
//! - Support for Ed25519 (AERA), secp256k1 (ETH/BTC)
//! - Zeroize for memory safety

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params, Version};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use bip39::{Mnemonic, Language};
use bip32::{DerivationPath, XPrv};
use bs58;
use keyring::Entry;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use std::str::FromStr;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum KeystoreError {
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Session locked")]
    SessionLocked,
    #[error("System storage error: {0}")]
    SystemStorage(String),
}

// ============================================================================
// Key Types
// ============================================================================

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// Ed25519 for AERA native transactions
    Ed25519,
    /// secp256k1 for Ethereum and Bitcoin
    Secp256k1,
}

/// Key purpose indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// AERA native network
    Aera,
    /// Ethereum (for bridge operations)
    Ethereum,
    /// Bitcoin (for bridge operations)
    Bitcoin,
    /// TRON network (TRC20 USDT)
    Tron,
    /// TON network (Jetton USDT)
    Ton,
}

// ============================================================================
// Encrypted Key Structure
// ============================================================================

/// Encrypted private key stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// Key identifier (address or public key hash)
    #[serde(rename = "address")]
    pub id: String,
    /// Algorithm used
    pub algorithm: KeyAlgorithm,
    /// Key purpose
    pub purpose: KeyPurpose,
    /// Encrypted private key bytes
    pub ciphertext: Vec<u8>,
    /// AES-GCM nonce (12 bytes)
    pub nonce: Vec<u8>,
    /// Argon2id salt (32 bytes)
    pub salt: Vec<u8>,
    /// Argon2id parameters
    pub kdf_params: KdfParams,
    /// Creation timestamp
    pub created_at: u64,
}

/// Argon2id parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB
    pub m_cost: u32,
    /// Time cost (iterations)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
    /// Output length
    pub output_len: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65536,   // 64 MiB
            t_cost: 3,       // 3 iterations
            p_cost: 4,       // 4 parallel threads
            output_len: 32,  // 256 bits
        }
    }
}

// ============================================================================
// Keystore File
// ============================================================================

/// Keystore file format (stored on disk)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreFile {
    /// Version for migration
    pub version: u32,
    /// Encrypted keys
    pub keys: Vec<EncryptedKey>,
    /// Optional encrypted master mnemonic/seed
    pub mnemonic: Option<EncryptedMnemonic>,
}

/// Encrypted mnemonic phrase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMnemonic {
    /// Encrypted phrase bytes
    pub ciphertext: Vec<u8>,
    /// AES-GCM nonce
    pub nonce: Vec<u8>,
    /// Salt
    pub salt: Vec<u8>,
}

// ============================================================================
// Private Key Wrapper (zeroized on drop)
// ============================================================================

/// Decrypted private key (zeroized when dropped)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecryptedKey {
    /// Raw private key bytes
    bytes: Vec<u8>,
    /// Algorithm
    #[zeroize(skip)]
    algorithm: KeyAlgorithm,
}

#[allow(dead_code)]
impl DecryptedKey {
    /// Get key bytes (use carefully - copies data)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get algorithm
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }
}

// ============================================================================
// System Storage (Master Key Logic)
// ============================================================================

const SERVICE_NAME: &str = "aera-miner";
const MASTER_KEY_ID: &str = "master-key";

pub struct SystemStore;

impl SystemStore {
    /// Get the Master Key from the OS store, generate if not exists
    pub fn get_or_create_master_key() -> Result<[u8; 32], KeystoreError> {
        let entry = Entry::new(SERVICE_NAME, MASTER_KEY_ID)
            .map_err(|e| KeystoreError::SystemStorage(e.to_string()))?;

        match entry.get_password() {
            Ok(hex_key) => {
                let bytes = hex::decode(hex_key).map_err(|e| KeystoreError::SystemStorage(e.to_string()))?;
                let mut key = [0u8; 32];
                if bytes.len() == 32 {
                    key.copy_from_slice(&bytes);
                    Ok(key)
                } else {
                    Err(KeystoreError::SystemStorage("Invalid Master Key length".to_string()))
                }
            }
            Err(_) => {
                // Not found or error -> generate new
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                let hex_key = hex::encode(key);
                
                entry.set_password(&hex_key)
                    .map_err(|e| KeystoreError::SystemStorage(format!("Failed to store Master Key: {}. Please ensure Wallet can access OS Credential Manager.", e)))?;
                
                Ok(key)
            }
        }
    }
}

/// Secure key storage with encryption
pub struct KeyVault {
    /// Directory where keystore files are stored
    dir: PathBuf,
    /// Cached encrypted keys (never store decrypted)
    keys: HashMap<String, EncryptedKey>,
    /// KDF parameters for new keys
    kdf_params: KdfParams,
    /// Encrypted mnemonics per address
    mnemonics: HashMap<String, EncryptedMnemonic>,
    /// Active session data (zeroized on drop)
    active_session: Option<WalletSession>,
}

/// Active unlocked wallet session
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct WalletSession {
    /// AERA Address (Primary ID)
    #[zeroize(skip)]
    pub aera_address: String,
    
    /// TON Address (Derived dynamically)
    #[zeroize(skip)]
    pub ton_address: String,

    /// Session encryption key
    pub session_key: Vec<u8>,
    
    /// Session password
    pub session_password: Vec<u8>,

    /// Active mnemonic for dynamic address derivation
    pub mnemonic: Vec<u8>,
}

#[allow(dead_code)]
impl KeyVault {
    /// Create or open a KeyVault in the specified directory
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self, KeystoreError> {
        let dir = dir.as_ref().to_path_buf();
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
        }

        let mut vault = Self {
            dir: dir.clone(),
            keys: HashMap::new(),
            kdf_params: KdfParams::default(),
            mnemonics: HashMap::new(),
            active_session: None,
        };

        // Load ALL wallet files in the directory
        vault.reload_from_disk()?;

        // Hybrid logic: Ensure Master Key is accessible
        let _ = SystemStore::get_or_create_master_key()?;

        Ok(vault)
    }

    pub fn reload_from_disk(&mut self) -> Result<(), KeystoreError> {
        let dir = self.dir.clone();
        if !dir.is_dir() {
            return Ok(());
        }

        // Reset state before reloading to prevent duplicates or stale entries
        self.keys.clear();
        self.mnemonics.clear();

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                // Skip non-keystore jsons if we can detect them, but for now we try to load
                let _ = self.load_file(&path);
            }
        }
        Ok(())
    }

    /// Load a specific keystore file and merge its keys
    fn load_file(&mut self, path: &Path) -> Result<(), KeystoreError> {
        let data = std::fs::read(path)?;
        let keystore: KeystoreFile = serde_json::from_slice(&data)
            .map_err(|e| KeystoreError::Serialization(e.to_string()))?;

        for key in keystore.keys {
            // Normalize address IDs to lowercase to prevent mapping errors
            let id = key.id.to_lowercase();
            self.keys.insert(id.clone(), key);
            
            // If the file has a mnemonic, associate it with all AERA keys in this file
            if let Some(m) = &keystore.mnemonic {
                 self.mnemonics.insert(id, m.clone());
            }
        }

        Ok(())
    }

    /// Save keystore state to disk with physical sync
    fn save(&self) -> Result<(), KeystoreError> {
        // 1. Prepare data
        let keystore = KeystoreFile {
            version: 1,
            keys: self.keys.values().cloned().collect(),
            mnemonic: None, // Primary file no longer stores a global mnemonic
        };

        let data = serde_json::to_vec_pretty(&keystore)
            .map_err(|e| KeystoreError::Serialization(e.to_string()))?;

        // 2. Atomic-ish save for primary file
        {
            let primary_path = self.dir.join("keystore.json");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&primary_path)?;
            file.write_all(&data)?;
            file.sync_all()?;
            // Handle dropped here
        }

        // 3. Save individual files for each AERA address
        // Using "wallet_{address}.json" format for consistency
        for key in self.keys.values() {
            if key.purpose == KeyPurpose::Aera {
                let individual_file = self.dir.join(format!("wallet_{}.json", key.id.to_lowercase()));
                let individual_data = KeystoreFile {
                    version: 1,
                    keys: vec![key.clone()],
                    mnemonic: self.mnemonics.get(&key.id.to_lowercase()).cloned(),
                };
                let json = serde_json::to_vec_pretty(&individual_data)
                    .map_err(|e| KeystoreError::Serialization(e.to_string()))?;
                
                {
                    let mut f = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(individual_file)?;
                    f.write_all(&json)?;
                    f.sync_all()?;
                    // Handle dropped here
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // Key Derivation (Argon2id)
    // ========================================================================

    /// Derive encryption key from password using Argon2id with specific parameters
    fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<[u8; 32], KeystoreError> {
        // Argon2 requires a minimum salt length of 8 bytes.
        let salt_to_use = if salt.len() < 8 {
            let mut padded = vec![0u8; 8];
            let len = salt.len().min(8);
            padded[..len].copy_from_slice(&salt[..len]);
            padded
        } else {
            salt.to_vec()
        };

        let argon2_params = Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            Some(params.output_len as usize),
        ).map_err(|e| KeystoreError::Encryption(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);
        
        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt_to_use, &mut derived_key)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

        Ok(derived_key)
    }

    // ========================================================================
    // Encryption (AES-256-GCM)
    // ========================================================================

    /// Encrypt private key with AES-256-GCM using System Master Key + Password (Hybrid)
    fn encrypt_key_hybrid(
        &self,
        private_key: &[u8],
        password: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), KeystoreError> {
        // 1. Derive password key
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let derived_password_key = Self::derive_key(password, &salt, &self.kdf_params)?;

        // 2. Get Master Key from System
        let master_key = SystemStore::get_or_create_master_key()?;

        // 3. Combine keys (XOR) for actual encryption key
        let mut encryption_key = [0u8; 32];
        for i in 0..32 {
            encryption_key[i] = derived_password_key[i] ^ master_key[i];
        }

        // 4. Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        // 5. Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, private_key)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

        Ok((ciphertext, nonce_bytes.to_vec(), salt.to_vec()))
    }

    /// Encrypt private key with AES-256-GCM (Standard PBE)
    #[allow(dead_code)]
    fn encrypt_key(
        &self,
        private_key: &[u8],
        password: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), KeystoreError> {
        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive encryption key
        let encryption_key = Self::derive_key(password, &salt, &self.kdf_params)?;

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, private_key)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

        Ok((ciphertext, nonce_bytes.to_vec(), salt.to_vec()))
    }

    /// Decrypt private key (Hybrid: Master Key + Password)
    fn decrypt_key_hybrid(
        &self,
        encrypted: &EncryptedKey,
        password: &str,
    ) -> Result<DecryptedKey, KeystoreError> {
        // 1. Derive password key using params from the entry
        let derived_password_key = Self::derive_key(password, &encrypted.salt, &encrypted.kdf_params)?;

        // 2. Get Master Key from System
        let master_key = SystemStore::get_or_create_master_key()?;

        // 3. Combine keys
        let mut decryption_key = [0u8; 32];
        for i in 0..32 {
            decryption_key[i] = derived_password_key[i] ^ master_key[i];
        }

        // 4. Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&decryption_key)
            .map_err(|e| KeystoreError::Decryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);
        let bytes = cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|e| KeystoreError::Decryption(e.to_string()))?;

        let algorithm = encrypted.algorithm;
        Ok(DecryptedKey { bytes, algorithm })
    }

    /// Decrypt private key with AES-256-GCM using password (Standard PBE)
    fn decrypt_key(
        &self,
        encrypted: &EncryptedKey,
        password: &str,
    ) -> Result<DecryptedKey, KeystoreError> {
        // Derive decryption key using params from the entry
        let decryption_key = Self::derive_key(password, &encrypted.salt, &encrypted.kdf_params)?;

        // Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&decryption_key)
            .map_err(|e| KeystoreError::Decryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);
        let bytes = cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|e| KeystoreError::Decryption(e.to_string()))?;

        Ok(DecryptedKey {
            bytes,
            algorithm: encrypted.algorithm,
        })
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Unlock session by deriving a key from the password.
    pub fn unlock_session(&mut self, password: &str, target_address: Option<&str>) -> Result<(), KeystoreError> {
        // 1. Identify an entry to verify against
        let entry = if let Some(addr) = target_address {
            let normalized_addr = addr.to_lowercase();
            self.keys.get(&normalized_addr).cloned().ok_or_else(|| KeystoreError::KeyNotFound(addr.to_string()))?
        } else if let Some(first_key) = self.keys.values().next() {
            first_key.clone()
        } else {
            return Err(KeystoreError::KeyNotFound("No wallet to unlock".to_string()));
        };

        // 2. Derive session key from password (clean derivation)
        let session_key = Self::derive_key(password, &entry.salt, &entry.kdf_params)?;

        // 3. Verify password by attempting decryption
        let _decrypted = self.decrypt_key_hybrid(&entry, password)
            .or_else(|_| self.decrypt_key(&entry, password))
            .map_err(|_| KeystoreError::InvalidPassword)?;

        // 4. Dynamic Address Derivation from Seed (if available)
        let mut ton_address = "Address not generated".to_string();
        let mut mnemonic_bytes = Vec::new();

        if let Some(mnemonic_obj) = self.mnemonics.get(&entry.id.to_lowercase()) {
            // Attempt to decrypt mnemonic to derive dynamic addresses
             if let Ok(phrase_bytes) = self.decrypt_key_hybrid(&EncryptedKey {
                     id: "mnemonic".to_string(),
                     algorithm: KeyAlgorithm::Ed25519,
                     purpose: KeyPurpose::Aera, 
                     ciphertext: mnemonic_obj.ciphertext.clone(),
                     nonce: mnemonic_obj.nonce.clone(),
                     salt: mnemonic_obj.salt.clone(),
                     kdf_params: self.kdf_params.clone(),
                     created_at: 0,
                }, password) {
                 if let Ok(phrase) = String::from_utf8(phrase_bytes.as_bytes().to_vec()) {
                     if let Ok(_mnemonic) = Mnemonic::parse(&phrase) {
                         match Self::derive_ton_address(&phrase, password) {
                             Ok((addr, _)) => {
                                 ton_address = addr;
                                 info!("✅ Derived TON address from mnemonic for {}: {}", entry.id, ton_address);
                             }
                             Err(e) => {
                                 warn!("⚠️ Failed to derive TON address for {}: {}", entry.id, e);
                             }
                         }
                     }
                     mnemonic_bytes = phrase.as_bytes().to_vec();
                 }
            }
        }
        // Do not fall back to get_address_by_purpose(Ton): that would use another wallet's
        // TON key and make all wallets show the same TON address. Keep "Address not generated".

        // 5. Store Session
        self.active_session = Some(WalletSession {
            aera_address: entry.id.clone(),
            ton_address: ton_address.clone(), // Set even if failed (default is "Address not generated")
            session_key: session_key.to_vec(),
            session_password: password.as_bytes().to_vec(),
            mnemonic: mnemonic_bytes,
        });
    
        info!("🔓 Session unlocked for {}. TON Address: {}", entry.id, ton_address);

        Ok(())
    }

    /// Clear session from memory
    pub fn lock_session(&mut self) {
        // Taking the session drops it, triggering ZeroizeOnDrop
        if let Some(mut session) = self.active_session.take() {
            session.zeroize();
        }
        info!("🔒 Session locked and cleared from memory.");
    }

    /// Get session encryption key
    pub fn get_session_key(&self) -> Option<&[u8]> {
        self.active_session.as_ref().map(|s| s.session_key.as_slice())
    }

    // ========================================================================
    // Mnemonic Support
    // ========================================================================

    /// Create a new mnemonic wallet
    pub fn create_mnemonic_wallet(&mut self, password: &str) -> Result<(String, String), KeystoreError> {
        let mnemonic = Mnemonic::generate_in(Language::English, 12)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;
        let phrase = mnemonic.to_string();
        
        // 1. Encrypt and store the mnemonic for this wallet
        let (mn_ciphertext, mn_nonce, mn_salt) = self.encrypt_key_hybrid(phrase.as_bytes(), password)?;
        let encrypted_mnemonic = EncryptedMnemonic {
            ciphertext: mn_ciphertext,
            nonce: mn_nonce,
            salt: mn_salt,
        };
        
        // 2. Derive initial AERA key from seed
        let seed = mnemonic.to_seed("");
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed[0..32]);
        
        let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
        let address = Self::ed25519_to_address(&signing_key.verifying_key());
        
        // Associate mnemonic with this address
        self.mnemonics.insert(address.to_lowercase(), encrypted_mnemonic);
        
        // 3. Encrypt and save AERA key
        let (aera_ciphertext, aera_nonce, aera_salt) = self.encrypt_key_hybrid(signing_key.as_bytes(), password)?;
        let encrypted = EncryptedKey {
            id: address.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Aera,
            ciphertext: aera_ciphertext,
            nonce: aera_nonce,
            salt: aera_salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        
        self.keys.insert(address.to_lowercase(), encrypted);

        // 4. Unlock session immediately (AFTER key is inserted)
        self.unlock_session(password, Some(&address))?;

        // 5. Auto-generate TON key using unique derivation from seed
        let (ton_address, ton_key) = Self::derive_ton_address(&phrase, password)?;
        info!("🔑 Generated TON address for wallet {}: {}", address, ton_address);
        let (ton_ciphertext, ton_nonce, ton_salt) = self.encrypt_key_hybrid(ton_key.as_bytes(), password)?;

        let encrypted_ton = EncryptedKey {
            id: ton_address.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Ton,
            ciphertext: ton_ciphertext,
            nonce: ton_nonce,
            salt: ton_salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        self.keys.insert(ton_address.to_lowercase(), encrypted_ton);

        self.save()?;

        Ok((address, phrase))
    }

    /// Import wallet from mnemonic
    pub fn import_mnemonic_wallet(&mut self, phrase: &str, password: &str) -> Result<String, KeystoreError> {
        let mnemonic = Mnemonic::parse(phrase)
            .map_err(|_| KeystoreError::InvalidKeyFormat)?;
            
        // 1. Encrypt and store mnemonic for the imported wallet
        let (mn_ciphertext, mn_nonce, mn_salt) = self.encrypt_key_hybrid(phrase.as_bytes(), password)?;
        let encrypted_mnemonic = EncryptedMnemonic {
            ciphertext: mn_ciphertext,
            nonce: mn_nonce,
            salt: mn_salt,
        };

        // 2. Derive initial AERA key
        let seed = mnemonic.to_seed("");
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed[0..32]);
        
        let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
        let address = Self::ed25519_to_address(&signing_key.verifying_key());
        
        // Associate mnemonic with this address
        self.mnemonics.insert(address.to_lowercase(), encrypted_mnemonic);
        
        // 3. Encrypt and save AERA key
        let (aera_ciphertext, aera_nonce, aera_salt) = self.encrypt_key_hybrid(signing_key.as_bytes(), password)?;
        let encrypted = EncryptedKey {
            id: address.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Aera,
            ciphertext: aera_ciphertext,
            nonce: aera_nonce,
            salt: aera_salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        
        self.keys.insert(address.to_lowercase(), encrypted);

        // 4. Unlock session immediately (AFTER key is inserted)
        self.unlock_session(password, Some(&address))?;

        // 5. Auto-generate TON key on import
        let (ton_address, ton_key) = Self::derive_ton_address(phrase, password)?;
        info!("🔑 Imported TON address for wallet {}: {}", address, ton_address);
        let (ton_ciphertext, ton_nonce, ton_salt) = self.encrypt_key_hybrid(ton_key.as_bytes(), password)?;

        let encrypted_ton = EncryptedKey {
            id: ton_address.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Ton,
            ciphertext: ton_ciphertext,
            nonce: ton_nonce,
            salt: ton_salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        self.keys.insert(ton_address.to_lowercase(), encrypted_ton);

        self.save()?;

        Ok(address)
    }

    /// Get decrypted mnemonic
    pub fn get_mnemonic(&self, address: &str, password: &str) -> Result<String, KeystoreError> {
        let enc = self.mnemonics.get(&address.to_lowercase()).ok_or_else(|| KeystoreError::KeyNotFound(format!("Mnemonic for {}", address)))?;
        
        // Mnemonics use the vault's default KDF params for now
        let decryption_key = Self::derive_key(password, &enc.salt, &self.kdf_params)?;
        let cipher = Aes256Gcm::new_from_slice(&decryption_key)
            .map_err(|e| KeystoreError::Decryption(e.to_string()))?;
        
        // Check for hybrid decryption if standard fails
        let plaintext = match cipher.decrypt(Nonce::from_slice(&enc.nonce), enc.ciphertext.as_slice()) {
            Ok(p) => p,
            Err(_) => {
                // Fallback to Hybrid decryption for mnemonic
                let decrypted = self.decrypt_key_hybrid(&EncryptedKey {
                    id: "mnemonic".to_string(),
                    algorithm: KeyAlgorithm::Ed25519,
                    purpose: KeyPurpose::Aera,
                    ciphertext: enc.ciphertext.clone(),
                    nonce: enc.nonce.clone(),
                    salt: enc.salt.clone(),
                    kdf_params: self.kdf_params.clone(),
                    created_at: 0,
                }, password)?;
                decrypted.as_bytes().to_vec()
            }
        };
            
        let phrase = String::from_utf8(plaintext).map_err(|_| KeystoreError::Serialization("Invalid UTF-8".to_string()))?;
        Ok(phrase)
    }

    // ========================================================================
    // Key Generation
    // ========================================================================


    pub fn derive_ton_address(phrase: &str, password: &str) -> Result<(String, Ed25519SigningKey), KeystoreError> {
        let mnemonic = Mnemonic::parse(phrase).map_err(|e| KeystoreError::Encryption(e.to_string()))?;
        let seed = mnemonic.to_seed(password);
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        // SLIP-0010 initial derivation for Ed25519
        // I = HMAC-SHA512(Key="ed25519 seed", Data=seed)
        use hmac::digest::KeyInit;
        let mut mac = <HmacSha512 as KeyInit>::new_from_slice(b"ed25519 seed")
            .map_err(|e: hmac::digest::InvalidLength| KeystoreError::Encryption(e.to_string()))?;
        mac.update(&seed);
        let result = mac.finalize().into_bytes();
        
        let mut k = result[0..32].to_vec();
        let mut c = result[32..64].to_vec();

        // Path: m/44'/607'/0'/0'/0' (all hardened)
        let path: [u32; 5] = [44, 607, 0, 0, 0];
        
        for &index in &path {
            // For Ed25519, we only support hardened derivation
            // Z = HMAC-SHA512(Key=c, Data=0x00 || k || index')
            let mut mac = <HmacSha512 as KeyInit>::new_from_slice(&c)
                .map_err(|e: hmac::digest::InvalidLength| KeystoreError::Encryption(e.to_string()))?;
            mac.update(&[0x00]);
            mac.update(&k);
            let hardened_index = index | 0x8000_0000;
            mac.update(&hardened_index.to_be_bytes());
            
            let result = mac.finalize().into_bytes();
            k = result[0..32].to_vec();
            c = result[32..64].to_vec();
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&k);
        
        let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
        let address = Self::ed25519_to_ton_address(&signing_key.verifying_key());
        
        Ok((address, signing_key))
    }

    fn derive_secp256k1_private_key_from_mnemonic(
        phrase: &str,
        password: &str,
        path: &str,
    ) -> Result<[u8; 32], KeystoreError> {
        let mnemonic = Mnemonic::parse(phrase)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;
        let seed = mnemonic.to_seed(password);
        let derivation_path = DerivationPath::from_str(path)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;
        let child = XPrv::derive_from_path(&seed, &derivation_path)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;
        Ok(child.private_key().to_bytes().into())
    }

    fn derive_eth_address_from_mnemonic(
        phrase: &str,
        password: &str,
    ) -> Result<String, KeystoreError> {
        let priv_key = Self::derive_secp256k1_private_key_from_mnemonic(
            phrase,
            password,
            "m/44'/60'/0'/0/0",
        )?;
        Self::secp256k1_to_eth_address(&priv_key)
    }

    fn derive_tron_address_from_mnemonic(
        phrase: &str,
        password: &str,
    ) -> Result<String, KeystoreError> {
        let priv_key = Self::derive_secp256k1_private_key_from_mnemonic(
            phrase,
            password,
            "m/44'/195'/0'/0/0",
        )?;
        Self::secp256k1_to_tron_address(&priv_key)
    }

    /// Generate a new Ed25519 key for AERA
    pub fn generate_aera_key(&mut self, password: &str) -> Result<String, KeystoreError> {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        // Derive address from public key
        let address = Self::ed25519_to_address(&verifying_key);

        // Encrypt private key (Hybrid)
        let (ciphertext, nonce, salt) = self.encrypt_key_hybrid(signing_key.as_bytes(), password)?;

        // Create encrypted key entry
        let encrypted = EncryptedKey {
            id: address.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Aera,
            ciphertext,
            nonce,
            salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.keys.insert(address.to_lowercase(), encrypted);
        self.save()?;

        Ok(address)
    }

    /// Generate a new secp256k1 key for Ethereum
    pub fn generate_ethereum_key(&mut self, password: &str) -> Result<String, KeystoreError> {
        let mut private_key = [0u8; 32];
        OsRng.fill_bytes(&mut private_key);

        let address = Self::secp256k1_to_eth_address(&private_key)?;
        let (ciphertext, nonce, salt) = self.encrypt_key_hybrid(&private_key, password)?;
        private_key.zeroize();

        let encrypted = EncryptedKey {
            id: address.clone(),
            algorithm: KeyAlgorithm::Secp256k1,
            purpose: KeyPurpose::Ethereum,
            ciphertext,
            nonce,
            salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.keys.insert(address.to_lowercase(), encrypted);
        self.save()?;

        Ok(address)
    }

    /// Generate a new secp256k1 key for Bitcoin
    pub fn generate_bitcoin_key(&mut self, password: &str) -> Result<String, KeystoreError> {
        let mut private_key = [0u8; 32];
        OsRng.fill_bytes(&mut private_key);

        let address = Self::secp256k1_to_btc_address(&private_key)?;
        let (ciphertext, nonce, salt) = self.encrypt_key_hybrid(&private_key, password)?;
        private_key.zeroize();

        let encrypted = EncryptedKey {
            id: address.clone(),
            algorithm: KeyAlgorithm::Secp256k1,
            purpose: KeyPurpose::Bitcoin,
            ciphertext,
            nonce,
            salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.keys.insert(address.to_lowercase(), encrypted);
        self.save()?;

        Ok(address)
    }

    /// Generate a new secp256k1 key for TRON (TRC20)
    pub fn generate_tron_key(&mut self, password: &str) -> Result<String, KeystoreError> {
        let mut private_key = [0u8; 32];
        OsRng.fill_bytes(&mut private_key);

        let address = Self::secp256k1_to_tron_address(&private_key)?;
        let (ciphertext, nonce, salt) = self.encrypt_key_hybrid(&private_key, password)?;
        private_key.zeroize();

        let encrypted = EncryptedKey {
            id: address.clone(),
            algorithm: KeyAlgorithm::Secp256k1,
            purpose: KeyPurpose::Tron,
            ciphertext,
            nonce,
            salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.keys.insert(address.to_lowercase(), encrypted);
        self.save()?;

        Ok(address)
    }

    /// Generate a new Ed25519 key for TON
    pub fn generate_ton_key(&mut self, password: &str) -> Result<String, KeystoreError> {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        let address = Self::ed25519_to_ton_address(&verifying_key);
        let (ciphertext, nonce, salt) = self.encrypt_key_hybrid(signing_key.as_bytes(), password)?;

        let encrypted = EncryptedKey {
            id: address.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Ton,
            ciphertext,
            nonce,
            salt,
            kdf_params: self.kdf_params.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.keys.insert(address.to_lowercase(), encrypted);
        self.save()?;

        Ok(address)
    }

    // ========================================================================
    // Signing
    // ========================================================================

    /// Sign transaction data with the specified key
    pub fn sign_transaction(
        &self,
        key_id: &str,
        password: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, KeystoreError> {
        let normalized_id = key_id.to_lowercase();
        let encrypted = self.keys.get(&normalized_id)
            .ok_or_else(|| KeystoreError::KeyNotFound(key_id.to_string()))?;

        // Use provided password or session password
        let effective_password = if !password.is_empty() {
            password.to_string()
        } else if let Some(session) = &self.active_session {
            String::from_utf8(session.session_password.clone()).map_err(|_| KeystoreError::InvalidPassword)?
        } else {
            return Err(KeystoreError::SessionLocked);
        };

        if effective_password.is_empty() {
            return Err(KeystoreError::InvalidPassword);
        }

        let decrypted = self.decrypt_key_hybrid(encrypted, &effective_password)
            .or_else(|_| self.decrypt_key(encrypted, &effective_password))?;

        let signature = match decrypted.algorithm {
            KeyAlgorithm::Ed25519 => {
                self.sign_ed25519(decrypted.as_bytes(), data)?
            }
            KeyAlgorithm::Secp256k1 => {
                self.sign_secp256k1(decrypted.as_bytes(), data)?
            }
        };

        Ok(signature)
    }

    /// Sign with Ed25519
    fn sign_ed25519(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let key_bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| KeystoreError::InvalidKeyFormat)?;

        let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(data);

        Ok(signature.to_bytes().to_vec())
    }

    /// Sign with secp256k1 (ECDSA)
    fn sign_secp256k1(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        use ethers::core::k256::ecdsa::SigningKey;
        
        let signing_key = SigningKey::from_bytes(private_key.into())
            .map_err(|_e| KeystoreError::InvalidKeyFormat)?;

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());

        Ok(sig_bytes)
    }

    // ========================================================================
    // Address Derivation
    // ========================================================================

    /// Derive AERA address from Ed25519 public key
    fn ed25519_to_address(pubkey: &Ed25519VerifyingKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.as_bytes());
        let hash = hasher.finalize();
        format!("aera1{}", hex::encode(&hash))
    }

    /// Derive Ethereum address from secp256k1 private key
    fn secp256k1_to_eth_address(private_key: &[u8]) -> Result<String, KeystoreError> {
        use ethers::core::k256::ecdsa::SigningKey;
        use ethers::utils::keccak256;

        let signing_key = SigningKey::from_bytes(private_key.into())
            .map_err(|_| KeystoreError::InvalidKeyFormat)?;

        let public_key = signing_key.verifying_key();
        let public_key_bytes = public_key.to_encoded_point(false);
        
        let hash = keccak256(&public_key_bytes.as_bytes()[1..]);
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    /// Derive Bitcoin address from secp256k1 private key
    fn secp256k1_to_btc_address(private_key: &[u8]) -> Result<String, KeystoreError> {
        use ethers::core::k256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_bytes(private_key.into())
            .map_err(|_| KeystoreError::InvalidKeyFormat)?;

        let public_key = signing_key.verifying_key();
        let public_key_bytes = public_key.to_encoded_point(true);

        let mut hasher = Sha256::new();
        hasher.update(public_key_bytes.as_bytes());
        let hash = hasher.finalize();

        Ok(format!("btc1{}", hex::encode(&hash[..20])))
    }

    /// Derive TRON address from secp256k1 private key
    /// TRON addresses use Base58Check encoding with 0x41 prefix
    fn secp256k1_to_tron_address(private_key: &[u8]) -> Result<String, KeystoreError> {
        use ethers::core::k256::ecdsa::SigningKey;
        use ethers::utils::keccak256;

        let signing_key = SigningKey::from_bytes(private_key.into())
            .map_err(|_| KeystoreError::InvalidKeyFormat)?;

        let public_key = signing_key.verifying_key();
        let public_key_bytes = public_key.to_encoded_point(false);
        
        // Keccak256 hash of public key (same as ETH)
        let hash = keccak256(&public_key_bytes.as_bytes()[1..]);
        
        // TRON uses 0x41 prefix + last 20 bytes of hash
        let mut address_bytes = vec![0x41];
        address_bytes.extend_from_slice(&hash[12..]);
        
        // Double SHA256 for checksum
        let mut hasher = Sha256::new();
        hasher.update(&address_bytes);
        let hash1 = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(&hash1);
        let hash2 = hasher.finalize();
        
        // Append first 4 bytes of checksum
        address_bytes.extend_from_slice(&hash2[..4]);
        
        // Base58 encode
        Ok(bs58::encode(&address_bytes).into_string())
    }

    /// Derive TON address from Ed25519 public key
    /// Uses workchain 0 (basechain) with bounceable flag
    /// Format: EQ + hex(workchain + pubkey_hash + checksum)
    fn ed25519_to_ton_address(verifying_key: &Ed25519VerifyingKey) -> String {
        let public_key_bytes = verifying_key.as_bytes();
        
        // Use full 32-byte pubkey hash for uniqueness (not just 20 bytes)
        let mut hasher = Sha256::new();
        hasher.update(b"TON_ADDRESS_V1:");
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();
        
        // TON address format: EQ + hex(workchain 0 + hash[0..30] + checksum[0..2])
        // Using 30 bytes of hash + 2 bytes checksum for 32-byte total
        let mut addr_bytes = vec![0u8]; // workchain 0
        addr_bytes.extend_from_slice(&hash[..30]);
        
        // Simple checksum (first 2 bytes of double hash)
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(&addr_bytes);
        let checksum_hash = checksum_hasher.finalize();
        addr_bytes.extend_from_slice(&checksum_hash[..2]);
        
        format!("EQ{}", hex::encode(&addr_bytes).to_uppercase())
    }

    // ========================================================================
    // Utility
    // ========================================================================

    /// List all key IDs
    pub fn list_keys(&self) -> Vec<&String> {
        self.keys.keys().collect()
    }

    /// Get first address for a specific purpose.
    /// For Ton: always use active_session.ton_address when unlocked (never fall back to
    /// another wallet's TON key), so each wallet shows its own derived TON address.
    pub fn get_address_by_purpose(&self, purpose: KeyPurpose) -> Option<String> {
        if let Some(session) = &self.active_session {
            match purpose {
                KeyPurpose::Ton => return Some(session.ton_address.clone()),
                KeyPurpose::Aera => return Some(session.aera_address.clone()),
                KeyPurpose::Ethereum => {
                    if !session.mnemonic.is_empty() {
                        if let Ok(phrase) = String::from_utf8(session.mnemonic.clone()) {
                            let password = String::from_utf8_lossy(&session.session_password).to_string();
                            if let Ok(addr) = Self::derive_eth_address_from_mnemonic(&phrase, &password) {
                                return Some(addr);
                            }
                            warn!("Failed to derive ETH address from mnemonic for active session");
                        }
                    }
                }
                KeyPurpose::Tron => {
                    if !session.mnemonic.is_empty() {
                        if let Ok(phrase) = String::from_utf8(session.mnemonic.clone()) {
                            let password = String::from_utf8_lossy(&session.session_password).to_string();
                            if let Ok(addr) = Self::derive_tron_address_from_mnemonic(&phrase, &password) {
                                return Some(addr);
                            }
                            warn!("Failed to derive TRON address from mnemonic for active session");
                        }
                    }
                }
                _ => {}
            }
        }

        self.keys.values()
            .find(|k| k.purpose == purpose)
            .map(|k| k.id.clone())
    }

    pub fn get_eth_private_key_from_session(&self) -> Result<[u8; 32], KeystoreError> {
        let session = self.active_session.as_ref().ok_or(KeystoreError::SessionLocked)?;
        if session.mnemonic.is_empty() {
            return Err(KeystoreError::SessionLocked);
        }
        let phrase = String::from_utf8(session.mnemonic.clone())
            .map_err(|_| KeystoreError::Serialization("Invalid mnemonic UTF-8".to_string()))?;
        let password = String::from_utf8_lossy(&session.session_password).to_string();
        Self::derive_secp256k1_private_key_from_mnemonic(&phrase, &password, "m/44'/60'/0'/0/0")
    }

    pub fn get_tron_private_key_from_session(&self) -> Result<[u8; 32], KeystoreError> {
        let session = self.active_session.as_ref().ok_or(KeystoreError::SessionLocked)?;
        if session.mnemonic.is_empty() {
            return Err(KeystoreError::SessionLocked);
        }
        let phrase = String::from_utf8(session.mnemonic.clone())
            .map_err(|_| KeystoreError::Serialization("Invalid mnemonic UTF-8".to_string()))?;
        let password = String::from_utf8_lossy(&session.session_password).to_string();
        Self::derive_secp256k1_private_key_from_mnemonic(&phrase, &password, "m/44'/195'/0'/0/0")
    }

    /// Check if key exists
    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(&key_id.to_lowercase())
    }

    pub fn has_mnemonic(&self, address: &str) -> bool {
        self.mnemonics.contains_key(&address.to_lowercase())
    }

    /// Get the first AERA address found in the vault
    pub fn get_first_address(&self) -> Option<String> {
        // 1. Check active session first
        if let Some(session) = &self.active_session {
            return Some(session.aera_address.clone());
        }

        // 2. Fallback to storage
        self.keys.iter()
            .find(|(_, k)| k.purpose == KeyPurpose::Aera)
            .map(|(id, _)| id.clone())
    }

    /// Clear all keys and delete the keystore directory from disk
    pub fn clear(&mut self) -> Result<(), KeystoreError> {
        self.keys.clear();
        self.mnemonics.clear();
        self.lock_session();
        if self.dir.exists() {
            // Only remove json files to avoid nuking other data like state DB
            for entry in std::fs::read_dir(&self.dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ton_derivation_uniqueness() {
        let _mnemonic1 = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let _mnemonic2 = Mnemonic::parse("all all all all all all all all all all all all").unwrap();
        
        let (addr1, _) = KeyVault::derive_ton_address("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "").unwrap();
        let (addr2, _) = KeyVault::derive_ton_address("all all all all all all all all all all all all", "").unwrap();
        
        println!("Addr1: {}, Addr2: {}", addr1, addr2);
        assert_ne!(addr1, addr2, "TON addresses should be unique for different mnemonics");
        assert!(addr1.starts_with("EQ"), "TON address should start with EQ");
    }

    #[test]
    fn test_vault_mnemonic_mapping() {
        let tmp = tempdir().unwrap();
        let mut vault = KeyVault::open(tmp.path()).unwrap();
        let password = "test-password";
        
        // Create wallet 1
        let (addr1, _) = vault.create_mnemonic_wallet(password).unwrap();
        let ton1 = vault.get_address_by_purpose(KeyPurpose::Ton).unwrap();
        
        // Create wallet 2
        let (addr2, _) = vault.create_mnemonic_wallet(password).unwrap();
        
        // Unlock wallet 1 again
        vault.unlock_session(password, Some(&addr1)).unwrap();
        let ton1_again = vault.get_address_by_purpose(KeyPurpose::Ton).unwrap();
        assert_eq!(ton1, ton1_again);
        
        // Unlock wallet 2
        vault.unlock_session(password, Some(&addr2)).unwrap();
        let ton2 = vault.get_address_by_purpose(KeyPurpose::Ton).unwrap();
        
        assert_ne!(ton1, ton2, "Different wallets should have different TON addresses");
    }
}
