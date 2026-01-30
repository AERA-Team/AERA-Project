use reqwest::Client;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::error::Error;
use sha2::{Digest, Sha256};
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey};

#[derive(Debug, Clone)]
pub struct TronClient {
    client: Client,
    api_key: Option<String>,
    base_url: String,
    usdt_contract: String,
}

impl TronClient {
    pub fn new(api_key: Option<String>, base_url: String, usdt_contract: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            base_url,
            usdt_contract,
        }
    }

    /// Get USDT (TRC20) balance
    pub async fn get_usdt_balance(&self, address: &str) -> Result<f64, Box<dyn Error>> {
        let address_hex = self.base58_to_hex(address)?;
        let parameter = format!("{:0>64}", address_hex); 

        let url = format!("{}/wallet/triggerconstantcontract", self.base_url);
        
        let payload = serde_json::json!({
            "owner_address": address_hex, 
            "contract_address": self.base58_to_hex(&self.usdt_contract)?,
            "function_selector": "balanceOf(address)",
            "parameter": parameter,
            "visible": false
        });

        let mut req = self.client.post(&url).json(&payload);
        if let Some(key) = &self.api_key {
            req = req.header("TRON-PRO-API-KEY", key);
        }
        let resp = req.send().await?
            .json::<serde_json::Value>()
            .await?;

        if let Some(results) = resp.get("constant_result") {
            if let Some(hex_bal) = results.as_array().and_then(|a| a.get(0)).and_then(|v| v.as_str()) {
                let bal_u256 = u128::from_str_radix(hex_bal, 16).unwrap_or(0);
                return Ok(bal_u256 as f64 / 1_000_000.0);
            }
        }

        Ok(0.0)
    }

    /// Get native TRX balance
    pub async fn get_trx_balance(&self, address: &str) -> Result<f64, Box<dyn Error>> {
        let address_hex = self.base58_to_hex(address)?;
        let url = format!("{}/wallet/getaccount", self.base_url);
        let payload = serde_json::json!({
            "address": address_hex,
            "visible": false
        });

        let mut req = self.client.post(&url).json(&payload);
        if let Some(key) = &self.api_key {
            req = req.header("TRON-PRO-API-KEY", key);
        }
        let resp = req.send().await?.json::<serde_json::Value>().await?;
        let balance = resp.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(balance as f64 / 1_000_000.0)
    }

    /// Send USDT (TRC20) transfer via TronGrid
    pub async fn send_usdt(
        &self,
        from_address: &str,
        to_address: &str,
        amount: u128, // USDT has 6 decimals
        private_key: &[u8; 32],
    ) -> Result<String, Box<dyn Error>> {
        let owner_hex = self.base58_to_hex(from_address)?;
        let to_hex = self.base58_to_hex(to_address)?;

        let to_param = format!("{:0>64}", to_hex);
        let amount_hex = format!("{:0>64}", format!("{:x}", amount));
        let parameter = format!("{}{}", to_param, amount_hex);

        let url = format!("{}/wallet/triggersmartcontract", self.base_url);
        let payload = serde_json::json!({
            "owner_address": owner_hex,
            "contract_address": self.base58_to_hex(&self.usdt_contract)?,
            "function_selector": "transfer(address,uint256)",
            "parameter": parameter,
            "fee_limit": 10_000_000,
            "call_value": 0,
            "visible": false
        });

        let mut req = self.client.post(&url).json(&payload);
        if let Some(key) = &self.api_key {
            req = req.header("TRON-PRO-API-KEY", key);
        }
        let resp = req.send().await?.json::<serde_json::Value>().await?;

        if let Some(result) = resp.get("result").and_then(|v| v.get("result")).and_then(|v| v.as_bool()) {
            if !result {
                let msg = resp.get("result")
                    .and_then(|v| v.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Trigger failed");
                return Err(Self::decode_tron_message(msg).into());
            }
        }

        let tx = resp.get("transaction")
            .ok_or("Missing transaction in TRON response")?;
        let raw_hex = tx.get("raw_data_hex")
            .and_then(|v| v.as_str())
            .ok_or("Missing raw_data_hex in TRON response")?;
        let raw_bytes = hex::decode(raw_hex)?;

        // txid = sha256(raw_data)
        let txid = hex::encode(Sha256::digest(&raw_bytes));

        // Sign txid hash (32 bytes) with secp256k1 recoverable signature
        let hash = Sha256::digest(&raw_bytes);
        let msg = Message::from_digest_slice(hash.as_slice())?;
        let sk = SecretKey::from_slice(private_key)?;
        let secp = Secp256k1::new();
        let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &sk);
        let (rec_id, sig_bytes) = sig.serialize_compact();
        let mut sig = [0u8; 65];
        sig[..64].copy_from_slice(&sig_bytes);
        sig[64] = rec_id.to_i32() as u8;

        let mut signed_tx = tx.clone();
        signed_tx["signature"] = serde_json::json!([hex::encode(sig)]);

        let broadcast_url = format!("{}/wallet/broadcasttransaction", self.base_url);
        let mut breq = self.client.post(&broadcast_url).json(&signed_tx);
        if let Some(key) = &self.api_key {
            breq = breq.header("TRON-PRO-API-KEY", key);
        }
        let bresp = breq.send().await?.json::<serde_json::Value>().await?;
        if bresp.get("result").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(txid)
        } else {
            let msg = bresp.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Broadcast failed");
            Err(Self::decode_tron_message(msg).into())
        }
    }

    /// Send native TRX transfer via TronGrid
    pub async fn send_trx(
        &self,
        from_address: &str,
        to_address: &str,
        amount_sun: u128, // TRX has 6 decimals (sun)
        private_key: &[u8; 32],
    ) -> Result<String, Box<dyn Error>> {
        let owner_hex = self.base58_to_hex(from_address)?;
        let to_hex = self.base58_to_hex(to_address)?;

        let url = format!("{}/wallet/createtransaction", self.base_url);
        let payload = serde_json::json!({
            "owner_address": owner_hex,
            "to_address": to_hex,
            "amount": amount_sun,
            "visible": false
        });

        let mut req = self.client.post(&url).json(&payload);
        if let Some(key) = &self.api_key {
            req = req.header("TRON-PRO-API-KEY", key);
        }
        let resp = req.send().await?.json::<serde_json::Value>().await?;

        if let Some(msg) = resp.get("message").and_then(|v| v.as_str()) {
            return Err(Self::decode_tron_message(msg).into());
        }

        let raw_hex = resp.get("raw_data_hex")
            .and_then(|v| v.as_str())
            .ok_or("Missing raw_data_hex in TRON response")?;
        let raw_bytes = hex::decode(raw_hex)?;

        let txid = hex::encode(Sha256::digest(&raw_bytes));
        let hash = Sha256::digest(&raw_bytes);
        let msg = Message::from_digest_slice(hash.as_slice())?;
        let sk = SecretKey::from_slice(private_key)?;
        let secp = Secp256k1::new();
        let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &sk);
        let (rec_id, sig_bytes) = sig.serialize_compact();
        let mut sig = [0u8; 65];
        sig[..64].copy_from_slice(&sig_bytes);
        sig[64] = rec_id.to_i32() as u8;

        let mut signed_tx = resp.clone();
        signed_tx["signature"] = serde_json::json!([hex::encode(sig)]);

        let broadcast_url = format!("{}/wallet/broadcasttransaction", self.base_url);
        let mut breq = self.client.post(&broadcast_url).json(&signed_tx);
        if let Some(key) = &self.api_key {
            breq = breq.header("TRON-PRO-API-KEY", key);
        }
        let bresp = breq.send().await?.json::<serde_json::Value>().await?;
        if bresp.get("result").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(txid)
        } else {
            let msg = bresp.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Broadcast failed");
            Err(Self::decode_tron_message(msg).into())
        }
    }

    fn base58_to_hex(&self, address: &str) -> Result<String, Box<dyn Error>> {
        let bytes = bs58::decode(address).into_vec()?;
        if bytes.len() < 4 {
            return Err("Invalid address length".into());
        }
        let raw = &bytes[0..bytes.len() - 4];
        Ok(hex::encode(raw))
    }

    fn decode_tron_message(msg: &str) -> String {
        // TronGrid returns base64-encoded error messages
        if let Ok(bytes) = STANDARD.decode(msg) {
            if let Ok(s) = String::from_utf8(bytes) {
                return s;
            }
        }
        msg.to_string()
    }
}
