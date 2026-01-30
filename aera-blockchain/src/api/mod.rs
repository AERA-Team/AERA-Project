//! JSON-RPC API module (Core style)
//!
//! Provides RPC interface for wallet and node operations

use crate::state::StateDB;
use crate::types::Address;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
// use tracing::info;

/// RPC method types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum RpcMethod {
    /// Get account balance
    #[serde(rename = "aera_getBalance")]
    GetBalance { address: String },
    
    /// Send signed transaction
    #[serde(rename = "aera_sendTransaction")]
    SendTransaction { raw_tx: String },
    
    /// Get block by hash
    #[serde(rename = "aera_getBlockByHash")]
    GetBlockByHash { hash: String },
    
    /// Get block by height
    #[serde(rename = "aera_getBlockByNumber")]
    GetBlockByNumber { height: u64 },
    
    /// Get transaction by hash
    #[serde(rename = "aera_getTransaction")]
    GetTransaction { hash: String },
    
    /// Get current block height
    #[serde(rename = "aera_blockNumber")]
    BlockNumber,
    
    /// Get chain ID
    #[serde(rename = "aera_chainId")]
    ChainId,
    
    /// Get account nonce
    #[serde(rename = "aera_getTransactionCount")]
    GetTransactionCount { address: String },
    
    /// Estimate gas for transaction
    #[serde(rename = "aera_estimateGas")]
    EstimateGas { tx: TransactionRequest },
    
    /// Get node info
    #[serde(rename = "aera_nodeInfo")]
    NodeInfo,
    
    /// Get validator set
    #[serde(rename = "aera_getValidators")]
    GetValidators,
    
    /// Subscribe to events (WebSocket)
    #[serde(rename = "aera_subscribe")]
    Subscribe { event_type: String },
}

/// Transaction request for estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub from: String,
    pub to: String,
    pub value: Option<String>,
    pub data: Option<String>,
    pub gas: Option<String>,
    pub gas_price: Option<String>,
}

/// JSON-RPC request
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: Option<Value>,
}

/// JSON-RPC response
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// JSON-RPC error
#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

/// API server state
pub struct ApiServer {
    /// State database
    state: Arc<StateDB>,
    /// Chain ID
    chain_id: u32,
    /// Current block height
    current_height: Arc<RwLock<u64>>,
}

impl ApiServer {
    /// Create new API server
    pub fn new(state: Arc<StateDB>, chain_id: u32) -> Self {
        Self {
            state,
            chain_id,
            current_height: Arc::new(RwLock::new(0)),
        }
    }

    /// Handle JSON-RPC request
    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let result = self.dispatch(&request.method, request.params.as_ref()).await;
        
        match result {
            Ok(value) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(RpcError {
                    code: -32000,
                    message: e.to_string(),
                }),
            },
        }
    }

    /// Dispatch RPC method
    async fn dispatch(&self, method: &str, params: Option<&Value>) -> Result<Value> {
        match method {
            "aera_getBalance" => {
                let address = self.extract_address(params, "address")?;
                let balance = self.state.get_balance(&address)?;
                Ok(json!(format!("0x{:x}", balance)))
            }
            
            "aera_blockNumber" => {
                let height = *self.current_height.read().await;
                Ok(json!(format!("0x{:x}", height)))
            }
            
            "aera_chainId" => {
                Ok(json!(format!("0x{:x}", self.chain_id)))
            }
            
            "aera_getTransactionCount" => {
                let address = self.extract_address(params, "address")?;
                let account = self.state.get_account(&address)?;
                let nonce = account.map(|a| a.nonce).unwrap_or(0);
                Ok(json!(format!("0x{:x}", nonce)))
            }
            
            "aera_nodeInfo" => {
                Ok(json!({
                    "chain_id": self.chain_id,
                    "version": env!("CARGO_PKG_VERSION"),
                    "network": "aera-mainnet",
                }))
            }
            
            "aera_getValidators" => {
                let validators = self.state.get_active_validators()?;
                let v: Vec<_> = validators.iter().map(|v| {
                    json!({
                        "address": hex::encode(&v.address),
                        "stake": v.stake.to_string(),
                        "active": v.active,
                    })
                }).collect();
                Ok(json!(v))
            }
            
            "aera_estimateGas" => {
                // Simplified gas estimation
                Ok(json!("0x5208")) // 21000 gas for simple transfer
            }
            
            _ => Err(anyhow::anyhow!("Method not found: {}", method)),
        }
    }

    /// Extract address from params
    fn extract_address(&self, params: Option<&Value>, key: &str) -> Result<Address> {
        let params = params.ok_or_else(|| anyhow::anyhow!("Missing params"))?;
        
        let addr_str = if let Some(arr) = params.as_array() {
            arr.get(0)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Invalid address"))?
        } else {
            params.get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing address field"))?
        };
        
        let bytes = hex::decode(addr_str.trim_start_matches("0x"))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("Address must be 32 bytes"));
        }
        
        let mut address = [0u8; 32];
        address.copy_from_slice(&bytes);
        Ok(address)
    }

    /// Update current block height
    pub async fn set_height(&self, height: u64) {
        *self.current_height.write().await = height;
    }
}

/// API method specification (for documentation)
pub fn api_spec() -> Value {
    json!({
        "openrpc": "1.0.0",
        "info": {
            "title": "AERA Blockchain JSON-RPC API",
            "version": "1.0.0",
        },
        "methods": [
            {
                "name": "aera_getBalance",
                "params": [{"name": "address", "schema": {"type": "string"}}],
                "result": {"name": "balance", "schema": {"type": "string"}},
            },
            {
                "name": "aera_sendTransaction",
                "params": [{"name": "raw_tx", "schema": {"type": "string"}}],
                "result": {"name": "tx_hash", "schema": {"type": "string"}},
            },
            {
                "name": "aera_getBlockByHash",
                "params": [{"name": "hash", "schema": {"type": "string"}}],
                "result": {"name": "block", "schema": {"type": "object"}},
            },
            {
                "name": "aera_getBlockByNumber",
                "params": [{"name": "height", "schema": {"type": "integer"}}],
                "result": {"name": "block", "schema": {"type": "object"}},
            },
            {
                "name": "aera_blockNumber",
                "params": [],
                "result": {"name": "height", "schema": {"type": "string"}},
            },
            {
                "name": "aera_chainId",
                "params": [],
                "result": {"name": "chain_id", "schema": {"type": "string"}},
            },
            {
                "name": "aera_getValidators",
                "params": [],
                "result": {"name": "validators", "schema": {"type": "array"}},
            },
        ],
    })
}
