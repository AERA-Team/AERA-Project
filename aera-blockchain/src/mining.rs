use sha2::{Sha256, Digest};
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering}, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, error};
use serde::{Serialize, Deserialize};

/// Economic constants for AERA Mining
pub const MAX_MINING_SUPPLY: f64 = 4_000_000_000.0;
pub const INITIAL_REWARD: f64 = 200.0;
pub const HALVING_INTERVAL: u64 = 2_102_400; // ~4 years at 60s blocks

/// Target block time in seconds
pub const TARGET_BLOCK_TIME: u64 = 60;

/// Difficulty adjustment interval (blocks)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 10;

/// Initial difficulty (leading zero bits required)
pub const INITIAL_DIFFICULTY: u32 = 16; // ~30-40s on average CPU

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MiningStats {
    pub hashrate: f64,
    pub blocks_mined: u64,
    pub current_reward: f64,
    pub is_active: bool,
    pub difficulty: u32,
}

/// Callback type for block found events
pub type BlockFoundCallback = Arc<dyn Fn(String, f64) + Send + Sync>;

/// AERA Mining Manager (SHA-256 with PoW)
pub struct MiningManager {
    is_mining: Arc<AtomicBool>,
    blocks_mined: Arc<AtomicU64>,
    hashrate: Arc<AtomicU64>,
    target_difficulty: Arc<AtomicU32>,
    block_times: Arc<Mutex<Vec<u64>>>, // Timestamps of last 10 blocks
    miner_address: Arc<Mutex<Option<String>>>,
    block_found_callback: Arc<Mutex<Option<BlockFoundCallback>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MiningManager {
    pub fn new() -> Self {
        Self {
            is_mining: Arc::new(AtomicBool::new(false)),
            blocks_mined: Arc::new(AtomicU64::new(0)),
            hashrate: Arc::new(AtomicU64::new(0)),
            target_difficulty: Arc::new(AtomicU32::new(INITIAL_DIFFICULTY)),
            block_times: Arc::new(Mutex::new(Vec::new())),
            miner_address: Arc::new(Mutex::new(None)),
            block_found_callback: Arc::new(Mutex::new(None)),
            handle: None,
        }
    }

    /// Set the miner address (wallet that receives rewards)
    pub fn set_miner_address(&self, address: String) {
        match self.miner_address.lock() {
            Ok(mut addr) => {
                *addr = Some(address);
            }
            Err(err) => {
                error!("Failed to lock miner address: {}", err);
            }
        }
    }

    /// Set callback for when a block is found
    pub fn set_block_found_callback<F>(&self, callback: F)
    where
        F: Fn(String, f64) + Send + Sync + 'static,
    {
        match self.block_found_callback.lock() {
            Ok(mut cb) => {
                *cb = Some(Arc::new(callback));
            }
            Err(err) => {
                error!("Failed to lock block found callback: {}", err);
            }
        }
    }

    /// Start SHA-256 mining in a background thread
    pub fn start(&mut self) {
        if self.is_mining.load(Ordering::SeqCst) {
            return;
        }

        info!("⚒️ Initializing AERA SHA-256 PoW Mining Worker...");
        self.is_mining.store(true, Ordering::SeqCst);
        
        let is_mining = self.is_mining.clone();
        let blocks_mined = self.blocks_mined.clone();
        let hashrate = self.hashrate.clone();
        let target_difficulty = self.target_difficulty.clone();
        let block_times = self.block_times.clone();
        let miner_address = self.miner_address.clone();
        let block_found_callback = self.block_found_callback.clone();

        let handle = thread::spawn(move || {
            let mut last_stat_update = Instant::now();
            let mut local_hashes: u64 = 0;
            let mut nonce: u64 = 0;
            
            while is_mining.load(Ordering::Relaxed) {
                // Prepare block data (simplified: just nonce + block count)
                let block_count = blocks_mined.load(Ordering::Relaxed);
                let mut data = Vec::new();
                data.extend_from_slice(&block_count.to_le_bytes());
                data.extend_from_slice(&nonce.to_le_bytes());
                
                // Perform SHA-256 hash
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let hash = hasher.finalize();
                
                local_hashes += 1;
                nonce = nonce.wrapping_add(1);

                // Check if hash meets difficulty target
                let current_difficulty = target_difficulty.load(Ordering::Relaxed);
                if Self::check_difficulty(&hash, current_difficulty) {
                    // Block found!
                    let new_block_count = blocks_mined.fetch_add(1, Ordering::SeqCst) + 1;
                    let reward = Self::calculate_reward_static(new_block_count);
                    
                    info!("🎉 Block #{} found! Hash: {}, Reward: {} AERA", 
                          new_block_count, hex::encode(&hash[..8]), reward);
                    
                    // Record block time
                    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                        Ok(duration) => duration.as_secs(),
                        Err(err) => {
                            error!("System time is before UNIX_EPOCH: {}", err);
                            0
                        }
                    };
                    {
                        match block_times.lock() {
                            Ok(mut times) => {
                                times.push(now);
                                if times.len() > DIFFICULTY_ADJUSTMENT_INTERVAL as usize {
                                    times.remove(0);
                                }
                            }
                            Err(err) => {
                                error!("Failed to lock block times: {}", err);
                            }
                        }
                    }
                    
                    // Adjust difficulty every N blocks
                    if new_block_count % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                        Self::adjust_difficulty(&target_difficulty, &block_times);
                    }
                    
                    // Trigger callback to credit wallet
                    let maybe_addr = match miner_address.lock() {
                        Ok(addr) => addr.clone(),
                        Err(err) => {
                            error!("Failed to lock miner address: {}", err);
                            None
                        }
                    };
                    if let Some(addr) = maybe_addr {
                        let maybe_callback = match block_found_callback.lock() {
                            Ok(cb) => cb.clone(),
                            Err(err) => {
                                error!("Failed to lock block found callback: {}", err);
                                None
                            }
                        };
                        if let Some(callback) = maybe_callback {
                            callback(addr, reward);
                        }
                    }
                    
                    // Reset nonce for next block
                    nonce = 0;
                }

                // CPU-friendly micro-pause every 1000 hashes
                if local_hashes % 1000 == 0 {
                    std::hint::spin_loop();
                }

                // Stat update every second
                if last_stat_update.elapsed() >= Duration::from_secs(1) {
                    hashrate.store(local_hashes, Ordering::SeqCst);
                    local_hashes = 0;
                    last_stat_update = Instant::now();
                }
            }
            info!("⚒️ Mining worker stopped.");
        });

        self.handle = Some(handle);
    }

    /// Stop mining worker gracefully
    pub fn stop(&mut self) {
        if !self.is_mining.load(Ordering::SeqCst) {
            return;
        }
        
        info!("⚒️ Stopping mining worker...");
        self.is_mining.store(false, Ordering::SeqCst);
        
        if let Some(handle) = self.handle.take() {
            if let Err(e) = handle.join() {
                error!("Failed to join mining thread: {:?}", e);
            }
        }
    }

    /// Get current mining statistics and economic state
    pub fn get_status(&self) -> MiningStats {
        let total_blocks = self.blocks_mined.load(Ordering::SeqCst);
        let reward = self.calculate_reward(total_blocks);
        
        MiningStats {
            hashrate: self.hashrate.load(Ordering::SeqCst) as f64,
            blocks_mined: total_blocks,
            current_reward: if total_blocks >= 20_000_000 { 0.0 } else { reward },
            is_active: self.is_mining.load(Ordering::SeqCst),
            difficulty: self.target_difficulty.load(Ordering::SeqCst),
        }
    }

    /// Calculate block reward based on halving logic
    fn calculate_reward(&self, total_blocks: u64) -> f64 {
        Self::calculate_reward_static(total_blocks)
    }

    fn calculate_reward_static(total_blocks: u64) -> f64 {
        let halvings = total_blocks / HALVING_INTERVAL;
        if halvings >= 64 {
            return 0.0;
        }
        INITIAL_REWARD / (2.0f64.powi(halvings as i32))
    }

    /// Check if hash meets difficulty target (leading zero bits)
    fn check_difficulty(hash: &[u8], difficulty: u32) -> bool {
        let required_zero_bits = difficulty;
        let mut zero_bits = 0u32;
        
        for byte in hash.iter() {
            if *byte == 0 {
                zero_bits += 8;
            } else {
                zero_bits += byte.leading_zeros();
                break;
            }
            
            if zero_bits >= required_zero_bits {
                return true;
            }
        }
        
        zero_bits >= required_zero_bits
    }

    /// Dynamic Difficulty Adjustment (DDA)
    /// Adjusts difficulty to maintain TARGET_BLOCK_TIME average
    fn adjust_difficulty(
        target_difficulty: &Arc<AtomicU32>,
        block_times: &Arc<Mutex<Vec<u64>>>,
    ) {
        let times = match block_times.lock() {
            Ok(times) => times,
            Err(err) => {
                error!("Failed to lock block times for difficulty adjustment: {}", err);
                return;
            }
        };
        
        if times.len() < 2 {
            return; // Not enough data
        }
        
        // Calculate actual average time between blocks
        let time_span = times[times.len() - 1] - times[0];
        let num_intervals = (times.len() - 1) as u64;
        let actual_avg_time = time_span / num_intervals;
        
        let current_difficulty = target_difficulty.load(Ordering::SeqCst);
        
        // Calculate adjustment ratio
        let ratio = actual_avg_time as f64 / TARGET_BLOCK_TIME as f64;
        
        // Apply adjustment with bounds (0.5x to 2x change max)
        let adjustment_factor = if ratio > 2.0 {
            0.5 // Blocks too slow, reduce difficulty
        } else if ratio < 0.5 {
            2.0 // Blocks too fast, increase difficulty (exponential)
        } else {
            1.0 / ratio
        };
        
        let new_difficulty = ((current_difficulty as f64) * adjustment_factor).round() as u32;
        
        // Clamp difficulty to reasonable range (8 to 32 bits)
        let new_difficulty = new_difficulty.max(8).min(32);
        
        if new_difficulty != current_difficulty {
            info!("📊 Difficulty adjusted: {} -> {} (avg block time: {}s, target: {}s)",
                  current_difficulty, new_difficulty, actual_avg_time, TARGET_BLOCK_TIME);
            target_difficulty.store(new_difficulty, Ordering::SeqCst);
        }
    }
}

impl Default for MiningManager {
    fn default() -> Self {
        Self::new()
    }
}
