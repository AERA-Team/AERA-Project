//! P2P Networking module using libp2p
//!
//! Implements:
//! - Peer discovery via mDNS and Kademlia DHT
//! - Block/Transaction propagation via Gossipsub
//! - Request-Response for block sync
//! - Full duplex sync protocol (both request and respond)

use crate::types::{Block, BlockHeader, Hash, Transaction};
use anyhow::Result;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId},
    identify,
    kad::{self, store::MemoryStore},
    mdns,
    noise, ping,
    request_response::{self, ProtocolSupport, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
    futures::StreamExt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

// ============================================================================
// Topics
// ============================================================================

/// Gossipsub topic for new blocks
pub const TOPIC_BLOCKS: &str = "/aera/blocks/1.0.0";
/// Gossipsub topic for new transactions
pub const TOPIC_TRANSACTIONS: &str = "/aera/txs/1.0.0";
/// Gossipsub topic for consensus votes
pub const TOPIC_VOTES: &str = "/aera/votes/1.0.0";

// ============================================================================
// Network Events (outbound to main loop)
// ============================================================================

/// Events emitted from network layer to the main application loop
#[derive(Debug)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected  
    PeerDisconnected(PeerId),
    /// New block received via gossip
    NewBlock(Block),
    /// New transaction received via gossip
    NewTransaction(Transaction),
    /// Blocks received from sync request
    BlocksReceived { from_peer: PeerId, blocks: Vec<Block> },
    /// Peer requested blocks from us (we need to respond)
    BlocksRequested {
        peer: PeerId,
        from_height: u64,
        count: u32,
        channel: SyncResponseChannel,
    },
    /// Peer count updated
    PeerCountChanged(usize),
}

// ============================================================================
// Network Commands (inbound from main loop)
// ============================================================================

/// Commands sent from main application to network layer
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a new block to all peers
    BroadcastBlock(Block),
    /// Broadcast a new transaction to all peers
    BroadcastTransaction(Transaction),
    /// Request blocks from a specific peer for syncing
    RequestBlocks { peer: PeerId, from_height: u64, count: u32 },
    /// Request block by hash
    RequestBlockByHash { peer: PeerId, hash: Hash },
    /// Respond to a block sync request
    RespondBlocks { channel: SyncResponseChannel, blocks: Vec<Block> },
    /// Connect to a peer by multiaddr
    Dial(Multiaddr),
    /// Get current connected peer count
    GetPeerCount,
}

// ============================================================================
// Sync Protocol Messages
// ============================================================================

/// Request messages for the block sync protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Request blocks starting from height
    GetBlocks { from_height: u64, count: u32 },
    /// Request single block by hash
    GetBlockByHash(Hash),
    /// Request current chain tip info
    GetChainTip,
    /// Request block headers only (for light sync)
    GetHeaders { from_height: u64, count: u32 },
}

/// Response messages for the block sync protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Multiple blocks response
    Blocks(Vec<Block>),
    /// Single block response (may be None if not found)
    Block(Option<Block>),
    /// Chain tip info
    ChainTip { height: u64, hash: Hash },
    /// Block headers only
    Headers(Vec<BlockHeader>),
    /// Error response
    Error(String),
}

/// Wrapper for response channel to send in events
#[derive(Debug)]
pub struct SyncResponseChannel(pub ResponseChannel<SyncResponse>);

// Implement Send + Sync for channel wrapper
unsafe impl Send for SyncResponseChannel {}
unsafe impl Sync for SyncResponseChannel {}

// ============================================================================
// Network Behaviour
// ============================================================================

/// Combined libp2p network behaviour for AERA
#[derive(NetworkBehaviour)]
pub struct AeraBehaviour {
    /// Gossipsub for pub/sub block and transaction propagation
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery and routing
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// mDNS for local network peer discovery
    pub mdns: mdns::tokio::Behaviour,
    /// Identify protocol for peer information exchange
    pub identify: identify::Behaviour,
    /// Ping for connection liveness checks
    pub ping: ping::Behaviour,
    /// Request-Response protocol for block synchronization
    pub sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
}

// ============================================================================
// Peer Info
// ============================================================================

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
    pub chain_height: Option<u64>,
    pub last_seen: std::time::Instant,
}

// ============================================================================
// Network Service
// ============================================================================

/// Main P2P network service for AERA blockchain
pub struct NetworkService {
    /// Local peer ID
    pub local_peer_id: PeerId,
    /// Channel to receive network events
    event_rx: mpsc::Receiver<NetworkEvent>,
    /// Channel to send commands to network
    command_tx: mpsc::Sender<NetworkCommand>,
    /// Connected peers info (shared with event loop)
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
}

impl NetworkService {
    /// Create and start a new network service
    pub async fn start(listen_addr: Multiaddr) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::channel(512);
        let (command_tx, command_rx) = mpsc::channel(512);
        let peers = Arc::new(RwLock::new(HashMap::new()));

        // Generate node keypair
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        info!("🔑 Local peer ID: {}", local_peer_id);

        // Build libp2p swarm
        let swarm = Self::build_swarm(local_key)?;

        // Spawn network event loop as background task
        let peers_clone = Arc::clone(&peers);
        tokio::spawn(Self::run_event_loop(
            swarm,
            listen_addr,
            event_tx,
            command_rx,
            peers_clone,
        ));

        Ok(Self {
            local_peer_id,
            event_rx,
            command_tx,
            peers,
        })
    }

    /// Build the libp2p swarm with all behaviours
    fn build_swarm(local_key: libp2p::identity::Keypair) -> Result<Swarm<AeraBehaviour>> {
        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                // Gossipsub with custom message ID (to prevent duplicates)
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut hasher = Sha256::new();
                    hasher.update(&message.data);
                    hasher.update(message.source.unwrap_or(PeerId::random()).to_bytes());
                    MessageId::from(hasher.finalize().to_vec())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .max_transmit_size(10 * 1024 * 1024) // 10 MB for blocks
                    .build()
                    .expect("Valid gossipsub config");

                let gossipsub = gossipsub::Behaviour::new(
                    MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                ).expect("Valid gossipsub behaviour");

                // Kademlia DHT
                let mut kademlia_config = kad::Config::default();
                kademlia_config.set_protocol_names(vec![StreamProtocol::new("/aera/kad/1.0.0")]);
                
                let kademlia = kad::Behaviour::with_config(
                    PeerId::from(key.public()),
                    MemoryStore::new(PeerId::from(key.public())),
                    kademlia_config,
                );

                // mDNS for local discovery
                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    PeerId::from(key.public()),
                ).expect("Valid mDNS behaviour");

                // Identify protocol
                let identify = identify::Behaviour::new(
                    identify::Config::new("/aera/1.0.0".to_string(), key.public())
                        .with_agent_version(format!("aera-node/{}", env!("CARGO_PKG_VERSION"))),
                );

                // Ping
                let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30)));

                // Request-Response for sync
                let sync = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/aera/sync/1.0.0"), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(60)),
                );

                AeraBehaviour {
                    gossipsub,
                    kademlia,
                    mdns,
                    identify,
                    ping,
                    sync,
                }
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
            .build();

        Ok(swarm)
    }

    /// Main network event loop (runs in background task)
    async fn run_event_loop(
        mut swarm: Swarm<AeraBehaviour>,
        listen_addr: Multiaddr,
        event_tx: mpsc::Sender<NetworkEvent>,
        mut command_rx: mpsc::Receiver<NetworkCommand>,
        peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    ) {
        // Subscribe to gossipsub topics
        let blocks_topic = IdentTopic::new(TOPIC_BLOCKS);
        let txs_topic = IdentTopic::new(TOPIC_TRANSACTIONS);
        let votes_topic = IdentTopic::new(TOPIC_VOTES);

        swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic).ok();
        swarm.behaviour_mut().gossipsub.subscribe(&txs_topic).ok();
        swarm.behaviour_mut().gossipsub.subscribe(&votes_topic).ok();

        // Start listening
        if let Err(e) = swarm.listen_on(listen_addr.clone()) {
            error!("❌ Failed to listen on {}: {}", listen_addr, e);
            return;
        }

        info!("🌐 P2P network listening on {}", listen_addr);

        // Periodic bootstrap for Kademlia
        let mut bootstrap_interval = tokio::time::interval(Duration::from_secs(300));

        loop {
            tokio::select! {
                // Handle libp2p swarm events
                event = swarm.select_next_some() => {
                    Self::handle_swarm_event(&mut swarm, event, &event_tx, &peers).await;
                }
                
                // Handle commands from main application
                command = command_rx.recv() => {
                    match command {
                        Some(cmd) => Self::handle_command(&mut swarm, cmd, &event_tx).await,
                        None => {
                            info!("Command channel closed, shutting down network");
                            break;
                        }
                    }
                }
                
                // Periodic Kademlia bootstrap
                _ = bootstrap_interval.tick() => {
                    debug!("Running Kademlia bootstrap");
                    let _ = swarm.behaviour_mut().kademlia.bootstrap();
                }
            }
        }
    }

    /// Handle swarm events from libp2p
    async fn handle_swarm_event(
        swarm: &mut Swarm<AeraBehaviour>,
        event: SwarmEvent<AeraBehaviourEvent>,
        event_tx: &mpsc::Sender<NetworkEvent>,
        peers: &Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    ) {
        match event {
            // New listen address
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("📡 Listening on {}", address);
            }

            // Connection established
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                info!("🔗 Connected to peer: {}", peer_id);
                
                // Track peer
                let addr = endpoint.get_remote_address().clone();
                peers.write().await.insert(peer_id, PeerInfo {
                    peer_id,
                    addresses: vec![addr.clone()],
                    chain_height: None,
                    last_seen: std::time::Instant::now(),
                });

                // Add to Kademlia
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                
                // Notify main loop
                let _ = event_tx.send(NetworkEvent::PeerConnected(peer_id)).await;
                let peer_count = peers.read().await.len();
                let _ = event_tx.send(NetworkEvent::PeerCountChanged(peer_count)).await;
            }

            // Connection closed
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("🔌 Disconnected from peer: {}", peer_id);
                peers.write().await.remove(&peer_id);
                let _ = event_tx.send(NetworkEvent::PeerDisconnected(peer_id)).await;
                let peer_count = peers.read().await.len();
                let _ = event_tx.send(NetworkEvent::PeerCountChanged(peer_count)).await;
            }

            // Gossipsub message received
            SwarmEvent::Behaviour(AeraBehaviourEvent::Gossipsub(
                gossipsub::Event::Message { message, .. }
            )) => {
                let topic = message.topic.as_str();
                
                if topic == TOPIC_BLOCKS {
                    match bincode::deserialize::<Block>(&message.data) {
                        Ok(block) => {
                            debug!("📦 Received block #{} via gossip", block.header.height);
                            let _ = event_tx.send(NetworkEvent::NewBlock(block)).await;
                        }
                        Err(e) => warn!("Failed to deserialize block: {}", e),
                    }
                } else if topic == TOPIC_TRANSACTIONS {
                    match bincode::deserialize::<Transaction>(&message.data) {
                        Ok(tx) => {
                            debug!("📨 Received transaction via gossip");
                            let _ = event_tx.send(NetworkEvent::NewTransaction(tx)).await;
                        }
                        Err(e) => warn!("Failed to deserialize transaction: {}", e),
                    }
                }
            }

            // mDNS peer discovery
            SwarmEvent::Behaviour(AeraBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, addr) in list {
                    debug!("🔍 mDNS discovered: {} at {}", peer_id, addr);
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
            }
            
            SwarmEvent::Behaviour(AeraBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                for (peer_id, _) in list {
                    debug!("mDNS peer expired: {}", peer_id);
                }
            }

            // Identify protocol - peer info received
            SwarmEvent::Behaviour(AeraBehaviourEvent::Identify(identify::Event::Received { peer_id, info })) => {
                debug!("Identified peer {}: {} ({})", peer_id, info.agent_version, info.protocol_version);
                
                // Add observed addresses to Kademlia
                for addr in info.listen_addrs {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
            }

            // Sync protocol - incoming request
            SwarmEvent::Behaviour(AeraBehaviourEvent::Sync(
                request_response::Event::Message { peer, message }
            )) => {
                match message {
                    // Incoming request - forward to main loop to get blocks
                    request_response::Message::Request { request, channel, .. } => {
                        debug!("📥 Sync request from {}: {:?}", peer, request);
                        
                        match request {
                            SyncRequest::GetBlocks { from_height, count } => {
                                let _ = event_tx.send(NetworkEvent::BlocksRequested {
                                    peer,
                                    from_height,
                                    count,
                                    channel: SyncResponseChannel(channel),
                                }).await;
                            }
                            SyncRequest::GetBlockByHash(_hash) => {
                                // Handle single block request
                                let _ = event_tx.send(NetworkEvent::BlocksRequested {
                                    peer,
                                    from_height: 0,
                                    count: 1,
                                    channel: SyncResponseChannel(channel),
                                }).await;
                            }
                            SyncRequest::GetChainTip => {
                                // Respond with current chain tip
                                // (would need chain state access here)
                            }
                            SyncRequest::GetHeaders { from_height: _, count: _ } => {
                                // Headers-only sync for light clients
                            }
                        }
                    }
                    
                    // Incoming response to our request
                    request_response::Message::Response { response, .. } => {
                        debug!("📤 Sync response from {}", peer);
                        
                        match response {
                            SyncResponse::Blocks(blocks) => {
                                info!("Received {} blocks from {}", blocks.len(), peer);
                                let _ = event_tx.send(NetworkEvent::BlocksReceived {
                                    from_peer: peer,
                                    blocks,
                                }).await;
                            }
                            SyncResponse::Block(Some(block)) => {
                                let _ = event_tx.send(NetworkEvent::BlocksReceived {
                                    from_peer: peer,
                                    blocks: vec![block],
                                }).await;
                            }
                            SyncResponse::Error(err) => {
                                warn!("Sync error from {}: {}", peer, err);
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Sync request failed
            SwarmEvent::Behaviour(AeraBehaviourEvent::Sync(
                request_response::Event::OutboundFailure { peer, error, .. }
            )) => {
                warn!("Sync request to {} failed: {:?}", peer, error);
            }

            _ => {}
        }
    }

    /// Handle commands from main application
    async fn handle_command(
        swarm: &mut Swarm<AeraBehaviour>,
        command: NetworkCommand,
        event_tx: &mpsc::Sender<NetworkEvent>,
    ) {
        match command {
            NetworkCommand::BroadcastBlock(block) => {
                let topic = IdentTopic::new(TOPIC_BLOCKS);
                match bincode::serialize(&block) {
                    Ok(data) => {
                        debug!("📤 Broadcasting block #{}", block.header.height);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            warn!("Failed to broadcast block: {:?}", e);
                        }
                    }
                    Err(e) => error!("Failed to serialize block: {}", e),
                }
            }

            NetworkCommand::BroadcastTransaction(tx) => {
                let topic = IdentTopic::new(TOPIC_TRANSACTIONS);
                match bincode::serialize(&tx) {
                    Ok(data) => {
                        debug!("📤 Broadcasting transaction");
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            warn!("Failed to broadcast transaction: {:?}", e);
                        }
                    }
                    Err(e) => error!("Failed to serialize transaction: {}", e),
                }
            }

            NetworkCommand::RequestBlocks { peer, from_height, count } => {
                info!("📥 Requesting blocks {}-{} from {}", from_height, from_height + count as u64, peer);
                let request = SyncRequest::GetBlocks { from_height, count };
                swarm.behaviour_mut().sync.send_request(&peer, request);
            }

            NetworkCommand::RequestBlockByHash { peer, hash } => {
                debug!("Requesting block by hash from {}", peer);
                let request = SyncRequest::GetBlockByHash(hash);
                swarm.behaviour_mut().sync.send_request(&peer, request);
            }

            NetworkCommand::RespondBlocks { channel, blocks } => {
                debug!("Responding with {} blocks", blocks.len());
                let response = SyncResponse::Blocks(blocks);
                let _ = swarm.behaviour_mut().sync.send_response(channel.0, response);
            }

            NetworkCommand::Dial(addr) => {
                info!("📞 Dialing peer: {}", addr);
                if let Err(e) = swarm.dial(addr.clone()) {
                    warn!("Failed to dial {}: {}", addr, e);
                }
            }

            NetworkCommand::GetPeerCount => {
                let count = swarm.connected_peers().count();
                let _ = event_tx.send(NetworkEvent::PeerCountChanged(count)).await;
            }
        }
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Receive next network event (called from main loop)
    pub async fn recv_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    /// Send command to network layer
    pub async fn send_command(&self, command: NetworkCommand) -> Result<()> {
        self.command_tx.send(command).await?;
        Ok(())
    }

    /// Broadcast a new block to the network
    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        self.send_command(NetworkCommand::BroadcastBlock(block)).await
    }

    /// Broadcast a new transaction to the network
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<()> {
        self.send_command(NetworkCommand::BroadcastTransaction(tx)).await
    }

    /// Request blocks from a peer for syncing
    pub async fn request_blocks(&self, peer: PeerId, from_height: u64, count: u32) -> Result<()> {
        self.send_command(NetworkCommand::RequestBlocks { peer, from_height, count }).await
    }

    /// Respond to a block sync request
    pub async fn respond_blocks(&self, channel: SyncResponseChannel, blocks: Vec<Block>) -> Result<()> {
        self.send_command(NetworkCommand::RespondBlocks { channel, blocks }).await
    }

    /// Connect to a peer
    pub async fn dial(&self, addr: Multiaddr) -> Result<()> {
        self.send_command(NetworkCommand::Dial(addr)).await
    }

    /// Get current peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get list of connected peer IDs
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.read().await.keys().cloned().collect()
    }
}
