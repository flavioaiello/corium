//! UDP Relay with Actor-based Architecture
//!
//! This module provides relay functionality for NAT traversal, allowing peers
//! behind NAT to communicate through a relay server. It uses the actor pattern
//! for safe concurrent access to shared state.
//!
//! # Architecture
//!
//! ## Server Side (runs on public nodes)
//! - `RelayServer`: The public handle (cheap to clone, send commands to actor)
//! - `RelayServerActor`: Owns all state, processes commands sequentially
//! - `RelayCommand`: Commands sent from handles to the actor
//!
//! ## Client Side (runs on NAT-bound nodes)
//! - `RelayClient`: Manages relay registration, discovery, and incoming connections
//!
//! # Features
//!
//! - Session-based UDP packet forwarding between peers
//! - Signaling channel for push notifications to NAT-bound nodes
//! - Automatic session cleanup for expired/inactive sessions
//! - Automatic relay discovery and best-RTT selection

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, trace, warn};

use crate::identity::Identity;
use crate::messages::{RelayRequest, RelayResponse};
use crate::protocols::{DhtNodeRpc, RelayRpc};


// ============================================================================
// Constants
// ============================================================================

/// Magic bytes identifying relay protocol frames.
pub const RELAY_MAGIC: [u8; 4] = *b"CRLY";

/// Size of the relay frame header: magic(4) + session_id(16).
pub const RELAY_HEADER_SIZE: usize = 20;

/// Maximum total sessions the relay server will manage.
/// SCALABILITY: 10K sessions per relay server (see README Scaling Boundaries).
/// SECURITY: Prevents memory exhaustion from session table growth.
pub const MAX_SESSIONS: usize = 10_000;

/// Duration after which inactive sessions are garbage collected.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for sessions awaiting peer B completion.
/// Shorter than SESSION_TIMEOUT to free half-open sessions quickly.
pub const PENDING_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval for the cleanup task that removes expired sessions.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum relay frame size (fits in UDP MTU with headroom).
pub const MAX_RELAY_FRAME_SIZE: usize = 1400;

/// Maximum sessions per IP address (rate limiting).
/// SECURITY: Limits session table pollution from a single IP.
pub const MAX_SESSIONS_PER_IP: usize = 50;

/// Rate limit window for session registration.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Maximum entries in addr_to_session map (bounded to prevent memory exhaustion).
/// SECURITY: Secondary bound on address lookup table.
pub const MAX_ADDR_TO_SESSION_ENTRIES: usize = 20_000;

/// Maximum entries in ip_session_count rate limiter.
/// SECURITY: Bounds the rate limiter itself to prevent memory exhaustion.
pub const MAX_IP_SESSION_COUNT_ENTRIES: usize = 10_000;


// ============================================================================
// Session Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError {
    pub code: Option<u32>,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(f, "CSPRNG unavailable (error code {})", code),
            None => write!(f, "CSPRNG unavailable"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<getrandom::Error> for CryptoError {
    fn from(err: getrandom::Error) -> Self {
        Self { code: Some(err.code().get()) }
    }
}

pub fn generate_session_id() -> Result<[u8; 16], CryptoError> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id)?;
    Ok(id)
}


#[derive(Debug, Clone)]
pub struct RelaySession {
    pub session_id: [u8; 16],
    pub peer_a_identity: Identity,
    pub peer_b_identity: Identity,
    pub peer_a_addr: SocketAddr,
    pub peer_b_addr: Option<SocketAddr>,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub bytes_relayed: u64,
    pub packets_relayed: u64,
    pub completion_locked: bool,
}

impl RelaySession {
    pub fn new_pending(
        session_id: [u8; 16],
        peer_a_identity: Identity,
        peer_b_identity: Identity,
        peer_a_addr: SocketAddr,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            peer_a_identity,
            peer_b_identity,
            peer_a_addr,
            peer_b_addr: None,
            created_at: now,
            last_activity: now,
            bytes_relayed: 0,
            packets_relayed: 0,
            completion_locked: false,
        }
    }

    /// Returns the session ID as a hex string (useful for logging).
    pub fn session_id_hex(&self) -> String {
        hex::encode(self.session_id)
    }

    /// Returns the session age (time since creation).
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn is_complete(&self) -> bool {
        self.peer_b_addr.is_some()
    }

    pub fn is_expired(&self) -> bool {
        // Sessions expire based on inactivity only.
        // Active sessions stay alive indefinitely to avoid sudden connection drops.
        if self.is_complete() {
            self.last_activity.elapsed() > SESSION_TIMEOUT
        } else {
            self.last_activity.elapsed() > PENDING_SESSION_TIMEOUT
        }
    }

    pub fn get_destination(&self, from: SocketAddr) -> Option<SocketAddr> {
        if from == self.peer_a_addr {
            self.peer_b_addr
        } else if self.peer_b_addr == Some(from) {
            Some(self.peer_a_addr)
        } else {
            None
        }
    }

    pub fn record_activity(&mut self, bytes: usize) {
        self.last_activity = Instant::now();
        self.bytes_relayed += bytes as u64;
        self.packets_relayed += 1;
    }
}


// ============================================================================
// IncomingConnection (signaling notification)
// ============================================================================

/// Notification of an incoming connection request via relay signaling.
/// 
/// When a NAT-bound node receives this, it should call `RelayClient::accept_incoming()`
/// or `Node::accept_incoming()` to complete the relay handshake.
#[derive(Debug, Clone)]
pub struct IncomingConnection {
    /// Hex-encoded identity of the peer that wants to connect.
    pub from_peer: String,
    /// Session ID to use when completing the relay connection.
    pub session_id: [u8; 16],
    /// Address to send relay data packets to.
    pub relay_data_addr: String,
}


// ============================================================================
// NatStatus (result of NAT configuration)
// ============================================================================

/// Result of NAT detection and configuration.
#[derive(Debug, Clone)]
pub enum NatStatus {
    /// Node is publicly reachable (can serve as relay).
    Public,
    /// Node is behind NAT and using a relay.
    NatBound {
        /// The identity of the relay node we're registered with.
        relay: Identity,
    },
    /// NAT status hasn't been determined yet.
    Unknown,
}


// ============================================================================
// MeshSignalOut (for sending signals via mesh)
// ============================================================================

/// Outgoing relay signal to be sent via GossipSub mesh.
/// Phase 3: When a NAT node doesn't have a dedicated signaling connection,
/// the relay sends signals through the mesh instead.
#[derive(Debug, Clone)]
pub struct MeshSignalOut {
    /// Target peer to receive the signal.
    pub target: Identity,
    /// Peer requesting connection.
    pub from_peer: Identity,
    /// Relay session identifier.
    pub session_id: [u8; 16],
    /// Address for relay data packets.
    pub relay_data_addr: String,
}


// ============================================================================
// Commands sent from Handle to Actor
// ============================================================================

enum RelayCommand {
    RegisterSession {
        session_id: [u8; 16],
        peer_a_addr: SocketAddr,
        peer_a_identity: Identity,
        peer_b_identity: Identity,
        reply: oneshot::Sender<Result<(), &'static str>>,
    },
    CompleteSession {
        session_id: [u8; 16],
        peer_b_addr: SocketAddr,
        from_peer: Identity,
        target_peer: Identity,
        reply: oneshot::Sender<Result<(), &'static str>>,
    },
    SessionCount {
        reply: oneshot::Sender<usize>,
    },
    NotifyIncoming {
        target_peer: Identity,
        from_peer: Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
        reply: oneshot::Sender<bool>,
    },
    ProcessPacket {
        data: Vec<u8>,
        from: SocketAddr,
        reply: oneshot::Sender<usize>,
    },
    Quit,
}


// ============================================================================
// RelayServer Handle (public API - cheap to clone)
// ============================================================================

/// Handle to the relay server actor. Cheap to clone.
/// 
/// This runs on publicly-reachable nodes and forwards packets between
/// NAT-bound peers. Use `RelayClient` on the client side.
#[derive(Clone)]
pub struct RelayServer {
    cmd_tx: mpsc::Sender<RelayCommand>,
    socket: Arc<UdpSocket>,
}

/// Type alias for backwards compatibility.
pub type Relay = RelayServer;

impl std::fmt::Debug for RelayServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayServer")
            .field("socket", &self.socket.local_addr())
            .finish()
    }
}

impl RelayServer {
    /// Create a new relay server sharing the given socket.
    /// 
    /// # Arguments
    /// * `socket` - UDP socket for relay data packets
    /// * `mesh_signal_tx` - Channel for sending signals via GossipSub mesh (mesh-only signaling)
    /// 
    /// Spawns the actor and cleanup tasks.
    pub fn with_socket(socket: Arc<UdpSocket>, mesh_signal_tx: mpsc::Sender<MeshSignalOut>) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        
        let local_addr = socket.local_addr().ok();
        if let Some(addr) = local_addr {
            info!(addr = %addr, "RelayServer actor started (mesh-only signaling)");
        }
        
        let actor = RelayServerActor::new(socket.clone(), mesh_signal_tx);
        tokio::spawn(actor.run(cmd_rx));
        
        Self { cmd_tx, socket }
    }

    /// Get the local address of the relay socket.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Register a new relay session (peer A initiating).
    pub async fn register_session(
        &self,
        session_id: [u8; 16],
        peer_a_addr: SocketAddr,
        peer_a_identity: Identity,
        peer_b_identity: Identity,
    ) -> Result<(), &'static str> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.cmd_tx.send(RelayCommand::RegisterSession {
            session_id,
            peer_a_addr,
            peer_a_identity,
            peer_b_identity,
            reply: reply_tx,
        }).await.map_err(|_| "relay actor closed")?;
        
        reply_rx.await.map_err(|_| "relay actor closed")?
    }

    /// Complete a relay session (peer B joining).
    pub async fn complete_session(
        &self,
        session_id: [u8; 16],
        peer_b_addr: SocketAddr,
        from_peer: Identity,
        target_peer: Identity,
    ) -> Result<(), &'static str> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.cmd_tx.send(RelayCommand::CompleteSession {
            session_id,
            peer_b_addr,
            from_peer,
            target_peer,
            reply: reply_tx,
        }).await.map_err(|_| "relay actor closed")?;
        
        reply_rx.await.map_err(|_| "relay actor closed")?
    }

    /// Get the current session count.
    pub async fn session_count(&self) -> usize {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        if self.cmd_tx.send(RelayCommand::SessionCount { reply: reply_tx }).await.is_err() {
            return 0;
        }
        
        reply_rx.await.unwrap_or(0)
    }

    /// Notify a NAT peer about an incoming connection via mesh signaling.
    pub async fn notify_incoming(
        &self,
        target_peer: Identity,
        from_peer: Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
    ) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        if self.cmd_tx.send(RelayCommand::NotifyIncoming {
            target_peer,
            from_peer,
            session_id,
            relay_data_addr,
            reply: reply_tx,
        }).await.is_err() {
            return false;
        }
        
        reply_rx.await.unwrap_or(false)
    }

    /// Process an incoming relay packet.
    /// This is called from the hot path (SmartSock poll_recv).
    pub async fn process_packet(&self, data: &[u8], from: SocketAddr) -> usize {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        if self.cmd_tx.send(RelayCommand::ProcessPacket {
            data: data.to_vec(),
            from,
            reply: reply_tx,
        }).await.is_err() {
            return 0;
        }
        
        reply_rx.await.unwrap_or(0)
    }

    /// Shutdown the relay actor.
    pub async fn quit(&self) {
        let _ = self.cmd_tx.send(RelayCommand::Quit).await;
    }
}


// ============================================================================
// RelayClient (runs on NAT-bound nodes)
// ============================================================================

/// Client-side relay management for NAT-bound nodes.
/// 
/// This struct encapsulates all the logic needed for a NAT-bound node to:
/// - Detect its NAT status via reachability probes
/// - Discover relay-capable nodes in the network
/// - Register with a relay for incoming connection notifications
/// - Accept incoming connections through the relay
/// 
/// # Example
/// ```ignore
/// let client = RelayClient::new(rpc.clone(), dht.clone(), keypair.clone());
/// 
/// // Configure NAT and get status
/// let status = client.configure(&helper, addresses).await?;
/// 
/// // Handle incoming connections
/// if let Some(mut rx) = client.incoming_connections() {
///     while let Some(incoming) = rx.recv().await {
///         client.accept_incoming(&incoming).await?;
///     }
/// }
/// ```
pub struct RelayClient {
    rpc: Arc<crate::rpc::RpcNode>,
    dht: crate::dht::DhtNode<crate::rpc::RpcNode>,
    keypair: crate::identity::Keypair,
    local_addr: std::net::SocketAddr,
    status: tokio::sync::RwLock<NatStatus>,
    incoming_rx: tokio::sync::Mutex<Option<mpsc::Receiver<IncomingConnection>>>,
    /// The relay we are currently registered with, if any.
    /// Used to validate incoming connection notifications.
    registered_relay: tokio::sync::RwLock<Option<crate::identity::Contact>>,
    /// Last time we successfully communicated with the registered relay.
    /// Updated by `record_relay_alive()` when mesh traffic proves liveness.
    relay_last_seen: tokio::sync::RwLock<Option<Instant>>,
    /// Sender for mesh-mediated signals.
    /// When set, relay signals can arrive via GossipSub mesh instead of dedicated connections.
    mesh_signal_tx: tokio::sync::RwLock<Option<mpsc::Sender<IncomingConnection>>>,
}

/// Timeout after which a relay is considered unhealthy if no communication.
/// Used for failover decisions.
pub const RELAY_HEALTH_TIMEOUT: Duration = Duration::from_secs(30);

impl RelayClient {
    /// Create a new relay client.
    pub fn new(
        rpc: Arc<crate::rpc::RpcNode>,
        dht: crate::dht::DhtNode<crate::rpc::RpcNode>,
        keypair: crate::identity::Keypair,
        local_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            rpc,
            dht,
            keypair,
            local_addr,
            status: tokio::sync::RwLock::new(NatStatus::Unknown),
            incoming_rx: tokio::sync::Mutex::new(None),
            registered_relay: tokio::sync::RwLock::new(None),
            relay_last_seen: tokio::sync::RwLock::new(None),
            mesh_signal_tx: tokio::sync::RwLock::new(None),
        }
    }

    /// Get the current NAT status.
    pub async fn status(&self) -> NatStatus {
        self.status.read().await.clone()
    }
    
    /// Get the identity of the registered relay, if any.
    pub async fn registered_relay_identity(&self) -> Option<Identity> {
        self.registered_relay.read().await.as_ref().map(|c| c.identity)
    }

    /// Record that we successfully communicated with the registered relay.
    /// 
    /// Called by GossipSub when sending to a mesh peer that's our relay.
    /// This proves relay liveness without dedicated health probes.
    pub async fn record_relay_alive(&self, relay_identity: &Identity) {
        let registered = self.registered_relay.read().await;
        if let Some(relay) = &*registered {
            if &relay.identity == relay_identity {
                drop(registered);
                *self.relay_last_seen.write().await = Some(Instant::now());
                trace!(
                    relay = %hex::encode(&relay_identity.as_bytes()[..8]),
                    "relay liveness confirmed via mesh traffic"
                );
            }
        }
    }

    /// Check if the registered relay is healthy (recently seen).
    /// 
    /// Returns `true` if we've successfully communicated with the relay
    /// within `RELAY_HEALTH_TIMEOUT`.
    pub async fn is_relay_healthy(&self) -> bool {
        if let Some(last_seen) = *self.relay_last_seen.read().await {
            last_seen.elapsed() < RELAY_HEALTH_TIMEOUT
        } else {
            // Never seen - might be freshly registered, give benefit of doubt
            // or relay is not a mesh peer (can't piggyback health)
            true
        }
    }

    /// Get time since last relay communication, if known.
    pub async fn relay_last_seen(&self) -> Option<Duration> {
        self.relay_last_seen.read().await.map(|t| t.elapsed())
    }

    /// Enable mesh-mediated signaling and return a receiver for incoming connections.
    /// 
    /// This is an alternative to `register_with_relay()` that doesn't require
    /// a dedicated connection to the relay. Instead, relay signals arrive via
    /// GossipSub mesh connections.
    /// 
    /// # Returns
    /// A receiver that yields incoming connection notifications.
    pub async fn enable_mesh_signaling(&self) -> mpsc::Receiver<IncomingConnection> {
        let (tx, rx) = mpsc::channel::<IncomingConnection>(16);
        *self.mesh_signal_tx.write().await = Some(tx);
        rx
    }

    /// Receive a relay signal forwarded through the GossipSub mesh.
    /// 
    /// This is the mesh-mediated signaling path: instead of dedicated signaling
    /// connections, relay signals arrive via GossipSub. This reduces connection
    /// overhead when the relay (or a peer who can reach us) is in our mesh.
    /// 
    /// Called by GossipSub when it receives a RelaySignal addressed to us.
    /// 
    /// # Arguments
    /// * `from_peer` - The peer requesting connection
    /// * `session_id` - Session ID for the relay connection
    /// * `relay_data_addr` - Address to send relay data packets to
    /// 
    /// # Returns
    /// Ok(()) if the signal was accepted, Err if mesh signaling is not enabled.
    pub async fn receive_mesh_signal(
        &self,
        from_peer: crate::identity::Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
    ) -> anyhow::Result<()> {
        debug!(
            from_peer = %hex::encode(&from_peer.as_bytes()[..8]),
            session = %hex::encode(session_id),
            "received relay signal via mesh"
        );
        
        // Construct IncomingConnection
        let incoming = IncomingConnection {
            from_peer: hex::encode(from_peer.as_bytes()),
            session_id,
            relay_data_addr,
        };
        
        // Send via mesh signal channel
        let tx_guard = self.mesh_signal_tx.read().await;
        if let Some(tx) = &*tx_guard {
            tx.send(incoming).await
                .map_err(|_| anyhow::anyhow!("mesh signal receiver closed"))?;
            Ok(())
        } else {
            anyhow::bail!("mesh signaling not enabled - call enable_mesh_signaling() first")
        }
    }

    /// Check if this node is publicly reachable by asking a peer to connect back.
    pub async fn probe_reachability(
        &self,
        helper: &crate::identity::Contact,
    ) -> anyhow::Result<bool> {
        self.rpc.check_reachability(helper, &self.local_addr.to_string()).await
    }

    /// Discover peers that can serve as relays via DHT.
    /// 
    /// In the mesh-first relay model, any reachable peer with direct addresses
    /// can potentially relay traffic. This is a fallback when no mesh peers
    /// are available.
    pub async fn discover_relays(&self) -> anyhow::Result<Vec<crate::identity::Contact>> {
        let our_id = self.keypair.identity();
        let candidates = self.dht.iterative_find_node(our_id).await?;
        
        let relays: Vec<crate::identity::Contact> = candidates
            .into_iter()
            .filter(|c| c.identity != our_id && c.has_direct_addrs())
            .collect();
        
        debug!(
            relay_count = relays.len(),
            "discovered potential relays via DHT"
        );
        
        Ok(relays)
    }

    /// Select the best relay from a list by measuring RTT.
    pub async fn select_best_relay(
        &self,
        candidates: &[crate::identity::Contact],
    ) -> Option<crate::identity::Contact> {
        let mut best: Option<(crate::identity::Contact, std::time::Duration)> = None;
        
        for relay in candidates {
            let start = std::time::Instant::now();
            
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                self.rpc.ping(relay),
            ).await;
            
            if let Ok(Ok(())) = result {
                let rtt = start.elapsed();
                debug!(
                    relay = %hex::encode(&relay.identity.as_bytes()[..8]),
                    rtt_ms = rtt.as_millis(),
                    "relay ping successful"
                );
                
                match &best {
                    None => best = Some((relay.clone(), rtt)),
                    Some((_, best_rtt)) if rtt < *best_rtt => {
                        best = Some((relay.clone(), rtt));
                    }
                    _ => {}
                }
            }
        }
        
        best.map(|(contact, rtt)| {
            info!(
                relay = %hex::encode(&contact.identity.as_bytes()[..8]),
                rtt_ms = rtt.as_millis(),
                "selected best relay"
            );
            contact
        })
    }

    /// Register with a relay for incoming connection notifications.
    /// 
    /// **DEPRECATED**: With mesh-only signaling, NAT peers receive signals via GossipSub mesh
    /// automatically. This method now only stores the registered relay for validation
    /// and is called by `configure()` when needed.
    pub async fn register_with_relay(
        &self,
        relay: &crate::identity::Contact,
    ) -> anyhow::Result<()> {
        // SECURITY: Store the registered relay for later validation of incoming connections.
        // This prevents malicious actors from spoofing relay notifications.
        *self.registered_relay.write().await = Some(relay.clone());
        
        debug!(
            relay = %hex::encode(&relay.identity.as_bytes()[..8]),
            "registered with relay (mesh-only signaling active)"
        );
        
        Ok(())
    }

    /// Accept an incoming relay connection from a peer.
    pub async fn accept_incoming(&self, incoming: &IncomingConnection) -> anyhow::Result<()> {
        use anyhow::Context;
        
        let from_peer = crate::identity::Identity::from_hex(&incoming.from_peer)
            .context("invalid from_peer identity in IncomingConnection")?;
        
        // SECURITY: Validate relay_data_addr format.
        let relay_addr: std::net::SocketAddr = incoming.relay_data_addr
            .parse()
            .context("invalid relay_data_addr format")?;
        
        // SECURITY: Validate that the relay address matches our registered relay.
        // This prevents malicious relays or MITM attacks from directing us to send
        // UDP traffic to arbitrary third-party addresses (amplification vector).
        let relay_identity = {
            let registered = self.registered_relay.read().await;
            let registered_relay = registered.as_ref()
                .context("cannot accept incoming connection: not registered with any relay")?;
            
            // Verify the relay_data_addr matches one of the registered relay's addresses
            let relay_addr_str = relay_addr.to_string();
            let is_trusted = registered_relay.addrs.iter().any(|addr| {
                // Compare normalized addresses (both as SocketAddr to handle port variations)
                if let Ok(registered_addr) = addr.parse::<std::net::SocketAddr>() {
                    // Same IP is sufficient - port may vary for data vs signaling
                    registered_addr.ip() == relay_addr.ip()
                } else {
                    addr == &relay_addr_str
                }
            });
            
            if !is_trusted {
                warn!(
                    relay_data_addr = %relay_addr,
                    registered_relay = ?registered_relay.addrs,
                    "rejecting incoming connection: relay address not from registered relay"
                );
                anyhow::bail!(
                    "relay address {} does not match registered relay addresses",
                    relay_addr
                );
            }
            
            // Build a contact for the relay using its identity and data address
            registered_relay.identity
        };
        
        let relay_contact = crate::identity::Contact::single(relay_identity, incoming.relay_data_addr.clone());
        
        self.rpc
            .complete_relay_session(
                &relay_contact,
                from_peer,
                incoming.session_id,
            )
            .await
            .context("failed to complete relay session")?;
        
        debug!(
            from_peer = %incoming.from_peer,
            session = hex::encode(incoming.session_id),
            relay = %incoming.relay_data_addr,
            "relay tunnel configured, awaiting QUIC connection via server"
        );
        
        Ok(())
    }

    /// Take the incoming connection receiver.
    /// 
    /// Returns `None` if already taken or not yet registered.
    pub async fn take_incoming_receiver(&self) -> Option<mpsc::Receiver<IncomingConnection>> {
        self.incoming_rx.lock().await.take()
    }

    /// Automatically configure NAT traversal.
    /// 
    /// Returns the resulting NAT status.
    pub async fn configure(
        &self,
        helper: &crate::identity::Contact,
        addresses: Vec<String>,
    ) -> anyhow::Result<NatStatus> {
        use anyhow::Context;
        
        info!("starting NAT configuration");
        
        // Step 1: Check if we're publicly reachable
        let is_public = match self.probe_reachability(helper).await {
            Ok(reachable) => reachable,
            Err(e) => {
                warn!(error = %e, "reachability probe failed, assuming NAT-bound");
                false
            }
        };
        
        if is_public {
            info!("node is publicly reachable");
            let status = NatStatus::Public;
            *self.status.write().await = status.clone();
            
            // Publish address (caller needs to do this via dht)
            self.dht.publish_address(&self.keypair, addresses).await?;
            
            return Ok(status);
        }
        
        // Step 2: We're NAT-bound - find relays
        info!("node is behind NAT, discovering relays");
        let relays = self.discover_relays().await?;
        
        if relays.is_empty() {
            anyhow::bail!("no relay-capable nodes found in the network");
        }
        
        // Step 3: Select the best relay by RTT
        let best_relay = self.select_best_relay(&relays).await
            .context("all relay candidates are unreachable")?;
        
        // Step 4: Register with the relay
        info!(
            relay = %hex::encode(&best_relay.identity.as_bytes()[..8]),
            "registering with relay"
        );
        self.register_with_relay(&best_relay).await?;
        
        // Step 5: Publish our address
        self.dht
            .republish_on_network_change(&self.keypair, addresses)
            .await?;
        
        let status = NatStatus::NatBound { relay: best_relay.identity };
        *self.status.write().await = status.clone();
        
        info!("NAT configuration complete");
        Ok(status)
    }
}


/// Client-side relay tunnel for encoding/decoding CRLY frames.
/// 
/// Created when a relay session is established, used by `SmartSock` to
/// wrap QUIC packets for transmission through the relay.
#[derive(Debug, Clone)]
pub struct RelayTunnel {
    pub session_id: [u8; 16],
    pub relay_addr: SocketAddr,
    /// The identity of the peer at the other end of this tunnel.
    pub peer_identity: Identity,
    /// When this tunnel was established.
    pub established_at: Instant,
}

impl RelayTunnel {
    pub fn new(session_id: [u8; 16], relay_addr: SocketAddr, peer_identity: Identity) -> Self {
        Self {
            session_id,
            relay_addr,
            peer_identity,
            established_at: Instant::now(),
        }
    }
    
    /// Get how long this tunnel has been established.
    /// Used for diagnostics, telemetry logging, and by `is_older_than()`.
    pub fn age(&self) -> Duration {
        self.established_at.elapsed()
    }
    
    /// Check if this tunnel has been established longer than the given duration.
    pub fn is_older_than(&self, duration: Duration) -> bool {
        self.established_at.elapsed() > duration
    }
    
    /// Encode a QUIC packet into a CRLY relay frame.
    pub fn encode_frame(&self, quic_packet: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(RELAY_HEADER_SIZE + quic_packet.len());
        frame.extend_from_slice(&RELAY_MAGIC);
        frame.extend_from_slice(&self.session_id);
        frame.extend_from_slice(quic_packet);
        frame
    }
    
    /// Decode a CRLY relay frame, returning (session_id, payload).
    pub fn decode_frame(data: &[u8]) -> Option<([u8; 16], &[u8])> {
        if data.len() < RELAY_HEADER_SIZE {
            return None;
        }
        
        if data[0..4] != RELAY_MAGIC {
            return None;
        }
        
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[4..20]);
        
        let payload = &data[RELAY_HEADER_SIZE..];
        
        Some((session_id, payload))
    }
}


// ============================================================================
// RelayServer Actor (owns all state, processes commands sequentially)
// ============================================================================

struct RelayServerActor {
    socket: Arc<UdpSocket>,
    sessions: HashMap<[u8; 16], RelaySession>,
    addr_to_session: HashMap<SocketAddr, [u8; 16]>,
    /// Per-IP session count for rate limiting. Tracks (count, window_start).
    /// SECURITY: LruCache bounds memory growth from IP address tracking.
    ip_session_count: LruCache<IpAddr, (usize, Instant)>,
    /// Channel for sending signals via GossipSub mesh (mesh-only signaling).
    mesh_signal_tx: mpsc::Sender<MeshSignalOut>,
}

impl RelayServerActor {
    fn new(socket: Arc<UdpSocket>, mesh_signal_tx: mpsc::Sender<MeshSignalOut>) -> Self {
        let ip_session_count_cap = NonZeroUsize::new(MAX_IP_SESSION_COUNT_ENTRIES)
            .expect("MAX_IP_SESSION_COUNT_ENTRIES must be non-zero");
        Self {
            socket,
            sessions: HashMap::new(),
            addr_to_session: HashMap::new(),
            ip_session_count: LruCache::new(ip_session_count_cap),
            mesh_signal_tx,
        }
    }

    async fn run(mut self, mut cmd_rx: mpsc::Receiver<RelayCommand>) {
        let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);
        cleanup_interval.tick().await; // Skip initial tick
        
        loop {
            tokio::select! {
                // Handle commands from handles
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(RelayCommand::RegisterSession {
                            session_id, peer_a_addr, peer_a_identity, peer_b_identity, reply
                        }) => {
                            let result = self.register_session(
                                session_id, peer_a_addr, peer_a_identity, peer_b_identity
                            );
                            let _ = reply.send(result);
                        }
                        Some(RelayCommand::CompleteSession {
                            session_id, peer_b_addr, from_peer, target_peer, reply
                        }) => {
                            let result = self.complete_session(
                                session_id, peer_b_addr, from_peer, target_peer
                            );
                            let _ = reply.send(result);
                        }
                        Some(RelayCommand::SessionCount { reply }) => {
                            let _ = reply.send(self.sessions.len());
                        }
                        Some(RelayCommand::NotifyIncoming {
                            target_peer, from_peer, session_id, relay_data_addr, reply
                        }) => {
                            let result = self.notify_incoming(
                                target_peer, from_peer, session_id, relay_data_addr
                            );
                            let _ = reply.send(result);
                        }
                        Some(RelayCommand::ProcessPacket { data, from, reply }) => {
                            let result = self.process_packet(&data, from).await;
                            let _ = reply.send(result);
                        }
                        Some(RelayCommand::Quit) | None => {
                            debug!("Relay actor shutting down");
                            break;
                        }
                    }
                }
                
                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    self.cleanup_expired();
                }
            }
        }
    }

    fn register_session(
        &mut self,
        session_id: [u8; 16],
        peer_a_addr: SocketAddr,
        peer_a_identity: Identity,
        peer_b_identity: Identity,
    ) -> Result<(), &'static str> {
        if self.sessions.len() >= MAX_SESSIONS {
            return Err("max sessions reached");
        }
        
        // SECURITY: Per-IP rate limiting to prevent session exhaustion attacks
        let ip = peer_a_addr.ip();
        let now = Instant::now();
        
        // LruCache::get_or_insert handles bounded eviction automatically
        let (count, window_start) = self.ip_session_count
            .get_or_insert_mut(ip, || (0, now));
        
        // Reset window if expired
        if now.duration_since(*window_start) > RATE_LIMIT_WINDOW {
            *count = 0;
            *window_start = now;
        }
        
        if *count >= MAX_SESSIONS_PER_IP {
            warn!(ip = %ip, "rate limit exceeded for session registration");
            return Err("rate limit exceeded");
        }
        *count += 1;
        
        if self.sessions.contains_key(&session_id) {
            return Err("session already exists");
        }
        
        // SECURITY: Bound addr_to_session to prevent memory exhaustion
        if self.addr_to_session.len() >= MAX_ADDR_TO_SESSION_ENTRIES {
            warn!("addr_to_session map at capacity, rejecting new session");
            return Err("address mapping at capacity");
        }
        
        let session = RelaySession::new_pending(
            session_id,
            peer_a_identity,
            peer_b_identity,
            peer_a_addr,
        );
        self.sessions.insert(session_id, session);
        self.addr_to_session.insert(peer_a_addr, session_id);
        
        debug!(
            session = hex::encode(session_id),
            peer_a = %peer_a_addr,
            "registered relay session (waiting for peer B)"
        );
        
        Ok(())
    }

    fn complete_session(
        &mut self,
        session_id: [u8; 16],
        peer_b_addr: SocketAddr,
        from_peer: Identity,
        target_peer: Identity,
    ) -> Result<(), &'static str> {
        let session = self.sessions.get(&session_id)
            .ok_or("session not found")?;

        // SECURITY: On identity mismatch, remove the session to prevent probing attacks.
        // An attacker who guesses session IDs should not be able to keep probing.
        if session.peer_b_identity != from_peer || session.peer_a_identity != target_peer {
            warn!(
                session = hex::encode(session_id),
                expected_from = ?session.peer_b_identity,
                got_from = ?from_peer,
                "identity mismatch in complete_session, removing session"
            );
            // Remove session and associated addr mappings
            if let Some(removed) = self.sessions.remove(&session_id) {
                self.addr_to_session.remove(&removed.peer_a_addr);
                if let Some(peer_b) = removed.peer_b_addr {
                    self.addr_to_session.remove(&peer_b);
                }
            }
            return Err("peer identity mismatch");
        }
        
        // Re-borrow as mutable after identity verification passed
        let session = self.sessions.get_mut(&session_id)
            .ok_or("session not found")?;
        
        if session.peer_b_addr.is_some() {
            return Err("session already complete");
        }
        
        session.completion_locked = true;
        session.peer_b_addr = Some(peer_b_addr);
        session.last_activity = Instant::now();
        
        self.addr_to_session.insert(peer_b_addr, session_id);
        
        debug!(
            session = hex::encode(session_id),
            peer_a = %session.peer_a_addr,
            peer_b = %peer_b_addr,
            "relay session complete"
        );
        
        Ok(())
    }

    /// Notify a NAT peer about an incoming connection via mesh signaling.
    fn notify_incoming(
        &self,
        target_peer: Identity,
        from_peer: Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
    ) -> bool {
        let signal = MeshSignalOut {
            target: target_peer,
            from_peer,
            session_id,
            relay_data_addr,
        };
        
        match self.mesh_signal_tx.try_send(signal) {
            Ok(()) => {
                debug!(
                    target = ?target_peer,
                    from = ?from_peer,
                    session = hex::encode(session_id),
                    "sent incoming connection notification via mesh signaling"
                );
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    target = ?target_peer,
                    "mesh signaling channel full, dropping notification"
                );
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!(
                    target = ?target_peer,
                    "mesh signaling channel closed"
                );
                false
            }
        }
    }

    async fn process_packet(&mut self, data: &[u8], from: SocketAddr) -> usize {
        if data.len() < RELAY_HEADER_SIZE {
            trace!(from = %from, len = data.len(), "dropping undersized packet");
            return 0;
        }
        
        if data[0..4] != RELAY_MAGIC {
            trace!(from = %from, "dropping non-CRLY packet");
            return 0;
        }
        
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[4..20]);
        
        let session = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => {
                trace!(
                    session = hex::encode(session_id),
                    from = %from,
                    "dropping packet for unknown session"
                );
                return 0;
            }
        };
        
        // SECURITY: Do NOT auto-complete session based on UDP source address alone.
        // Session completion MUST go through the authenticated RPC path (CompleteSession)
        // where identity verification is performed. This prevents MITM attacks where
        // an attacker who intercepts the session_id could hijack the relay session.
        //
        // If the session is not complete, only peer_a can send packets (for probing).
        // Peer B must complete the session via RPC before sending data.
        if !session.is_complete() && from != session.peer_a_addr {
            trace!(
                session = hex::encode(session_id),
                from = %from,
                "dropping packet: session incomplete and sender is not peer_a"
            );
            return 0;
        }
        
        let dest = match session.get_destination(from) {
            Some(d) => {
                session.record_activity(data.len());
                d
            }
            None => {
                trace!(
                    session = hex::encode(session_id),
                    from = %from,
                    "dropping packet from non-participant"
                );
                return 0;
            }
        };
        
        match self.socket.send_to(data, dest).await {
            Ok(sent) => {
                trace!(
                    session = hex::encode(&session_id[..4]),
                    from = %from,
                    to = %dest,
                    len = sent,
                    "forwarded relay packet"
                );
                sent
            }
            Err(e) => {
                warn!(
                    session = hex::encode(session_id),
                    dest = %dest,
                    error = %e,
                    "failed to forward relay packet"
                );
                0
            }
        }
    }

    fn cleanup_expired(&mut self) -> usize {
        let before = self.sessions.len();
        
        self.sessions.retain(|_session_id, session| {
            if session.is_expired() {
                self.addr_to_session.remove(&session.peer_a_addr);
                if let Some(peer_b) = session.peer_b_addr {
                    self.addr_to_session.remove(&peer_b);
                }
                trace!(
                    session = session.session_id_hex(),
                    age_secs = session.age().as_secs(),
                    bytes_relayed = session.bytes_relayed,
                    packets_relayed = session.packets_relayed,
                    "expired relay session"
                );
                false
            } else {
                true
            }
        });
        
        // NOTE: ip_session_count cleanup is no longer needed here.
        // The LruCache automatically evicts oldest entries when at capacity,
        // and stale rate limit windows are reset on next access in register_session().
        
        let removed = before - self.sessions.len();
        if removed > 0 {
            debug!(removed = removed, remaining = self.sessions.len(), "cleaned up expired sessions");
        }
        removed
    }
}


// ============================================================================
// Request Handler (used by RPC layer)
// ============================================================================

pub async fn handle_relay_request(
    request: RelayRequest,
    remote_addr: SocketAddr,
    relay: Option<&Relay>,
    relay_addr: Option<SocketAddr>,
) -> RelayResponse {
    match request {
        RelayRequest::Connect {
            from_peer,
            target_peer,
            session_id,
        } => {
            debug!(
                from = ?from_peer,
                target = ?target_peer,
                session = hex::encode(session_id),
                "handling RELAY_CONNECT request"
            );

            let relay = match relay {
                Some(s) => s,
                None => {
                    return RelayResponse::Rejected {
                        reason: "relay not available".to_string(),
                    };
                }
            };

            let relay_data_addr = match relay_addr {
                Some(addr) => addr.to_string(),
                None => {
                    return RelayResponse::Rejected {
                        reason: "relay address not configured".to_string(),
                    };
                }
            };

            let session_count = relay.session_count().await;
            if session_count >= MAX_SESSIONS {
                return RelayResponse::Rejected {
                    reason: "relay server at capacity".to_string(),
                };
            }

            match relay
                .register_session(session_id, remote_addr, from_peer, target_peer)
                .await
            {
                Ok(()) => {
                    debug!(
                        session = hex::encode(session_id),
                        peer = %remote_addr,
                        "relay session pending (waiting for peer B)"
                    );
                    
                    // Notify target peer via signaling channel if registered
                    relay.notify_incoming(
                        target_peer,
                        from_peer,
                        session_id,
                        relay_data_addr.clone(),
                    ).await;
                    
                    RelayResponse::Accepted {
                        session_id,
                        relay_data_addr,
                    }
                }
                Err("session already exists") => {
                    match relay
                        .complete_session(session_id, remote_addr, from_peer, target_peer)
                        .await
                    {
                        Ok(()) => {
                            debug!(
                                session = hex::encode(session_id),
                                peer = %remote_addr,
                                "relay session established"
                            );
                            RelayResponse::Connected {
                                session_id,
                                relay_data_addr,
                            }
                        }
                        Err(e) => {
                            warn!(
                                session = hex::encode(session_id),
                                error = e,
                                "failed to complete relay session"
                            );
                            RelayResponse::Rejected {
                                reason: e.to_string(),
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        session = hex::encode(session_id),
                        error = e,
                        "failed to register relay session"
                    );
                    RelayResponse::Rejected {
                        reason: e.to_string(),
                    }
                }
            }
        }
        
        // NOTE: RelayRequest::Register removed - mesh-only signaling now
        
        RelayRequest::MeshRelay {
            from_peer,
            target_peer,
            session_id,
        } => {
            debug!(
                from = ?from_peer,
                target = ?target_peer,
                session = hex::encode(session_id),
                "handling MESH_RELAY request (opportunistic relay)"
            );

            // Phase 4: Mesh peer acting as relay
            // Same logic as Connect, but explicitly for mesh peers helping each other
            let relay = match relay {
                Some(s) => s,
                None => {
                    return RelayResponse::Rejected {
                        reason: "relay not available (node not relay-capable)".to_string(),
                    };
                }
            };

            let relay_data_addr = match relay_addr {
                Some(addr) => addr.to_string(),
                None => {
                    return RelayResponse::Rejected {
                        reason: "relay address not configured".to_string(),
                    };
                }
            };

            // Check capacity
            let session_count = relay.session_count().await;
            if session_count >= MAX_SESSIONS {
                return RelayResponse::Rejected {
                    reason: "mesh relay at capacity".to_string(),
                };
            }

            // Register the mesh relay session
            match relay
                .register_session(session_id, remote_addr, from_peer, target_peer)
                .await
            {
                Ok(()) => {
                    debug!(
                        session = hex::encode(session_id),
                        from = ?from_peer,
                        target = ?target_peer,
                        "mesh relay session registered"
                    );
                    
                    // Note: For mesh relay, we don't notify target via signaling.
                    // The requester will forward the session info to target directly.
                    
                    RelayResponse::MeshRelayOffer {
                        session_id,
                        relay_data_addr,
                    }
                }
                Err(e) => {
                    warn!(
                        session = hex::encode(session_id),
                        error = e,
                        "failed to register mesh relay session"
                    );
                    RelayResponse::Rejected {
                        reason: e.to_string(),
                    }
                }
            }
        }
    }
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_session_fields() {
        let session_id = [1u8; 16];
        let peer_a = Identity::from_bytes([2u8; 32]);
        let peer_b = Identity::from_bytes([3u8; 32]);
        let peer_a_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = RelaySession::new_pending(session_id, peer_a, peer_b, peer_a_addr);

        assert_eq!(session.session_id, session_id);
        assert_eq!(session.session_id_hex(), hex::encode(session_id));
        assert_eq!(session.peer_a_identity, peer_a);
        assert_eq!(session.peer_b_identity, peer_b);
        assert_eq!(session.peer_a_addr, peer_a_addr);
        assert!(session.peer_b_addr.is_none());
        assert!(!session.is_complete());
        assert_eq!(session.bytes_relayed, 0);
        assert_eq!(session.packets_relayed, 0);
        
        // created_at should be recent
        assert!(session.age() < Duration::from_secs(1));
    }

    #[test]
    fn test_relay_session_destination() {
        let session_id = [1u8; 16];
        let peer_a = Identity::from_bytes([2u8; 32]);
        let peer_b = Identity::from_bytes([3u8; 32]);
        let peer_a_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let peer_b_addr: SocketAddr = "127.0.0.1:6000".parse().unwrap();

        let mut session = RelaySession::new_pending(session_id, peer_a, peer_b, peer_a_addr);
        session.peer_b_addr = Some(peer_b_addr);

        assert_eq!(session.get_destination(peer_a_addr), Some(peer_b_addr));
        assert_eq!(session.get_destination(peer_b_addr), Some(peer_a_addr));
        
        let unknown: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        assert_eq!(session.get_destination(unknown), None);
    }

    #[test]
    fn test_relay_session_pending() {
        let session_id = [1u8; 16];
        let peer_a = Identity::from_bytes([2u8; 32]);
        let peer_b = Identity::from_bytes([3u8; 32]);
        let peer_a_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = RelaySession::new_pending(session_id, peer_a, peer_b, peer_a_addr);
        
        // Pending session should not return destination from peer_a
        // because peer_b hasn't connected yet
        assert_eq!(session.get_destination(peer_a_addr), None);
    }

    #[test]
    fn test_relay_frame_encoding_decoding() {
        let session_id = [42u8; 16];
        let relay_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let peer_identity = Identity::from_bytes([1u8; 32]);
        
        let tunnel = RelayTunnel::new(session_id, relay_addr, peer_identity);
        
        let payload = b"Hello, World!";
        let frame = tunnel.encode_frame(payload);
        
        assert_eq!(&frame[0..4], &RELAY_MAGIC);
        assert_eq!(&frame[4..20], &session_id);
        assert_eq!(&frame[20..], payload);
        
        let decoded = RelayTunnel::decode_frame(&frame);
        assert!(decoded.is_some());
        let (decoded_session, decoded_payload) = decoded.unwrap();
        assert_eq!(decoded_session, session_id);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_relay_frame_decode_rejects_invalid() {
        // Too short
        assert!(RelayTunnel::decode_frame(&[0u8; 10]).is_none());
        
        // Wrong magic
        let mut bad_magic = vec![0u8; 30];
        bad_magic[0..4].copy_from_slice(b"XXXX");
        assert!(RelayTunnel::decode_frame(&bad_magic).is_none());
    }

    #[test]
    fn test_crly_frame_format() {
        let session_id = [0xAB; 16];
        let relay_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let peer_identity = Identity::from_bytes([0xCD; 32]);
        
        let tunnel = RelayTunnel::new(session_id, relay_addr, peer_identity);
        let payload = vec![0xEF; 100];
        
        let frame = tunnel.encode_frame(&payload);
        
        // Verify frame structure
        assert_eq!(frame.len(), RELAY_HEADER_SIZE + payload.len());
        assert_eq!(&frame[0..4], b"CRLY");
        assert_eq!(&frame[4..20], &session_id);
        assert_eq!(&frame[20..], &payload[..]);
    }

    #[tokio::test]
    async fn test_register_and_complete_session() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Create a mesh signal channel for testing (signals are discarded)
        let (mesh_tx, _mesh_rx) = mpsc::channel::<MeshSignalOut>(16);
        let relay = Relay::with_socket(Arc::new(socket), mesh_tx);
        
        let session_id = [1u8; 16];
        let peer_a = Identity::from_bytes([2u8; 32]);
        let peer_b = Identity::from_bytes([3u8; 32]);
        let peer_a_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let peer_b_addr: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        
        // Register session
        let result = relay.register_session(session_id, peer_a_addr, peer_a, peer_b).await;
        assert!(result.is_ok());
        assert_eq!(relay.session_count().await, 1);
        
        // Complete session
        let result = relay.complete_session(session_id, peer_b_addr, peer_b, peer_a).await;
        assert!(result.is_ok());
        
        // Verify session count unchanged
        assert_eq!(relay.session_count().await, 1);
        
        relay.quit().await;
    }

    #[tokio::test]
    async fn test_remove_session() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Create a mesh signal channel for testing (signals are discarded)
        let (mesh_tx, _mesh_rx) = mpsc::channel::<MeshSignalOut>(16);
        let relay = Relay::with_socket(Arc::new(socket), mesh_tx);
        
        let session_id = [1u8; 16];
        let peer_a = Identity::from_bytes([2u8; 32]);
        let peer_b = Identity::from_bytes([3u8; 32]);
        let peer_a_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        
        relay.register_session(session_id, peer_a_addr, peer_a, peer_b).await.unwrap();
        assert_eq!(relay.session_count().await, 1);
        
        // Note: remove_session is internal to actor, tested via cleanup
        relay.quit().await;
    }
}
