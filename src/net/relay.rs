//! UDP Relay Forwarder for SmartSock tunnels.
//!
//! This module implements a UDP packet forwarder that enables E2E encrypted
//! relay tunnels. When two peers cannot connect directly (due to NAT), they
//! both connect to a relay node which forwards encrypted packets between them.
//!
//! # Protocol
//!
//! Relay frames use the CRLY format: `[CRLY magic: 4][session_id: 16][payload: N]`
//!
//! The forwarder:
//! 1. Receives CRLY-framed UDP packets from peers
//! 2. Looks up session_id → (peer_a_addr, peer_b_addr) mapping
//! 3. Forwards the frame (unchanged) to the other peer
//!
//! # Security Model
//!
//! - The relay cannot decrypt the payload (true E2E encryption via QUIC)
//! - Session IDs are cryptographically random and verified during RPC setup
//! - Unknown session IDs are silently dropped (no error oracle)
//! - Session timeout prevents resource exhaustion

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::identity::Identity;

// =============================================================================
// Constants
// =============================================================================

/// Magic bytes for relay frames (must match SmartSock)
pub const RELAY_MAGIC: [u8; 4] = *b"CRLY";

/// Header size: magic (4) + session_id (16)
pub const RELAY_HEADER_SIZE: usize = 20;

/// Maximum frame size (MTU-safe)
pub const MAX_FRAME_SIZE: usize = 1500;

/// Maximum concurrent relay sessions
pub const MAX_SESSIONS: usize = 10_000;

/// Session timeout (no activity)
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// How often to run cleanup
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Timeout for direct connection attempts before falling back to relay.
pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// =============================================================================
// NAT Types & Detection
// =============================================================================

/// NAT type classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT - we have a public IP.
    None,
    /// Full cone NAT - any external host can send to the mapped address.
    FullCone,
    /// Restricted cone NAT - only hosts we've sent to can reply.
    RestrictedCone,
    /// Port restricted cone NAT - only (host, port) we've sent to can reply.
    PortRestrictedCone,
    /// Symmetric NAT - different mapping for each destination.
    Symmetric,
    /// Unknown - couldn't determine type.
    Unknown,
}

/// Result of STUN-based NAT type detection.
#[derive(Clone, Debug)]
pub struct NatReport {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// Our public address as seen by STUN server 1.
    pub mapped_addr_1: Option<SocketAddr>,
    /// Our public address as seen by STUN server 2 (for symmetric detection).
    pub mapped_addr_2: Option<SocketAddr>,
    /// Whether we appear to have a public IP.
    pub has_public_ip: bool,
    /// Whether UDP is blocked.
    pub udp_blocked: bool,
}

impl Default for NatReport {
    fn default() -> Self {
        Self {
            nat_type: NatType::Unknown,
            mapped_addr_1: None,
            mapped_addr_2: None,
            has_public_ip: false,
            udp_blocked: false,
        }
    }
}

/// Detect NAT type from STUN responses.
///
/// Compares mapped addresses from two STUN servers to classify the NAT.
pub fn detect_nat_type(
    mapped_1: Option<SocketAddr>,
    mapped_2: Option<SocketAddr>,
    local_addr: SocketAddr,
) -> NatReport {
    let mut report = NatReport::default();

    match (mapped_1, mapped_2) {
        (None, None) => {
            report.udp_blocked = true;
            report.nat_type = NatType::Unknown;
        }
        (Some(addr1), None) | (None, Some(addr1)) => {
            report.mapped_addr_1 = Some(addr1);
            if addr1.ip() == local_addr.ip() {
                report.has_public_ip = true;
                report.nat_type = NatType::None;
            } else {
                report.nat_type = NatType::Unknown;
            }
        }
        (Some(addr1), Some(addr2)) => {
            report.mapped_addr_1 = Some(addr1);
            report.mapped_addr_2 = Some(addr2);

            if addr1.ip() == local_addr.ip() {
                report.has_public_ip = true;
                report.nat_type = NatType::None;
            } else if addr1 == addr2 {
                report.nat_type = NatType::FullCone;
            } else {
                report.nat_type = NatType::Symmetric;
            }
        }
    }

    report
}

// =============================================================================
// Relay Info (for DHT publishing)
// =============================================================================

/// Information about a node's relay capabilities published to DHT.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayInfo {
    /// The relay node's peer ID.
    pub relay_peer: Identity,
    /// Addresses where the relay can be reached.
    pub relay_addrs: Vec<String>,
    /// Current load (0.0 - 1.0).
    pub load: f32,
    /// Whether this relay is currently accepting new sessions.
    pub accepting: bool,
    /// Observed RTT to this relay in milliseconds.
    #[serde(default)]
    pub rtt_ms: Option<f32>,
    /// Tiering level (0 = fastest tier).
    #[serde(default)]
    pub tier: Option<u8>,
}

impl RelayInfo {
    /// Calculate a score for relay selection (lower is better).
    pub fn selection_score(&self) -> f32 {
        let rtt_score = self.rtt_ms.unwrap_or(200.0);
        let load_penalty = self.load * 100.0;
        let tier_penalty = self.tier.map(|t| t as f32 * 20.0).unwrap_or(40.0);
        rtt_score + load_penalty + tier_penalty
    }

    /// Check if this relay has known latency metrics.
    pub fn has_latency_info(&self) -> bool {
        self.rtt_ms.is_some() || self.tier.is_some()
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Error indicating failure to obtain cryptographic random bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError {
    /// The underlying getrandom error code, if available.
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

/// Generate a cryptographically random session ID.
pub fn generate_session_id() -> Result<[u8; 16], CryptoError> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id)?;
    Ok(id)
}

// =============================================================================
// Session State
// =============================================================================

/// State of a relay session between two peers.
#[derive(Debug, Clone)]
pub struct RelaySession {
    /// Session ID
    pub session_id: [u8; 16],
    /// Address of peer A (initiator)
    pub peer_a_addr: SocketAddr,
    /// Address of peer B (responder)
    pub peer_b_addr: Option<SocketAddr>,
    /// When the session was created
    pub created_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Total bytes forwarded
    pub bytes_forwarded: u64,
    /// Total packets forwarded
    pub packets_forwarded: u64,
}

impl RelaySession {
    /// Create a new pending session (waiting for peer B).
    pub fn new_pending(session_id: [u8; 16], peer_a_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            peer_a_addr,
            peer_b_addr: None,
            created_at: now,
            last_activity: now,
            bytes_forwarded: 0,
            packets_forwarded: 0,
        }
    }

    /// Check if this session is complete (both peers connected).
    pub fn is_complete(&self) -> bool {
        self.peer_b_addr.is_some()
    }

    /// Check if this session has timed out.
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT
    }

    /// Get the destination address for a packet from the given source.
    /// Returns None if the source is not part of this session.
    pub fn get_destination(&self, from: SocketAddr) -> Option<SocketAddr> {
        if from == self.peer_a_addr {
            self.peer_b_addr
        } else if self.peer_b_addr == Some(from) {
            Some(self.peer_a_addr)
        } else {
            None
        }
    }

    /// Update last activity and increment counters.
    pub fn record_forward(&mut self, bytes: usize) {
        self.last_activity = Instant::now();
        self.bytes_forwarded += bytes as u64;
        self.packets_forwarded += 1;
    }
}

// =============================================================================
// Relay Forwarder
// =============================================================================

/// UDP relay forwarder for SmartSock tunnels.
///
/// Handles CRLY-framed packets and forwards them between peers.
#[derive(Debug)]
pub struct UdpRelayForwarder {
    /// The UDP socket for receiving and sending relay frames
    socket: Arc<UdpSocket>,
    /// Active sessions: session_id → RelaySession
    sessions: RwLock<HashMap<[u8; 16], RelaySession>>,
    /// Reverse lookup: peer_addr → session_id (for fast lookup)
    addr_to_session: RwLock<HashMap<SocketAddr, [u8; 16]>>,
}

impl UdpRelayForwarder {
    /// Create a new relay forwarder bound to the given address.
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        info!(addr = %socket.local_addr()?, "UDP relay forwarder started");
        
        Ok(Self {
            socket: Arc::new(socket),
            sessions: RwLock::new(HashMap::new()),
            addr_to_session: RwLock::new(HashMap::new()),
        })
    }

    /// Create a forwarder using an existing socket.
    pub fn with_socket(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            sessions: RwLock::new(HashMap::new()),
            addr_to_session: RwLock::new(HashMap::new()),
        }
    }

    /// Get the local address of the forwarder.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Register a new relay session.
    ///
    /// Called when a RelayConnect RPC establishes a session.
    /// The first peer's address is recorded; the second will be learned
    /// from the first CRLY frame they send.
    pub async fn register_session(
        &self,
        session_id: [u8; 16],
        peer_a_addr: SocketAddr,
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write().await;
        
        if sessions.len() >= MAX_SESSIONS {
            return Err("max sessions reached");
        }
        
        if sessions.contains_key(&session_id) {
            return Err("session already exists");
        }
        
        let session = RelaySession::new_pending(session_id, peer_a_addr);
        sessions.insert(session_id, session);
        
        // Add reverse lookup
        let mut addr_map = self.addr_to_session.write().await;
        addr_map.insert(peer_a_addr, session_id);
        
        debug!(
            session = hex::encode(session_id),
            peer_a = %peer_a_addr,
            "registered relay session (waiting for peer B)"
        );
        
        Ok(())
    }

    /// Complete a session by adding peer B's address.
    pub async fn complete_session(
        &self,
        session_id: [u8; 16],
        peer_b_addr: SocketAddr,
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write().await;
        
        let session = sessions.get_mut(&session_id)
            .ok_or("session not found")?;
        
        if session.peer_b_addr.is_some() {
            return Err("session already complete");
        }
        
        session.peer_b_addr = Some(peer_b_addr);
        session.last_activity = Instant::now();
        
        // Add reverse lookup for peer B
        let mut addr_map = self.addr_to_session.write().await;
        addr_map.insert(peer_b_addr, session_id);
        
        debug!(
            session = hex::encode(session_id),
            peer_a = %session.peer_a_addr,
            peer_b = %peer_b_addr,
            "relay session complete"
        );
        
        Ok(())
    }

    /// Remove a session.
    pub async fn remove_session(&self, session_id: &[u8; 16]) {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.remove(session_id) {
            let mut addr_map = self.addr_to_session.write().await;
            addr_map.remove(&session.peer_a_addr);
            if let Some(peer_b) = session.peer_b_addr {
                addr_map.remove(&peer_b);
            }
            
            debug!(
                session = hex::encode(session_id),
                packets = session.packets_forwarded,
                bytes = session.bytes_forwarded,
                "removed relay session"
            );
        }
    }

    /// Get session statistics.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Clean up expired sessions.
    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let mut addr_map = self.addr_to_session.write().await;
        
        let before = sessions.len();
        
        sessions.retain(|session_id, session| {
            if session.is_expired() {
                addr_map.remove(&session.peer_a_addr);
                if let Some(peer_b) = session.peer_b_addr {
                    addr_map.remove(&peer_b);
                }
                trace!(
                    session = hex::encode(session_id),
                    "expired relay session"
                );
                false
            } else {
                true
            }
        });
        
        let removed = before - sessions.len();
        if removed > 0 {
            debug!(removed = removed, remaining = sessions.len(), "cleaned up expired sessions");
        }
        removed
    }

    /// Process a single incoming packet.
    ///
    /// Returns the number of bytes forwarded (0 if dropped).
    async fn process_packet(&self, data: &[u8], from: SocketAddr) -> usize {
        // Must have at least header
        if data.len() < RELAY_HEADER_SIZE {
            trace!(from = %from, len = data.len(), "dropping undersized packet");
            return 0;
        }
        
        // Check magic
        if &data[0..4] != &RELAY_MAGIC {
            trace!(from = %from, "dropping non-CRLY packet");
            return 0;
        }
        
        // Extract session ID
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[4..20]);
        
        // Look up session and find destination
        let dest = {
            let mut sessions = self.sessions.write().await;
            
            let session = match sessions.get_mut(&session_id) {
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
            
            // If session is pending and this is from an unknown address,
            // this might be peer B's first packet - complete the session
            if !session.is_complete() && from != session.peer_a_addr {
                session.peer_b_addr = Some(from);
                
                // Add reverse lookup
                drop(sessions);
                let mut addr_map = self.addr_to_session.write().await;
                addr_map.insert(from, session_id);
                
                // Re-acquire to get destination
                let sessions = self.sessions.read().await;
                let session = sessions.get(&session_id).unwrap();
                session.get_destination(from)
            } else {
                let dest = session.get_destination(from);
                if dest.is_some() {
                    session.record_forward(data.len());
                }
                dest
            }
        };
        
        let dest = match dest {
            Some(d) => d,
            None => {
                trace!(
                    session = hex::encode(session_id),
                    from = %from,
                    "dropping packet from non-participant"
                );
                return 0;
            }
        };
        
        // Forward the entire frame unchanged
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

    /// Run the forwarder loop.
    ///
    /// This processes incoming packets and forwards them to their destinations.
    /// Runs until cancelled.
    pub async fn run(&self) {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);
        
        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from)) => {
                            self.process_packet(&buf[..len], from).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "relay socket recv error");
                        }
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_expired().await;
                }
            }
        }
    }

    /// Spawn the forwarder as a background task.
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    #[test]
    fn test_relay_session_pending() {
        let session_id = [0xAB; 16];
        let session = RelaySession::new_pending(session_id, test_addr(1000));
        
        assert!(!session.is_complete());
        assert_eq!(session.peer_a_addr.port(), 1000);
        assert!(session.peer_b_addr.is_none());
    }

    #[test]
    fn test_relay_session_destination() {
        let session_id = [0xAB; 16];
        let mut session = RelaySession::new_pending(session_id, test_addr(1000));
        session.peer_b_addr = Some(test_addr(2000));
        
        assert!(session.is_complete());
        
        // Peer A sends → destination is peer B
        assert_eq!(session.get_destination(test_addr(1000)), Some(test_addr(2000)));
        
        // Peer B sends → destination is peer A
        assert_eq!(session.get_destination(test_addr(2000)), Some(test_addr(1000)));
        
        // Unknown sender → None
        assert_eq!(session.get_destination(test_addr(9999)), None);
    }

    #[tokio::test]
    async fn test_register_and_complete_session() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder = UdpRelayForwarder::with_socket(Arc::new(socket));
        
        let session_id = [0xCD; 16];
        let peer_a = test_addr(3000);
        let peer_b = test_addr(4000);
        
        // Register pending session
        forwarder.register_session(session_id, peer_a).await.unwrap();
        assert_eq!(forwarder.session_count().await, 1);
        
        // Complete session
        forwarder.complete_session(session_id, peer_b).await.unwrap();
        
        // Verify session is complete
        let sessions = forwarder.sessions.read().await;
        let session = sessions.get(&session_id).unwrap();
        assert!(session.is_complete());
        assert_eq!(session.peer_b_addr, Some(peer_b));
    }

    #[tokio::test]
    async fn test_remove_session() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder = UdpRelayForwarder::with_socket(Arc::new(socket));
        
        let session_id = [0xEF; 16];
        forwarder.register_session(session_id, test_addr(5000)).await.unwrap();
        assert_eq!(forwarder.session_count().await, 1);
        
        forwarder.remove_session(&session_id).await;
        assert_eq!(forwarder.session_count().await, 0);
    }

    #[test]
    fn test_crly_frame_format() {
        // Verify our constants match SmartSock
        assert_eq!(RELAY_MAGIC, *b"CRLY");
        assert_eq!(RELAY_HEADER_SIZE, 20);
    }
}
