//! SmartSock: Unified transport abstraction for seamless path switching.
//!
//! This module implements [`SmartSock`], which provides:
//!
//! - **Transparent path switching**: Relay↔direct without reconnection
//! - **True E2E encryption**: Relay cannot decrypt traffic
//! - **Fake address mapping**: Quinn sees stable addresses, we translate to real paths
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Quinn Endpoint                              │
//! │  Sees: SmartAddr (fd00:c0r1:um::<peer_id>)                     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                     SmartSock                                   │
//! │  Translates: SmartAddr ↔ Real transport (UDP or Relay tunnel)  │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  UDP Socket  │  Relay Tunnels (raw encrypted QUIC forwarding)  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Fake Address Scheme
//!
//! We use a Unique Local Address (ULA) range that will never conflict with real IPs:
//! - Prefix: `fd00:c0r1:um00::/48` (corium in hex-ish)
//! - Format: `fd00:c0r1:um00:PPPP:PPPP:PPPP:PPPP:PPPP` where P = peer_id bytes
//!
//! Quinn connects to these fake addresses; SmartSock translates to real paths.

use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use quinn::{AsyncUdpSocket, UdpPoller};
use quinn::udp::{RecvMeta, Transmit};
use tokio::sync::RwLock;

use crate::identity::Identity;

// =============================================================================
// Constants
// =============================================================================

/// Magic bytes for relay tunnel frames: "CRLY" (Corium ReLaY)
const RELAY_MAGIC: [u8; 4] = *b"CRLY";

/// Relay frame header size: magic (4) + session_id (16) = 20 bytes
const RELAY_HEADER_SIZE: usize = 20;

/// Maximum relay frame size (MTU-safe)
const MAX_RELAY_FRAME_SIZE: usize = 1400;

// -----------------------------------------------------------------------------
// Path Probing Constants
// -----------------------------------------------------------------------------

/// Magic bytes for path probe messages: "SMPR" (SmartSock PRobe)
const PROBE_MAGIC: [u8; 4] = *b"SMPR";

/// Probe message type: request
const PROBE_TYPE_REQUEST: u8 = 0x01;

/// Probe message type: response  
const PROBE_TYPE_RESPONSE: u8 = 0x02;

/// Probe header size: magic (4) + type (1) + tx_id (8) + timestamp (8) = 21 bytes
const PROBE_HEADER_SIZE: usize = 21;

/// Interval between path probes
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Timeout for considering a path stale
pub const PATH_STALE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum probe failures before marking path as failed
pub const MAX_PROBE_FAILURES: u32 = 3;

/// RTT threshold (ms) - relay must be this much faster to beat direct
const RELAY_RTT_ADVANTAGE_MS: f32 = 50.0;

/// EMA smoothing factor for RTT (weight of old value)
const RTT_EMA_OLD: f32 = 0.8;

/// EMA smoothing factor for RTT (weight of new sample)
const RTT_EMA_NEW: f32 = 0.2;

// =============================================================================
// RelayTunnel: Connection to a relay for forwarding packets
// =============================================================================

/// A tunnel through a relay for E2E encrypted packet forwarding.
///
/// The relay sees only:
/// - Session ID (16 bytes) - for routing to the other peer
/// - Opaque payload - the raw encrypted QUIC packet
///
/// This enables true E2E encryption: relay cannot decrypt the payload.
#[derive(Debug, Clone)]
pub struct RelayTunnel {
    /// Session ID for this tunnel (shared with peer via signaling)
    pub session_id: [u8; 16],
    /// Address of the relay server
    pub relay_addr: SocketAddr,
    /// The peer at the other end of the tunnel
    pub peer_identity: Identity,
    /// When this tunnel was established
    pub established_at: Instant,
    /// Last activity on this tunnel
    pub last_activity: Instant,
}

impl RelayTunnel {
    /// Create a new relay tunnel.
    pub fn new(session_id: [u8; 16], relay_addr: SocketAddr, peer_identity: Identity) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            relay_addr,
            peer_identity,
            established_at: now,
            last_activity: now,
        }
    }
    
    /// Encode a QUIC packet into a relay frame.
    ///
    /// Format: [CRLY magic: 4][session_id: 16][payload: N]
    pub fn encode_frame(&self, quic_packet: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(RELAY_HEADER_SIZE + quic_packet.len());
        frame.extend_from_slice(&RELAY_MAGIC);
        frame.extend_from_slice(&self.session_id);
        frame.extend_from_slice(quic_packet);
        frame
    }
    
    /// Decode a relay frame, returning the session_id and payload.
    ///
    /// Returns None if the frame is malformed or not a relay frame.
    pub fn decode_frame(data: &[u8]) -> Option<([u8; 16], &[u8])> {
        if data.len() < RELAY_HEADER_SIZE {
            return None;
        }
        
        // Check magic
        if data[0..4] != RELAY_MAGIC {
            return None;
        }
        
        // Extract session_id
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[4..20]);
        
        // Payload is the rest
        let payload = &data[RELAY_HEADER_SIZE..];
        
        Some((session_id, payload))
    }
}

// =============================================================================
// PathProbe: RTT measurement messages
// =============================================================================

/// A path probe request for RTT measurement.
///
/// Sent periodically to each candidate path to measure latency and detect
/// reachability. The peer echoes back the tx_id and timestamp in a PathProbeResponse.
#[derive(Debug, Clone)]
pub struct PathProbeRequest {
    /// Transaction ID to match response
    pub tx_id: u64,
    /// Timestamp when probe was sent (ms since epoch)
    pub timestamp_ms: u64,
}

impl PathProbeRequest {
    /// Create a new probe request with the given transaction ID.
    pub fn new(tx_id: u64) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self { tx_id, timestamp_ms }
    }
    
    /// Encode to wire format.
    ///
    /// Format: [SMPR magic: 4][type: 1][tx_id: 8][timestamp_ms: 8] = 21 bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROBE_HEADER_SIZE);
        buf.extend_from_slice(&PROBE_MAGIC);
        buf.push(PROBE_TYPE_REQUEST);
        buf.extend_from_slice(&self.tx_id.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf
    }
    
    /// Decode from wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < PROBE_HEADER_SIZE {
            return None;
        }
        if &data[0..4] != &PROBE_MAGIC || data[4] != PROBE_TYPE_REQUEST {
            return None;
        }
        Some(Self {
            tx_id: u64::from_le_bytes(data[5..13].try_into().ok()?),
            timestamp_ms: u64::from_le_bytes(data[13..21].try_into().ok()?),
        })
    }
    
    /// Check if data looks like a probe request (quick magic check).
    pub fn is_probe_request(data: &[u8]) -> bool {
        data.len() >= 5 && &data[0..4] == &PROBE_MAGIC && data[4] == PROBE_TYPE_REQUEST
    }
}

/// A path probe response echoing the request.
#[derive(Debug, Clone)]
pub struct PathProbeResponse {
    /// Transaction ID echoed from request
    pub tx_id: u64,
    /// Original timestamp echoed from request
    pub echo_timestamp_ms: u64,
    /// Observed source address of the probe sender
    pub observed_addr: SocketAddr,
}

impl PathProbeResponse {
    /// Create a response to a probe request.
    pub fn from_request(req: &PathProbeRequest, observed_addr: SocketAddr) -> Self {
        Self {
            tx_id: req.tx_id,
            echo_timestamp_ms: req.timestamp_ms,
            observed_addr,
        }
    }
    
    /// Encode to wire format.
    ///
    /// Format: [SMPR magic: 4][type: 1][tx_id: 8][timestamp_ms: 8][addr_type: 1][addr: 4 or 16][port: 2]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&PROBE_MAGIC);
        buf.push(PROBE_TYPE_RESPONSE);
        buf.extend_from_slice(&self.tx_id.to_le_bytes());
        buf.extend_from_slice(&self.echo_timestamp_ms.to_le_bytes());
        
        match self.observed_addr {
            SocketAddr::V4(addr) => {
                buf.push(4);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_le_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.push(6);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_le_bytes());
            }
        }
        buf
    }
    
    /// Decode from wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < PROBE_HEADER_SIZE + 1 {
            return None;
        }
        if &data[0..4] != &PROBE_MAGIC || data[4] != PROBE_TYPE_RESPONSE {
            return None;
        }
        
        let tx_id = u64::from_le_bytes(data[5..13].try_into().ok()?);
        let echo_timestamp_ms = u64::from_le_bytes(data[13..21].try_into().ok()?);
        
        let addr_type = data[21];
        let observed_addr = match addr_type {
            4 if data.len() >= 28 => {
                let ip = Ipv4Addr::new(data[22], data[23], data[24], data[25]);
                let port = u16::from_le_bytes(data[26..28].try_into().ok()?);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            6 if data.len() >= 40 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[22..38]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_le_bytes(data[38..40].try_into().ok()?);
                SocketAddr::new(IpAddr::V6(ip), port)
            }
            _ => return None,
        };
        
        Some(Self { tx_id, echo_timestamp_ms, observed_addr })
    }
    
    /// Check if data looks like a probe response (quick magic check).
    pub fn is_probe_response(data: &[u8]) -> bool {
        data.len() >= 5 && &data[0..4] == &PROBE_MAGIC && data[4] == PROBE_TYPE_RESPONSE
    }
    
    /// Calculate RTT in milliseconds from the echo timestamp.
    pub fn rtt_ms(&self) -> f32 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        (now_ms.saturating_sub(self.echo_timestamp_ms)) as f32
    }
}

// =============================================================================
// PathCandidateState: Per-path probing state
// =============================================================================

/// State of a path candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCandidateState {
    /// Not yet probed
    Unknown,
    /// Probe sent, waiting for response
    Probing,
    /// Received successful response
    Active,
    /// Too many failures
    Failed,
}

/// A candidate path to a peer with RTT tracking.
#[derive(Debug, Clone)]
pub struct PathCandidateInfo {
    /// Address of this path endpoint
    pub addr: SocketAddr,
    /// Whether this is a relay path
    pub is_relay: bool,
    /// For relay paths, the session ID
    pub session_id: Option<[u8; 16]>,
    /// Current state
    pub state: PathCandidateState,
    /// Smoothed RTT in milliseconds (EMA)
    pub rtt_ms: Option<f32>,
    /// Last successful probe time
    pub last_success: Option<Instant>,
    /// Last probe sent time
    pub last_probe: Option<Instant>,
    /// Consecutive failure count
    pub failures: u32,
    /// Current probe sequence number
    pub probe_seq: u64,
}

impl PathCandidateInfo {
    /// Create a new direct path candidate.
    pub fn new_direct(addr: SocketAddr) -> Self {
        Self {
            addr,
            is_relay: false,
            session_id: None,
            state: PathCandidateState::Unknown,
            rtt_ms: None,
            last_success: None,
            last_probe: None,
            failures: 0,
            probe_seq: 0,
        }
    }
    
    /// Create a new relay path candidate.
    pub fn new_relay(relay_addr: SocketAddr, session_id: [u8; 16]) -> Self {
        Self {
            addr: relay_addr,
            is_relay: true,
            session_id: Some(session_id),
            state: PathCandidateState::Unknown,
            rtt_ms: None,
            last_success: None,
            last_probe: None,
            failures: 0,
            probe_seq: 0,
        }
    }
    
    /// Check if this path needs a probe.
    pub fn needs_probe(&self) -> bool {
        match self.state {
            PathCandidateState::Failed => false,
            PathCandidateState::Unknown => true,
            PathCandidateState::Probing | PathCandidateState::Active => {
                self.last_probe
                    .map(|t| t.elapsed() >= PATH_PROBE_INTERVAL)
                    .unwrap_or(true)
            }
        }
    }
    
    /// Check if this path is usable for sending.
    pub fn is_usable(&self) -> bool {
        matches!(self.state, PathCandidateState::Active | PathCandidateState::Probing)
            && self.last_success
                .map(|t| t.elapsed() < PATH_STALE_TIMEOUT)
                .unwrap_or(false)
    }
    
    /// Record a successful probe response.
    pub fn record_success(&mut self, rtt: Duration) {
        let rtt_sample = rtt.as_secs_f32() * 1000.0;
        self.rtt_ms = Some(match self.rtt_ms {
            Some(prev) => prev * RTT_EMA_OLD + rtt_sample * RTT_EMA_NEW,
            None => rtt_sample,
        });
        self.state = PathCandidateState::Active;
        self.last_success = Some(Instant::now());
        self.failures = 0;
    }
    
    /// Record a probe failure.
    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= MAX_PROBE_FAILURES {
            self.state = PathCandidateState::Failed;
        }
    }
    
    /// Mark that a probe was sent.
    pub fn mark_probed(&mut self) {
        self.last_probe = Some(Instant::now());
        self.probe_seq = self.probe_seq.wrapping_add(1);
        if self.state == PathCandidateState::Unknown {
            self.state = PathCandidateState::Probing;
        }
    }
}

// =============================================================================
// SmartAddr: Fake IPv6 address mapped to peer identity
// =============================================================================

/// Fake IPv6 address that Quinn sees, mapped to a real peer identity.
///
/// Uses ULA prefix `fd00:c0r1:um00::/48` to avoid conflicts with real addresses.
/// The peer's 32-byte identity is hashed to fit in the remaining 80 bits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmartAddr(SocketAddr);

impl SmartAddr {
    /// ULA prefix for SmartSock addresses: fd00:c0r1:um00::/48
    const PREFIX: [u8; 6] = [0xfd, 0x00, 0xc0, 0xf1, 0x00, 0x00];
    
    /// Default port for SmartAddr (arbitrary, not used for routing)
    const DEFAULT_PORT: u16 = 1;

    /// Create a SmartAddr from a peer identity.
    ///
    /// The identity is hashed to create a unique IPv6 address in our ULA range.
    pub fn from_identity(identity: &Identity) -> Self {
        let hash = blake3::hash(identity.as_bytes());
        let hash_bytes = hash.as_bytes();
        
        // Build IPv6: fd00:c0r1:um00:HHHH:HHHH:HHHH:HHHH:HHHH
        let mut octets = [0u8; 16];
        octets[..6].copy_from_slice(&Self::PREFIX);
        octets[6..16].copy_from_slice(&hash_bytes[..10]);
        
        let ipv6 = Ipv6Addr::from(octets);
        Self(SocketAddr::new(IpAddr::V6(ipv6), Self::DEFAULT_PORT))
    }
    
    /// Check if a SocketAddr is a SmartAddr (in our ULA range).
    pub fn is_smart_addr(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                octets[..6] == Self::PREFIX
            }
            IpAddr::V4(_) => false,
        }
    }
    
    /// Get the underlying SocketAddr.
    pub fn socket_addr(&self) -> SocketAddr {
        self.0
    }
}

impl Debug for SmartAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SmartAddr({})", self.0)
    }
}

impl From<SmartAddr> for SocketAddr {
    fn from(addr: SmartAddr) -> Self {
        addr.0
    }
}

// =============================================================================
// PathChoice: Which transport to use for a peer
// =============================================================================

/// The chosen path to reach a peer.
#[derive(Debug, Clone)]
pub enum PathChoice {
    /// Direct UDP to peer's address
    Direct { addr: SocketAddr, rtt_ms: f32 },
    /// Via relay tunnel (relay forwards raw QUIC packets)
    Relay { 
        relay_addr: SocketAddr, 
        session_id: [u8; 16],
        rtt_ms: f32,
    },
}

/// Per-peer path state with RTT tracking.
#[derive(Debug)]
pub struct PeerPathState {
    /// The peer's identity
    pub identity: Identity,
    /// Known direct addresses for this peer
    pub direct_addrs: Vec<SocketAddr>,
    /// Active relay tunnels for this peer (session_id -> RelayTunnel)
    pub relay_tunnels: HashMap<[u8; 16], RelayTunnel>,
    /// Currently selected best path
    pub active_path: Option<PathChoice>,
    /// Last successful send time
    pub last_send: Option<Instant>,
    /// Last successful receive time  
    pub last_recv: Option<Instant>,
    /// Path candidates with probe state (addr -> PathCandidateInfo)
    pub candidates: HashMap<SocketAddr, PathCandidateInfo>,
    /// Pending probes awaiting response (tx_id -> (addr, sent_at))
    pub pending_probes: HashMap<u64, (SocketAddr, Instant)>,
    /// Next probe transaction ID
    pub next_probe_id: u64,
}

impl PeerPathState {
    pub fn new(identity: Identity) -> Self {
        // Generate a random starting probe ID to prevent prediction
        let mut id_bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut id_bytes);
        let next_probe_id = u64::from_le_bytes(id_bytes);
        
        Self {
            identity,
            direct_addrs: Vec::new(),
            relay_tunnels: HashMap::new(),
            active_path: None,
            last_send: None,
            last_recv: None,
            candidates: HashMap::new(),
            pending_probes: HashMap::new(),
            next_probe_id,
        }
    }
    
    /// Get the best address to send to, or None if no path is known.
    pub fn best_addr(&self) -> Option<SocketAddr> {
        match &self.active_path {
            Some(PathChoice::Direct { addr, .. }) => Some(*addr),
            Some(PathChoice::Relay { relay_addr, .. }) => Some(*relay_addr),
            None => {
                // Fallback: try first direct, then first relay tunnel
                self.direct_addrs.first().copied()
                    .or_else(|| self.relay_tunnels.values().next().map(|t| t.relay_addr))
            }
        }
    }
    
    /// Get the active relay tunnel, if using relay path.
    pub fn active_tunnel(&self) -> Option<&RelayTunnel> {
        match &self.active_path {
            Some(PathChoice::Relay { session_id, .. }) => {
                self.relay_tunnels.get(session_id)
            }
            _ => None,
        }
    }
    
    /// Check if currently using a relay path.
    pub fn is_relayed(&self) -> bool {
        matches!(self.active_path, Some(PathChoice::Relay { .. }))
    }
    
    /// Add a direct path candidate.
    pub fn add_direct_candidate(&mut self, addr: SocketAddr) {
        if !self.candidates.contains_key(&addr) {
            self.candidates.insert(addr, PathCandidateInfo::new_direct(addr));
        }
        if !self.direct_addrs.contains(&addr) {
            self.direct_addrs.push(addr);
        }
    }
    
    /// Add a relay path candidate.
    pub fn add_relay_candidate(&mut self, relay_addr: SocketAddr, session_id: [u8; 16]) {
        if !self.candidates.contains_key(&relay_addr) {
            self.candidates.insert(relay_addr, PathCandidateInfo::new_relay(relay_addr, session_id));
        }
    }
    
    /// Get candidates that need probing.
    pub fn candidates_needing_probe(&self) -> Vec<SocketAddr> {
        self.candidates
            .iter()
            .filter(|(_, c)| c.needs_probe())
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    /// Generate a probe for a candidate, returning (tx_id, probe).
    pub fn generate_probe(&mut self, addr: SocketAddr) -> Option<(u64, PathProbeRequest)> {
        let candidate = self.candidates.get_mut(&addr)?;
        
        let tx_id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1);
        
        candidate.mark_probed();
        self.pending_probes.insert(tx_id, (addr, Instant::now()));
        
        Some((tx_id, PathProbeRequest::new(tx_id)))
    }
    
    /// Handle a probe response, updating RTT and path state.
    /// Returns true if the path state changed significantly (might trigger path switch).
    pub fn handle_probe_response(&mut self, tx_id: u64, rtt: Duration) -> bool {
        let (addr, _sent_at) = match self.pending_probes.remove(&tx_id) {
            Some(info) => info,
            None => return false,
        };
        
        let candidate = match self.candidates.get_mut(&addr) {
            Some(c) => c,
            None => return false,
        };
        
        let was_failed = candidate.state == PathCandidateState::Failed;
        candidate.record_success(rtt);
        
        tracing::debug!(
            peer = ?self.identity,
            addr = %addr,
            rtt_ms = ?candidate.rtt_ms,
            is_relay = candidate.is_relay,
            "probe response received"
        );
        
        // Return true if path became active from non-active state
        was_failed || candidate.state == PathCandidateState::Active
    }
    
    /// Expire old pending probes and record failures.
    pub fn expire_probes(&mut self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<_> = self.pending_probes
            .iter()
            .filter(|(_, (_, sent))| now.duration_since(*sent) > timeout)
            .map(|(tx_id, (addr, _))| (*tx_id, *addr))
            .collect();
        
        for (tx_id, addr) in expired {
            self.pending_probes.remove(&tx_id);
            if let Some(candidate) = self.candidates.get_mut(&addr) {
                candidate.record_failure();
            }
        }
    }
    
    /// Select the best path based on RTT and path type.
    /// Returns Some(new_choice) if a better path is available.
    pub fn select_best_path(&self) -> Option<PathChoice> {
        let usable: Vec<_> = self.candidates
            .iter()
            .filter(|(_, c)| c.is_usable())
            .collect();
        
        if usable.is_empty() {
            return None;
        }
        
        // Find best direct path
        let best_direct = usable.iter()
            .filter(|(_, c)| !c.is_relay)
            .min_by(|(_, a), (_, b)| {
                a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal)
            });
        
        // Find best relay path
        let best_relay = usable.iter()
            .filter(|(_, c)| c.is_relay)
            .min_by(|(_, a), (_, b)| {
                a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal)
            });
        
        match (best_direct, best_relay) {
            (Some((_, direct)), Some((_, relay))) => {
                let direct_rtt = direct.rtt_ms.unwrap_or(f32::MAX);
                let relay_rtt = relay.rtt_ms.unwrap_or(f32::MAX);
                
                // Prefer direct unless relay is significantly faster
                if relay_rtt + RELAY_RTT_ADVANTAGE_MS < direct_rtt {
                    Some(PathChoice::Relay {
                        relay_addr: relay.addr,
                        session_id: relay.session_id.unwrap_or([0; 16]),
                        rtt_ms: relay_rtt,
                    })
                } else {
                    Some(PathChoice::Direct {
                        addr: direct.addr,
                        rtt_ms: direct_rtt,
                    })
                }
            }
            (Some((_, direct)), None) => {
                Some(PathChoice::Direct {
                    addr: direct.addr,
                    rtt_ms: direct.rtt_ms.unwrap_or(f32::MAX),
                })
            }
            (None, Some((_, relay))) => {
                Some(PathChoice::Relay {
                    relay_addr: relay.addr,
                    session_id: relay.session_id.unwrap_or([0; 16]),
                    rtt_ms: relay.rtt_ms.unwrap_or(f32::MAX),
                })
            }
            (None, None) => None,
        }
    }
    
    /// Check if we should switch to a better path.
    /// Returns Some(new_path) if switch is recommended.
    pub fn maybe_switch_path(&mut self) -> Option<PathChoice> {
        let best = self.select_best_path()?;
        
        let should_switch = match (&self.active_path, &best) {
            (None, _) => true,
            (Some(PathChoice::Relay { .. }), PathChoice::Direct { .. }) => {
                // Always prefer direct over relay
                true
            }
            (Some(PathChoice::Direct { rtt_ms: old_rtt, .. }), PathChoice::Direct { rtt_ms: new_rtt, .. }) => {
                // Switch direct paths if significantly better (10ms+)
                *new_rtt + 10.0 < *old_rtt
            }
            (Some(PathChoice::Direct { rtt_ms: direct_rtt, .. }), PathChoice::Relay { rtt_ms: relay_rtt, .. }) => {
                // Only switch from direct to relay if relay is much faster
                *relay_rtt + RELAY_RTT_ADVANTAGE_MS < *direct_rtt
            }
            (Some(PathChoice::Relay { rtt_ms: old_rtt, .. }), PathChoice::Relay { rtt_ms: new_rtt, .. }) => {
                // Switch relay paths if significantly better
                *new_rtt + 20.0 < *old_rtt
            }
        };
        
        if should_switch {
            tracing::info!(
                peer = ?self.identity,
                old_path = ?self.active_path,
                new_path = ?best,
                "switching to better path"
            );
            self.active_path = Some(best.clone());
            Some(best)
        } else {
            None
        }
    }
}

// =============================================================================
// SmartSock: The unified socket abstraction
// =============================================================================

/// Unified socket that presents fake addresses to Quinn and translates to real paths.
///
/// Implements [`quinn::AsyncUdpSocket`] to integrate transparently with Quinn's
/// endpoint. Quinn sees stable [`SmartAddr`] addresses; we translate sends/receives
/// to the best available path (direct UDP or relay tunnel).
///
/// # Thread Safety
///
/// SmartSock is `Send + Sync` and can be shared across tasks. Internal state
/// is protected by `RwLock`.
pub struct SmartSock {
    /// The underlying UDP socket for direct sends/receives
    inner: Arc<tokio::net::UdpSocket>,
    
    /// Mapping: SmartAddr → peer path state
    /// Used to translate outgoing packets to real destinations
    peers: RwLock<HashMap<SmartAddr, PeerPathState>>,
    
    /// Reverse mapping: real SocketAddr → SmartAddr
    /// Used to translate incoming packets to fake source addresses
    reverse_map: RwLock<HashMap<SocketAddr, SmartAddr>>,
    
    /// Our local SmartAddr (for incoming connection handling)
    local_addr: SocketAddr,
}

impl SmartSock {
    /// Create a new SmartSock bound to the given address.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        
        Ok(Self {
            inner: Arc::new(socket),
            peers: RwLock::new(HashMap::new()),
            reverse_map: RwLock::new(HashMap::new()),
            local_addr,
        })
    }
    
    /// Register a peer with their identity and known addresses.
    ///
    /// Returns the SmartAddr that Quinn should use for this peer.
    pub async fn register_peer(
        &self,
        identity: Identity,
        direct_addrs: Vec<SocketAddr>,
    ) -> SmartAddr {
        let smart_addr = SmartAddr::from_identity(&identity);
        
        let mut state = PeerPathState::new(identity);
        state.direct_addrs = direct_addrs.clone();
        
        // Set initial active path (prefer direct if available)
        if let Some(addr) = direct_addrs.first() {
            state.active_path = Some(PathChoice::Direct { 
                addr: *addr, 
                rtt_ms: f32::MAX, // Unknown RTT
            });
        }
        
        // Update mappings
        {
            let mut peers = self.peers.write().await;
            peers.insert(smart_addr, state);
        }
        
        {
            let mut reverse = self.reverse_map.write().await;
            for addr in direct_addrs {
                reverse.insert(addr, smart_addr);
            }
        }
        
        smart_addr
    }
    
    /// Add a relay tunnel for a peer.
    ///
    /// This establishes a tunnel through the specified relay for E2E encrypted
    /// packet forwarding to the peer.
    pub async fn add_relay_tunnel(
        &self,
        identity: &Identity,
        session_id: [u8; 16],
        relay_addr: SocketAddr,
    ) -> Option<SmartAddr> {
        let smart_addr = SmartAddr::from_identity(identity);
        
        let tunnel = RelayTunnel::new(session_id, relay_addr, *identity);
        
        let mut peers = self.peers.write().await;
        let state = peers.get_mut(&smart_addr)?;
        
        // Add tunnel to peer's state
        state.relay_tunnels.insert(session_id, tunnel);
        
        // Update reverse mapping so incoming relay frames can be translated
        drop(peers);
        {
            let mut reverse = self.reverse_map.write().await;
            reverse.insert(relay_addr, smart_addr);
        }
        
        tracing::debug!(
            peer = ?identity,
            session = hex::encode(session_id),
            relay = %relay_addr,
            "added relay tunnel for peer"
        );
        
        Some(smart_addr)
    }
    
    /// Remove a relay tunnel.
    pub async fn remove_relay_tunnel(
        &self,
        identity: &Identity,
        session_id: &[u8; 16],
    ) {
        let smart_addr = SmartAddr::from_identity(identity);
        
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            if let Some(tunnel) = state.relay_tunnels.remove(session_id) {
                // Remove from reverse map
                drop(peers);
                let mut reverse = self.reverse_map.write().await;
                reverse.remove(&tunnel.relay_addr);
                
                tracing::debug!(
                    peer = ?identity,
                    session = hex::encode(session_id),
                    "removed relay tunnel"
                );
            }
        }
    }
    
    /// Set the active path for a peer to use a relay tunnel.
    pub async fn use_relay_path(
        &self,
        identity: &Identity,
        session_id: [u8; 16],
    ) -> bool {
        let smart_addr = SmartAddr::from_identity(identity);
        
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            if let Some(tunnel) = state.relay_tunnels.get(&session_id) {
                state.active_path = Some(PathChoice::Relay {
                    relay_addr: tunnel.relay_addr,
                    session_id,
                    rtt_ms: f32::MAX, // Will be updated by path probing
                });
                tracing::debug!(
                    peer = ?identity,
                    session = hex::encode(session_id),
                    "switched to relay path"
                );
                return true;
            }
        }
        false
    }
    
    /// Set the active path for a peer to use direct UDP.
    pub async fn use_direct_path(
        &self,
        identity: &Identity,
        addr: SocketAddr,
    ) -> bool {
        let smart_addr = SmartAddr::from_identity(identity);
        
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            state.active_path = Some(PathChoice::Direct {
                addr,
                rtt_ms: f32::MAX,
            });
            tracing::debug!(
                peer = ?identity,
                addr = %addr,
                "switched to direct path"
            );
            return true;
        }
        false
    }
    
    /// Update the best path for a peer.
    pub async fn update_path(&self, identity: &Identity, path: PathChoice) {
        let smart_addr = SmartAddr::from_identity(identity);
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            tracing::debug!(
                peer = ?identity,
                path = ?path,
                "updating peer path"
            );
            state.active_path = Some(path);
        }
    }
    
    // =========================================================================
    // Path Probing Methods
    // =========================================================================
    
    /// Add a direct path candidate for a peer.
    pub async fn add_direct_candidate(&self, identity: &Identity, addr: SocketAddr) {
        let smart_addr = SmartAddr::from_identity(identity);
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            state.add_direct_candidate(addr);
        }
        drop(peers);
        
        // Update reverse mapping
        let mut reverse = self.reverse_map.write().await;
        reverse.insert(addr, smart_addr);
    }
    
    /// Add a relay path candidate for a peer.
    pub async fn add_relay_candidate(&self, identity: &Identity, relay_addr: SocketAddr, session_id: [u8; 16]) {
        let smart_addr = SmartAddr::from_identity(identity);
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            state.add_relay_candidate(relay_addr, session_id);
        }
    }
    
    /// Generate probes for all peers that need probing.
    /// Returns a list of (destination_addr, probe_bytes) to send.
    pub async fn generate_probes(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut probes = Vec::new();
        let mut peers = self.peers.write().await;
        
        for (_, state) in peers.iter_mut() {
            let addrs_to_probe = state.candidates_needing_probe();
            for addr in addrs_to_probe {
                if let Some((_, probe)) = state.generate_probe(addr) {
                    probes.push((addr, probe.to_bytes()));
                }
            }
        }
        
        probes
    }
    
    /// Send path probes to all peers that need probing.
    /// This should be called periodically (e.g., every 5 seconds).
    pub async fn probe_all_paths(&self) -> io::Result<usize> {
        let probes = self.generate_probes().await;
        let count = probes.len();
        
        for (addr, probe_bytes) in probes {
            // Send probe directly via UDP (not framed as relay)
            if let Err(e) = self.inner.send_to(&probe_bytes, addr).await {
                tracing::trace!(
                    addr = %addr,
                    error = %e,
                    "failed to send path probe"
                );
            }
        }
        
        Ok(count)
    }
    
    /// Handle an incoming probe request by generating a response.
    /// Returns the response bytes to send back to the sender.
    pub fn handle_probe_request(&self, data: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        let request = PathProbeRequest::from_bytes(data)?;
        let response = PathProbeResponse::from_request(&request, from);
        Some(response.to_bytes())
    }
    
    /// Handle an incoming probe response.
    /// Returns true if any path state changed.
    pub async fn handle_probe_response(&self, data: &[u8]) -> bool {
        let response = match PathProbeResponse::from_bytes(data) {
            Some(r) => r,
            None => return false,
        };
        
        let rtt = Duration::from_millis(response.rtt_ms() as u64);
        
        // Find the peer this probe belongs to and update state
        let mut peers = self.peers.write().await;
        for (_, state) in peers.iter_mut() {
            if state.handle_probe_response(response.tx_id, rtt) {
                // Check if we should switch paths
                state.maybe_switch_path();
                return true;
            }
        }
        
        false
    }
    
    /// Expire old probes and record failures.
    pub async fn expire_probes(&self) {
        let timeout = PATH_PROBE_INTERVAL * 2;
        let mut peers = self.peers.write().await;
        for (_, state) in peers.iter_mut() {
            state.expire_probes(timeout);
        }
    }
    
    /// Trigger path switching for all peers that have better paths available.
    pub async fn switch_to_best_paths(&self) {
        let mut peers = self.peers.write().await;
        for (_, state) in peers.iter_mut() {
            state.maybe_switch_path();
        }
    }
    
    /// Spawn a background task that periodically probes paths and switches as needed.
    pub fn spawn_probe_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let sock = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PATH_PROBE_INTERVAL);
            loop {
                interval.tick().await;
                
                // Expire old probes
                sock.expire_probes().await;
                
                // Send new probes
                match sock.probe_all_paths().await {
                    Ok(count) if count > 0 => {
                        tracing::trace!(probes_sent = count, "path probing tick");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "path probing error");
                    }
                    _ => {}
                }
                
                // Check for path switches
                sock.switch_to_best_paths().await;
            }
        })
    }

    /// Get the real address to send to for a SmartAddr.
    async fn resolve_destination(&self, smart_addr: &SmartAddr) -> Option<SocketAddr> {
        let peers = self.peers.read().await;
        peers.get(smart_addr).and_then(|state| state.best_addr())
    }
    
    /// Translate a real source address to its SmartAddr.
    async fn translate_source(&self, real_addr: SocketAddr) -> Option<SmartAddr> {
        let reverse = self.reverse_map.read().await;
        reverse.get(&real_addr).copied()
    }
    
    /// Get the inner UDP socket (for use by UdpPoller).
    pub fn inner_socket(&self) -> &Arc<tokio::net::UdpSocket> {
        &self.inner
    }
    
    /// Create a Quinn Endpoint using this SmartSock as the underlying transport.
    ///
    /// This is the key integration point: Quinn will see fake SmartAddrs while
    /// we translate to real transport paths underneath.
    ///
    /// # Arguments
    /// * `server_config` - QUIC server configuration (with TLS certs)
    ///
    /// # Returns
    /// A tuple of (Endpoint, Arc<SmartSock>) so the caller can both use the
    /// endpoint and register peers with the SmartSock.
    pub fn into_endpoint(
        self,
        server_config: quinn::ServerConfig,
    ) -> io::Result<(quinn::Endpoint, Arc<Self>)> {
        let smartsock = Arc::new(self);
        
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime found"))?;
        
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            smartsock.clone(),
            runtime,
        )?;
        
        Ok((endpoint, smartsock))
    }
    
    /// Bind and immediately create a Quinn Endpoint.
    ///
    /// Convenience method combining `bind()` and `into_endpoint()`.
    pub async fn bind_endpoint(
        addr: std::net::SocketAddr,
        server_config: quinn::ServerConfig,
    ) -> io::Result<(quinn::Endpoint, Arc<Self>)> {
        let smartsock = Self::bind(addr).await?;
        smartsock.into_endpoint(server_config)
    }
}

impl Debug for SmartSock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmartSock")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// SmartSockPoller: Writable notification for SmartSock
// =============================================================================

/// Poller for SmartSock write readiness.
struct SmartSockPoller {
    inner: Arc<tokio::net::UdpSocket>,
}

impl Debug for SmartSockPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmartSockPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for SmartSockPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.inner.poll_send_ready(cx)
    }
}

// =============================================================================
// AsyncUdpSocket implementation for SmartSock
// =============================================================================

impl AsyncUdpSocket for SmartSock {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SmartSockPoller {
            inner: self.inner.clone(),
        })
    }
    
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Check if destination is a SmartAddr
        if SmartAddr::is_smart_addr(&transmit.destination) {
            let smart_addr = SmartAddr(transmit.destination);
            
            // We need to resolve synchronously, but our mapping is async.
            // For now, we'll use try_read which doesn't block.
            let peers_guard = match self.peers.try_read() {
                Ok(guard) => guard,
                Err(_) => {
                    // Lock contention - signal WouldBlock to retry
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "peer map locked"
                    ));
                }
            };
            
            let state = match peers_guard.get(&smart_addr) {
                Some(s) => s,
                None => {
                    tracing::warn!(
                        dest = ?transmit.destination,
                        "no peer state for SmartAddr"
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "unknown peer"
                    ));
                }
            };
            
            // Check if using relay path and get tunnel info
            match &state.active_path {
                Some(PathChoice::Relay { relay_addr, session_id, .. }) => {
                    // Using relay - frame the packet
                    if let Some(tunnel) = state.relay_tunnels.get(session_id) {
                        let frame = tunnel.encode_frame(transmit.contents);
                        let relay_dest = *relay_addr;
                        drop(peers_guard);
                        
                        // Send framed packet to relay
                        if frame.len() > MAX_RELAY_FRAME_SIZE {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "relay frame too large"
                            ));
                        }
                        
                        self.inner.try_send_to(&frame, relay_dest)
                            .map(|_| ())
                    } else {
                        drop(peers_guard);
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "relay tunnel not found"
                        ))
                    }
                }
                Some(PathChoice::Direct { addr, .. }) => {
                    // Direct path - send raw
                    let dest = *addr;
                    drop(peers_guard);
                    self.inner.try_send_to(transmit.contents, dest)
                        .map(|_| ())
                }
                None => {
                    // No active path - try best_addr fallback
                    if let Some(addr) = state.best_addr() {
                        drop(peers_guard);
                        self.inner.try_send_to(transmit.contents, addr)
                            .map(|_| ())
                    } else {
                        drop(peers_guard);
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "no path to peer"
                        ))
                    }
                }
            }
        } else {
            // Regular address - send directly
            self.inner.try_send_to(transmit.contents, transmit.destination)
                .map(|_| ())
        }
    }
    
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty() && !meta.is_empty());
        
        let mut buf = [0u8; 65535];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        
        // Use poll_recv_from to get the source address
        match self.inner.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(src_addr)) => {
                let received = read_buf.filled();
                
                // Check if this is a path probe request (SMPR magic + type 0x01)
                if PathProbeRequest::is_probe_request(received) {
                    // Handle probe request: send response back
                    if let Some(response_bytes) = self.handle_probe_request(received, src_addr) {
                        // Send response back (best effort, don't block)
                        let _ = self.inner.try_send_to(&response_bytes, src_addr);
                    }
                    // Return Pending to get more data - probe requests are not for Quinn
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                
                // Check if this is a path probe response (SMPR magic + type 0x02)
                if PathProbeResponse::is_probe_response(received) {
                    // Handle probe response asynchronously
                    // We use try_write to avoid blocking - if it fails, we lose this probe
                    if let Some(response) = PathProbeResponse::from_bytes(received) {
                        let rtt = Duration::from_millis(response.rtt_ms() as u64);
                        if let Ok(mut peers) = self.peers.try_write() {
                            for (_, state) in peers.iter_mut() {
                                if state.handle_probe_response(response.tx_id, rtt) {
                                    state.maybe_switch_path();
                                    break;
                                }
                            }
                        }
                    }
                    // Return Pending to get more data - probe responses are not for Quinn
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                
                // Check if this is a relay frame (starts with CRLY magic)
                let (payload, translated_addr) = if let Some((session_id, payload)) = RelayTunnel::decode_frame(received) {
                    // Relay frame - look up which peer this session belongs to
                    let smart_addr = match self.reverse_map.try_read() {
                        Ok(guard) => {
                            // First check if we have a mapping for the relay address
                            guard.get(&src_addr).copied()
                        }
                        Err(_) => None,
                    };
                    
                    // If we found a smart_addr, verify the session_id matches
                    let verified_smart_addr = smart_addr.and_then(|sa| {
                        match self.peers.try_read() {
                            Ok(peers) => {
                                if let Some(state) = peers.get(&sa) {
                                    if state.relay_tunnels.contains_key(&session_id) {
                                        return Some(sa);
                                    }
                                }
                                None
                            }
                            Err(_) => Some(sa), // Fallback on contention
                        }
                    });
                    
                    let addr = verified_smart_addr
                        .map(|sa| sa.0)
                        .unwrap_or(src_addr);
                    
                    (payload, addr)
                } else {
                    // Direct packet - translate source if known
                    let translated = match self.reverse_map.try_read() {
                        Ok(guard) => guard.get(&src_addr).map(|sa| sa.0).unwrap_or(src_addr),
                        Err(_) => src_addr,
                    };
                    (received, translated)
                };
                
                // Copy payload to provided buffer
                let copy_len = payload.len().min(bufs[0].len());
                bufs[0][..copy_len].copy_from_slice(&payload[..copy_len]);
                
                meta[0] = RecvMeta {
                    addr: translated_addr,
                    len: copy_len,
                    stride: copy_len,
                    ecn: None,
                    dst_ip: None,
                };
                
                Poll::Ready(Ok(1))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
    
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    
    fn max_transmit_segments(&self) -> usize {
        // Single datagram for now, could add GSO support later
        1
    }
    
    fn max_receive_segments(&self) -> usize {
        // Single datagram for now, could add GRO support later
        1
    }
    
    fn may_fragment(&self) -> bool {
        // We don't set don't-fragment flags yet
        true
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_smart_addr_from_identity() {
        let identity = Identity::from([1u8; 32]);
        let addr = SmartAddr::from_identity(&identity);
        
        // Should be in our ULA range
        assert!(SmartAddr::is_smart_addr(&addr.socket_addr()));
        
        // Same identity should produce same address
        let addr2 = SmartAddr::from_identity(&identity);
        assert_eq!(addr.socket_addr(), addr2.socket_addr());
        
        // Different identity should produce different address
        let other = Identity::from([2u8; 32]);
        let addr3 = SmartAddr::from_identity(&other);
        assert_ne!(addr.socket_addr(), addr3.socket_addr());
    }
    
    #[test]
    fn test_smart_addr_detection() {
        let identity = Identity::from([1u8; 32]);
        let smart = SmartAddr::from_identity(&identity);
        
        assert!(SmartAddr::is_smart_addr(&smart.socket_addr()));
        
        // Regular addresses should not be detected as SmartAddr
        let regular_v4: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let regular_v6: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        
        assert!(!SmartAddr::is_smart_addr(&regular_v4));
        assert!(!SmartAddr::is_smart_addr(&regular_v6));
    }
    
    #[test]
    fn test_relay_frame_encoding_decoding() {
        let identity = Identity::from([42u8; 32]);
        let session_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let relay_addr: SocketAddr = "192.168.1.100:4433".parse().unwrap();
        
        let tunnel = RelayTunnel::new(session_id, relay_addr, identity);
        
        // Test encoding
        let payload = b"Hello, QUIC packet!";
        let frame = tunnel.encode_frame(payload);
        
        // Frame should have correct size
        assert_eq!(frame.len(), RELAY_HEADER_SIZE + payload.len());
        
        // Frame should start with CRLY magic
        assert_eq!(&frame[0..4], &RELAY_MAGIC);
        
        // Session ID should follow magic
        assert_eq!(&frame[4..20], &session_id);
        
        // Payload should be at the end
        assert_eq!(&frame[RELAY_HEADER_SIZE..], payload.as_slice());
        
        // Test decoding
        let decoded = RelayTunnel::decode_frame(&frame);
        assert!(decoded.is_some());
        
        let (decoded_session, decoded_payload) = decoded.unwrap();
        assert_eq!(decoded_session, session_id);
        assert_eq!(decoded_payload, payload.as_slice());
    }
    
    #[test]
    fn test_relay_frame_decode_rejects_invalid() {
        // Too short
        assert!(RelayTunnel::decode_frame(&[1, 2, 3]).is_none());
        
        // Wrong magic
        let mut bad_magic = [0u8; 30];
        bad_magic[0..4].copy_from_slice(b"NOPE");
        assert!(RelayTunnel::decode_frame(&bad_magic).is_none());
        
        // Empty frame
        assert!(RelayTunnel::decode_frame(&[]).is_none());
        
        // Exactly header size (no payload) should still work
        let mut header_only = [0u8; RELAY_HEADER_SIZE];
        header_only[0..4].copy_from_slice(&RELAY_MAGIC);
        let result = RelayTunnel::decode_frame(&header_only);
        assert!(result.is_some());
        let (_, payload) = result.unwrap();
        assert!(payload.is_empty());
    }
    
    #[test]
    fn test_path_choice_relay_includes_session_id() {
        let session_id = [0xAB; 16];
        let relay_addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        
        let path = PathChoice::Relay {
            relay_addr,
            session_id,
            rtt_ms: 50.0,
        };
        
        if let PathChoice::Relay { session_id: sid, relay_addr: addr, rtt_ms } = path {
            assert_eq!(sid, [0xAB; 16]);
            assert_eq!(addr.port(), 1234);
            assert_eq!(rtt_ms, 50.0);
        } else {
            panic!("Expected PathChoice::Relay");
        }
    }
    
    #[test]
    fn test_path_probe_request_encoding_decoding() {
        let probe = PathProbeRequest::new(12345);
        let bytes = probe.to_bytes();
        
        // Check magic and type
        assert_eq!(&bytes[0..4], &PROBE_MAGIC);
        assert_eq!(bytes[4], PROBE_TYPE_REQUEST);
        
        // Decode
        let decoded = PathProbeRequest::from_bytes(&bytes);
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.tx_id, 12345);
        assert_eq!(decoded.timestamp_ms, probe.timestamp_ms);
        
        // Check detection
        assert!(PathProbeRequest::is_probe_request(&bytes));
        assert!(!PathProbeResponse::is_probe_response(&bytes));
    }
    
    #[test]
    fn test_path_probe_response_encoding_decoding() {
        let request = PathProbeRequest::new(67890);
        let observed: SocketAddr = "192.168.1.1:4433".parse().unwrap();
        let response = PathProbeResponse::from_request(&request, observed);
        
        let bytes = response.to_bytes();
        
        // Check magic and type
        assert_eq!(&bytes[0..4], &PROBE_MAGIC);
        assert_eq!(bytes[4], PROBE_TYPE_RESPONSE);
        
        // Decode
        let decoded = PathProbeResponse::from_bytes(&bytes);
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.tx_id, 67890);
        assert_eq!(decoded.echo_timestamp_ms, request.timestamp_ms);
        assert_eq!(decoded.observed_addr, observed);
        
        // Check detection
        assert!(PathProbeResponse::is_probe_response(&bytes));
        assert!(!PathProbeRequest::is_probe_request(&bytes));
    }
    
    #[test]
    fn test_path_probe_response_ipv6() {
        let request = PathProbeRequest::new(99999);
        let observed: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let response = PathProbeResponse::from_request(&request, observed);
        
        let bytes = response.to_bytes();
        let decoded = PathProbeResponse::from_bytes(&bytes).unwrap();
        
        assert_eq!(decoded.observed_addr, observed);
    }
    
    #[test]
    fn test_path_candidate_state_machine() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut candidate = PathCandidateInfo::new_direct(addr);
        
        // Initial state
        assert_eq!(candidate.state, PathCandidateState::Unknown);
        assert!(candidate.needs_probe());
        assert!(!candidate.is_usable());
        
        // Mark probed
        candidate.mark_probed();
        assert_eq!(candidate.state, PathCandidateState::Probing);
        
        // Record success
        candidate.record_success(Duration::from_millis(50));
        assert_eq!(candidate.state, PathCandidateState::Active);
        assert!(candidate.is_usable());
        assert!(candidate.rtt_ms.is_some());
        
        // RTT should be around 50ms
        let rtt = candidate.rtt_ms.unwrap();
        assert!(rtt > 40.0 && rtt < 60.0);
        
        // EMA smoothing
        candidate.record_success(Duration::from_millis(100));
        let new_rtt = candidate.rtt_ms.unwrap();
        // Should be 0.8 * 50 + 0.2 * 100 = 60
        assert!(new_rtt > 55.0 && new_rtt < 65.0);
    }
    
    #[test]
    fn test_path_candidate_failure_handling() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut candidate = PathCandidateInfo::new_direct(addr);
        
        candidate.mark_probed();
        candidate.record_success(Duration::from_millis(50));
        
        // Record failures
        for _ in 0..MAX_PROBE_FAILURES {
            assert_ne!(candidate.state, PathCandidateState::Failed);
            candidate.record_failure();
        }
        
        assert_eq!(candidate.state, PathCandidateState::Failed);
        assert!(!candidate.needs_probe());
    }
    
    #[test]
    fn test_peer_path_state_best_path_selection() {
        let identity = Identity::from([1u8; 32]);
        let mut state = PeerPathState::new(identity);
        
        // Add candidates
        let direct1: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let direct2: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let relay: SocketAddr = "192.168.1.100:4433".parse().unwrap();
        
        state.add_direct_candidate(direct1);
        state.add_direct_candidate(direct2);
        state.add_relay_candidate(relay, [0xAB; 16]);
        
        // Make direct1 active with 50ms RTT
        state.candidates.get_mut(&direct1).unwrap().record_success(Duration::from_millis(50));
        
        // Make direct2 active with 30ms RTT (better)
        state.candidates.get_mut(&direct2).unwrap().record_success(Duration::from_millis(30));
        
        // Make relay active with 20ms RTT (best)
        state.candidates.get_mut(&relay).unwrap().record_success(Duration::from_millis(20));
        
        // Best path should be direct2 (30ms) since relay needs to be 50ms+ faster
        let best = state.select_best_path();
        assert!(best.is_some());
        let best = best.unwrap();
        
        // Direct should win since relay (20ms) is not 50ms+ faster than direct2 (30ms)
        match best {
            PathChoice::Direct { addr, .. } => assert_eq!(addr, direct2),
            _ => panic!("Expected direct path"),
        }
    }
    
    #[test]
    fn test_peer_path_state_relay_wins_when_much_faster() {
        let identity = Identity::from([2u8; 32]);
        let mut state = PeerPathState::new(identity);
        
        let direct: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let relay: SocketAddr = "192.168.1.100:4433".parse().unwrap();
        
        state.add_direct_candidate(direct);
        state.add_relay_candidate(relay, [0xCD; 16]);
        
        // Direct: 150ms RTT
        state.candidates.get_mut(&direct).unwrap().record_success(Duration::from_millis(150));
        
        // Relay: 50ms RTT (100ms faster - more than 50ms threshold)
        state.candidates.get_mut(&relay).unwrap().record_success(Duration::from_millis(50));
        
        let best = state.select_best_path();
        assert!(best.is_some());
        
        // Relay should win since it's 100ms faster (> 50ms threshold)
        match best.unwrap() {
            PathChoice::Relay { relay_addr, .. } => assert_eq!(relay_addr, relay),
            _ => panic!("Expected relay path"),
        }
    }
}
