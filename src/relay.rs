//! NAT traversal via STUN/TURN/ICE and relay nodes.
//!
//! This module implements comprehensive NAT traversal using:
//!
//! # ICE (Interactive Connectivity Establishment)
//!
//! ICE is the umbrella protocol that coordinates connectivity checks:
//! 1. **Candidate Gathering**: Collect all possible paths (host, srflx, relay)
//! 2. **Connectivity Checks**: Test each candidate pair with STUN binding
//! 3. **Candidate Selection**: Choose the best working path
//! 4. **Keepalives**: Maintain the selected path
//!
//! # STUN (Session Traversal Utilities for NAT)
//!
//! STUN provides address discovery and connectivity testing:
//! - **Binding Request**: Discover our public IP:port (server-reflexive address)
//! - **Binding Response**: Returns the observed source address
//! - **NAT Type Detection**: Compare responses from multiple servers
//!
//! # TURN (Traversal Using Relays around NAT)
//!
//! TURN provides relay fallback when direct paths fail:
//! - **Allocate**: Reserve a relay address on the TURN server
//! - **CreatePermission**: Allow specific peers to send through relay
//! - **ChannelBind**: Optimize relay path with channel numbers
//! - **Send/Data**: Relay packets through the allocated address
//!
//! # QuicMesh Integration
//!
//! QuicMesh uses ICE-lite with QUIC-native transport:
//! - STUN binding via `WhatIsMyAddr` DHT request
//! - TURN-style relay via `RelayServer`/`RelayClient`
//! - Path probing via `PathProber` for connectivity checks
//! - QUIC connection migration for seamless path switching
//!
//! # Design Principles
//!
//! - **ICE-lite**: Server role only (no full ICE state machine)
//! - **QUIC-native**: Uses QUIC's built-in encryption (no DTLS)
//! - **E2E encryption**: Relay sees only encrypted packets
//! - **DHT integration**: Uses sDHT for STUN/relay discovery

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, trace, warn};

use crate::identity::Identity;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum number of relay sessions a node will host.
pub const MAX_RELAY_SESSIONS: usize = 100;

/// Maximum permissions per TURN allocation.
/// Prevents resource exhaustion from excessive permission requests.
const MAX_PERMISSIONS_PER_ALLOCATION: usize = 64;

/// Maximum channel bindings per TURN allocation.
/// Prevents resource exhaustion from excessive channel bindings.
const MAX_CHANNELS_PER_ALLOCATION: usize = 32;

/// Maximum TURN allocations per server.
/// Prevents resource exhaustion from excessive allocations.
const MAX_TURN_ALLOCATIONS: usize = 1000;

/// How long a relay session can be idle before expiration.
pub const RELAY_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum packet size for relayed data.
pub const MAX_RELAY_PACKET_SIZE: usize = 1500;

/// Timeout for direct connection attempts before falling back to relay.
pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// Error Types
// ============================================================================

/// Error indicating failure to obtain cryptographic random bytes.
///
/// This error is critical for security-sensitive operations like session ID
/// generation. Callers should not fall back to weaker randomness sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError {
    /// The underlying getrandom error code, if available.
    pub code: Option<u32>,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(
                f,
                "CSPRNG unavailable (error code {}). \
                 Cryptographic random number generator required for secure operation.",
                code
            ),
            None => write!(
                f,
                "CSPRNG unavailable. \
                 Cryptographic random number generator required for secure operation."
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<getrandom::Error> for CryptoError {
    fn from(err: getrandom::Error) -> Self {
        Self {
            code: Some(err.code().get()),
        }
    }
}

/// STUN binding request timeout.
pub const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// ICE connectivity check interval.
pub const ICE_CHECK_INTERVAL: Duration = Duration::from_millis(50);

/// ICE keepalive interval for nominated pairs.
pub const ICE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// TURN allocation lifetime (must refresh before expiry).
pub const TURN_ALLOCATION_LIFETIME: Duration = Duration::from_secs(600);

// ============================================================================
// ICE Candidate Types
// ============================================================================

/// ICE candidate type per RFC 8445.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CandidateType {
    /// Host candidate: local interface address.
    Host,
    /// Server-reflexive candidate: public address from STUN.
    ServerReflexive,
    /// Peer-reflexive candidate: discovered during connectivity check.
    PeerReflexive,
    /// Relay candidate: allocated address on TURN server.
    Relay,
}

impl CandidateType {
    /// Get the priority type preference (higher is better).
    /// Per RFC 8445: host=126, srflx=100, prflx=110, relay=0
    pub fn type_preference(&self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::ServerReflexive => 100,
            CandidateType::PeerReflexive => 110,
            CandidateType::Relay => 0,
        }
    }
}

/// An ICE candidate representing a potential path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Unique identifier for this candidate.
    pub foundation: String,
    /// Component ID (1 for RTP, 2 for RTCP; we use 1 for QUIC).
    pub component: u8,
    /// Transport protocol.
    pub transport: TransportProtocol,
    /// Priority (higher is better).
    pub priority: u32,
    /// The address of this candidate.
    pub addr: SocketAddr,
    /// Type of candidate.
    pub candidate_type: CandidateType,
    /// Related address (base for srflx/prflx, relay for relay).
    pub related_addr: Option<SocketAddr>,
    /// For relay candidates: the relay server's Identity.
    pub relay_peer: Option<Identity>,
}

impl IceCandidate {
    /// Create a host candidate.
    pub fn host(addr: SocketAddr, component: u8) -> Self {
        let priority = Self::compute_priority(CandidateType::Host, 0, component);
        Self {
            foundation: format!("host-{}", addr),
            component,
            transport: TransportProtocol::Udp,
            priority,
            addr,
            candidate_type: CandidateType::Host,
            related_addr: None,
            relay_peer: None,
        }
    }

    /// Create a server-reflexive candidate from STUN response.
    pub fn server_reflexive(public_addr: SocketAddr, base_addr: SocketAddr, component: u8) -> Self {
        let priority = Self::compute_priority(CandidateType::ServerReflexive, 0, component);
        Self {
            foundation: format!("srflx-{}", public_addr),
            component,
            transport: TransportProtocol::Udp,
            priority,
            addr: public_addr,
            candidate_type: CandidateType::ServerReflexive,
            related_addr: Some(base_addr),
            relay_peer: None,
        }
    }

    /// Create a relay candidate from TURN allocation.
    pub fn relay(
        relay_addr: SocketAddr,
        base_addr: SocketAddr,
        relay_peer: Identity,
        component: u8,
    ) -> Self {
        let priority = Self::compute_priority(CandidateType::Relay, 0, component);
        Self {
            foundation: format!("relay-{}", relay_addr),
            component,
            transport: TransportProtocol::Udp,
            priority,
            addr: relay_addr,
            candidate_type: CandidateType::Relay,
            related_addr: Some(base_addr),
            relay_peer: Some(relay_peer),
        }
    }

    /// Compute candidate priority per RFC 8445.
    /// priority = (2^24) * type_preference + (2^8) * local_preference + (256 - component)
    pub fn compute_priority(candidate_type: CandidateType, local_preference: u32, component: u8) -> u32 {
        let type_pref = candidate_type.type_preference();
        let local_pref = local_preference.min(65535);
        let comp = (256 - component as u32).min(255);
        (type_pref << 24) + (local_pref << 8) + comp
    }
}

/// Transport protocol for ICE candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    /// UDP transport (standard for QUIC).
    Udp,
    /// TCP transport (fallback).
    Tcp,
}

// ============================================================================
// ICE Candidate Pair
// ============================================================================

/// State of an ICE candidate pair check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckState {
    /// Waiting to be checked.
    Waiting,
    /// Check is in progress.
    InProgress,
    /// Check succeeded.
    Succeeded,
    /// Check failed.
    Failed,
    /// This pair was nominated.
    Nominated,
}

/// A pair of local and remote candidates for connectivity checking.
#[derive(Clone, Debug)]
pub struct CandidatePair {
    /// Local candidate.
    pub local: IceCandidate,
    /// Remote candidate.
    pub remote: IceCandidate,
    /// Combined priority for pair ordering.
    pub priority: u64,
    /// Current check state.
    pub state: CheckState,
    /// Measured RTT if check succeeded.
    pub rtt_ms: Option<f32>,
    /// Number of check attempts.
    pub attempts: u32,
    /// Last check timestamp.
    pub last_check: Option<Instant>,
}

impl CandidatePair {
    /// Create a new candidate pair.
    pub fn new(local: IceCandidate, remote: IceCandidate, is_controlling: bool) -> Self {
        let priority = Self::compute_pair_priority(
            local.priority as u64,
            remote.priority as u64,
            is_controlling,
        );
        Self {
            local,
            remote,
            priority,
            state: CheckState::Waiting,
            rtt_ms: None,
            attempts: 0,
            last_check: None,
        }
    }

    /// Compute pair priority per RFC 8445.
    /// For controlling: 2^32 * MIN(G,D) + 2 * MAX(G,D) + 1
    /// For controlled:  2^32 * MIN(G,D) + 2 * MAX(G,D)
    fn compute_pair_priority(g: u64, d: u64, is_controlling: bool) -> u64 {
        let min = g.min(d);
        let max = g.max(d);
        let base = (min << 32) + (max << 1);
        if is_controlling { base + 1 } else { base }
    }
}

// ============================================================================
// STUN Messages (simplified, embedded in DHT protocol)
// ============================================================================

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
    /// Whether we're behind a firewall.
    pub behind_firewall: bool,
    /// Detected RTT to STUN server (ms).
    pub stun_rtt_ms: Option<f32>,
}

impl Default for NatReport {
    fn default() -> Self {
        Self {
            nat_type: NatType::Unknown,
            mapped_addr_1: None,
            mapped_addr_2: None,
            has_public_ip: false,
            udp_blocked: false,
            behind_firewall: false,
            stun_rtt_ms: None,
        }
    }
}

// ============================================================================
// TURN Allocation State
// ============================================================================

/// State of a TURN allocation.
#[derive(Clone, Debug)]
pub struct TurnAllocation {
    /// The relay server's Identity.
    pub relay_peer: Identity,
    /// Allocated relay address (where peers send to reach us).
    pub relay_addr: SocketAddr,
    /// Lifetime of the allocation.
    pub lifetime: Duration,
    /// When the allocation was created.
    pub created_at: Instant,
    /// When the allocation expires.
    pub expires_at: Instant,
    /// Permissions granted to remote peers.
    pub permissions: HashMap<SocketAddr, Instant>,
    /// Channel bindings for optimized forwarding.
    pub channels: HashMap<u16, SocketAddr>,
}

impl TurnAllocation {
    /// Create a new TURN allocation.
    pub fn new(relay_peer: Identity, relay_addr: SocketAddr, lifetime: Duration) -> Self {
        let now = Instant::now();
        Self {
            relay_peer,
            relay_addr,
            lifetime,
            created_at: now,
            expires_at: now + lifetime,
            permissions: HashMap::new(),
            channels: HashMap::new(),
        }
    }

    /// Check if the allocation is expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Refresh the allocation with a new lifetime.
    pub fn refresh(&mut self, lifetime: Duration) {
        self.lifetime = lifetime;
        self.expires_at = Instant::now() + lifetime;
    }

    /// Add a permission for a remote address.
    /// Returns false if the permission limit is reached.
    pub fn add_permission(&mut self, addr: SocketAddr) -> bool {
        // Clean expired permissions first
        let now = Instant::now();
        self.permissions.retain(|_, expires| *expires > now);
        
        // Check limit
        if self.permissions.len() >= MAX_PERMISSIONS_PER_ALLOCATION {
            return false;
        }
        
        self.permissions.insert(addr, Instant::now() + Duration::from_secs(300));
        true
    }

    /// Bind a channel number to a remote address.
    /// Returns false if the channel limit is reached.
    pub fn bind_channel(&mut self, channel: u16, addr: SocketAddr) -> bool {
        // Check limit (but allow replacing existing binding)
        if !self.channels.contains_key(&channel) 
            && self.channels.len() >= MAX_CHANNELS_PER_ALLOCATION 
        {
            return false;
        }
        
        self.channels.insert(channel, addr);
        true
    }
}

// ============================================================================
// ICE Agent
// ============================================================================

/// ICE agent role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceRole {
    /// Controlling agent (makes final decisions).
    Controlling,
    /// Controlled agent (follows controlling agent's decisions).
    Controlled,
}

/// ICE connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceState {
    /// Initial state, gathering candidates.
    New,
    /// Candidates gathered, checking connectivity.
    Checking,
    /// At least one candidate pair succeeded.
    Connected,
    /// All checks completed, best pair selected.
    Completed,
    /// All checks failed.
    Failed,
    /// ICE agent was closed.
    Closed,
}

/// ICE agent managing candidate gathering and connectivity checks.
#[derive(Debug)]
pub struct IceAgent {
    /// Our role in the ICE negotiation.
    role: IceRole,
    /// Current ICE state.
    state: IceState,
    /// Local candidates gathered.
    local_candidates: Vec<IceCandidate>,
    /// Remote candidates received.
    remote_candidates: Vec<IceCandidate>,
    /// Candidate pairs sorted by priority.
    check_list: Vec<CandidatePair>,
    /// The nominated pair (if any).
    nominated_pair: Option<usize>,
    /// TURN allocations.
    turn_allocations: HashMap<Identity, TurnAllocation>,
    /// NAT detection results.
    nat_report: NatReport,
}

impl IceAgent {
    /// Create a new ICE agent.
    pub fn new(role: IceRole) -> Self {
        Self {
            role,
            state: IceState::New,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            check_list: Vec::new(),
            nominated_pair: None,
            turn_allocations: HashMap::new(),
            nat_report: NatReport::default(),
        }
    }

    /// Add a local candidate.
    pub fn add_local_candidate(&mut self, candidate: IceCandidate) {
        self.local_candidates.push(candidate);
    }

    /// Add a remote candidate and form pairs.
    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        // Form pairs with all local candidates
        for local in &self.local_candidates {
            // Only pair compatible candidates (same component, transport)
            if local.component == candidate.component && local.transport == candidate.transport {
                let pair = CandidatePair::new(
                    local.clone(),
                    candidate.clone(),
                    self.role == IceRole::Controlling,
                );
                self.check_list.push(pair);
            }
        }
        self.remote_candidates.push(candidate);
        
        // Sort check list by priority (highest first)
        self.check_list.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Get the next pair to check.
    pub fn next_check(&mut self) -> Option<&mut CandidatePair> {
        self.check_list
            .iter_mut()
            .find(|p| p.state == CheckState::Waiting)
    }

    /// Mark a check as succeeded.
    pub fn check_succeeded(&mut self, pair_index: usize, rtt_ms: f32) {
        if let Some(pair) = self.check_list.get_mut(pair_index) {
            pair.state = CheckState::Succeeded;
            pair.rtt_ms = Some(rtt_ms);
            
            if self.state == IceState::Checking {
                self.state = IceState::Connected;
            }
        }
    }

    /// Mark a check as failed.
    pub fn check_failed(&mut self, pair_index: usize) {
        if let Some(pair) = self.check_list.get_mut(pair_index) {
            pair.state = CheckState::Failed;
        }
        
        // If all checks failed, transition to Failed state
        if self.check_list.iter().all(|p| p.state == CheckState::Failed) {
            self.state = IceState::Failed;
        }
    }

    /// Nominate the best succeeded pair.
    pub fn nominate_best(&mut self) -> Option<&CandidatePair> {
        // Find best succeeded pair by priority
        let best_idx = self.check_list
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == CheckState::Succeeded)
            .max_by_key(|(_, p)| p.priority)
            .map(|(i, _)| i);
        
        if let Some(idx) = best_idx {
            self.check_list[idx].state = CheckState::Nominated;
            self.nominated_pair = Some(idx);
            self.state = IceState::Completed;
            Some(&self.check_list[idx])
        } else {
            None
        }
    }

    /// Get the nominated pair.
    pub fn get_nominated(&self) -> Option<&CandidatePair> {
        self.nominated_pair.map(|i| &self.check_list[i])
    }

    /// Get current ICE state.
    pub fn state(&self) -> IceState {
        self.state
    }

    /// Start checking phase.
    pub fn start_checks(&mut self) {
        if !self.check_list.is_empty() {
            self.state = IceState::Checking;
        }
    }

    /// Add a TURN allocation.
    /// Returns false if the allocation limit is reached.
    pub fn add_turn_allocation(&mut self, allocation: TurnAllocation) -> bool {
        // Clean expired allocations first
        self.turn_allocations.retain(|_, a| !a.is_expired());
        
        // Check limit
        if self.turn_allocations.len() >= MAX_TURN_ALLOCATIONS {
            return false;
        }
        
        self.turn_allocations.insert(allocation.relay_peer, allocation);
        true
    }

    /// Get active TURN allocations.
    pub fn get_allocations(&self) -> &HashMap<Identity, TurnAllocation> {
        &self.turn_allocations
    }

    /// Set NAT report from STUN discovery.
    pub fn set_nat_report(&mut self, report: NatReport) {
        self.nat_report = report;
    }

    /// Get NAT report.
    pub fn nat_report(&self) -> &NatReport {
        &self.nat_report
    }
}

// ============================================================================
// ICE Candidate Gathering
// ============================================================================

/// Gather all local host candidates from system interfaces.
pub fn gather_host_candidates(local_addrs: &[SocketAddr], component: u8) -> Vec<IceCandidate> {
    local_addrs
        .iter()
        .map(|addr| IceCandidate::host(*addr, component))
        .collect()
}

/// Detect NAT type by comparing STUN responses from multiple servers.
///
/// Algorithm:
/// 1. Query two different STUN servers
/// 2. If responses show same public address → Cone NAT
/// 3. If responses show different ports → Symmetric NAT
/// 4. If no response → UDP blocked or behind firewall
pub fn detect_nat_type(
    mapped_addr_1: Option<SocketAddr>,
    mapped_addr_2: Option<SocketAddr>,
    local_addr: SocketAddr,
) -> NatReport {
    let mut report = NatReport::default();

    match (mapped_addr_1, mapped_addr_2) {
        (None, None) => {
            // No responses - UDP might be blocked
            report.nat_type = NatType::Unknown;
            report.udp_blocked = true;
        }
        (Some(addr1), None) | (None, Some(addr1)) => {
            // Only one response - might be firewall or partial UDP blocking
            report.mapped_addr_1 = Some(addr1);
            report.nat_type = NatType::Unknown;
            report.behind_firewall = true;
            report.has_public_ip = addr1.ip() == local_addr.ip();
        }
        (Some(addr1), Some(addr2)) => {
            report.mapped_addr_1 = Some(addr1);
            report.mapped_addr_2 = Some(addr2);
            report.has_public_ip = addr1.ip() == local_addr.ip();

            if addr1.ip() == local_addr.ip() && addr2.ip() == local_addr.ip() {
                // We have a public IP
                report.nat_type = NatType::None;
            } else if addr1 == addr2 {
                // Same mapping from both servers - likely Cone NAT
                // (Could be Full, Restricted, or Port-Restricted)
                report.nat_type = NatType::FullCone; // Assume best case
            } else if addr1.ip() == addr2.ip() && addr1.port() != addr2.port() {
                // Same IP but different ports - Symmetric NAT
                report.nat_type = NatType::Symmetric;
            } else {
                // Different IPs - unusual, but could be multi-homed NAT
                report.nat_type = NatType::Symmetric;
            }
        }
    }

    report
}

/// Determine best connection strategy using ICE-like candidate selection.
///
/// Priority order:
/// 1. Direct host-to-host (if both have public IPs)
/// 2. Direct via server-reflexive (hole punching possible)
/// 3. Relay via TURN
pub fn ice_connection_strategy(
    local_candidates: &[IceCandidate],
    remote_candidates: &[IceCandidate],
    nat_report: &NatReport,
) -> Vec<CandidatePair> {
    let mut pairs = Vec::new();

    // Form all valid pairs
    for local in local_candidates {
        for remote in remote_candidates {
            // Only pair compatible candidates
            if local.component == remote.component && local.transport == remote.transport {
                let pair = CandidatePair::new(local.clone(), remote.clone(), true);
                pairs.push(pair);
            }
        }
    }

    // Sort by priority (higher first)
    pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

    // For symmetric NAT, prioritize relay candidates
    if nat_report.nat_type == NatType::Symmetric {
        pairs.sort_by(|a, b| {
            let a_is_relay = a.local.candidate_type == CandidateType::Relay
                || a.remote.candidate_type == CandidateType::Relay;
            let b_is_relay = b.local.candidate_type == CandidateType::Relay
                || b.remote.candidate_type == CandidateType::Relay;
            
            // Put relay pairs first for symmetric NAT
            match (a_is_relay, b_is_relay) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b.priority.cmp(&a.priority),
            }
        });
    }

    pairs
}

// ============================================================================
// Relay Protocol Messages
// ============================================================================

/// Request to establish a relay session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayRequest {
    /// The peer we want to reach through the relay.
    pub target_peer: Identity,
    /// Our own peer ID for the relay to match connections.
    pub from_peer: Identity,
    /// Session ID to correlate the two halves of the relay.
    pub session_id: [u8; 16],
}

/// Response to a relay request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelayResponse {
    /// Relay accepted, waiting for peer to connect.
    Accepted {
        /// Session ID confirmed.
        session_id: [u8; 16],
    },
    /// Relay session established (both peers connected).
    Connected {
        /// Session ID.
        session_id: [u8; 16],
    },
    /// Relay rejected (at capacity or peer not found).
    Rejected {
        /// Reason for rejection.
        reason: String,
    },
}

/// A packet being relayed between peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayPacket {
    /// The sender's identity.
    pub from: Identity,
    /// Session ID for routing.
    pub session_id: [u8; 16],
    /// Encrypted payload (QUIC packet, opaque to relay).
    pub payload: Vec<u8>,
}

/// Notification of relay session state changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelayNotification {
    /// Peer connected to the relay session.
    PeerConnected { session_id: [u8; 16] },
    /// Session closed (peer disconnected or timeout).
    SessionClosed { session_id: [u8; 16], reason: String },
}

// ============================================================================
// Relay Info for DHT Publishing
// ============================================================================

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
    /// Observed RTT to this relay in milliseconds (from DHT tiering).
    /// None if we haven't measured RTT yet.
    #[serde(default)]
    pub rtt_ms: Option<f32>,
    /// Tiering level (0 = fastest tier).
    /// Used for latency-aware relay selection.
    #[serde(default)]
    pub tier: Option<u8>,
    /// Capabilities supported by this relay.
    #[serde(default)]
    pub capabilities: RelayCapabilities,
}

/// Capabilities supported by a relay server.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelayCapabilities {
    /// Supports STUN binding requests (WhatIsMyAddr).
    #[serde(default)]
    pub stun: bool,
    /// Supports TURN allocation (relay forwarding).
    #[serde(default)]
    pub turn: bool,
    /// Supports ICE-lite (connectivity checks).
    #[serde(default)]
    pub ice_lite: bool,
    /// Maximum bandwidth in Kbps (0 = unlimited).
    #[serde(default)]
    pub max_bandwidth_kbps: u32,
    /// Geographic region hint.
    #[serde(default)]
    pub region: Option<String>,
}

impl RelayInfo {
    /// Calculate a score for relay selection (lower is better).
    ///
    /// This combines:
    /// - RTT latency (weighted heavily - we want fast relays)
    /// - Load (prefer less loaded relays)
    /// - Tier level (prefer nodes in faster tiers)
    ///
    /// The formula prioritizes latency over load since relay overhead
    /// adds to every packet's round trip.
    pub fn selection_score(&self) -> f32 {
        // Base score from RTT (if known)
        let rtt_score = self.rtt_ms.unwrap_or(200.0); // Default to 200ms if unknown
        
        // Load penalty (0-100ms equivalent)
        let load_penalty = self.load * 100.0;
        
        // Tier penalty (20ms per tier level)
        let tier_penalty = self.tier.map(|t| t as f32 * 20.0).unwrap_or(40.0);
        
        rtt_score + load_penalty + tier_penalty
    }

    /// Check if this relay has known latency metrics.
    pub fn has_latency_info(&self) -> bool {
        self.rtt_ms.is_some() || self.tier.is_some()
    }
}

// ============================================================================
// Relay Session State
// ============================================================================

/// A pending relay session waiting for the second peer.
#[derive(Debug)]
pub struct PendingSession {
    /// The first peer that connected.
    pub initiator: Identity,
    /// The target peer we're waiting for.
    pub target: Identity,
    /// When this session was created.
    pub created_at: Instant,
    /// Channel to send packets to the initiator.
    pub initiator_tx: tokio::sync::mpsc::Sender<RelayPacket>,
}

/// An active relay session between two peers.
#[derive(Debug)]
pub struct ActiveSession {
    /// First peer (initiator).
    pub peer_a: Identity,
    /// Second peer (responder).
    pub peer_b: Identity,
    /// Channel to send packets to peer A.
    pub peer_a_tx: tokio::sync::mpsc::Sender<RelayPacket>,
    /// Channel to send packets to peer B.
    pub peer_b_tx: tokio::sync::mpsc::Sender<RelayPacket>,
    /// When this session was established.
    pub established_at: Instant,
    /// Last activity timestamp.
    pub last_activity: Instant,
}

// ============================================================================
// Forwarder Task Registry
// ============================================================================

/// Maximum number of concurrent forwarder tasks.
/// Prevents DoS via unbounded task spawning.
const MAX_FORWARDER_TASKS: usize = 200;

/// Tracks and limits relay forwarder task handles.
///
/// This prevents DoS attacks where an attacker spawns many relay sessions,
/// each creating a long-lived forwarder task that consumes resources.
///
/// # Security
///
/// - Limits total concurrent forwarder tasks to MAX_FORWARDER_TASKS
/// - Aborts tasks when sessions are explicitly closed
/// - Periodically cleans up completed tasks
pub struct ForwarderRegistry {
    /// Task handles by session ID.
    handles: RwLock<HashMap<[u8; 16], tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for ForwarderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwarderRegistry")
            .field("handles_count", &"<async>")
            .finish()
    }
}

impl Default for ForwarderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwarderRegistry {
    /// Create a new forwarder registry.
    pub fn new() -> Self {
        Self {
            handles: RwLock::new(HashMap::new()),
        }
    }

    /// Check if we can accept a new forwarder task.
    ///
    /// Returns false if we're at capacity, indicating the relay request
    /// should be rejected to prevent resource exhaustion.
    pub async fn can_accept(&self) -> bool {
        let handles = self.handles.read().await;
        handles.len() < MAX_FORWARDER_TASKS
    }

    /// Get the current number of active forwarder tasks.
    pub async fn active_count(&self) -> usize {
        let handles = self.handles.read().await;
        handles.len()
    }

    /// Register a forwarder task handle.
    ///
    /// Returns false if we're at capacity and the task was not registered.
    /// The caller should abort the task and reject the relay request.
    pub async fn register(&self, session_id: [u8; 16], handle: tokio::task::JoinHandle<()>) -> bool {
        let mut handles = self.handles.write().await;
        
        // Check capacity before inserting
        if handles.len() >= MAX_FORWARDER_TASKS {
            // Abort the task we were given since we can't track it
            handle.abort();
            return false;
        }
        
        // If there's an existing handle for this session, abort it first
        if let Some(old_handle) = handles.remove(&session_id) {
            old_handle.abort();
        }
        
        handles.insert(session_id, handle);
        true
    }

    /// Abort and remove a forwarder task for a session.
    ///
    /// Called when a session is explicitly closed. This ensures the
    /// forwarder task is terminated immediately rather than waiting
    /// for the timeout.
    pub async fn abort(&self, session_id: &[u8; 16]) {
        let mut handles = self.handles.write().await;
        if let Some(handle) = handles.remove(session_id) {
            handle.abort();
            trace!(
                session = hex::encode(session_id),
                "aborted forwarder task for closed session"
            );
        }
    }

    /// Clean up completed (finished or aborted) forwarder tasks.
    ///
    /// Should be called periodically to reclaim capacity from tasks
    /// that have naturally completed.
    pub async fn cleanup_completed(&self) {
        let mut handles = self.handles.write().await;
        let before = handles.len();
        
        // Retain only tasks that are still running
        handles.retain(|session_id, handle| {
            if handle.is_finished() {
                trace!(
                    session = hex::encode(session_id),
                    "cleaning up completed forwarder task"
                );
                false
            } else {
                true
            }
        });
        
        let removed = before - handles.len();
        if removed > 0 {
            debug!(
                removed = removed,
                remaining = handles.len(),
                "cleaned up completed forwarder tasks"
            );
        }
    }

    /// Abort all forwarder tasks.
    ///
    /// Used during shutdown or when the relay server is being stopped.
    pub async fn abort_all(&self) {
        let mut handles = self.handles.write().await;
        let count = handles.len();
        
        for (session_id, handle) in handles.drain() {
            handle.abort();
            trace!(
                session = hex::encode(session_id),
                "aborted forwarder task during shutdown"
            );
        }
        
        if count > 0 {
            info!(count = count, "aborted all forwarder tasks");
        }
    }
}

// ============================================================================
// Relay Server State
// ============================================================================

/// Manages relay sessions for this node.
///
/// When acting as a relay, this tracks pending and active sessions
/// and handles packet forwarding between peers.
///
/// # Security
///
/// The server implements multiple layers of session validation:
///
/// 1. **Session ID Tracking**: Only session IDs that were actually issued by
///    this server are accepted for forwarding. This prevents attackers from
///    injecting packets into sessions by guessing session IDs.
///
/// 2. **Participant Verification**: Only the two peers who established a
///    session can forward packets through it.
///
/// 3. **Forwarder Task Limiting**: A ForwarderRegistry limits the number of
///    concurrent forwarder tasks to prevent DoS attacks.
///
/// 4. **Optional HMAC Authentication**: Sessions can be verified using an
///    HMAC computed with a server-side secret, providing cryptographic
///    proof that the session was issued by this server.
#[derive(Debug)]
pub struct RelayServer {
    /// Pending sessions (waiting for second peer).
    pending: RwLock<HashMap<[u8; 16], PendingSession>>,
    /// Active sessions (both peers connected).
    active: RwLock<HashMap<[u8; 16], ActiveSession>>,
    /// Session IDs that were actually issued by this server.
    /// Provides defense against session ID guessing attacks.
    issued_sessions: RwLock<std::collections::HashSet<[u8; 16]>>,
    /// Server secret for computing session authentication tokens (HMAC).
    /// Generated randomly at server startup.
    server_secret: [u8; 32],
    /// Maximum concurrent sessions.
    max_sessions: usize,
    /// Metrics for load calculation.
    metrics: Mutex<RelayMetrics>,
    /// Registry of forwarder task handles.
    forwarder_registry: ForwarderRegistry,
}

#[derive(Debug, Default)]
struct RelayMetrics {
    total_sessions: u64,
    total_bytes_relayed: u64,
    active_count: usize,
}

impl RelayServer {
    /// Create a new relay server with default capacity.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if the system CSPRNG is unavailable. This is a
    /// security-critical requirement - running a relay server without proper
    /// randomness would allow session prediction attacks.
    pub fn new() -> Result<Self, CryptoError> {
        Self::with_capacity(MAX_RELAY_SESSIONS)
    }

    /// Create a new relay server with specified capacity.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if the system CSPRNG is unavailable. This is a
    /// security-critical requirement - running a relay server without proper
    /// randomness would allow session prediction attacks.
    pub fn with_capacity(max_sessions: usize) -> Result<Self, CryptoError> {
        // Generate server secret for session authentication
        let mut server_secret = [0u8; 32];
        getrandom::getrandom(&mut server_secret)?;
        
        Ok(Self {
            pending: RwLock::new(HashMap::new()),
            active: RwLock::new(HashMap::new()),
            issued_sessions: RwLock::new(std::collections::HashSet::new()),
            server_secret,
            max_sessions,
            metrics: Mutex::new(RelayMetrics::default()),
            forwarder_registry: ForwarderRegistry::new(),
        })
    }


    /// Check if a session ID was issued by this server.
    ///
    /// # Security
    ///
    /// This is the primary defense against session ID guessing attacks.
    /// An attacker cannot inject packets into a session without knowing
    /// a valid session ID that was actually issued by this server.
    pub async fn is_session_issued(&self, session_id: &[u8; 16]) -> bool {
        let issued = self.issued_sessions.read().await;
        issued.contains(session_id)
    }

    /// Compute an HMAC authentication token for a session.
    ///
    /// This can be used by peers to verify that a session was issued by
    /// this specific relay server. The token is computed as:
    /// `BLAKE3-MAC(server_secret, session_id || initiator || target)`
    ///
    /// # Security
    ///
    /// The authentication token provides cryptographic proof that:
    /// 1. The session was created by this relay server
    /// 2. The session is for the specified peer pair
    /// 3. The token cannot be forged without the server secret
    pub fn compute_session_token(
        &self,
        session_id: &[u8; 16],
        initiator: &Identity,
        target: &Identity,
    ) -> [u8; 32] {
        use blake3::Hasher;
        
        let mut hasher = Hasher::new_keyed(&self.server_secret);
        hasher.update(session_id);
        hasher.update(initiator.as_bytes());
        hasher.update(target.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verify a session authentication token.
    ///
    /// Returns true if the token is valid for the given session and peer pair.
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_session_token(
        &self,
        session_id: &[u8; 16],
        initiator: &Identity,
        target: &Identity,
        token: &[u8; 32],
    ) -> bool {
        let expected = self.compute_session_token(session_id, initiator, target);
        // Constant-time comparison to prevent timing attacks
        // XOR all bytes and accumulate - result is 0 only if all bytes match
        let mut diff: u8 = 0;
        for (a, b) in expected.iter().zip(token.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Get the forwarder registry for task management.
    ///
    /// Used by the connection handler to register forwarder task handles
    /// and check capacity before spawning new tasks.
    pub fn forwarder_registry(&self) -> &ForwarderRegistry {
        &self.forwarder_registry
    }

    /// Get current load factor (0.0 - 1.0).
    pub async fn load(&self) -> f32 {
        let active = self.active.read().await.len();
        let pending = self.pending.read().await.len();
        let total = active + pending;
        total as f32 / self.max_sessions as f32
    }

    /// Check if accepting new sessions.
    pub async fn is_accepting(&self) -> bool {
        self.load().await < 0.9
    }

    /// Handle a relay request from a peer.
    ///
    /// If this is the first peer for the session, creates a pending session.
    /// If the second peer connects, promotes to active and returns Connected.
    pub async fn handle_request(
        &self,
        request: RelayRequest,
        sender_tx: tokio::sync::mpsc::Sender<RelayPacket>,
    ) -> RelayResponse {
        // Check capacity
        if !self.is_accepting().await {
            return RelayResponse::Rejected {
                reason: "relay at capacity".to_string(),
            };
        }

        let session_id = request.session_id;

        // Check if this is the second peer connecting
        {
            let mut pending = self.pending.write().await;
            if let Some(pending_session) = pending.remove(&session_id) {
                // Verify this is the expected target
                if pending_session.target != request.from_peer {
                    // Wrong peer - put it back
                    pending.insert(session_id, pending_session);
                    // Security: Use opaque error message to prevent session enumeration
                    // Don't reveal that the session ID exists or that we're waiting for
                    // a different peer - this could help attackers probe for sessions
                    return RelayResponse::Rejected {
                        reason: "relay request failed".to_string(),
                    };
                }

                // Promote to active session
                let active_session = ActiveSession {
                    peer_a: pending_session.initiator,
                    peer_b: request.from_peer,
                    peer_a_tx: pending_session.initiator_tx,
                    peer_b_tx: sender_tx,
                    established_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                let mut active = self.active.write().await;
                active.insert(session_id, active_session);

                debug!(
                    session_id = hex::encode(session_id),
                    "relay session established"
                );

                let mut metrics = self.metrics.lock().await;
                metrics.total_sessions = metrics.total_sessions.saturating_add(1);
                metrics.active_count = active.len();

                return RelayResponse::Connected { session_id };
            }
        }

        // First peer - create pending session
        let pending_session = PendingSession {
            initiator: request.from_peer,
            target: request.target_peer,
            created_at: Instant::now(),
            initiator_tx: sender_tx,
        };

        let mut pending = self.pending.write().await;
        
        // Clean up expired pending sessions and collect their IDs
        // to also remove from issued_sessions (prevents unbounded growth)
        let now = Instant::now();
        let mut expired_ids: Vec<[u8; 16]> = Vec::new();
        pending.retain(|id, s| {
            let expired = now.duration_since(s.created_at) >= RELAY_SESSION_TIMEOUT;
            if expired {
                expired_ids.push(*id);
            }
            !expired
        });
        
        // Check pending session limit to prevent memory exhaustion
        // An attacker could create many pending sessions that never complete
        if pending.len() >= self.max_sessions {
            debug!(
                session_id = hex::encode(session_id),
                pending_count = pending.len(),
                "rejecting relay request: pending session limit reached"
            );
            // Clean up expired IDs from issued_sessions before returning
            if !expired_ids.is_empty() {
                let mut issued = self.issued_sessions.write().await;
                for id in &expired_ids {
                    issued.remove(id);
                }
            }
            return RelayResponse::Rejected {
                reason: "relay request failed".to_string(),
            };
        }
        
        // Remove expired session IDs from issued_sessions tracking
        // and add the new session ID atomically to prevent unbounded growth
        {
            let mut issued = self.issued_sessions.write().await;
            for id in &expired_ids {
                issued.remove(id);
            }
            // Track that this session ID was issued by this server
            // This enables rejection of forged/guessed session IDs later
            issued.insert(session_id);
        }
        
        pending.insert(session_id, pending_session);

        debug!(
            session_id = hex::encode(session_id),
            "relay session pending, waiting for peer"
        );

        RelayResponse::Accepted { session_id }
    }

    /// Forward a packet to the other peer in a session.
    ///
    /// # Security
    ///
    /// This method implements multiple security checks:
    ///
    /// 1. **Session Issuance Verification**: Verifies that the session ID was
    ///    actually issued by this server, preventing session ID guessing attacks.
    ///
    /// 2. **Participant Verification**: Only peers who established the session
    ///    can forward packets through it.
    ///
    /// 3. **Payload Size Limit**: Prevents memory exhaustion from large payloads.
    ///
    /// Error messages are intentionally opaque to prevent session enumeration.
    /// Attackers should not be able to distinguish between "session doesn't exist"
    /// and "you're not authorized for this session".
    pub async fn forward_packet(
        &self,
        from_peer: &Identity,
        packet: RelayPacket,
    ) -> Result<(), String> {
        if packet.payload.len() > MAX_RELAY_PACKET_SIZE {
            return Err("relay request failed".to_string());
        }

        // Security Check 1: Verify this session was issued by this server
        // This prevents attackers from guessing/brute-forcing session IDs
        if !self.is_session_issued(&packet.session_id).await {
            // Log for security monitoring - this indicates a potential attack
            debug!(
                session_id = hex::encode(packet.session_id),
                from = ?hex::encode(&from_peer.as_bytes()[..8]),
                "rejecting forward: session ID was not issued by this server"
            );
            return Err("relay request failed".to_string());
        }

        let mut active = self.active.write().await;
        let session = active
            .get_mut(&packet.session_id)
            // Security: Use opaque error to prevent session probing
            .ok_or_else(|| "relay request failed".to_string())?;

        // Update activity timestamp
        session.last_activity = Instant::now();

        // Determine which peer to forward to
        let target_tx = if &session.peer_a == from_peer {
            &session.peer_b_tx
        } else if &session.peer_b == from_peer {
            &session.peer_a_tx
        } else {
            // Security: Don't reveal that the session exists but sender isn't part of it
            return Err("relay request failed".to_string());
        };

        // Update metrics
        {
            let mut metrics = self.metrics.lock().await;
            metrics.total_bytes_relayed = metrics.total_bytes_relayed.saturating_add(packet.payload.len() as u64);
        }

        target_tx
            .send(packet)
            .await
            .map_err(|_| "peer disconnected".to_string())
    }

    /// Close a relay session.
    ///
    /// # Security
    ///
    /// Only participants in the session can close it. The `from_peer` parameter
    /// must be either peer_a or peer_b in the active session, or the initiator
    /// or target in a pending session.
    ///
    /// # Task Cleanup
    ///
    /// When a session is closed, the associated forwarder task is aborted
    /// immediately to free resources. This prevents resource exhaustion from
    /// accumulated tasks waiting for timeout.
    pub async fn close_session(&self, session_id: &[u8; 16], from_peer: &Identity, reason: &str) {
        // Check active sessions first
        let mut active = self.active.write().await;
        if let Some(session) = active.get(session_id) {
            // Verify the requester is a participant in this session
            if &session.peer_a != from_peer && &session.peer_b != from_peer {
                warn!(
                    session_id = hex::encode(session_id),
                    from = ?hex::encode(&from_peer.as_bytes()[..8]),
                    "rejecting RELAY_CLOSE: requester is not a session participant"
                );
                return;
            }
            
            active.remove(session_id);
            
            // Remove from issued sessions tracking
            {
                let mut issued = self.issued_sessions.write().await;
                issued.remove(session_id);
            }
            
            // Abort the forwarder task immediately when session is closed
            self.forwarder_registry.abort(session_id).await;
            
            debug!(
                session_id = hex::encode(session_id),
                reason = reason,
                "relay session closed"
            );
            
            let mut metrics = self.metrics.lock().await;
            metrics.active_count = active.len();
            return;
        }
        drop(active);

        // Also check pending sessions
        let mut pending = self.pending.write().await;
        if let Some(session) = pending.get(session_id) {
            // Verify the requester is the initiator or target
            if &session.initiator != from_peer && &session.target != from_peer {
                warn!(
                    session_id = hex::encode(session_id),
                    from = ?hex::encode(&from_peer.as_bytes()[..8]),
                    "rejecting RELAY_CLOSE: requester is not a session participant"
                );
                return;
            }
            
            pending.remove(session_id);
            
            // Remove from issued sessions tracking
            {
                let mut issued = self.issued_sessions.write().await;
                issued.remove(session_id);
            }
            
            // Abort any forwarder task for pending sessions too
            self.forwarder_registry.abort(session_id).await;
            
            debug!(
                session_id = hex::encode(session_id),
                reason = reason,
                "pending relay session closed"
            );
        }
    }

    /// Clean up expired sessions and completed forwarder tasks.
    ///
    /// # Task Cleanup
    ///
    /// Also cleans up completed forwarder tasks to reclaim capacity.
    ///
    /// # Session Tracking Cleanup
    ///
    /// Expired session IDs are removed from the issued_sessions set to
    /// prevent unbounded memory growth.
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();

        // Clean pending sessions and collect expired IDs
        let expired_pending_ids: Vec<[u8; 16]> = {
            let mut pending = self.pending.write().await;
            let mut expired_ids = Vec::new();
            
            pending.retain(|id, s| {
                let expired = now.duration_since(s.created_at) >= RELAY_SESSION_TIMEOUT;
                if expired {
                    trace!(session_id = hex::encode(id), "pending session expired");
                    expired_ids.push(*id);
                }
                !expired
            });
            
            expired_ids
        };

        // Clean active sessions
        let expired_session_ids: Vec<[u8; 16]> = {
            let mut active = self.active.write().await;
            let mut expired_ids = Vec::new();
            
            active.retain(|id, s| {
                let expired = now.duration_since(s.last_activity) >= RELAY_SESSION_TIMEOUT;
                if expired {
                    debug!(session_id = hex::encode(id), "active session expired");
                    expired_ids.push(*id);
                }
                !expired
            });

            let mut metrics = self.metrics.lock().await;
            metrics.active_count = active.len();
            
            expired_ids
        };
        
        // Remove all expired session IDs from issued sessions tracking
        {
            let mut issued = self.issued_sessions.write().await;
            for session_id in &expired_pending_ids {
                issued.remove(session_id);
            }
            for session_id in &expired_session_ids {
                issued.remove(session_id);
            }
        }
        
        // Abort forwarder tasks for expired sessions
        for session_id in &expired_session_ids {
            self.forwarder_registry.abort(session_id).await;
        }
        
        // Clean up completed forwarder tasks to reclaim capacity
        self.forwarder_registry.cleanup_completed().await;
    }

    /// Get relay info for DHT publishing.
    pub async fn get_relay_info(&self, our_peer: Identity, our_addrs: Vec<String>) -> RelayInfo {
        RelayInfo {
            relay_peer: our_peer,
            relay_addrs: our_addrs,
            load: self.load().await,
            accepting: self.is_accepting().await,
            rtt_ms: None,  // Will be filled by the receiver's measurements
            tier: None,
            capabilities: RelayCapabilities {
                stun: true,
                turn: true,
                ice_lite: true,
                max_bandwidth_kbps: 0,
                region: None,
            },
        }
    }
}

// Note: RelayServer does not implement Default because initialization
// requires a working CSPRNG for security. Use RelayServer::new() instead.

// ============================================================================
// Relay Client State
// ============================================================================

/// Maximum pending relay data packets per session.
/// Prevents memory exhaustion if receiver is slow.
const MAX_PENDING_RELAY_DATA: usize = 64;

/// Incoming relay data packet ready for processing.
#[derive(Debug, Clone)]
pub struct IncomingRelayData {
    /// The session this data belongs to.
    pub session_id: [u8; 16],
    /// The peer who sent this data (the other end of the relay session).
    pub from_peer: Identity,
    /// The E2E encrypted payload (QUIC packet data).
    pub payload: Vec<u8>,
    /// When this data was received.
    pub received_at: std::time::Instant,
}

/// Client-side state for using relays.
///
/// Tracks which relays we're connected to and active relay sessions.
/// Uses RTT metrics from the sDHT tiering system for intelligent relay selection.
///
/// # Receiving Relay Data
///
/// When data arrives via a relay, it is queued and can be retrieved via
/// [`RelayClient::recv_data`] or by taking the receiver channel.
#[derive(Debug)]
pub struct RelayClient {
    /// Known relays and their info (including RTT metrics).
    known_relays: RwLock<Vec<RelayInfo>>,
    /// Active sessions through relays (session_id -> relay_peer).
    active_sessions: RwLock<HashMap<[u8; 16], Identity>>,
    /// Channel sender for incoming relay data.
    data_tx: tokio::sync::mpsc::Sender<IncomingRelayData>,
    /// Channel receiver for incoming relay data (taken by consumer).
    data_rx: Mutex<Option<tokio::sync::mpsc::Receiver<IncomingRelayData>>>,
}

impl RelayClient {
    /// Create a new relay client.
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(MAX_PENDING_RELAY_DATA);
        Self {
            known_relays: RwLock::new(Vec::new()),
            active_sessions: RwLock::new(HashMap::new()),
            data_tx: tx,
            data_rx: Mutex::new(Some(rx)),
        }
    }

    /// Take the relay data receiver channel.
    ///
    /// This can only be called once. Subsequent calls return `None`.
    /// The receiver can be used to process incoming relay data in a dedicated task.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let rx = relay_client.take_data_receiver().await.unwrap();
    /// tokio::spawn(async move {
    ///     while let Some(data) = rx.recv().await {
    ///         // Process relayed QUIC packet
    ///         handle_relay_data(data.session_id, data.from_peer, data.payload);
    ///     }
    /// });
    /// ```
    pub async fn take_data_receiver(&self) -> Option<tokio::sync::mpsc::Receiver<IncomingRelayData>> {
        self.data_rx.lock().await.take()
    }

    /// Queue incoming relay data for processing.
    ///
    /// Called by the RPC handler when `RelayData` messages are received.
    /// Returns `Ok(())` if the data was queued, or `Err` if the queue is full
    /// or no receiver is listening.
    ///
    /// # Security
    ///
    /// The caller must verify the session before calling this method.
    /// This method assumes the session has already been validated.
    pub async fn queue_incoming_data(
        &self,
        session_id: [u8; 16],
        from_peer: Identity,
        payload: Vec<u8>,
    ) -> Result<(), &'static str> {
        let data = IncomingRelayData {
            session_id,
            from_peer,
            payload,
            received_at: std::time::Instant::now(),
        };

        self.data_tx
            .try_send(data)
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    "relay data queue full"
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    "relay data receiver closed"
                }
            })
    }

    /// Update known relays from DHT lookups.
    ///
    /// Relays are sorted by selection score (RTT + load + tier).
    /// This enables latency-aware relay selection using sDHT metrics.
    pub async fn update_relays(&self, relays: Vec<RelayInfo>) {
        let mut known = self.known_relays.write().await;
        *known = relays;
        // Sort by selection score (lower is better - considers RTT, load, and tier)
        known.sort_by(|a, b| {
            a.selection_score()
                .partial_cmp(&b.selection_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Update RTT metrics for a known relay.
    ///
    /// Call this when the DHT tiering system updates latency measurements.
    pub async fn update_relay_rtt(&self, relay_peer: &Identity, rtt_ms: f32, tier: u8) {
        let mut known = self.known_relays.write().await;
        for relay in known.iter_mut() {
            if &relay.relay_peer == relay_peer {
                relay.rtt_ms = Some(rtt_ms);
                relay.tier = Some(tier);
            }
        }
        // Re-sort after updating metrics
        known.sort_by(|a, b| {
            a.selection_score()
                .partial_cmp(&b.selection_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Get best available relays for a connection attempt.
    ///
    /// Returns relays sorted by selection score (RTT + load + tier).
    /// Prefers relays with known latency metrics.
    pub async fn get_relays(&self, count: usize) -> Vec<RelayInfo> {
        let known = self.known_relays.read().await;
        known
            .iter()
            .filter(|r| r.accepting)
            .take(count)
            .cloned()
            .collect()
    }

    /// Get info for a specific relay.
    pub async fn get_relay_info(&self, identity: &Identity) -> Option<RelayInfo> {
        let known = self.known_relays.read().await;
        known.iter().find(|r| &r.relay_peer == identity).cloned()
    }

    /// Check if an identity is a known/registered relay.
    ///
    /// This is used to validate incoming `RelayData` messages - we only accept
    /// relayed data from relays we have previously discovered and registered.
    /// This provides defense-in-depth against rogue nodes claiming to be relays.
    ///
    /// # Returns
    /// * `true` if the identity is in our known relays list
    /// * `false` if the identity is not a known relay
    pub async fn is_known_relay(&self, identity: &Identity) -> bool {
        let known = self.known_relays.read().await;
        known.iter().any(|r| &r.relay_peer == identity)
    }

    /// Get relays that have been measured (have RTT data).
    ///
    /// Useful when you want to prioritize relays with known performance.
    pub async fn get_measured_relays(&self, count: usize) -> Vec<RelayInfo> {
        let known = self.known_relays.read().await;
        known
            .iter()
            .filter(|r| r.accepting && r.has_latency_info())
            .take(count)
            .cloned()
            .collect()
    }

    /// Generate a new session ID for a relay connection.
    ///
    /// Uses cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if the system CSPRNG is unavailable. Session IDs
    /// must be unpredictable to prevent session hijacking attacks.
    pub fn generate_session_id() -> Result<[u8; 16], CryptoError> {
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id)?;
        Ok(id)
    }
    
    /// Generate a session ID with collision checking against existing sessions.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if the system CSPRNG is unavailable. Session IDs
    /// must be unpredictable to prevent session hijacking attacks.
    ///
    /// Returns `None` (wrapped in `Ok`) if a unique ID could not be generated
    /// after maximum retries, indicating possible RNG quality issues.
    pub fn generate_unique_session_id(
        existing: &std::collections::HashSet<[u8; 16]>,
    ) -> Result<Option<[u8; 16]>, CryptoError> {
        const MAX_RETRIES: usize = 10;
        
        for attempt in 0..MAX_RETRIES {
            let id = Self::generate_session_id()?;
            if !existing.contains(&id) {
                if attempt > 0 {
                    debug!(
                        attempts = attempt + 1,
                        "session ID collision avoided after retries"
                    );
                }
                return Ok(Some(id));
            }
            // Log collision - this is unexpected with CSPRNG, concerning with fallback
            warn!(
                attempt = attempt + 1,
                "session ID collision detected, retrying"
            );
        }
        
        error!(
            "failed to generate unique session ID after {} attempts - possible RNG failure",
            MAX_RETRIES
        );
        Ok(None)
    }

    /// Register an active relay session.
    pub async fn register_session(&self, session_id: [u8; 16], relay: Identity) {
        let mut sessions = self.active_sessions.write().await;
        sessions.insert(session_id, relay);
    }

    /// Remove a relay session.
    pub async fn remove_session(&self, session_id: &[u8; 16]) -> Option<Identity> {
        let mut sessions = self.active_sessions.write().await;
        sessions.remove(session_id)
    }

    /// Verify that a relay session is active and belongs to the expected relay.
    ///
    /// This is used to validate incoming `RelayData` messages - we only accept
    /// relayed data from the relay server we established the session with.
    ///
    /// # Arguments
    /// * `session_id` - The session ID from the RelayData message
    /// * `relay_identity` - The identity of the connection the message arrived on
    ///
    /// # Returns
    /// * `true` if we have an active session with this ID through this relay
    /// * `false` if the session doesn't exist or belongs to a different relay
    pub async fn verify_session(&self, session_id: &[u8; 16], relay_identity: &Identity) -> bool {
        let sessions = self.active_sessions.read().await;
        sessions.get(session_id).map(|r| r == relay_identity).unwrap_or(false)
    }

    /// Check if we have an active session with the given ID.
    pub async fn has_session(&self, session_id: &[u8; 16]) -> bool {
        let sessions = self.active_sessions.read().await;
        sessions.contains_key(session_id)
    }

    /// Get the relay identity for a given session.
    pub async fn get_session_relay(&self, session_id: &[u8; 16]) -> Option<Identity> {
        let sessions = self.active_sessions.read().await;
        sessions.get(session_id).cloned()
    }
}

impl Default for RelayClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Connection Strategy
// ============================================================================

/// Strategy for connecting to a peer.
#[derive(Clone, Debug)]
pub enum ConnectionStrategy {
    /// Direct connection to known addresses.
    Direct {
        /// Addresses to try.
        addrs: Vec<String>,
    },
    /// Connection via a relay.
    Relayed {
        /// Relay to use.
        relay: RelayInfo,
        /// Session ID for this relay connection.
        session_id: [u8; 16],
    },
}

/// Determines the best connection strategy for reaching a peer.
///
/// Uses sophisticated path selection based on sDHT RTT metrics:
/// 1. Tries direct connection first (if addresses available and not failed)
/// 2. Falls back to relay, selecting based on:
///    - RTT latency (from DHT tiering)
///    - Current load
///    - Tier level
///
/// Prefers relays that both peers have access to (peer-advertised relays).
///
/// # Errors
///
/// Returns `CryptoError` if a relay strategy is selected but session ID
/// generation fails due to CSPRNG unavailability.
pub fn choose_connection_strategy(
    direct_addrs: &[String],
    known_relays: &[RelayInfo],
    peer_relays: &[RelayInfo],
    direct_failed: bool,
) -> Result<ConnectionStrategy, CryptoError> {
    // If we have direct addresses and haven't failed yet, try direct
    if !direct_addrs.is_empty() && !direct_failed {
        return Ok(ConnectionStrategy::Direct {
            addrs: direct_addrs.to_vec(),
        });
    }

    // Find best relay using scoring (RTT + load + tier)
    // First, try to find a mutual relay (peer-advertised that we also know)
    let best_mutual = find_best_mutual_relay(known_relays, peer_relays);
    if let Some(relay) = best_mutual {
        return Ok(ConnectionStrategy::Relayed {
            relay,
            session_id: RelayClient::generate_session_id()?,
        });
    }
    
    // If no mutual relay, prefer peer's relays (they're proven reachable by peer)
    // Sort by score and take the best
    let mut peer_sorted: Vec<_> = peer_relays.iter().filter(|r| r.accepting).cloned().collect();
    peer_sorted.sort_by(|a, b| {
        a.selection_score()
            .partial_cmp(&b.selection_score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    
    if let Some(relay) = peer_sorted.into_iter().next() {
        return Ok(ConnectionStrategy::Relayed {
            relay,
            session_id: RelayClient::generate_session_id()?,
        });
    }

    // Fall back to our known relays (already sorted by score in RelayClient)
    if let Some(relay) = known_relays.iter().find(|r| r.accepting).cloned() {
        return Ok(ConnectionStrategy::Relayed {
            relay,
            session_id: RelayClient::generate_session_id()?,
        });
    }

    // Last resort: try direct even if it failed before
    Ok(ConnectionStrategy::Direct {
        addrs: direct_addrs.to_vec(),
    })
}

/// Find the best relay that both we and the peer know about.
///
/// Mutual relays are optimal because:
/// 1. Both sides can connect outbound
/// 2. We have RTT measurements to it
/// 3. The peer has already verified it works
fn find_best_mutual_relay(our_relays: &[RelayInfo], peer_relays: &[RelayInfo]) -> Option<RelayInfo> {
    let mut mutual: Vec<RelayInfo> = Vec::new();
    
    for our in our_relays {
        for peer in peer_relays {
            if our.relay_peer == peer.relay_peer && our.accepting && peer.accepting {
                // Use our relay info (has our RTT measurements)
                mutual.push(our.clone());
                break;
            }
        }
    }
    
    // Sort by score and return best
    mutual.sort_by(|a, b| {
        a.selection_score()
            .partial_cmp(&b.selection_score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    
    mutual.into_iter().next()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relay(id: u8, rtt: Option<f32>, tier: Option<u8>, load: f32) -> RelayInfo {
        RelayInfo {
            relay_peer: Identity::from_bytes([id; 32]),
            relay_addrs: vec![format!("relay-{}:4433", id)],
            load,
            accepting: true,
            rtt_ms: rtt,
            tier,
            capabilities: Default::default(),
        }
    }

    #[test]
    fn test_session_id_generation() {
        let id1 = RelayClient::generate_session_id().unwrap();
        let id2 = RelayClient::generate_session_id().unwrap();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 16);
    }

    #[tokio::test]
    async fn test_relay_server_capacity() {
        let server = RelayServer::with_capacity(10).unwrap();
        assert!(server.is_accepting().await);
        assert!(server.load().await < 0.1);
    }

    #[test]
    fn test_connection_strategy_direct_first() {
        let addrs = vec!["192.168.1.1:4433".to_string()];
        let strategy = choose_connection_strategy(&addrs, &[], &[], false).unwrap();
        
        match strategy {
            ConnectionStrategy::Direct { addrs: a } => {
                assert_eq!(a.len(), 1);
            }
            _ => panic!("expected direct strategy"),
        }
    }

    #[test]
    fn test_connection_strategy_fallback_to_relay() {
        let addrs = vec!["192.168.1.1:4433".to_string()];
        let relay = make_relay(1, Some(50.0), Some(0), 0.5);
        
        let strategy = choose_connection_strategy(&addrs, &[relay], &[], true).unwrap();
        
        match strategy {
            ConnectionStrategy::Relayed { relay: r, .. } => {
                assert_eq!(r.relay_addrs[0], "relay-1:4433");
            }
            _ => panic!("expected relayed strategy"),
        }
    }

    #[test]
    fn test_relay_selection_score() {
        // Fast relay: low RTT, low load, tier 0
        let fast_relay = make_relay(1, Some(20.0), Some(0), 0.1);
        
        // Slow relay: high RTT, high load, tier 2
        let slow_relay = make_relay(2, Some(150.0), Some(2), 0.8);
        
        // Fast relay should have lower (better) score
        assert!(fast_relay.selection_score() < slow_relay.selection_score());
    }

    #[test]
    fn test_relay_selection_prefers_measured() {
        // Relay with measurements
        let measured = make_relay(1, Some(30.0), Some(0), 0.5);
        
        // Relay without measurements (uses defaults: 200ms RTT, tier penalty 40ms)
        let unmeasured = make_relay(2, None, None, 0.2);
        
        // Measured relay should be preferred (lower score)
        assert!(measured.selection_score() < unmeasured.selection_score());
        assert!(measured.has_latency_info());
        assert!(!unmeasured.has_latency_info());
    }

    #[test]
    fn test_mutual_relay_selection() {
        let relay_a = make_relay(1, Some(100.0), Some(1), 0.3);
        let relay_b = make_relay(2, Some(50.0), Some(0), 0.2);  // Better RTT
        
        // Both know about relay_a and relay_b, but with different metrics
        let our_relays = vec![relay_a.clone(), relay_b.clone()];
        let peer_relays = vec![
            make_relay(1, None, None, 0.4),
            make_relay(2, None, None, 0.3),
        ];
        
        let result = find_best_mutual_relay(&our_relays, &peer_relays);
        assert!(result.is_some());
        
        // Should pick relay_b (better score due to lower RTT and tier)
        let selected = result.unwrap();
        assert_eq!(selected.relay_peer, Identity::from_bytes([2u8; 32]));
    }

    // ========== ICE Tests ==========

    #[test]
    fn test_ice_candidate_priority() {
        // Host should have highest type preference
        let host = IceCandidate::host("192.168.1.1:4433".parse().unwrap(), 1);
        let srflx = IceCandidate::server_reflexive(
            "1.2.3.4:5678".parse().unwrap(),
            "192.168.1.1:4433".parse().unwrap(),
            1,
        );
        let relay = IceCandidate::relay(
            "5.6.7.8:9999".parse().unwrap(),
            "192.168.1.1:4433".parse().unwrap(),
            Identity::from_bytes([1u8; 32]),
            1,
        );
        
        assert!(host.priority > srflx.priority);
        assert!(srflx.priority > relay.priority);
    }

    #[test]
    fn test_ice_candidate_types() {
        assert_eq!(CandidateType::Host.type_preference(), 126);
        assert_eq!(CandidateType::ServerReflexive.type_preference(), 100);
        assert_eq!(CandidateType::PeerReflexive.type_preference(), 110);
        assert_eq!(CandidateType::Relay.type_preference(), 0);
    }

    #[test]
    fn test_nat_type_detection() {
        let local: SocketAddr = "192.168.1.1:4433".parse().unwrap();
        
        // No responses - UDP blocked
        let report = detect_nat_type(None, None, local);
        assert_eq!(report.nat_type, NatType::Unknown);
        assert!(report.udp_blocked);
        
        // Same address from both servers - Cone NAT
        let public: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let report = detect_nat_type(Some(public), Some(public), local);
        assert_eq!(report.nat_type, NatType::FullCone);
        
        // Different ports - Symmetric NAT
        let public1: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let public2: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let report = detect_nat_type(Some(public1), Some(public2), local);
        assert_eq!(report.nat_type, NatType::Symmetric);
        
        // Public IP matches local - No NAT
        let public: SocketAddr = "192.168.1.1:4433".parse().unwrap();
        let report = detect_nat_type(Some(public), Some(public), local);
        assert_eq!(report.nat_type, NatType::None);
    }

    #[test]
    fn test_ice_agent_candidate_pairing() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        let local = IceCandidate::host("192.168.1.1:4433".parse().unwrap(), 1);
        agent.add_local_candidate(local);
        
        let remote = IceCandidate::host("192.168.2.1:4433".parse().unwrap(), 1);
        agent.add_remote_candidate(remote);
        
        assert_eq!(agent.check_list.len(), 1);
        assert_eq!(agent.check_list[0].state, CheckState::Waiting);
    }

    #[test]
    fn test_ice_agent_check_flow() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        agent.add_local_candidate(IceCandidate::host("192.168.1.1:4433".parse().unwrap(), 1));
        agent.add_remote_candidate(IceCandidate::host("192.168.2.1:4433".parse().unwrap(), 1));
        
        agent.start_checks();
        assert_eq!(agent.state(), IceState::Checking);
        
        // Simulate successful check
        agent.check_succeeded(0, 25.0);
        assert_eq!(agent.state(), IceState::Connected);
        assert_eq!(agent.check_list[0].rtt_ms, Some(25.0));
        
        // Nominate
        let nominated = agent.nominate_best();
        assert!(nominated.is_some());
        assert_eq!(agent.state(), IceState::Completed);
    }

    #[test]
    fn test_turn_allocation() {
        let mut alloc = TurnAllocation::new(
            Identity::from_bytes([1u8; 32]),
            "1.2.3.4:5678".parse().unwrap(),
            Duration::from_secs(300),
        );
        
        assert!(!alloc.is_expired());
        
        // Add permission
        alloc.add_permission("5.6.7.8:9999".parse().unwrap());
        assert_eq!(alloc.permissions.len(), 1);
        
        // Bind channel
        alloc.bind_channel(0x4000, "5.6.7.8:9999".parse().unwrap());
        assert_eq!(alloc.channels.len(), 1);
    }

    #[test]
    fn test_gather_host_candidates() {
        let addrs: Vec<SocketAddr> = vec![
            "192.168.1.1:4433".parse().unwrap(),
            "10.0.0.1:4433".parse().unwrap(),
        ];
        
        let candidates = gather_host_candidates(&addrs, 1);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|c| c.candidate_type == CandidateType::Host));
    }

    #[test]
    fn test_ice_connection_strategy_symmetric_nat() {
        let local_host = IceCandidate::host("192.168.1.1:4433".parse().unwrap(), 1);
        let local_relay = IceCandidate::relay(
            "1.2.3.4:5678".parse().unwrap(),
            "192.168.1.1:4433".parse().unwrap(),
            Identity::from_bytes([1u8; 32]),
            1,
        );
        
        let remote_host = IceCandidate::host("192.168.2.1:4433".parse().unwrap(), 1);
        
        let local_candidates = vec![local_host, local_relay];
        let remote_candidates = vec![remote_host];
        
        // With symmetric NAT, relay pairs should be prioritized
        let symmetric_report = NatReport {
            nat_type: NatType::Symmetric,
            ..Default::default()
        };
        
        let pairs = ice_connection_strategy(&local_candidates, &remote_candidates, &symmetric_report);
        assert!(!pairs.is_empty());
        
        // First pair should involve relay for symmetric NAT
        assert!(
            pairs[0].local.candidate_type == CandidateType::Relay
            || pairs[0].remote.candidate_type == CandidateType::Relay
        );
    }

    #[tokio::test]
    async fn test_relay_client_session_verification() {
        let client = RelayClient::new();
        let session_id = RelayClient::generate_session_id().unwrap();
        let relay_identity = Identity::from_bytes([1u8; 32]);
        let other_relay = Identity::from_bytes([2u8; 32]);
        let unknown_session: [u8; 16] = [0xFF; 16];
        
        // Initially no session registered
        assert!(!client.verify_session(&session_id, &relay_identity).await);
        assert!(!client.has_session(&session_id).await);
        
        // Register session
        client.register_session(session_id, relay_identity).await;
        
        // Session should now verify with correct relay
        assert!(client.verify_session(&session_id, &relay_identity).await);
        assert!(client.has_session(&session_id).await);
        
        // Session should NOT verify with different relay (prevents injection)
        assert!(!client.verify_session(&session_id, &other_relay).await);
        
        // Unknown session should not verify
        assert!(!client.verify_session(&unknown_session, &relay_identity).await);
        
        // Get session relay should return correct identity
        assert_eq!(client.get_session_relay(&session_id).await, Some(relay_identity));
        assert_eq!(client.get_session_relay(&unknown_session).await, None);
        
        // Remove session
        let removed = client.remove_session(&session_id).await;
        assert_eq!(removed, Some(relay_identity));
        
        // Session should no longer verify after removal
        assert!(!client.verify_session(&session_id, &relay_identity).await);
    }
}
