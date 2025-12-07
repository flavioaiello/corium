//! High-level peer connectivity with automatic NAT traversal.
//!
//! This module provides [`QuinnNetwork`] and its [`smart_connect`][QuinnNetwork::smart_connect]
//! method, which is the **primary API for connecting to peers**. Consumers should use
//! `smart_connect` exclusively—it abstracts away all transport complexity including:
//!
//! - Direct QUIC connections when network conditions allow
//! - Automatic relay fallback when behind Symmetric NAT (CGNAT)
//! - NAT type detection and connection strategy selection
//! - Connection upgrade probing (relay → direct when conditions improve)
//!
//! # Why Use `smart_connect` Instead of Raw QUIC?
//!
//! **You don't need to manage quinn/QUIC connections directly.** The `smart_connect` method
//! returns a [`SmartConnection`] that works regardless of network topology:
//!
//! ```ignore
//! // This is all you need—no quinn APIs required in your code!
//! let conn = network.smart_connect(&endpoint_record).await?;
//! 
//! // Use the connection for DHT operations
//! network.rpc(&conn.connection().remote_address().to_string(), request).await?;
//! ```
//!
//! The returned [`SmartConnection`] transparently handles:
//! - **Public IP / Full Cone NAT**: Direct QUIC connection
//! - **Restricted Cone NAT**: Direct with hole-punching coordination  
//! - **Symmetric NAT (CGNAT)**: Automatic relay with E2E encryption
//! - **Mixed topologies**: Optimal path selection based on RTT
//!
//! # Cryptographic Addressing
//!
//! Peers are identified by their Ed25519 public key ([`Identity`]). To connect:
//!
//! 1. **Resolve**: Look up `BLAKE3(Identity)` in the DHT to get [`EndpointRecord`]
//! 2. **Smart Connect**: Call `smart_connect(&record)` — handles all connectivity
//! 3. **Verify**: TLS certificate verification happens automatically
//!
//! # NAT Traversal (Handled Automatically)
//!
//! When direct connection fails, the network uses relay-based traversal:
//!
//! 1. **Direct first**: Always try direct UDP connection
//! 2. **Relay fallback**: If blocked by NAT, connect via relay
//! 3. **Upgrade probing**: Periodically attempt direct connection
//! 4. **Seamless upgrade**: When direct becomes available, migrate off relay
//!
//! This reduces relay load and latency when NAT conditions change.
//!
//! # Protocol
//!
//! The network uses the ALPN identifier `corium` for connection negotiation.
//! All RPC calls are serialized using bincode over QUIC streams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;

use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::core::{Contact, DhtNetwork, Key};
use crate::identity::Keypair;
use crate::identity::{EndpointRecord, Identity};
use crate::protocol::{DhtRequest, DhtResponse};
use crate::relay::{ConnectionStrategy, NatType, RelayClient, RelayInfo, detect_nat_type, DIRECT_CONNECT_TIMEOUT};

/// Default crypto provider for TLS signature verification.
static CRYPTO_PROVIDER: std::sync::LazyLock<Arc<rustls::crypto::CryptoProvider>> =
    std::sync::LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));

/// How often to attempt upgrading relayed connections to direct.
pub const UPGRADE_PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// ALPN protocol identifier for Corium connections.
pub const ALPN: &[u8] = b"corium";

/// Maximum size of an RPC response in bytes (1 MB).
/// Larger than request to accommodate FIND_VALUE responses with data.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Maximum number of contacts allowed in a single response.
///
/// # Security
///
/// Limits the number of Contact entries a peer can return in FIND_NODE
/// or FIND_VALUE responses. This prevents:
/// - Memory exhaustion from processing huge contact lists
/// - CPU exhaustion from sorting/processing thousands of entries
/// - Routing table pollution attacks
///
/// Set to 100, which is 5x the typical k=20 value. Legitimate nodes
/// should never return more than k contacts.
const MAX_CONTACTS_PER_RESPONSE: usize = 100;

/// Maximum size of a value in FIND_VALUE responses.
///
/// # Security
///
/// Limits the size of data returned in DHT lookups. This is separate from
/// MAX_RESPONSE_SIZE because we want to specifically limit user data.
/// Set to 1MB to allow reasonably large values while preventing abuse.
const MAX_VALUE_SIZE: usize = crate::protocol::MAX_VALUE_SIZE;

/// Clock skew tolerance for hole punch timing (milliseconds).
///
/// # Security
///
/// Handles clock drift between peers and rendezvous server. If the server's
/// clock is behind the client's clock, the client would otherwise start
/// punching immediately, potentially before the peer is ready.
///
/// This value documents the expected tolerance; the actual implementation
/// uses MIN_WAIT and MAX_WAIT bounds for robustness.
#[allow(dead_code)]
const HOLE_PUNCH_CLOCK_SKEW_TOLERANCE_MS: u64 = 2000;

/// Minimum wait time before starting hole punch (milliseconds).
///
/// # Security
///
/// Even if timestamps indicate we should start immediately, wait this
/// minimum time to account for network delays and clock skew. This ensures
/// both peers have a chance to be ready.
const HOLE_PUNCH_MIN_WAIT_MS: u64 = 100;

/// Maximum wait time for hole punch start (milliseconds).
///
/// # Security
///
/// Prevents a malicious rendezvous server from causing extremely long waits
/// by returning a far-future timestamp. Limits the wait to a reasonable
/// maximum of 10 seconds.
const HOLE_PUNCH_MAX_WAIT_MS: u64 = 10_000;

/// Timeout for hole punch attempts.
pub const HOLE_PUNCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for both peers to register before starting punch.
pub const HOLE_PUNCH_RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(10);

/// Delay between simultaneous connection attempts (stagger to improve success).
pub const HOLE_PUNCH_STAGGER: Duration = Duration::from_millis(50);

/// Maximum number of cached peer connections.
/// Prevents memory exhaustion from connection accumulation.
const MAX_CACHED_CONNECTIONS: usize = 1000;

/// Maximum time a cached connection can be idle before being considered stale.
///
/// # Security
///
/// Connections that haven't been successfully used within this duration are
/// considered potentially stale and require verification before reuse.
/// This prevents timeout cascades where many RPCs queue up behind a dead
/// connection that hasn't been explicitly closed.
///
/// Set to 60 seconds to balance between connection reuse (saves 1-RTT handshake)
/// and avoiding stale connection accumulation.
const CONNECTION_STALE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval between connection health checks.
/// This ensures we detect dead connections proactively using passive stats.
pub const CONNECTION_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Number of RTT samples to keep for health statistics.
const RTT_SAMPLE_HISTORY_SIZE: usize = 10;

/// Maximum acceptable RTT before considering connection degraded (ms).
const MAX_HEALTHY_RTT_MS: f32 = 2000.0;

/// Consecutive failures before marking connection as unhealthy.
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Maximum number of path probers to track.
/// Prevents memory exhaustion from prober accumulation.
const MAX_PATH_PROBERS: usize = 1000;

/// A cached connection with metadata for liveness checking.
///
/// # Security
///
/// Tracks when the connection was last successfully used to detect stale
/// connections that may have died without an explicit close. This prevents
/// timeout cascades where RPCs wait on dead connections.
///
/// # Health Monitoring
///
/// Includes RTT tracking and health status for proactive connection management.
/// Unhealthy connections are invalidated before they cause timeout cascades.
#[derive(Clone)]
struct CachedConnection {
    /// The QUIC connection.
    connection: Connection,
    /// Timestamp of last successful RPC or stream operation.
    last_success: Instant,
    /// Timestamp of last health check (keepalive probe).
    last_health_check: Instant,
    /// Consecutive probe failures.
    consecutive_failures: u32,
    /// RTT samples in milliseconds (ring buffer for recent history).
    rtt_samples: Vec<f32>,
    /// Index for next RTT sample insertion (ring buffer).
    rtt_sample_index: usize,
    /// Current health status.
    health_status: ConnectionHealthStatus,
}

/// Health status of a cached connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionHealthStatus {
    /// Connection is healthy (recent success, good RTT).
    Healthy,
    /// Connection is degraded (high RTT or recent failures).
    Degraded,
    /// Connection is unhealthy (multiple failures, needs replacement).
    Unhealthy,
    /// Connection health is unknown (not yet checked).
    Unknown,
}

/// Connection health statistics for observability.
#[derive(Clone, Debug)]
pub struct ConnectionHealthStats {
    /// Remote address.
    pub remote_addr: SocketAddr,
    /// Current health status.
    pub status: ConnectionHealthStatus,
    /// Smoothed RTT in milliseconds.
    pub rtt_ms: Option<f32>,
    /// RTT jitter (standard deviation) in milliseconds.
    pub rtt_jitter_ms: Option<f32>,
    /// Time since last successful use.
    pub time_since_success: Duration,
    /// Time since last health check.
    pub time_since_health_check: Duration,
    /// Consecutive failures.
    pub consecutive_failures: u32,
}

/// Summary of connection health across all cached connections.
#[derive(Clone, Debug, Default)]
pub struct ConnectionHealthSummary {
    /// Total number of cached connections.
    pub total: usize,
    /// Number of healthy connections.
    pub healthy: usize,
    /// Number of degraded connections.
    pub degraded: usize,
    /// Number of unhealthy connections.
    pub unhealthy: usize,
    /// Number of connections with unknown health.
    pub unknown: usize,
    /// Average RTT across all connections (ms).
    pub average_rtt_ms: Option<f32>,
    /// RTT samples for statistical analysis.
    #[doc(hidden)]
    pub rtt_samples: Vec<f32>,
}

impl CachedConnection {
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            last_success: Instant::now(),
            last_health_check: Instant::now(),
            consecutive_failures: 0,
            rtt_samples: Vec::with_capacity(RTT_SAMPLE_HISTORY_SIZE),
            rtt_sample_index: 0,
            health_status: ConnectionHealthStatus::Unknown,
        }
    }

    /// Check if connection is explicitly closed.
    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    /// Check if connection is stale (not used recently).
    fn is_stale(&self) -> bool {
        self.last_success.elapsed() > CONNECTION_STALE_TIMEOUT
    }

    /// Check if connection needs a health check.
    fn needs_health_check(&self) -> bool {
        self.last_health_check.elapsed() > CONNECTION_HEALTH_CHECK_INTERVAL
    }

    /// Update last successful use timestamp and reset failure count.
    fn mark_success(&mut self) {
        self.last_success = Instant::now();
        self.consecutive_failures = 0;
        if self.health_status != ConnectionHealthStatus::Healthy {
            self.health_status = ConnectionHealthStatus::Healthy;
        }
    }

    /// Record a health check failure.
    fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_health_check = Instant::now();
        self.update_health_status();
    }

    /// Record a successful health check with RTT measurement.
    fn record_health_check_success(&mut self, rtt: Duration) {
        let rtt_ms = rtt.as_secs_f32() * 1000.0;
        
        // Add RTT sample to ring buffer
        if self.rtt_samples.len() < RTT_SAMPLE_HISTORY_SIZE {
            self.rtt_samples.push(rtt_ms);
        } else {
            self.rtt_samples[self.rtt_sample_index] = rtt_ms;
        }
        self.rtt_sample_index = (self.rtt_sample_index + 1) % RTT_SAMPLE_HISTORY_SIZE;
        
        self.last_health_check = Instant::now();
        self.consecutive_failures = 0;
        self.update_health_status();
    }

    /// Update health status based on current metrics.
    fn update_health_status(&mut self) {
        if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            self.health_status = ConnectionHealthStatus::Unhealthy;
            return;
        }
        
        if let Some(avg_rtt) = self.average_rtt_ms() {
            if avg_rtt > MAX_HEALTHY_RTT_MS {
                self.health_status = ConnectionHealthStatus::Degraded;
                return;
            }
        }
        
        if self.consecutive_failures > 0 {
            self.health_status = ConnectionHealthStatus::Degraded;
        } else if !self.rtt_samples.is_empty() {
            self.health_status = ConnectionHealthStatus::Healthy;
        }
        // Otherwise, keep current status (Unknown if never checked)
    }

    /// Get average RTT from samples.
    fn average_rtt_ms(&self) -> Option<f32> {
        if self.rtt_samples.is_empty() {
            return None;
        }
        Some(self.rtt_samples.iter().sum::<f32>() / self.rtt_samples.len() as f32)
    }

    /// Get RTT jitter (standard deviation) from samples.
    fn rtt_jitter_ms(&self) -> Option<f32> {
        if self.rtt_samples.len() < 2 {
            return None;
        }
        let avg = self.average_rtt_ms()?;
        let variance: f32 = self.rtt_samples.iter()
            .map(|&x| (x - avg).powi(2))
            .sum::<f32>() / self.rtt_samples.len() as f32;
        Some(variance.sqrt())
    }

    /// Get health statistics for this connection.
    fn health_stats(&self) -> ConnectionHealthStats {
        ConnectionHealthStats {
            remote_addr: self.connection.remote_address(),
            status: self.health_status,
            rtt_ms: self.average_rtt_ms(),
            rtt_jitter_ms: self.rtt_jitter_ms(),
            time_since_success: self.last_success.elapsed(),
            time_since_health_check: self.last_health_check.elapsed(),
            consecutive_failures: self.consecutive_failures,
        }
    }

    /// Check connection health using Quinn's passive path statistics.
    ///
    /// This method uses Quinn's built-in RTT estimates and connection state
    /// rather than opening invasive probe streams. Returns Some(rtt) if the
    /// connection appears healthy, None if it's closed or degraded.
    fn check_health_passive(&self) -> Option<Duration> {
        // First check if the connection has been explicitly closed
        if let Some(reason) = self.connection.close_reason() {
            trace!(
                remote = %self.connection.remote_address(),
                reason = ?reason,
                "connection closed, health check failed"
            );
            return None;
        }

        // Get the current RTT estimate from Quinn's path statistics.
        // Quinn continuously updates this based on ACK timing, so it reflects
        // actual connection health without requiring additional probes.
        let rtt = self.connection.rtt();

        // If RTT is zero, the connection might not have completed handshake
        // or has no recent path data. Treat as unknown/degraded.
        if rtt.is_zero() {
            trace!(
                remote = %self.connection.remote_address(),
                "connection has zero RTT estimate, may be stale"
            );
            // Return None to trigger degraded status rather than healthy
            return None;
        }

        // Check for unreasonably high RTT which indicates severe degradation
        let max_acceptable_rtt = Duration::from_millis(MAX_HEALTHY_RTT_MS as u64 * 2);
        if rtt > max_acceptable_rtt {
            trace!(
                remote = %self.connection.remote_address(),
                rtt_ms = rtt.as_millis(),
                "connection RTT exceeds maximum acceptable threshold"
            );
            return None;
        }

        Some(rtt)
    }
}

/// A transport-agnostic connection to a peer.
///
/// `SmartConnection` is the **primary connection type** returned by
/// [`QuinnNetwork::smart_connect`]. It abstracts away the underlying
/// transport mechanism (direct QUIC, relay, hole-punch), so consumers
/// can use it without worrying about NAT traversal or quinn internals.
///
/// # Why Use This Instead of `quinn::Connection`?
///
/// - **Automatic NAT handling**: Works behind any NAT type, including CGNAT
/// - **Transparent relay**: When direct fails, relay is used automatically
/// - **Upgrade probing**: Relayed connections probe for direct path upgrades
/// - **No quinn dependency needed**: Your code doesn't import or use quinn directly
///
/// # Usage
///
/// ```ignore
/// // Get connection - works regardless of NAT topology
/// let smart_conn = network.smart_connect(&endpoint_record).await?;
///
/// // Check connection type (optional - usually you don't need to care)
/// if smart_conn.is_direct() {
///     println!("Direct connection");
/// } else {
///     println!("Relayed - upgrade may happen automatically");
/// }
///
/// // Use the connection - same API regardless of type
/// let underlying = smart_conn.connection();
/// ```
#[derive(Debug, Clone)]
pub enum SmartConnection {
    /// Direct QUIC connection to the peer.
    Direct(Connection),
    /// Connection through a relay, session pending (waiting for peer).
    RelayPending {
        /// Connection to the relay node.
        relay_connection: Connection,
        /// Session ID for this relay session.
        session_id: [u8; 16],
        /// The relay's peer ID.
        relay_peer: Identity,
        /// Peer's direct addresses for upgrade attempts.
        direct_addrs: Vec<String>,
    },
    /// Active relayed connection (both peers connected).
    Relayed {
        /// Connection to the relay node.
        relay_connection: Connection,
        /// Session ID for this relay session.
        session_id: [u8; 16],
        /// The relay's peer ID.
        relay_peer: Identity,
        /// Peer's direct addresses for upgrade attempts.
        direct_addrs: Vec<String>,
    },
}

impl SmartConnection {
    /// Check if this is a direct connection.
    pub fn is_direct(&self) -> bool {
        matches!(self, SmartConnection::Direct(_))
    }

    /// Check if this is a relayed connection.
    pub fn is_relayed(&self) -> bool {
        matches!(self, SmartConnection::Relayed { .. } | SmartConnection::RelayPending { .. })
    }

    /// Get the underlying connection (relay connection for relayed).
    pub fn connection(&self) -> &Connection {
        match self {
            SmartConnection::Direct(conn) => conn,
            SmartConnection::RelayPending { relay_connection, .. } => relay_connection,
            SmartConnection::Relayed { relay_connection, .. } => relay_connection,
        }
    }

    /// Get the session ID if relayed.
    pub fn session_id(&self) -> Option<[u8; 16]> {
        match self {
            SmartConnection::Direct(_) => None,
            SmartConnection::RelayPending { session_id, .. } => Some(*session_id),
            SmartConnection::Relayed { session_id, .. } => Some(*session_id),
        }
    }

    /// Get peer's direct addresses (for upgrade attempts).
    pub fn direct_addrs(&self) -> Option<&[String]> {
        match self {
            SmartConnection::Direct(_) => None,
            SmartConnection::RelayPending { direct_addrs, .. } => Some(direct_addrs),
            SmartConnection::Relayed { direct_addrs, .. } => Some(direct_addrs),
        }
    }

    /// Check if this relayed connection can potentially be upgraded to direct.
    pub fn can_attempt_upgrade(&self) -> bool {
        match self {
            SmartConnection::Direct(_) => false,
            SmartConnection::RelayPending { direct_addrs, .. } => !direct_addrs.is_empty(),
            SmartConnection::Relayed { direct_addrs, .. } => !direct_addrs.is_empty(),
        }
    }
}

// ============================================================================
// Parallel Path Probing
// ============================================================================

/// Probe interval for checking alternate paths.
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// How long before a path is considered stale without probes.
pub const PATH_STALE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of probe failures before marking path as dead.
pub const MAX_PROBE_FAILURES: u32 = 3;

/// Maximum candidate paths per connection.
/// Prevents resource exhaustion from excessive path candidates.
const MAX_CANDIDATE_PATHS: usize = 16;

/// Maximum pending probes to track.
/// Prevents unbounded growth if responses are lost.
const MAX_PENDING_PROBES: usize = 64;

/// State of a path candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Path hasn't been probed yet.
    Unknown,
    /// Currently sending probes.
    Probing,
    /// Path is active and working.
    Active,
    /// Path failed too many probes.
    Failed,
}

/// A candidate network path to a peer.
#[derive(Debug, Clone)]
pub struct PathCandidate {
    /// The socket address for this path.
    pub addr: SocketAddr,
    /// Current state of this path.
    pub state: PathState,
    /// Is this the relay path (vs direct)?
    pub is_relay: bool,
    /// Smoothed RTT in milliseconds (exponential moving average).
    pub rtt_ms: Option<f32>,
    /// Last successful probe time.
    pub last_success: Option<Instant>,
    /// Last probe attempt time.
    pub last_probe: Option<Instant>,
    /// Consecutive probe failures.
    pub failures: u32,
    /// Probe sequence number for matching responses.
    probe_seq: u64,
}

impl PathCandidate {
    /// Create a new path candidate.
    pub fn new(addr: SocketAddr, is_relay: bool) -> Self {
        Self {
            addr,
            state: PathState::Unknown,
            is_relay,
            rtt_ms: None,
            last_success: None,
            last_probe: None,
            failures: 0,
            probe_seq: 0,
        }
    }

    /// Check if this path needs probing.
    pub fn needs_probe(&self) -> bool {
        match self.state {
            PathState::Failed => false,
            PathState::Unknown => true,
            PathState::Probing | PathState::Active => {
                self.last_probe
                    .map(|t| t.elapsed() >= PATH_PROBE_INTERVAL)
                    .unwrap_or(true)
            }
        }
    }

    /// Check if this path is usable for traffic.
    pub fn is_usable(&self) -> bool {
        matches!(self.state, PathState::Active | PathState::Probing)
            && self.last_success
                .map(|t| t.elapsed() < PATH_STALE_TIMEOUT)
                .unwrap_or(false)
    }

    /// Record a successful probe with RTT.
    pub fn record_success(&mut self, rtt: Duration) {
        let rtt_ms = rtt.as_secs_f32() * 1000.0;
        
        // Exponential moving average for RTT (alpha = 0.2)
        self.rtt_ms = Some(match self.rtt_ms {
            Some(prev) => prev * 0.8 + rtt_ms * 0.2,
            None => rtt_ms,
        });
        
        self.state = PathState::Active;
        self.last_success = Some(Instant::now());
        self.failures = 0;
    }

    /// Record a probe failure.
    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= MAX_PROBE_FAILURES {
            self.state = PathState::Failed;
        }
    }
}

/// Manages parallel path probing for a single peer connection.
///
/// Implements parallel path discovery:
/// 1. Maintains multiple candidate paths (direct + relay)
/// 2. Sends probes on all paths in parallel
/// 3. Tracks latency and selects best path
/// 4. QUIC connection migration handles path switching automatically
///
/// # Path Selection
///
/// The best path is chosen based on:
/// - Prefer direct over relay (if latency is within 50ms)
/// - Otherwise, prefer lowest latency path
///
/// # QUIC Connection Migration
///
/// Quinn handles connection migration automatically:
/// - Server accepts packets from new client addresses
/// - Client sends on preferred path; connection migrates seamlessly
/// - No new handshake needed (saves 1-2 RTTs)
///
/// # Security
///
/// Probe sequence numbers are generated using cryptographic randomness
/// to prevent attackers from guessing valid sequences. The pending_probes
/// map is strictly bounded to MAX_PENDING_PROBES entries.
#[derive(Debug)]
pub struct PathProber {
    /// The QUIC connection being managed.
    connection: Connection,
    /// Our local endpoint key (Ed25519 public key bytes).
    local_endpoint_key: [u8; 32],
    /// All candidate paths to the peer.
    paths: Vec<PathCandidate>,
    /// Index of currently active path.
    active_path: usize,
    /// Probe sequence counter - uses cryptographically random base.
    next_probe_seq: u64,
    /// Random offset added to probe sequences to prevent prediction.
    probe_seq_offset: u64,
    /// Pending probes: seq -> (path_index, send_time).
    pending_probes: HashMap<u64, (usize, Instant)>,
}

impl PathProber {
    /// Create a new path prober for an existing connection.
    pub fn new(connection: Connection, initial_addr: SocketAddr, is_relay: bool) -> Self {
        Self::with_endpoint_key(connection, initial_addr, is_relay, [0u8; 32])
    }

    /// Create a new path prober with a specific endpoint key.
    pub fn with_endpoint_key(
        connection: Connection,
        initial_addr: SocketAddr,
        is_relay: bool,
        endpoint_key: [u8; 32],
    ) -> Self {
        // Generate cryptographically random offset for probe sequences
        // This prevents attackers from guessing valid sequence numbers
        let mut offset_bytes = [0u8; 8];
        getrandom::getrandom(&mut offset_bytes).unwrap_or_else(|_| {
            // Fallback to timestamp-based if getrandom fails
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            offset_bytes = ts.to_le_bytes();
        });
        let probe_seq_offset = u64::from_le_bytes(offset_bytes);
        
        Self {
            connection,
            local_endpoint_key: endpoint_key,
            paths: vec![PathCandidate::new(initial_addr, is_relay)],
            active_path: 0,
            next_probe_seq: 1,
            probe_seq_offset,
            pending_probes: HashMap::new(),
        }
    }

    /// Add a candidate path to probe.
    /// Returns false if the path limit is reached or path already exists.
    pub fn add_candidate(&mut self, addr: SocketAddr, is_relay: bool) -> bool {
        // Don't add duplicates
        if self.paths.iter().any(|p| p.addr == addr) {
            return false;
        }
        
        // Enforce path limit
        if self.paths.len() >= MAX_CANDIDATE_PATHS {
            return false;
        }
        
        self.paths.push(PathCandidate::new(addr, is_relay));
        true
    }

    /// Add multiple direct address candidates from endpoint record.
    pub fn add_direct_candidates(&mut self, addrs: &[String]) {
        for addr_str in addrs {
            if let Ok(addr) = addr_str.parse() {
                let _ = self.add_candidate(addr, false);
            }
        }
    }

    /// Get the current active path's address.
    pub fn active_addr(&self) -> SocketAddr {
        self.paths[self.active_path].addr
    }

    /// Check if currently using a relay path.
    pub fn is_using_relay(&self) -> bool {
        self.paths[self.active_path].is_relay
    }

    /// Get the underlying QUIC connection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Get RTT of active path in milliseconds.
    pub fn active_rtt_ms(&self) -> Option<f32> {
        self.paths[self.active_path].rtt_ms
    }

    /// Get statistics about all paths.
    pub fn path_stats(&self) -> Vec<PathStats> {
        self.paths.iter().enumerate().map(|(i, p)| PathStats {
            addr: p.addr,
            is_relay: p.is_relay,
            is_active: i == self.active_path,
            state: p.state,
            rtt_ms: p.rtt_ms,
        }).collect()
    }

    /// Select the best path based on latency and type.
    ///
    /// Prefers direct paths unless relay is significantly faster (>50ms).
    fn select_best_path(&self) -> Option<usize> {
        let usable: Vec<_> = self.paths.iter()
            .enumerate()
            .filter(|(_, p)| p.is_usable())
            .collect();

        if usable.is_empty() {
            return None;
        }

        // Find best direct and best relay
        let best_direct = usable.iter()
            .filter(|(_, p)| !p.is_relay)
            .min_by(|(_, a), (_, b)| {
                a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal)
            });

        let best_relay = usable.iter()
            .filter(|(_, p)| p.is_relay)
            .min_by(|(_, a), (_, b)| {
                a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal)
            });

        match (best_direct, best_relay) {
            (Some((di, dp)), Some((ri, rp))) => {
                // Prefer direct unless relay is >50ms faster
                let direct_rtt = dp.rtt_ms.unwrap_or(f32::MAX);
                let relay_rtt = rp.rtt_ms.unwrap_or(f32::MAX);
                
                if relay_rtt + 50.0 < direct_rtt {
                    Some(*ri)
                } else {
                    Some(*di)
                }
            }
            (Some((i, _)), None) => Some(*i),
            (None, Some((i, _))) => Some(*i),
            (None, None) => None,
        }
    }

    /// Select a new active path.
    ///
    /// Note: quinn 0.11 handles QUIC connection migration automatically when
    /// packets arrive from a new address. This method marks the preferred path
    /// and returns whether the connection needs to be replaced (for relay→direct).
    ///
    /// Returns `Some((old_addr, new_addr))` if a different path was selected.
    pub fn select_path(&mut self, path_index: usize) -> Option<(SocketAddr, SocketAddr)> {
        if path_index >= self.paths.len() {
            return None;
        }

        let new_addr = self.paths[path_index].addr;
        let old_addr = self.paths[self.active_path].addr;

        if new_addr != old_addr {
            let old_is_relay = self.paths[self.active_path].is_relay;
            let new_is_relay = self.paths[path_index].is_relay;
            
            // Path changes are operationally significant - keep at info
            info!(
                from = %old_addr,
                to = %new_addr,
                from_relay = old_is_relay,
                to_relay = new_is_relay,
                "selected new preferred path"
            );
            
            self.active_path = path_index;
            return Some((old_addr, new_addr));
        }

        self.active_path = path_index;
        None
    }

    /// Check if we should switch to a better path.
    ///
    /// Returns `Some((old_addr, new_addr))` if a better path is available.
    /// Note: QUIC connection migration handles the actual path switch
    /// automatically when we send traffic on the new path.
    pub fn maybe_switch_path(&mut self) -> Option<(SocketAddr, SocketAddr)> {
        if let Some(best) = self.select_best_path() {
            if best != self.active_path {
                return self.select_path(best);
            }
        }
        None
    }

    /// Get the currently preferred path address.
    ///
    /// This is the address we should send traffic to.
    /// QUIC migration will handle the path switch when the peer responds.
    pub fn preferred_addr(&self) -> SocketAddr {
        self.paths[self.active_path].addr
    }

    /// Check if a direct path is available (even if not currently active).
    pub fn has_direct_path(&self) -> bool {
        self.paths.iter().any(|p| !p.is_relay && p.state == PathState::Active)
    }

    /// Generate probe packets for all paths that need probing.
    ///
    /// Returns list of (address, probe_data) to send.
    /// The probe_data should be sent as a QUIC datagram or ping.
    ///
    /// # Security
    ///
    /// Probe sequences are randomized using a cryptographically random offset
    /// to prevent attackers from guessing valid sequences. The pending_probes
    /// map is strictly bounded to MAX_PENDING_PROBES entries.
    pub fn generate_probes(&mut self) -> Vec<(SocketAddr, PathProbe)> {
        let now = Instant::now();
        let mut probes = Vec::new();

        for (idx, path) in self.paths.iter_mut().enumerate() {
            // Enforce pending probes limit strictly
            if self.pending_probes.len() >= MAX_PENDING_PROBES {
                debug!(
                    pending = self.pending_probes.len(),
                    "pending probes limit reached, skipping new probes"
                );
                break;
            }
            
            if path.needs_probe() {
                // Generate randomized sequence number
                // The offset makes sequences unpredictable to attackers
                let seq = self.next_probe_seq.wrapping_add(self.probe_seq_offset);
                self.next_probe_seq = self.next_probe_seq.wrapping_add(1);
                
                path.probe_seq = seq;
                path.last_probe = Some(now);
                path.state = PathState::Probing;
                
                self.pending_probes.insert(seq, (idx, now));
                
                probes.push((path.addr, PathProbe::new(seq, self.local_endpoint_key)));
            }
        }

        probes
    }

    /// Handle a probe response.
    ///
    /// Returns true if a better path was found (caller should check needs_new_connection).
    ///
    /// # Security
    ///
    /// Only processes probe responses that match a pending probe sequence.
    /// Unknown sequences are silently dropped to prevent memory exhaustion
    /// from spoofed responses.
    pub fn handle_probe_response(&mut self, seq: u64) -> bool {
        // Only process if we have a matching pending probe
        // This prevents attackers from injecting fake responses or
        // causing memory growth with unknown sequences
        if let Some((path_idx, send_time)) = self.pending_probes.remove(&seq) {
            let rtt = send_time.elapsed();
            
            // Validate path_idx is still valid (defensive check)
            if path_idx >= self.paths.len() {
                debug!(seq = seq, path_idx = path_idx, "probe response for invalid path index");
                return false;
            }
            
            if let Some(path) = self.paths.get_mut(path_idx) {
                path.record_success(rtt);
                
                debug!(
                    addr = %path.addr,
                    rtt_ms = rtt.as_secs_f32() * 1000.0,
                    is_relay = path.is_relay,
                    "probe response received"
                );
            }

            // Check if we should switch paths
            return self.maybe_switch_path().is_some();
        }
        
        // Unknown sequence - likely spoofed or stale probe
        trace!(seq = seq, "probe response for unknown sequence, ignoring");
        false
    }

    /// Mark paths as failed if probes timed out.
    pub fn expire_probes(&mut self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<_> = self.pending_probes.iter()
            .filter(|(_, (_, send_time))| now.duration_since(*send_time) > timeout)
            .map(|(seq, (idx, _))| (*seq, *idx))
            .collect();

        for (seq, path_idx) in expired {
            self.pending_probes.remove(&seq);
            if let Some(path) = self.paths.get_mut(path_idx) {
                path.record_failure();
                debug!(addr = %path.addr, "probe timeout");
            }
        }
    }

    /// Clean up stale paths that haven't worked in a while.
    pub fn cleanup_stale_paths(&mut self) {
        // Capture active path address before retain
        let active_addr = self.paths[self.active_path].addr;
        
        // Don't remove the active path or paths with recent success
        self.paths.retain(|p| {
            p.state != PathState::Failed || p.addr == active_addr
        });
        
        // Recalculate active_path index after potential removal
        self.active_path = self.paths.iter()
            .position(|p| p.addr == active_addr)
            .unwrap_or(0);
    }
}

// ============================================================================
// Path Discovery Protocol
// ============================================================================

/// Magic bytes for path discovery messages.
const PATH_MAGIC: &[u8; 4] = b"QMPD";

/// Message type identifiers.
const MSG_PATH_PROBE: u8 = 0x01;
const MSG_PATH_REPLY: u8 = 0x02;
const MSG_REACH_ME: u8 = 0x03;

/// A path probe message sent to discover and measure paths.
///
/// Similar to STUN binding request - opens NAT holes and measures latency.
#[derive(Debug, Clone)]
pub struct PathProbe {
    /// Transaction ID for matching replies.
    pub tx_id: u64,
    /// Sender's endpoint key (Ed25519 public key, first 32 bytes).
    pub endpoint_key: [u8; 32],
    /// Timestamp when probe was sent (Unix millis).
    pub timestamp_ms: u64,
}

impl PathProbe {
    /// Create a new path probe.
    pub fn new(tx_id: u64, endpoint_key: [u8; 32]) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            tx_id,
            endpoint_key,
            timestamp_ms,
        }
    }

    /// Serialize for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(53);
        buf.extend_from_slice(PATH_MAGIC);
        buf.push(MSG_PATH_PROBE);
        buf.extend_from_slice(&self.tx_id.to_le_bytes());
        buf.extend_from_slice(&self.endpoint_key);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 53 || &data[0..4] != PATH_MAGIC || data[4] != MSG_PATH_PROBE {
            return None;
        }
        Some(Self {
            tx_id: u64::from_le_bytes(data[5..13].try_into().ok()?),
            endpoint_key: data[13..45].try_into().ok()?,
            timestamp_ms: u64::from_le_bytes(data[45..53].try_into().ok()?),
        })
    }

    /// Create a reply to this probe.
    pub fn to_reply(&self, observed_addr: SocketAddr) -> PathReply {
        PathReply {
            tx_id: self.tx_id,
            observed_addr,
            echo_timestamp_ms: self.timestamp_ms,
        }
    }
}

/// Reply to a path probe, confirming connectivity and reporting observed address.
///
/// The observed_addr field acts like STUN - tells the sender what their
/// public IP:port looks like from the responder's perspective.
#[derive(Debug, Clone)]
pub struct PathReply {
    /// Transaction ID (echoed from probe).
    pub tx_id: u64,
    /// Sender's observed public address (STUN-like).
    pub observed_addr: SocketAddr,
    /// Echoed timestamp for RTT calculation.
    pub echo_timestamp_ms: u64,
}

impl PathReply {
    /// Serialize for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(PATH_MAGIC);
        buf.push(MSG_PATH_REPLY);
        buf.extend_from_slice(&self.tx_id.to_le_bytes());
        buf.extend_from_slice(&self.echo_timestamp_ms.to_le_bytes());
        
        // Encode observed address
        match self.observed_addr {
            SocketAddr::V4(addr) => {
                buf.push(4); // IPv4 marker
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_le_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.push(6); // IPv6 marker
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_le_bytes());
            }
        }
        buf
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 23 || &data[0..4] != PATH_MAGIC || data[4] != MSG_PATH_REPLY {
            return None;
        }
        
        let tx_id = u64::from_le_bytes(data[5..13].try_into().ok()?);
        let echo_timestamp_ms = u64::from_le_bytes(data[13..21].try_into().ok()?);
        
        let observed_addr = match data[21] {
            4 if data.len() >= 28 => {
                let ip = std::net::Ipv4Addr::new(data[22], data[23], data[24], data[25]);
                let port = u16::from_le_bytes(data[26..28].try_into().ok()?);
                SocketAddr::from((ip, port))
            }
            6 if data.len() >= 40 => {
                let octets: [u8; 16] = data[22..38].try_into().ok()?;
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_le_bytes(data[38..40].try_into().ok()?);
                SocketAddr::from((ip, port))
            }
            _ => return None,
        };
        
        Some(Self {
            tx_id,
            observed_addr,
            echo_timestamp_ms,
        })
    }

    /// Calculate RTT from the echoed timestamp.
    pub fn rtt_ms(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now.saturating_sub(self.echo_timestamp_ms)
    }
}

/// Request to attempt direct connection - sent via relay.
///
/// Contains all our endpoints so the peer can probe them directly.
/// This is the trigger for NAT hole punching coordination.
#[derive(Debug, Clone)]
pub struct ReachMe {
    /// Our endpoint key (Ed25519 public key).
    pub endpoint_key: [u8; 32],
    /// All our known endpoints (local + STUN-discovered).
    pub endpoints: Vec<SocketAddr>,
}

impl ReachMe {
    /// Create a new ReachMe message.
    pub fn new(endpoint_key: [u8; 32], endpoints: Vec<SocketAddr>) -> Self {
        Self { endpoint_key, endpoints }
    }

    /// Serialize for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(37 + self.endpoints.len() * 19);
        buf.extend_from_slice(PATH_MAGIC);
        buf.push(MSG_REACH_ME);
        buf.extend_from_slice(&self.endpoint_key);
        buf.push(self.endpoints.len() as u8);
        
        for addr in &self.endpoints {
            match addr {
                SocketAddr::V4(a) => {
                    buf.push(4);
                    buf.extend_from_slice(&a.ip().octets());
                    buf.extend_from_slice(&a.port().to_le_bytes());
                }
                SocketAddr::V6(a) => {
                    buf.push(6);
                    buf.extend_from_slice(&a.ip().octets());
                    buf.extend_from_slice(&a.port().to_le_bytes());
                }
            }
        }
        buf
    }

    /// Parse from bytes.
    ///
    /// # Security
    ///
    /// Validates that the data buffer contains enough bytes for the declared
    /// endpoint count before allocating memory, preventing memory exhaustion
    /// attacks from maliciously crafted packets.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 38 || &data[0..4] != PATH_MAGIC || data[4] != MSG_REACH_ME {
            return None;
        }
        
        let endpoint_key: [u8; 32] = data[5..37].try_into().ok()?;
        let count = data[37] as usize;
        
        // Security: Validate minimum data length before allocation
        // Each endpoint requires at least 7 bytes (1 type + 4 IPv4 + 2 port)
        // This prevents memory exhaustion from packets claiming many endpoints
        // but not actually containing the data
        let min_bytes_needed = 38 + count * 7; // header + count * min_endpoint_size
        if data.len() < min_bytes_needed {
            return None;
        }
        
        // Cap allocation to prevent excessive memory use even with valid data
        // 255 endpoints is the protocol max (u8 count), but we limit further
        const MAX_ENDPOINTS: usize = 64;
        if count > MAX_ENDPOINTS {
            return None;
        }
        
        let mut endpoints = Vec::with_capacity(count);
        let mut pos = 38;
        
        for _ in 0..count {
            if pos >= data.len() {
                break;
            }
            match data[pos] {
                4 if pos + 7 <= data.len() => {
                    let ip = std::net::Ipv4Addr::new(
                        data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]
                    );
                    let port = u16::from_le_bytes(data[pos + 5..pos + 7].try_into().ok()?);
                    endpoints.push(SocketAddr::from((ip, port)));
                    pos += 7;
                }
                6 if pos + 19 <= data.len() => {
                    let octets: [u8; 16] = data[pos + 1..pos + 17].try_into().ok()?;
                    let ip = std::net::Ipv6Addr::from(octets);
                    let port = u16::from_le_bytes(data[pos + 17..pos + 19].try_into().ok()?);
                    endpoints.push(SocketAddr::from((ip, port)));
                    pos += 19;
                }
                _ => break,
            }
        }
        
        Some(Self { endpoint_key, endpoints })
    }
}

/// All path discovery message types.
#[derive(Debug, Clone)]
pub enum PathMessage {
    /// Probe to discover/measure a path.
    Probe(PathProbe),
    /// Reply confirming path with observed address.
    Reply(PathReply),
    /// Request to attempt direct connection.
    ReachMe(ReachMe),
}

impl PathMessage {
    /// Parse any path discovery message from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 5 || &data[0..4] != PATH_MAGIC {
            return None;
        }
        match data[4] {
            MSG_PATH_PROBE => PathProbe::from_bytes(data).map(PathMessage::Probe),
            MSG_PATH_REPLY => PathReply::from_bytes(data).map(PathMessage::Reply),
            MSG_REACH_ME => ReachMe::from_bytes(data).map(PathMessage::ReachMe),
            _ => None,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PathMessage::Probe(p) => p.to_bytes(),
            PathMessage::Reply(r) => r.to_bytes(),
            PathMessage::ReachMe(r) => r.to_bytes(),
        }
    }
}

/// Statistics for a single path.
#[derive(Debug, Clone)]
pub struct PathStats {
    /// Socket address of this path.
    pub addr: SocketAddr,
    /// Whether this is a relay path.
    pub is_relay: bool,
    /// Whether this is the currently active path.
    pub is_active: bool,
    /// Current state.
    pub state: PathState,
    /// Smoothed RTT in milliseconds.
    pub rtt_ms: Option<f32>,
}

// ============================================================================
// Connection Manager with Parallel Path Probing
// ============================================================================

/// Probe timeout duration.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Manages peer connections with parallel path probing.
///
/// Uses parallel path discovery:
/// 1. Tracks multiple candidate paths per peer (direct + relay)
/// 2. Sends probes on all paths in parallel
/// 3. Measures latency and tracks best path
/// 4. QUIC connection migration handles path switching automatically
///
/// # QUIC Connection Migration
///
/// Quinn handles migration seamlessly:
/// - When we send on a new path, the server accepts the new source address
/// - The connection migrates without a new handshake
/// - This saves 1-2 RTTs compared to creating a new connection
///
/// # Example
///
/// ```ignore
/// let manager = Arc::new(ConnectionManager::new());
///
/// // Register a connection with its initial path
/// manager.register_with_paths(
///     peer_id,
///     connection,
///     initial_addr,
///     is_relay,
///     &direct_addrs,
/// ).await;
///
/// // Start background probing loop
/// let handle = manager.clone().spawn_probe_loop();
///
/// // Get preferred address for sending (may have changed)
/// if let Some(addr) = manager.preferred_addr(&peer_id).await {
///     // Send traffic to this address - QUIC migrates automatically
/// }
/// ```
pub struct ConnectionManager {
    /// Path probers per peer (bounded LruCache to prevent memory exhaustion).
    probers: RwLock<LruCache<Identity, PathProber>>,
    /// Shared UDP socket for probes to avoid FD exhaustion.
    probe_socket: RwLock<Option<Arc<tokio::net::UdpSocket>>>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new() -> Self {
        Self {
            probers: RwLock::new(LruCache::new(
                NonZeroUsize::new(MAX_PATH_PROBERS).unwrap()
            )),
            probe_socket: RwLock::new(None),
        }
    }

    /// Register a connection with parallel path probing.
    pub async fn register_with_paths(
        &self,
        peer_id: Identity,
        connection: Connection,
        initial_addr: SocketAddr,
        is_relay: bool,
        direct_addrs: &[String],
    ) {
        let mut prober = PathProber::new(connection, initial_addr, is_relay);
        prober.add_direct_candidates(direct_addrs);
        
        let mut probers = self.probers.write().await;
        // LruCache automatically evicts least-recently-used entries when full
        probers.put(peer_id, prober);
    }

    /// Register a SmartConnection for path probing.
    pub async fn register(&self, peer_id: Identity, smart_conn: SmartConnection) {
        let (connection, initial_addr, is_relay, direct_addrs) = match &smart_conn {
            SmartConnection::Direct(conn) => {
                let addr = conn.remote_address();
                (conn.clone(), addr, false, vec![])
            }
            SmartConnection::RelayPending { relay_connection, direct_addrs, .. } |
            SmartConnection::Relayed { relay_connection, direct_addrs, .. } => {
                let addr = relay_connection.remote_address();
                (relay_connection.clone(), addr, true, direct_addrs.clone())
            }
        };

        self.register_with_paths(peer_id, connection, initial_addr, is_relay, &direct_addrs).await;
    }

    /// Add direct address candidates for a peer.
    pub async fn add_direct_candidates(&self, peer_id: &Identity, addrs: &[String]) {
        let mut probers = self.probers.write().await;
        if let Some(prober) = probers.get_mut(peer_id) {
            prober.add_direct_candidates(addrs);
        }
    }

    /// Get the current connection for a peer.
    pub async fn get(&self, peer_id: &Identity) -> Option<Connection> {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| p.connection().clone())
    }

    /// Check if connection to peer is currently using direct path.
    pub async fn is_direct(&self, peer_id: &Identity) -> bool {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| !p.is_using_relay()).unwrap_or(false)
    }

    /// Get the active path's RTT for a peer.
    pub async fn active_rtt_ms(&self, peer_id: &Identity) -> Option<f32> {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).and_then(|p| p.active_rtt_ms())
    }

    /// Remove a connection.
    pub async fn remove(&self, peer_id: &Identity) {
        let mut probers = self.probers.write().await;
        probers.pop(peer_id);
    }

    /// Probe all paths for all peers and handle migrations.
    ///
    /// This sends probe packets on all candidate paths and processes
    /// any pending probe responses.
    pub async fn probe_all_paths(&self) {
        // Generate probes for all peers
        let probes: Vec<(Identity, Vec<(SocketAddr, PathProbe)>)> = {
            let mut probers = self.probers.write().await;
            probers.iter_mut()
                .map(|(peer_id, prober)| {
                    // Expire old probes first
                    prober.expire_probes(PROBE_TIMEOUT);
                    (*peer_id, prober.generate_probes())
                })
                .filter(|(_, probes)| !probes.is_empty())
                .collect()
        };

        // Send probes (could be done in parallel with tokio::spawn)
        for (peer_id, path_probes) in probes {
            for (addr, probe) in path_probes {
                // Send probe using QUIC datagrams or endpoint socket
                if let Err(e) = self.send_probe(addr, &probe).await {
                    debug!(peer = ?peer_id, addr = %addr, error = %e, "failed to send probe");
                }
            }
        }
    }

    /// Send a probe packet to an address.
    ///
    /// Uses a shared UDP socket to avoid FD exhaustion from creating new sockets
    /// for every probe. The socket is lazily initialized on first use.
    async fn send_probe(&self, addr: SocketAddr, probe: &PathProbe) -> Result<()> {
        let probe_bytes = probe.to_bytes();
        
        // Get or create shared probe socket (lazy initialization)
        let socket = {
            let mut socket_guard = self.probe_socket.write().await;
            if socket_guard.is_none() {
                let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                *socket_guard = Some(Arc::new(udp));
            }
            socket_guard.as_ref().unwrap().clone()
        };
        
        // Send probe using shared socket
        socket.send_to(&probe_bytes, addr).await?;
        debug!(addr = %addr, seq = probe.tx_id, "sent probe");
        Ok(())
    }

    /// Handle a probe response for a peer.
    ///
    /// Returns true if a better path was found.
    /// Note: QUIC migration handles the actual path switch automatically.
    pub async fn handle_probe_response(&self, peer_id: &Identity, seq: u64) -> bool {
        let mut probers = self.probers.write().await;
        if let Some(prober) = probers.get_mut(peer_id) {
            let better_path_found = prober.handle_probe_response(seq);
            if better_path_found {
                let addr = prober.preferred_addr();
                info!(peer = ?peer_id, addr = %addr, "better path found, QUIC will migrate on next send");
            }
            return better_path_found;
        }
        false
    }

    /// Get the preferred address for sending to a peer.
    ///
    /// This is the best path based on latency measurements.
    /// Send traffic to this address and QUIC migration will handle the rest.
    pub async fn preferred_addr(&self, peer_id: &Identity) -> Option<SocketAddr> {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| p.preferred_addr())
    }

    /// Check if a direct path is available for a peer.
    pub async fn has_direct_path(&self, peer_id: &Identity) -> bool {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| p.has_direct_path()).unwrap_or(false)
    }

    /// Spawn a background task for continuous path probing.
    ///
    /// This task probes all paths periodically to measure latency.
    /// QUIC connection migration handles path switching automatically
    /// when traffic is sent on the preferred path.
    pub fn spawn_probe_loop(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PATH_PROBE_INTERVAL);
            loop {
                interval.tick().await;
                self.probe_all_paths().await;
            }
        })
    }

    /// Get path statistics for a peer.
    pub async fn path_stats(&self, peer_id: &Identity) -> Option<Vec<PathStats>> {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| p.path_stats())
    }

    /// Get overall connection statistics.
    pub async fn stats(&self) -> ConnectionStats {
        let probers = self.probers.write().await;
        let total = probers.len();
        let direct = probers.iter().filter(|(_, p)| !p.is_using_relay()).count();
        let relayed = total - direct;
        let upgradeable = probers.iter()
            .filter(|(_, p)| p.is_using_relay() && p.paths.iter().any(|path| !path.is_relay))
            .count();
        
        ConnectionStats {
            total,
            direct,
            relayed,
            upgradeable,
        }
    }
}

/// Statistics about managed connections.
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Total number of connections.
    pub total: usize,
    /// Number of connections using direct paths.
    pub direct: usize,
    /// Number of connections using relay paths.
    pub relayed: usize,
    /// Number of relayed connections with direct candidates to try.
    pub upgradeable: usize,
}

// ============================================================================
// QUIC Hole Punching (per arXiv:2408.01791)
// ============================================================================

/// State of a hole punch attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolePunchState {
    /// Discovering our public address via STUN.
    DiscoveringAddress,
    /// Waiting for peer at rendezvous server.
    WaitingForPeer,
    /// Both peers ready, attempting simultaneous open.
    Punching,
    /// Hole punch succeeded.
    Success,
    /// Hole punch failed.
    Failed(String),
}

/// Result of a hole punch attempt.
#[derive(Debug)]
pub struct HolePunchResult {
    /// Final state of the punch attempt.
    pub state: HolePunchState,
    /// The established connection if successful.
    pub connection: Option<Connection>,
    /// Our public address as discovered.
    pub our_public_addr: Option<SocketAddr>,
    /// Peer's public address.
    pub peer_public_addr: Option<SocketAddr>,
    /// Time taken for the hole punch.
    pub duration: Duration,
}

/// QUIC-based hole punching implementation.
///
/// Based on arXiv:2408.01791 "Implementing NAT Hole Punching with QUIC".
///
/// # Algorithm
///
/// 1. **Address Discovery**: Both peers query STUN servers to learn their public addresses
/// 2. **Rendezvous**: Peers exchange addresses via DHT or rendezvous server
/// 3. **Simultaneous Open**: Both peers send QUIC Initial packets at the same time
/// 4. **Fallback**: If punch fails, fall back to relay
///
/// # Advantages over TCP (from the paper)
///
/// - 1-RTT handshake vs 3-way TCP handshake
/// - Better performance in weak networks
/// - Connection migration saves 2-3 RTTs on reconnection
#[derive(Debug)]
pub struct HolePuncher {
    /// The QUIC endpoint.
    endpoint: Endpoint,
    /// Client config for connections.
    client_config: ClientConfig,
    /// Our peer ID.
    our_peer_id: Identity,
    /// Current state.
    state: HolePunchState,
    /// Our discovered public address.
    our_public_addr: Option<SocketAddr>,
}

impl HolePuncher {
    /// Create a new hole puncher.
    pub fn new(endpoint: Endpoint, client_config: ClientConfig, our_peer_id: Identity) -> Self {
        Self {
            endpoint,
            client_config,
            our_peer_id,
            state: HolePunchState::DiscoveringAddress,
            our_public_addr: None,
        }
    }

    /// Discover our public address using STUN-like queries.
    ///
    /// Queries multiple DHT nodes and returns the most common response.
    pub async fn discover_public_addr(
        &mut self,
        stun_contacts: &[Contact],
        network: &QuinnNetwork,
    ) -> Result<SocketAddr> {
        self.state = HolePunchState::DiscoveringAddress;
        
        let (consistent, all_addrs) = network.discover_public_addr(stun_contacts, 3).await;
        
        if let Some(addr) = consistent {
            self.our_public_addr = Some(addr);
            debug!(addr = %addr, "discovered public address (consistent)");
            Ok(addr)
        } else if let Some(addr) = all_addrs.first() {
            // Use first address if no consensus (might be symmetric NAT)
            self.our_public_addr = Some(*addr);
            debug!(addr = %addr, all = ?all_addrs, "discovered public address (inconsistent - possible symmetric NAT)");
            Ok(*addr)
        } else {
            anyhow::bail!("failed to discover public address - no STUN responses")
        }
    }

    /// Attempt hole punch to a peer.
    ///
    /// This implements the simultaneous open technique:
    /// 1. Both peers have each other's public addresses
    /// 2. Both send QUIC Initial packets at approximately the same time
    /// 3. NAT creates mappings in both directions
    /// 4. One connection succeeds (the other is ignored)
    pub async fn punch(
        &mut self,
        peer_public_addr: SocketAddr,
        peer_id: &Identity,
    ) -> Result<Connection> {
        self.state = HolePunchState::Punching;
        let start = Instant::now();
        
        info!(
            peer = ?peer_id,
            peer_addr = %peer_public_addr,
            our_addr = ?self.our_public_addr,
            "attempting QUIC hole punch"
        );

        // Send multiple connection attempts in quick succession
        // This increases the chance of NAT mapping before timeout
        let mut attempts = Vec::new();
        for i in 0..3 {
            // Use the peer's identity (public key) as the SNI.
            // The custom Ed25519CertVerifier will verify that the peer's certificate
            // public key matches this identity during the handshake.
            let sni = identity_to_sni(&peer_id);
            let connecting = self.endpoint.connect_with(
                self.client_config.clone(),
                peer_public_addr,
                &sni,
            );
            
            match connecting {
                Ok(connecting) => attempts.push(connecting),
                Err(e) => {
                    debug!(attempt = i, error = %e, "hole punch attempt failed to initiate");
                }
            }
            
            // Stagger attempts slightly
            if i < 2 {
                tokio::time::sleep(HOLE_PUNCH_STAGGER).await;
            }
        }
        
        if attempts.is_empty() {
            self.state = HolePunchState::Failed("failed to initiate any connection attempts".into());
            anyhow::bail!("hole punch failed: no connection attempts initiated");
        }

        // Race all attempts with timeout
        let timeout = tokio::time::sleep(HOLE_PUNCH_TIMEOUT);
        tokio::pin!(timeout);

        // Use select to race all connection attempts
        let result = tokio::select! {
            _ = &mut timeout => {
                Err(anyhow::anyhow!("hole punch timed out"))
            }
            result = Self::race_connections(attempts) => {
                result
            }
        };

        match result {
            Ok(conn) => {
                // Identity verification is now handled during the TLS handshake via SNI pinning.
                // If we reached this point, the peer's identity is already verified.
                
                let duration = start.elapsed();
                self.state = HolePunchState::Success;
                info!(
                    peer = ?peer_id,
                    duration_ms = duration.as_millis(),
                    "hole punch succeeded (identity verified via SNI)"
                );
                Ok(conn)
            }
            Err(e) => {
                self.state = HolePunchState::Failed(e.to_string());
                debug!(peer = ?peer_id, error = %e, "hole punch failed");
                Err(e)
            }
        }
    }

    /// Race multiple connection attempts, return first success.
    async fn race_connections(
        attempts: Vec<quinn::Connecting>,
    ) -> Result<Connection> {
        use futures::future::select_all;
        
        let futures: Vec<_> = attempts
            .into_iter()
            .map(Box::pin)
            .collect();
        
        if futures.is_empty() {
            anyhow::bail!("no connection attempts");
        }

        let mut remaining = futures;
        
        while !remaining.is_empty() {
            let (result, _index, rest) = select_all(remaining).await;
            match result {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    debug!(error = %e, "connection attempt failed");
                    remaining = rest;
                }
            }
        }
        
        anyhow::bail!("all hole punch attempts failed")
    }

    /// Attempt hole punch with rendezvous coordination.
    ///
    /// Uses a rendezvous server to synchronize the punch timing.
    pub async fn punch_with_rendezvous(
        &mut self,
        target_peer: &Identity,
        rendezvous_contact: &Contact,
        network: &QuinnNetwork,
    ) -> Result<HolePunchResult> {
        let start = Instant::now();
        
        // Step 1: Discover our public address if not known
        if self.our_public_addr.is_none() {
            self.discover_public_addr(std::slice::from_ref(rendezvous_contact), network).await?;
        }
        // Use ok_or_else for better error handling
        let our_addr = self.our_public_addr
            .ok_or_else(|| anyhow::anyhow!("failed to discover public address"))?;
        
        // Step 2: Generate punch session ID
        let mut punch_id = [0u8; 16];
        // Handle getrandom failure gracefully with fallback
        if getrandom::getrandom(&mut punch_id).is_err() {
            // Fallback: use timestamp + counter as entropy source
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            punch_id[..8].copy_from_slice(&(ts as u64).to_le_bytes());
            punch_id[8..].copy_from_slice(&(ts.wrapping_mul(31337) as u64).to_le_bytes());
        }
        
        // Step 3: Register with rendezvous server
        self.state = HolePunchState::WaitingForPeer;
        debug!(
            target = ?target_peer,
            rendezvous = %rendezvous_contact.addr,
            "registering for hole punch"
        );
        
        let register_request = DhtRequest::HolePunchRegister {
            from_peer: self.our_peer_id,
            target_peer: *target_peer,
            our_public_addr: our_addr.to_string(),
            punch_id,
        };
        
        let response = network.rpc(rendezvous_contact, register_request).await?;
        
        let peer_addr: SocketAddr = match response {
            DhtResponse::HolePunchReady { peer_addr, start_time_ms, .. } => {
                // Calculate wait time with clock skew tolerance
                let now_ms = crate::now_ms();
                
                // Calculate how long to wait based on start_time
                let raw_wait_ms = if start_time_ms > now_ms {
                    start_time_ms - now_ms
                } else {
                    // Server's clock is behind ours, but we should still wait a bit
                    // to give the peer time to also receive their response
                    0
                };
                
                // Apply minimum and maximum bounds
                let wait_ms = raw_wait_ms
                    .max(HOLE_PUNCH_MIN_WAIT_MS)  // Always wait at least minimum
                    .min(HOLE_PUNCH_MAX_WAIT_MS); // Never wait longer than maximum
                
                if wait_ms != raw_wait_ms {
                    debug!(
                        raw_wait_ms = raw_wait_ms,
                        adjusted_wait_ms = wait_ms,
                        "adjusted hole punch wait time for clock skew tolerance"
                    );
                }
                
                let wait = Duration::from_millis(wait_ms);
                debug!(wait_ms = wait.as_millis(), "waiting for synchronized punch start");
                tokio::time::sleep(wait).await;
                
                peer_addr.parse()
                    .context("invalid peer address from rendezvous")?
            }
            DhtResponse::HolePunchWaiting { .. } => {
                // We registered first, wait for peer
                debug!("waiting for peer to register...");
                
                // Poll for ready signal
                let deadline = Instant::now() + HOLE_PUNCH_RENDEZVOUS_TIMEOUT;
                loop {
                    if Instant::now() >= deadline {
                        return Ok(HolePunchResult {
                            state: HolePunchState::Failed("peer did not register in time".into()),
                            connection: None,
                            our_public_addr: Some(our_addr),
                            peer_public_addr: None,
                            duration: start.elapsed(),
                        });
                    }
                    
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    
                    // Check if peer has registered (poll with start request)
                    let poll = DhtRequest::HolePunchStart { punch_id };
                    if let Ok(DhtResponse::HolePunchReady { peer_addr, .. }) = 
                        network.rpc(rendezvous_contact, poll).await 
                    {
                        break peer_addr.parse()
                            .context("invalid peer address from rendezvous")?;
                    }
                }
            }
            DhtResponse::HolePunchFailed { reason } => {
                return Ok(HolePunchResult {
                    state: HolePunchState::Failed(reason),
                    connection: None,
                    our_public_addr: Some(our_addr),
                    peer_public_addr: None,
                    duration: start.elapsed(),
                });
            }
            other => {
                return Ok(HolePunchResult {
                    state: HolePunchState::Failed(format!("unexpected response: {:?}", other)),
                    connection: None,
                    our_public_addr: Some(our_addr),
                    peer_public_addr: None,
                    duration: start.elapsed(),
                });
            }
        };
        
        // Step 4: Perform simultaneous open
        match self.punch(peer_addr, target_peer).await {
            Ok(conn) => Ok(HolePunchResult {
                state: HolePunchState::Success,
                connection: Some(conn),
                our_public_addr: Some(our_addr),
                peer_public_addr: Some(peer_addr),
                duration: start.elapsed(),
            }),
            Err(e) => Ok(HolePunchResult {
                state: HolePunchState::Failed(e.to_string()),
                connection: None,
                our_public_addr: Some(our_addr),
                peer_public_addr: Some(peer_addr),
                duration: start.elapsed(),
            }),
        }
    }

    /// Get current state.
    pub fn state(&self) -> &HolePunchState {
        &self.state
    }

    /// Get our discovered public address.
    pub fn public_addr(&self) -> Option<SocketAddr> {
        self.our_public_addr
    }
}

/// High-level network layer with automatic NAT traversal.
///
/// `QuinnNetwork` provides the [`smart_connect`][Self::smart_connect] method, which is the
/// **recommended way to connect to peers**. It handles all transport complexity internally:
///
/// - Direct QUIC connections when possible
/// - Automatic relay fallback for Symmetric NAT (CGNAT)
/// - NAT type detection via [`detect_nat`][Self::detect_nat]
/// - Connection caching and reuse
///
/// # Recommended Usage
///
/// ```ignore
/// // Create network (quinn setup happens once at startup)
/// let network = QuinnNetwork::with_identity(endpoint, contact, config, identity);
///
/// // Detect NAT type during bootstrap
/// network.detect_nat(&bootstrap_contacts).await;
///
/// // Connect to any peer—NAT traversal is automatic!
/// let conn = network.smart_connect(&peer_record).await?;
/// ```
///
/// # Why This Abstracts Quinn
///
/// Consumers don't need to interact with quinn directly. The `smart_connect` method
/// returns a [`SmartConnection`] that works across all network topologies. Quinn is
/// an implementation detail—your application code never imports `quinn::*`.
///
/// # NAT Traversal
///
/// When direct connection fails, the network will attempt to connect via relay
/// nodes. Both endpoints connect outbound to the relay (which always traverses
/// NAT), and the relay forwards E2E-encrypted packets it cannot read.
#[derive(Clone)]
pub struct QuinnNetwork {
    /// The quinn endpoint used for QUIC connections.
    pub endpoint: Endpoint,
    /// Contact info for the local node (included in all RPC requests).
    pub self_contact: Contact,
    /// Client configuration for outgoing connections.
    client_config: ClientConfig,
    /// Our own peer ID for relay negotiations.
    our_peer_id: Option<Identity>,
    /// Relay client for NAT traversal.
    relay_client: Arc<RelayClient>,
    /// Detected NAT type (for connection strategy decisions).
    nat_type: Arc<RwLock<NatType>>,
    /// Our public address as seen by STUN servers.
    public_addr: Arc<RwLock<Option<SocketAddr>>>,
    /// Cached connections to peers for connection reuse.
    /// QUIC connections are long-lived and multiplexed, so we reuse them
    /// rather than creating a new connection for each RPC.
    /// Uses LruCache to prevent unbounded memory growth.
    /// Uses CachedConnection to track liveness.
    connections: Arc<RwLock<LruCache<Identity, CachedConnection>>>,
}

impl QuinnNetwork {
    /// Create a new QuinnNetwork with the given endpoint and self contact.
    pub fn new(endpoint: Endpoint, self_contact: Contact, client_config: ClientConfig) -> Self {
        Self {
            endpoint,
            self_contact,
            client_config,
            our_peer_id: None,
            relay_client: Arc::new(RelayClient::new()),
            nat_type: Arc::new(RwLock::new(NatType::Unknown)),
            public_addr: Arc::new(RwLock::new(None)),
            connections: Arc::new(RwLock::new(LruCache::<Identity, CachedConnection>::new(
                NonZeroUsize::new(MAX_CACHED_CONNECTIONS).unwrap()
            ))),
        }
    }

    /// Create a QuinnNetwork with our Identity for relay negotiations.
    pub fn with_identity(
        endpoint: Endpoint,
        self_contact: Contact,
        client_config: ClientConfig,
        our_peer_id: Identity,
    ) -> Self {
        Self {
            endpoint,
            self_contact,
            client_config,
            our_peer_id: Some(our_peer_id),
            relay_client: Arc::new(RelayClient::new()),
            nat_type: Arc::new(RwLock::new(NatType::Unknown)),
            public_addr: Arc::new(RwLock::new(None)),
            connections: Arc::new(RwLock::new(LruCache::<Identity, CachedConnection>::new(
                NonZeroUsize::new(MAX_CACHED_CONNECTIONS).unwrap()
            ))),
        }
    }

    /// Get the relay client for managing relay connections.
    pub fn relay_client(&self) -> &Arc<RelayClient> {
        &self.relay_client
    }

    /// Get our detected NAT type.
    pub async fn nat_type(&self) -> NatType {
        *self.nat_type.read().await
    }

    /// Get our public address (if detected).
    pub async fn public_addr(&self) -> Option<SocketAddr> {
        *self.public_addr.read().await
    }

    /// Detect our NAT type by querying multiple STUN-like servers.
    ///
    /// This should be called during initialization with at least 2 bootstrap contacts.
    /// The method queries each contact for our public address and determines:
    /// - If addresses match: Cone NAT (hole punch may work)
    /// - If addresses differ: Symmetric NAT (need relay for CGNAT↔CGNAT)
    ///
    /// # Arguments
    ///
    /// * `stun_contacts` - At least 2 contacts to query for address discovery
    ///
    /// # Returns
    ///
    /// The detected NAT type. Also stored internally for `smart_connect` decisions.
    pub async fn detect_nat(&self, stun_contacts: &[Contact]) -> NatType {
        if stun_contacts.len() < 2 {
            debug!("not enough STUN contacts for NAT detection, need at least 2");
            return NatType::Unknown;
        }

        // Query first two contacts for our public address
        let mut mapped_addrs: Vec<SocketAddr> = Vec::new();
        
        for contact in stun_contacts.iter().take(2) {
            match self.what_is_my_addr(contact).await {
                Ok(addr) => {
                    mapped_addrs.push(addr);
                }
                Err(e) => {
                    debug!(contact = %contact.addr, error = %e, "STUN query failed");
                }
            }
        }

        // Parse our local address for comparison
        let local_addr: SocketAddr = self.self_contact.addr.parse().unwrap_or_else(|_| {
            "0.0.0.0:0".parse().unwrap()
        });

        // Detect NAT type
        let report = detect_nat_type(
            mapped_addrs.first().copied(),
            mapped_addrs.get(1).copied(),
            local_addr,
        );

        // Store results
        {
            let mut nat_type = self.nat_type.write().await;
            *nat_type = report.nat_type;
        }
        
        if let Some(addr) = report.mapped_addr_1 {
            let mut public_addr = self.public_addr.write().await;
            *public_addr = Some(addr);
        }

        info!(
            nat_type = ?report.nat_type,
            public_addr = ?report.mapped_addr_1,
            "NAT detection complete"
        );

        report.nat_type
    }

    /// Check if we're behind Symmetric NAT (CGNAT).
    ///
    /// When true, hole punching won't work and relay is required for mesh connectivity.
    pub async fn is_symmetric_nat(&self) -> bool {
        matches!(*self.nat_type.read().await, NatType::Symmetric)
    }

    /// Parse a contact's address from the stored socket address string.
    fn parse_addr(&self, contact: &Contact) -> Result<SocketAddr> {
        contact
            .addr
            .parse()
            .with_context(|| format!("invalid socket address: {}", contact.addr))
    }

    /// Connect to a remote contact and return the connection.
    /// This creates a NEW connection, bypassing the cache. 
    /// For cached connections, use `get_or_connect` instead.
    /// 
    /// # Security
    /// 
    /// Uses SNI-based identity pinning. The peer's identity is encoded in the SNI,
    /// and the TLS handshake verifies that the certificate's public key matches the identity.
    async fn connect(&self, contact: &Contact) -> Result<Connection> {
        let addr = self.parse_addr(contact)?;
        let sni = identity_to_sni(&contact.identity);
        
        // Use the peer's identity (public key) as the SNI.
        // The custom Ed25519CertVerifier will verify that the peer's certificate
        // public key matches this identity during the handshake.
        let conn = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, &sni)
            .with_context(|| format!("failed to initiate connection to {}", addr))?
            .await
            .with_context(|| format!("failed to establish connection to {}", addr))?;
        
        Ok(conn)
    }

    /// Get an existing connection or create a new one.
    /// 
    /// QUIC connections are long-lived and multiplexed, so we reuse them
    /// rather than paying the 1-RTT (or 3-RTT for full handshake) overhead
    /// for each RPC. Connections are automatically cleaned up when they
    /// are closed (via Quinn's idle timeout or explicit close).
    /// 
    /// # Security
    ///
    /// Uses enhanced liveness checking to prevent timeout cascades:
    /// 1. Rejects connections that are explicitly closed
    /// 2. Probes stale connections (not used recently) before reuse
    /// 3. Invalidates dead connections immediately rather than waiting for timeout
    /// 
    /// Uses bounded LruCache to prevent memory exhaustion from connection accumulation.
    async fn get_or_connect(&self, contact: &Contact) -> Result<Connection> {
        let peer_id = contact.identity;
        
        // Fast path: check if we have a cached connection
        // Note: LruCache.get() requires &mut self, so we need write lock
        {
            let mut cache = self.connections.write().await;
            if let Some(cached) = cache.get_mut(&peer_id) {
                // Check 1: Connection explicitly closed
                if cached.is_closed() {
                    trace!(
                        peer = hex::encode(&peer_id.as_bytes()[..8]),
                        "cached connection is closed, removing"
                    );
                    cache.pop(&peer_id);
                    // Fall through to create new connection
                }
                // Check 2: Connection is fresh (used recently) - reuse without probe
                else if !cached.is_stale() {
                    return Ok(cached.connection.clone());
                }
                // Check 3: Connection is stale - use passive health check via Quinn stats
                else {
                    // Use passive health check - no need to drop lock since it's synchronous
                    if let Some(rtt) = cached.check_health_passive() {
                        // Connection appears healthy based on Quinn's path statistics
                        cached.record_health_check_success(rtt);
                        cached.mark_success();
                        return Ok(cached.connection.clone());
                    } else {
                        // Connection is closed or degraded, record failure and remove it
                        debug!(
                            peer = hex::encode(&peer_id.as_bytes()[..8]),
                            "stale connection failed passive health check, removing"
                        );
                        cached.record_failure();
                        cache.pop(&peer_id);
                        // Fall through to create new connection
                    }
                }
            }
        }
        
        // Slow path: create a new connection and cache it
        let conn = self.connect(contact).await?;
        
        // Cache the new connection with current timestamp
        // LruCache automatically evicts least-recently-used entries when full
        {
            let mut cache = self.connections.write().await;
            cache.put(peer_id, CachedConnection::new(conn.clone()));
        }
        
        Ok(conn)
    }

    /// Invalidate a cached connection (e.g., after RPC failure).
    ///
    /// # Security
    ///
    /// Call this when an RPC fails to ensure we don't keep retrying with
    /// a broken connection. This prevents timeout cascades where multiple
    /// callers wait on the same dead connection.
    async fn invalidate_connection(&self, peer_id: &Identity) {
        let mut cache = self.connections.write().await;
        if cache.pop(peer_id).is_some() {
            debug!(
                peer = hex::encode(&peer_id.as_bytes()[..8]),
                "invalidated cached connection after failure"
            );
        }
    }

    /// Mark a connection as successfully used.
    ///
    /// Updates the last_success timestamp to prevent premature staleness checks.
    async fn mark_connection_success(&self, peer_id: &Identity) {
        let mut cache = self.connections.write().await;
        if let Some(cached) = cache.get_mut(peer_id) {
            cached.mark_success();
        }
    }

    /// Run a single health check cycle on all cached connections.
    ///
    /// This checks connections that need health checks (haven't been checked
    /// recently) and removes unhealthy ones. Uses Quinn's passive path statistics
    /// rather than invasive stream probing. Call this periodically or spawn
    /// as a background task with `run_health_monitor`.
    ///
    /// Returns the number of connections checked and removed.
    pub async fn check_connection_health(&self) -> (usize, usize) {
        // Perform health checks while holding the write lock
        // This is now fast since we use passive stats instead of I/O probes
        let mut cache = self.connections.write().await;
        
        let mut checked = 0;
        let mut removed = 0;
        let mut to_remove = Vec::new();

        for (peer_id, cached) in cache.iter_mut() {
            if !cached.needs_health_check() || cached.is_closed() {
                continue;
            }
            
            checked += 1;
            
            match cached.check_health_passive() {
                Some(rtt) => {
                    // Connection appears healthy based on Quinn's path statistics
                    cached.record_health_check_success(rtt);
                    trace!(
                        peer = hex::encode(&peer_id.as_bytes()[..8]),
                        rtt_ms = rtt.as_millis(),
                        "connection health check passed"
                    );
                }
                None => {
                    // Connection is closed or degraded
                    cached.record_failure();
                    
                    // Mark for removal if unhealthy
                    if cached.health_status == ConnectionHealthStatus::Unhealthy {
                        to_remove.push(*peer_id);
                        removed += 1;
                        debug!(
                            peer = hex::encode(&peer_id.as_bytes()[..8]),
                            "removed unhealthy connection"
                        );
                    }
                }
            }
        }

        // Remove unhealthy connections
        for peer_id in to_remove {
            cache.pop(&peer_id);
        }

        if checked > 0 {
            trace!(
                checked,
                removed,
                "connection health check cycle complete"
            );
        }

        (checked, removed)
    }

    /// Get health statistics for all cached connections.
    ///
    /// Returns a snapshot of health metrics for observability and debugging.
    pub async fn connection_health_stats(&self) -> Vec<ConnectionHealthStats> {
        let cache = self.connections.read().await;
        cache.iter()
            .map(|(_, c)| c.health_stats())
            .collect()
    }

    /// Get overall connection cache health summary.
    ///
    /// Returns counts by health status for high-level monitoring.
    pub async fn connection_health_summary(&self) -> ConnectionHealthSummary {
        let cache = self.connections.read().await;
        let mut summary = ConnectionHealthSummary::default();
        
        for (_, c) in cache.iter() {
            summary.total += 1;
            match c.health_status {
                ConnectionHealthStatus::Healthy => summary.healthy += 1,
                ConnectionHealthStatus::Degraded => summary.degraded += 1,
                ConnectionHealthStatus::Unhealthy => summary.unhealthy += 1,
                ConnectionHealthStatus::Unknown => summary.unknown += 1,
            }
            
            if let Some(rtt) = c.average_rtt_ms() {
                summary.rtt_samples.push(rtt);
            }
        }
        
        // Calculate average RTT across all connections
        if !summary.rtt_samples.is_empty() {
            summary.average_rtt_ms = Some(
                summary.rtt_samples.iter().sum::<f32>() / summary.rtt_samples.len() as f32
            );
        }
        
        summary
    }

    /// Run the health monitor loop as a background task.
    ///
    /// This runs periodic health checks on all cached connections and
    /// removes unhealthy ones proactively. Should be spawned as a background
    /// task during node initialization.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let network = QuinnNetwork::new(...);
    /// tokio::spawn(async move {
    ///     network.run_health_monitor().await;
    /// });
    /// ```
    pub async fn run_health_monitor(&self) {
        let mut interval = tokio::time::interval(CONNECTION_HEALTH_CHECK_INTERVAL);
        
        loop {
            interval.tick().await;
            let (checked, removed) = self.check_connection_health().await;
            
            if removed > 0 {
                debug!(
                    checked,
                    removed,
                    "health monitor removed unhealthy connections"
                );
            }
        }
    }

    /// Send an RPC request and receive the response.
    ///
    /// # Security
    ///
    /// On failure, the cached connection is invalidated to prevent timeout
    /// cascades where multiple callers retry with a broken connection.
    /// On success, the connection's last_success timestamp is updated.
    async fn rpc(&self, contact: &Contact, request: DhtRequest) -> Result<DhtResponse> {
        let peer_id = contact.identity;
        let conn = self.get_or_connect(contact).await?;
        
        // Attempt the RPC, invalidating the connection cache on failure
        let result = self.rpc_inner(&conn, contact, request).await;
        
        match &result {
            Ok(_) => {
                // Success - update last_success timestamp
                self.mark_connection_success(&peer_id).await;
            }
            Err(e) => {
                // Failure - check if it's a connection-level error that should invalidate
                // the cache. We check for common QUIC connection errors.
                let error_str = format!("{:?}", e);
                if error_str.contains("connection") 
                    || error_str.contains("stream")
                    || error_str.contains("timeout")
                    || error_str.contains("reset")
                    || error_str.contains("closed")
                {
                    self.invalidate_connection(&peer_id).await;
                }
            }
        }
        
        result
    }

    /// Internal RPC implementation (separated to allow cache management in rpc()).
    async fn rpc_inner(&self, conn: &Connection, contact: &Contact, request: DhtRequest) -> Result<DhtResponse> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open bidirectional stream")?;

        // Serialize and send request
        let request_bytes = bincode::serialize(&request).context("failed to serialize request")?;
        let len = request_bytes.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&request_bytes).await?;
        send.finish()?;

        // Receive response
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Validate response size to prevent memory exhaustion
        if len > MAX_RESPONSE_SIZE {
            warn!(
                peer = %contact.addr,
                size = len,
                max = MAX_RESPONSE_SIZE,
                "peer sent oversized response"
            );
            anyhow::bail!("response too large: {} bytes (max {})", len, MAX_RESPONSE_SIZE);
        }

        let mut response_bytes = vec![0u8; len];
        recv.read_exact(&mut response_bytes).await?;

        let response: DhtResponse =
            crate::protocol::deserialize_response(&response_bytes).context("failed to deserialize response")?;
        Ok(response)
    }

    /// Query a remote node for our public address (STUN-like).
    ///
    /// This sends a `WhatIsMyAddr` request to the specified contact and returns
    /// our observed public IP:port as seen by that node. Useful for:
    /// - NAT type detection (compare responses from multiple servers)
    /// - Discovering our public address for hole punching
    /// - Detecting address changes (network migration)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let relay_contact = Contact { id: relay_id, addr: "1.2.3.4:5678".into() };
    /// let my_public_addr = network.what_is_my_addr(&relay_contact).await?;
    /// println!("My public address: {}", my_public_addr);
    /// ```
    pub async fn what_is_my_addr(&self, contact: &Contact) -> Result<SocketAddr> {
        let response = self.rpc(contact, DhtRequest::WhatIsMyAddr).await?;
        
        match response {
            DhtResponse::YourAddr { addr } => {
                addr.parse()
                    .with_context(|| format!("invalid address in response: {}", addr))
            }
            other => anyhow::bail!("unexpected response to WhatIsMyAddr: {:?}", other),
        }
    }

    /// Discover our public address by querying multiple nodes.
    ///
    /// Queries up to `count` nodes and returns addresses where at least 2 nodes
    /// agree, helping detect consistent NAT behavior vs symmetric NAT.
    ///
    /// Returns `(consistent_addr, all_observed)` where:
    /// - `consistent_addr` is Some if multiple nodes see the same address
    /// - `all_observed` contains all unique addresses seen
    pub async fn discover_public_addr(
        &self,
        contacts: &[Contact],
        count: usize,
    ) -> (Option<SocketAddr>, Vec<SocketAddr>) {
        use std::collections::HashMap;
        
        let mut addr_counts: HashMap<SocketAddr, usize> = HashMap::new();
        let mut all_addrs = Vec::new();
        
        for contact in contacts.iter().take(count) {
            if let Ok(addr) = self.what_is_my_addr(contact).await {
                *addr_counts.entry(addr).or_insert(0) += 1;
                if !all_addrs.contains(&addr) {
                    all_addrs.push(addr);
                }
            }
        }
        
        // Find address seen by at least 2 nodes
        let consistent = addr_counts
            .into_iter()
            .find(|(_, count)| *count >= 2)
            .map(|(addr, _)| addr);
        
        (consistent, all_addrs)
    }

    /// Connect to a peer by their cryptographic identity.
    ///
    /// This method:
    /// 1. Resolves the Identity to a network address via the provided resolver
    /// 2. Establishes a QUIC connection
    /// 3. Verifies the peer's TLS certificate matches their Identity
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The Ed25519 public key of the peer to connect to
    /// * `addrs` - Known addresses for this peer (from DHT lookup or cache)
    ///
    /// # Returns
    ///
    /// A verified QUIC connection to the peer.
    pub async fn connect_to_peer(
        &self,
        peer_id: &Identity,
        addrs: &[String],
    ) -> Result<Connection> {
        // Try each address until one works
        let mut last_error = None;
        
        for addr_str in addrs {
            let addr: SocketAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    last_error = Some(anyhow::anyhow!("invalid address {}: {}", addr_str, e));
                    continue;
                }
            };
            
            match self.connect_and_verify(addr, peer_id).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no addresses provided for peer")))
    }

    /// Connect to an address and verify the peer's identity.
    async fn connect_and_verify(
        &self,
        addr: SocketAddr,
        expected_peer_id: &Identity,
    ) -> Result<Connection> {
        // Use the peer's identity (public key) as the SNI.
        // The custom Ed25519CertVerifier will verify that the peer's certificate
        // public key matches this identity during the handshake.
        let sni = identity_to_sni(expected_peer_id);
        let conn = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, &sni)
            .with_context(|| format!("failed to initiate connection to {}", addr))?
            .await
            .with_context(|| format!("failed to establish connection to {}", addr))?;
        
        // Identity verification is now handled during the TLS handshake via SNI pinning.
        
        Ok(conn)
    }

    /// Create a Contact from a PeerId and address.
    ///
    /// This is a convenience method for creating contacts when you know
    /// both the peer's identity and their current address.
    pub fn contact_from_peer(peer_id: &Identity, addr: String) -> Contact {
        Contact {
            identity: *peer_id,
            addr,
        }
    }

    /// Smart connect: tries direct first, falls back to relay on failure.
    ///
    /// This implements the NAT traversal strategy:
    /// 1. Check NAT type - if Symmetric (CGNAT), skip direct and use relay
    /// 2. Try direct UDP connection with timeout
    /// 3. If blocked by NAT, negotiate relay via sDHT
    /// 4. Both connect outbound to relay (always traverses NAT)
    /// 5. Relay forwards E2E-encrypted packets it cannot read
    ///
    /// For CGNAT ↔ CGNAT scenarios, this automatically uses relay since
    /// hole punching is unreliable with Symmetric NAT.
    ///
    /// # This Is the Primary Connection API
    ///
    /// **Use this method instead of managing QUIC connections directly.**
    /// It abstracts all transport complexity, so your code works regardless
    /// of NAT topology. The returned [`SmartConnection`] provides a unified
    /// interface whether the connection is direct or relayed.
    ///
    /// # Arguments
    ///
    /// * `record` - The peer's endpoint record from DHT (resolve via DHT lookup)
    ///
    /// # Returns
    ///
    /// A [`SmartConnection`] that works transparently across all NAT types.
    /// Use [`SmartConnection::connection()`] to access the underlying transport.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Resolve peer's endpoint record from DHT
    /// let record = dht.resolve_identity(&peer_identity).await?;
    ///
    /// // Connect—NAT traversal handled automatically
    /// let conn = network.smart_connect(&record).await?;
    ///
    /// // Connection works regardless of network topology
    /// println!("Connected: direct={}", conn.is_direct());
    /// ```
    pub async fn smart_connect(&self, record: &EndpointRecord) -> Result<SmartConnection> {
        let peer_id = &record.identity;
        
        // Check if we're behind Symmetric NAT (CGNAT)
        // In this case, skip direct connection attempts as hole punching won't work
        let our_nat_type = *self.nat_type.read().await;
        let skip_direct = our_nat_type == NatType::Symmetric;
        
        if skip_direct {
            debug!(
                peer = ?peer_id,
                nat_type = ?our_nat_type,
                "Symmetric NAT detected, skipping direct connection (CGNAT mode)"
            );
        }

        // Try direct connection if:
        // - We have addresses AND
        // - We're NOT behind Symmetric NAT (or Unknown - try anyway)
        if !record.addrs.is_empty() && !skip_direct {
            debug!(peer = ?peer_id, addrs = ?record.addrs, "trying direct connection");
            
            let direct_result = tokio::time::timeout(
                DIRECT_CONNECT_TIMEOUT,
                self.connect_to_peer(peer_id, &record.addrs),
            )
            .await;

            match direct_result {
                Ok(Ok(conn)) => {
                    debug!(peer = ?peer_id, "direct connection successful");
                    return Ok(SmartConnection::Direct(conn));
                }
                Ok(Err(e)) => {
                    debug!(peer = ?peer_id, error = %e, "direct connection failed");
                }
                Err(_) => {
                    debug!(peer = ?peer_id, "direct connection timed out");
                }
            }
        }

        // Direct failed or no direct addresses - try relay
        if record.has_relays() {
            debug!(peer = ?peer_id, relays = record.relays.len(), "trying relay connection");
            
            let our_peer_id = self.our_peer_id.as_ref()
                .context("cannot use relay without our_peer_id set")?;
            
            // Convert peer's relays to RelayInfo
            // Note: We don't have RTT measurements to these relays yet
            let peer_relays: Vec<RelayInfo> = record.relays.iter().map(|r| RelayInfo {
                relay_peer: r.relay_identity,
                relay_addrs: r.relay_addrs.clone(),
                load: 0.5, // Unknown, assume medium load
                accepting: true,
                rtt_ms: None,  // No measurements from peer's perspective
                tier: None,
                capabilities: Default::default(),
            }).collect();
            
            // Get our known relays (already have RTT metrics from DHT tiering)
            let our_relays = self.relay_client.get_relays(3).await;
            
            // Choose connection strategy using RTT-aware scoring
            let strategy = crate::relay::choose_connection_strategy(
                &record.addrs,
                &our_relays,
                &peer_relays,
                true, // direct already failed
            ).context("failed to generate session ID for relay")?;
            
            match strategy {
                ConnectionStrategy::Relayed { relay, session_id } => {
                    // Connect to the relay
                    let relay_peer_id = relay.relay_peer;
                    let relay_conn = self.connect_to_peer(&relay_peer_id, &relay.relay_addrs).await
                        .context("failed to connect to relay")?;
                    
                    // Request relay session
                    let request = DhtRequest::RelayConnect {
                        from_peer: *our_peer_id,
                        target_peer: *peer_id,
                        session_id,
                    };
                    
                    let response = self.rpc_on_connection(&relay_conn, request).await?;
                    
                    // Keep direct addrs for potential upgrade later
                    let direct_addrs = record.addrs.clone();
                    
                    match response {
                        DhtResponse::RelayAccepted { session_id } => {
                            debug!(
                                peer = ?peer_id,
                                relay = ?relay_peer_id,
                                session = hex::encode(session_id),
                                "relay session pending, waiting for peer"
                            );
                            
                            self.relay_client.register_session(session_id, relay_peer_id).await;
                            
                            Ok(SmartConnection::RelayPending {
                                relay_connection: relay_conn,
                                session_id,
                                relay_peer: relay_peer_id,
                                direct_addrs,
                            })
                        }
                        DhtResponse::RelayConnected { session_id } => {
                            debug!(
                                peer = ?peer_id,
                                relay = ?relay_peer_id,
                                session = hex::encode(session_id),
                                "relay session established"
                            );
                            
                            self.relay_client.register_session(session_id, relay_peer_id).await;
                            
                            Ok(SmartConnection::Relayed {
                                relay_connection: relay_conn,
                                session_id,
                                relay_peer: relay_peer_id,
                                direct_addrs,
                            })
                        }
                        DhtResponse::RelayRejected { reason } => {
                            anyhow::bail!("relay rejected: {}", reason);
                        }
                        _ => anyhow::bail!("unexpected relay response"),
                    }
                }
                ConnectionStrategy::Direct { .. } => {
                    anyhow::bail!("no relay available and direct connection failed");
                }
            }
        } else {
            anyhow::bail!("direct connection failed and no relays available");
        }
    }

    /// Send an RPC request on an existing connection.
    async fn rpc_on_connection(&self, conn: &Connection, request: DhtRequest) -> Result<DhtResponse> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open bidirectional stream")?;

        // Serialize and send request
        let request_bytes = bincode::serialize(&request).context("failed to serialize request")?;
        let len = request_bytes.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&request_bytes).await?;
        send.finish()?;

        // Receive response
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Validate response size to prevent memory exhaustion
        if len > MAX_RESPONSE_SIZE {
            warn!(
                size = len,
                max = MAX_RESPONSE_SIZE,
                "peer sent oversized response on existing connection"
            );
            anyhow::bail!("response too large: {} bytes (max {})", len, MAX_RESPONSE_SIZE);
        }

        let mut response_bytes = vec![0u8; len];
        recv.read_exact(&mut response_bytes).await?;

        let response: DhtResponse =
            crate::protocol::deserialize_response(&response_bytes).context("failed to deserialize response")?;
        Ok(response)
    }

    /// Update known relays from the DHT.
    pub async fn update_known_relays(&self, relays: Vec<RelayInfo>) {
        self.relay_client.update_relays(relays).await;
    }

    /// Attempt to upgrade a relayed connection to direct.
    ///
    /// This should be called periodically for relayed connections to check
    /// if direct connectivity has become available (e.g., NAT mapping changed,
    /// peer moved networks, firewall rules updated).
    ///
    /// # How it works
    ///
    /// 1. Tries direct connection to peer's known addresses with short timeout
    /// 2. If successful, verifies peer identity via TLS certificate
    /// 3. Returns the new direct connection (caller should close relay session)
    ///
    /// # Benefits of upgrading
    ///
    /// - **Lower latency**: Direct path vs relay hop
    /// - **Reduced relay load**: Frees relay capacity for other peers
    /// - **Better throughput**: No relay bottleneck
    ///
    /// # When to call
    ///
    /// - Periodically (e.g., every 30-60 seconds) for long-lived connections
    /// - After network change events (WiFi reconnect, etc.)
    /// - When relay latency degrades
    pub async fn try_upgrade_to_direct(
        &self,
        peer_id: &Identity,
        current: &SmartConnection,
    ) -> Result<Option<Connection>> {
        // Only attempt for relayed connections with direct addresses
        let direct_addrs = match current {
            SmartConnection::Direct(_) => return Ok(None), // Already direct
            SmartConnection::RelayPending { direct_addrs, .. } => direct_addrs,
            SmartConnection::Relayed { direct_addrs, .. } => direct_addrs,
        };

        if direct_addrs.is_empty() {
            return Ok(None); // No addresses to try
        }

        debug!(
            peer = ?peer_id,
            addrs = ?direct_addrs,
            "attempting relay-to-direct upgrade"
        );

        // Try direct connection with short timeout
        let upgrade_timeout = std::time::Duration::from_secs(3);
        
        let result = tokio::time::timeout(
            upgrade_timeout,
            self.connect_to_peer(peer_id, direct_addrs),
        )
        .await;

        match result {
            Ok(Ok(conn)) => {
                debug!(peer = ?peer_id, "relay-to-direct upgrade successful!");
                Ok(Some(conn))
            }
            Ok(Err(e)) => {
                debug!(peer = ?peer_id, error = %e, "direct upgrade failed");
                Ok(None)
            }
            Err(_) => {
                debug!(peer = ?peer_id, "direct upgrade timed out");
                Ok(None)
            }
        }
    }

    /// Close a relay session after upgrading to direct.
    ///
    /// Call this after successfully upgrading via `try_upgrade_to_direct`.
    pub async fn close_relay_session(&self, session_id: [u8; 16]) -> Result<()> {
        let our_peer_id = self.our_peer_id.as_ref()
            .context("cannot close relay session without our_peer_id set")?;
            
        if let Some(relay_id) = self.relay_client.remove_session(&session_id).await {
            // Send RelayClose to the relay
            if let Some(relay_info) = self.relay_client.get_relay_info(&relay_id).await {
                let contact = Contact {
                    identity: relay_info.relay_peer,
                    addr: relay_info.relay_addrs.first().cloned().unwrap_or_default(),
                };
                let request = DhtRequest::RelayClose {
                    from_peer: *our_peer_id,
                    session_id,
                };
                // Best effort, ignore errors
                let _ = self.rpc(&contact, request).await;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl DhtNetwork for QuinnNetwork {
    /// Send a FIND_NODE RPC to find contacts near a target identity.
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>> {
        let request = DhtRequest::FindNode {
            from: self.self_contact.clone(),
            target,
        };
        match self.rpc(to, request).await? {
            DhtResponse::Nodes(nodes) => {
                // Limit contacts to prevent memory/CPU exhaustion
                if nodes.len() > MAX_CONTACTS_PER_RESPONSE {
                    warn!(
                        peer = %to.addr,
                        count = nodes.len(),
                        max = MAX_CONTACTS_PER_RESPONSE,
                        "peer returned too many contacts, truncating"
                    );
                    // Truncate rather than reject to be tolerant of edge cases
                    Ok(nodes.into_iter().take(MAX_CONTACTS_PER_RESPONSE).collect())
                } else {
                    Ok(nodes)
                }
            }
            other => anyhow::bail!("unexpected response to FindNode: {:?}", other),
        }
    }

    /// Send a FIND_VALUE RPC to retrieve a value or get closer contacts.
    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)> {
        let request = DhtRequest::FindValue {
            from: self.self_contact.clone(),
            key,
        };
        match self.rpc(to, request).await? {
            DhtResponse::Value { value, closer } => {
                // Validate value size
                if let Some(ref v) = value {
                    if v.len() > MAX_VALUE_SIZE {
                        warn!(
                            peer = %to.addr,
                            size = v.len(),
                            max = MAX_VALUE_SIZE,
                            "peer returned oversized value, rejecting"
                        );
                        anyhow::bail!("value too large: {} bytes (max {})", v.len(), MAX_VALUE_SIZE);
                    }
                }
                
                // Limit contacts to prevent memory/CPU exhaustion
                let closer = if closer.len() > MAX_CONTACTS_PER_RESPONSE {
                    warn!(
                        peer = %to.addr,
                        count = closer.len(),
                        max = MAX_CONTACTS_PER_RESPONSE,
                        "peer returned too many contacts in FIND_VALUE, truncating"
                    );
                    closer.into_iter().take(MAX_CONTACTS_PER_RESPONSE).collect()
                } else {
                    closer
                };
                
                Ok((value, closer))
            }
            other => anyhow::bail!("unexpected response to FindValue: {:?}", other),
        }
    }

    /// Send a STORE RPC to store a key-value pair on a node.
    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()> {
        let request = DhtRequest::Store {
            from: self.self_contact.clone(),
            key,
            value,
        };
        match self.rpc(to, request).await? {
            DhtResponse::Ack => Ok(()),
            other => anyhow::bail!("unexpected response to Store: {:?}", other),
        }
    }

    /// Send a PING RPC to check if a node is responsive.
    async fn ping(&self, to: &Contact) -> Result<()> {
        let request = DhtRequest::Ping {
            from: self.self_contact.clone(),
        };
        match self.rpc(to, request).await? {
            DhtResponse::Ack => Ok(()),
            other => anyhow::bail!("unexpected response to Ping: {:?}", other),
        }
    }
}

/// Generate a self-signed Ed25519 certificate for QUIC connections.
///
/// This creates a certificate using the provided Ed25519 keypair, allowing
/// the node's cryptographic identity to be tied to its TLS certificate.
/// The Identity is the same as the keypair's public key.
pub fn generate_ed25519_cert(
    keypair: &Keypair,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Build the Ed25519 key pair in PKCS8 format for rcgen
    let secret_key = keypair.secret_key_bytes();
    let public_key = keypair.public_key_bytes();
    
    // Ed25519 PKCS8 format (RFC 8410)
    // This is a minimal PKCS#8 structure for Ed25519 private keys
    // OID 1.3.101.112 (Ed25519)
    const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    const PKCS8_VERSION: [u8; 3] = [0x02, 0x01, 0x00];
    
    let mut pkcs8 = Vec::with_capacity(48);
    // PKCS#8 header for Ed25519
    pkcs8.extend_from_slice(&[
        0x30, 0x2e, // SEQUENCE, 46 bytes
    ]);
    pkcs8.extend_from_slice(&PKCS8_VERSION); // INTEGER 0 (version)
    pkcs8.extend_from_slice(&[
        0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
    ]);
    pkcs8.extend_from_slice(&ED25519_OID);
    pkcs8.extend_from_slice(&[
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
    ]);
    pkcs8.extend_from_slice(&secret_key);
    
    // Create KeyPair from PKCS8 DER - rcgen will auto-detect Ed25519
    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.clone());
    let key_pair = rcgen::KeyPair::try_from(&pkcs8_der)
        .context("failed to create Ed25519 key pair for certificate")?;
    
    // Create certificate with the node's public key encoded in the subject
    let mut params = rcgen::CertificateParams::new(vec!["corium".to_string()])
        .context("failed to create certificate params")?;
    
    // Encode the public key in the common name for peer verification
    // Use Utf8String instead of PrintableString for hex-encoded data
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String(hex::encode(public_key)),
    );
    
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate self-signed Ed25519 certificate")?;
    
    let key = PrivateKeyDer::Pkcs8(pkcs8.into());
    let cert_der = CertificateDer::from(cert.der().to_vec());
    
    Ok((vec![cert_der], key))
}

/// Create a server configuration for accepting QUIC connections.
///
/// Enables connection migration by default, allowing clients to change
/// their IP address (e.g., switching from relay to direct) without
/// re-establishing the connection.
pub fn create_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    // Require client certificates for mutual TLS - enables peer identity verification
    let client_cert_verifier = Arc::new(Ed25519ClientCertVerifier);
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(certs, key)
        .context("failed to create server TLS config")?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("failed to create QUIC server config")?,
    ));
    
    // Enable connection migration - allows clients to change addresses
    // (e.g., switching from relay to direct path)
    server_config.migration(true);
    
    // Configure transport parameters for security and resource management
    // Arc::get_mut is safe here because we just created server_config and hold the only reference
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .expect("transport config should be exclusively owned immediately after creation");
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(60)
            .try_into()
            .expect("60 seconds is a valid VarInt duration"),
    ));
    // Bound concurrent inbound streams to mitigate resource exhaustion.
    transport_config.max_concurrent_bidi_streams(64u32.into());
    transport_config.max_concurrent_uni_streams(64u32.into());

    Ok(server_config)
}

/// Create a client config that enforces peer identity via SNI.
///
/// The verifier extracts the expected peer Identity from the SNI (Server Name Indication)
/// field during the handshake and verifies that the peer's certificate matches it.
///
/// This allows a single `ClientConfig` to be used for connecting to any peer,
/// provided the connection is initiated with the correct SNI (the peer's Identity hex string).
pub fn create_client_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ClientConfig> {
    let verifier = Ed25519CertVerifier::new();

    // For self-signed certs, accept valid Ed25519 certificates and enforce
    // the identity pinned in the SNI.
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(certs, key)
        .context("failed to create client TLS config with client auth")?;

    let mut client_crypto_with_alpn = client_crypto;
    client_crypto_with_alpn.alpn_protocols = vec![ALPN.to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto_with_alpn)
            .context("failed to create QUIC client config")?,
    ));

    Ok(client_config)
}

/// Extract the Ed25519 public key from a peer's certificate.
///
/// The public key is extracted from the Subject Public Key Info (SPKI) field.
/// Returns `None` if the certificate doesn't contain a valid Ed25519 public key.
pub fn extract_public_key_from_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    // Parse the certificate to extract the public key from the Subject Public Key Info (SPKI)
    // This ensures the identity is derived from the key used for the TLS handshake,
    // preventing identity spoofing via the Common Name.
    use x509_parser::prelude::*;
    
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    
    // Extract the public key bytes from the SPKI
    let spki = cert.public_key();
    let key_bytes = &spki.subject_public_key.data;
    
    // Ed25519 public keys are exactly 32 bytes
    if key_bytes.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        Some(key)
    } else {
        None
    }
}

/// Verify that a peer's certificate matches their claimed identity.
///
/// This extracts the Ed25519 public key from the certificate and verifies
/// that it matches the expected identity (public key bytes).
///
/// # Use Cases
///
/// - **Post-handshake verification**: After QUIC handshake completes, verify
///   that the peer's certificate identity matches what we expected
/// - **Sybil protection**: Ensure peers can't claim to be a different identity
pub fn verify_peer_identity(cert_der: &[u8], expected_identity: &Identity) -> bool {
    if let Some(public_key) = extract_public_key_from_cert(cert_der) {
        crate::identity::verify_identity(expected_identity, &public_key)
    } else {
        false
    }
}

/// Certificate verifier for Ed25519 self-signed certificates in mesh networks.
///
/// This verifier accepts any certificate with a valid Ed25519 signature.
/// Identity verification should be done at the application layer using
/// [`verify_peer_identity`].
/// Client certificate verifier for mutual TLS.
///
/// Accepts any client certificate - actual identity verification is done at the
/// application layer after extracting the public key from the certificate.
#[derive(Debug)]
struct Ed25519ClientCertVerifier;

impl rustls::server::danger::ClientCertVerifier for Ed25519ClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Accept any certificate - identity verification is done at app layer
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Actually verify the cryptographic signature using the certificate's public key
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Actually verify the cryptographic signature using the certificate's public key
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// Encode an Identity as a valid DNS-style SNI hostname for TLS identity pinning.
///
/// The hex-encoded Identity (64 chars) exceeds the DNS label limit (63 chars),
/// so we split it into two labels: `<first32>.<last32>`
///
/// # Formal Invariant
/// `∀ id. parse_identity_from_sni(&identity_to_sni(id)) == Some(id)`
fn identity_to_sni(identity: &Identity) -> String {
    let hex = hex::encode(identity);
    format!("{}.{}", &hex[..32], &hex[32..])
}

/// Parse an Identity from a DNS-style SNI hostname.
///
/// # Formal Invariant
/// Roundtrip: `parse_identity_from_sni(&identity_to_sni(id))` recovers the original.
fn parse_identity_from_sni(sni: &str) -> Option<Identity> {
    // Split by '.' and concatenate the hex parts
    let hex_str: String = sni.split('.').collect();
    let bytes = hex::decode(&hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Identity::from_bytes(arr))
}

/// Certificate verifier implementing SNI-based identity pinning.
///
/// # Formal Property (P3 - SNI Identity Pinning)
///
/// This verifier enforces the invariant:
/// ```text
/// verify_server_cert(cert, sni) succeeds ⟺
///     ∃ pk ∈ cert.SPKI : pk == parse_identity_from_sni(sni)
/// ```
///
/// The verification chain is:
/// 1. Extract expected identity from SNI hostname (DNS-encoded)
/// 2. Extract actual public key from certificate's Subject Public Key Info
/// 3. Compare: public key must equal expected identity (zero-hash model)
///
/// This prevents MITM attacks where an attacker presents a different certificate.
#[derive(Debug)]
struct Ed25519CertVerifier;

impl Ed25519CertVerifier {
    fn new() -> Self {
        Self
    }
}

impl rustls::client::danger::ServerCertVerifier for Ed25519CertVerifier {
    /// Verify server certificate matches the expected identity encoded in SNI.
    ///
    /// # Formal Verification Steps
    ///
    /// 1. **SNI → Expected Identity**: Parse DNS-encoded identity from SNI hostname
    /// 2. **Certificate → Actual Public Key**: Extract Ed25519 public key from SPKI
    /// 3. **Identity Comparison**: Verify public key == expected identity (constant-time)
    ///
    /// # Security Properties
    ///
    /// - **P3**: SNI Identity Pinning - certificate's public key must match expected identity
    /// - TLS signature verification is handled by `verify_tls1[23]_signature`
    /// - Prevents certificate substitution attacks
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // FORMAL VERIFICATION STEP 1:
        // Extract expected identity from SNI (DNS-style encoded)
        let expected_identity_sni = match server_name {
            rustls::pki_types::ServerName::DnsName(name) => name.as_ref(),
            rustls::pki_types::ServerName::IpAddress(_) => {
                // P3 violation: Cannot verify identity without SNI
                // Connecting by IP address bypasses identity pinning
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
            _ => {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        };

        // Parse SNI as Identity (zero-hash model: identity = public key)
        let expected_identity = parse_identity_from_sni(expected_identity_sni).ok_or_else(|| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // FORMAL VERIFICATION STEP 2:
        // Extract actual public key from certificate's SPKI
        let public_key = extract_public_key_from_cert(end_entity.as_ref())
            .ok_or(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))?;

        // FORMAL VERIFICATION STEP 3:
        // Zero-hash model: Identity IS the public key, no hashing needed
        // Compare expected identity vs actual public key
        let actual_identity = Identity::from_bytes(public_key);
        if actual_identity != expected_identity {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        }

        // Certificate is valid and its public key matches the pinned identity.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Actually verify the cryptographic signature using the certificate's public key
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Actually verify the cryptographic signature using the certificate's public key
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            // Keep other schemes for backwards compatibility
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_candidate_rtt_smoothing() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut path = PathCandidate::new(addr, false);
        
        assert_eq!(path.state, PathState::Unknown);
        assert!(path.rtt_ms.is_none());
        
        // First RTT measurement
        path.record_success(Duration::from_millis(100));
        assert_eq!(path.rtt_ms, Some(100.0));
        assert_eq!(path.state, PathState::Active);
        
        // Second measurement - EMA smoothing (0.8 * 100 + 0.2 * 50 = 90)
        path.record_success(Duration::from_millis(50));
        assert!((path.rtt_ms.unwrap() - 90.0).abs() < 0.1);
        
        // Third measurement - EMA continues
        path.record_success(Duration::from_millis(50));
        assert!((path.rtt_ms.unwrap() - 82.0).abs() < 0.1);
    }

    #[test]
    fn test_path_candidate_failure_handling() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut path = PathCandidate::new(addr, false);
        
        // Mark active first
        path.record_success(Duration::from_millis(50));
        assert_eq!(path.state, PathState::Active);
        assert_eq!(path.failures, 0);
        
        // Failures accumulate
        path.record_failure();
        assert_eq!(path.failures, 1);
        assert_eq!(path.state, PathState::Active);
        
        path.record_failure();
        assert_eq!(path.failures, 2);
        assert_eq!(path.state, PathState::Active);
        
        // Third failure marks as failed
        path.record_failure();
        assert_eq!(path.failures, 3);
        assert_eq!(path.state, PathState::Failed);
    }

    #[test]
    fn test_path_probe_serialization() {
        let endpoint_key = [0x42u8; 32];
        let probe = PathProbe::new(0x123456789ABCDEF0, endpoint_key);
        
        let bytes = probe.to_bytes();
        assert_eq!(&bytes[0..4], PATH_MAGIC);
        assert_eq!(bytes[4], MSG_PATH_PROBE);
        
        let parsed = PathProbe::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.tx_id, probe.tx_id);
        assert_eq!(parsed.endpoint_key, endpoint_key);
        assert_eq!(parsed.timestamp_ms, probe.timestamp_ms);
    }

    #[test]
    fn test_path_reply_serialization() {
        let observed_addr: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let reply = PathReply {
            tx_id: 42,
            observed_addr,
            echo_timestamp_ms: 12345,
        };
        
        let bytes = reply.to_bytes();
        assert_eq!(&bytes[0..4], PATH_MAGIC);
        assert_eq!(bytes[4], MSG_PATH_REPLY);
        
        let parsed = PathReply::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.tx_id, reply.tx_id);
        assert_eq!(parsed.observed_addr, reply.observed_addr);
        assert_eq!(parsed.echo_timestamp_ms, reply.echo_timestamp_ms);
    }

    #[test]
    fn test_reach_me_serialization() {
        let endpoint_key = [0xAB; 32];
        let endpoints = vec![
            "192.168.1.1:8080".parse().unwrap(),
            "[2001:db8::1]:9090".parse().unwrap(),
        ];
        let reach = ReachMe::new(endpoint_key, endpoints.clone());
        
        let bytes = reach.to_bytes();
        assert_eq!(&bytes[0..4], PATH_MAGIC);
        assert_eq!(bytes[4], MSG_REACH_ME);
        
        let parsed = ReachMe::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.endpoint_key, endpoint_key);
        assert_eq!(parsed.endpoints.len(), 2);
        assert_eq!(parsed.endpoints[0], endpoints[0]);
        assert_eq!(parsed.endpoints[1], endpoints[1]);
    }

    #[test]
    fn test_path_selection_prefers_direct() {
        let direct_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let relay_addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        
        let mut paths = [
            PathCandidate::new(relay_addr, true),
            PathCandidate::new(direct_addr, false),
        ];
        
        // Both paths active with same RTT - should prefer direct (index 1)
        paths[0].record_success(Duration::from_millis(50));
        paths[1].record_success(Duration::from_millis(50));
        
        // Simulate selection logic
        let usable: Vec<_> = paths.iter().enumerate()
            .filter(|(_, p)| p.is_usable())
            .collect();
        
        let best_direct = usable.iter()
            .filter(|(_, p)| !p.is_relay)
            .min_by(|(_, a), (_, b)| {
                a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal)
            });
        
        assert!(best_direct.is_some());
        assert_eq!(best_direct.unwrap().0, 1); // Direct path at index 1
    }

    #[test]
    fn test_path_selection_relay_faster_threshold() {
        let direct_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let relay_addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        
        let mut paths = [
            PathCandidate::new(relay_addr, true),
            PathCandidate::new(direct_addr, false),
        ];
        
        // Relay is 60ms faster (above 50ms threshold) - should prefer relay
        paths[0].record_success(Duration::from_millis(40));
        paths[1].record_success(Duration::from_millis(100));
        
        let relay_rtt = paths[0].rtt_ms.unwrap();
        let direct_rtt = paths[1].rtt_ms.unwrap();
        
        // Relay + 50 < direct means relay is preferred
        assert!(relay_rtt + 50.0 < direct_rtt);
    }
}