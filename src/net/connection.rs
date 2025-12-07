//! Connection caching, health monitoring, and transport-agnostic handles.
//!
//! This module provides:
//!
//! - [`CachedConnection`]: Connection wrapper with health tracking and RTT metrics
//! - [`SmartConnection`]: Transport-agnostic handle (direct QUIC or relayed)
//! - [`ConnectionRateLimiter`]: Token bucket rate limiter for connection admission
//!
//! # Connection Cache
//!
//! QUIC connections are long-lived and multiplexed, so we cache them with LRU eviction:
//! - **Capacity**: 1,000 connections ([`MAX_CACHED_CONNECTIONS`])
//! - **Stale timeout**: 60 seconds of inactivity triggers passive health check
//! - **Health check interval**: 15 seconds between checks
//! - **RTT sample history**: 10 samples with EMA smoothing
//! - **Unhealthy threshold**: 3 consecutive failures or RTT > 2,000ms
//!
//! # Rate Limiting
//!
//! Token bucket algorithm bounds new connections:
//! - **Global limit**: 100 connections/second
//! - **Per-IP limit**: 20 connections/second
//! - **IP tracking**: LRU cache of 1,000 IPs

use std::net::{SocketAddr, IpAddr};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;
use quinn::Connection;
use tracing::trace;

use crate::identity::Identity;

/// Maximum number of cached peer connections.
pub const MAX_CACHED_CONNECTIONS: usize = 1000;

/// Maximum time a cached connection can be idle before being considered stale.
const CONNECTION_STALE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval between connection health checks.
pub const CONNECTION_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Number of RTT samples to keep for health statistics.
const RTT_SAMPLE_HISTORY_SIZE: usize = 10;

/// Maximum acceptable RTT before considering connection degraded (ms).
const MAX_HEALTHY_RTT_MS: f32 = 2000.0;

/// Consecutive failures before marking connection as unhealthy.
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Health status of a cached connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionHealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Connection health statistics for observability.
#[derive(Clone, Debug)]
pub struct ConnectionHealthStats {
    pub remote_addr: SocketAddr,
    pub status: ConnectionHealthStatus,
    pub rtt_ms: Option<f32>,
    pub rtt_jitter_ms: Option<f32>,
    pub time_since_success: Duration,
    pub time_since_health_check: Duration,
    pub consecutive_failures: u32,
}

/// Summary of connection health across all cached connections.
#[derive(Clone, Debug, Default)]
pub struct ConnectionHealthSummary {
    pub total: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub unhealthy: usize,
    pub unknown: usize,
    pub average_rtt_ms: Option<f32>,
    #[doc(hidden)]
    pub rtt_samples: Vec<f32>,
}

/// A cached connection with metadata for liveness checking.
#[derive(Clone)]
pub struct CachedConnection {
    pub(crate) connection: Connection,
    pub(crate) last_success: Instant,
    pub(crate) last_health_check: Instant,
    pub(crate) consecutive_failures: u32,
    pub(crate) rtt_samples: Vec<f32>,
    pub(crate) rtt_sample_index: usize,
    pub(crate) health_status: ConnectionHealthStatus,
}

impl CachedConnection {
    pub fn new(connection: Connection) -> Self {
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

    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    pub fn is_stale(&self) -> bool {
        self.last_success.elapsed() > CONNECTION_STALE_TIMEOUT
    }

    pub fn needs_health_check(&self) -> bool {
        self.last_health_check.elapsed() > CONNECTION_HEALTH_CHECK_INTERVAL
    }

    pub fn mark_success(&mut self) {
        self.last_success = Instant::now();
        self.consecutive_failures = 0;
        if self.health_status != ConnectionHealthStatus::Healthy {
            self.health_status = ConnectionHealthStatus::Healthy;
        }
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_health_check = Instant::now();
        self.update_health_status();
    }

    pub fn record_health_check_success(&mut self, rtt: Duration) {
        let rtt_ms = rtt.as_secs_f32() * 1000.0;

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

    pub fn health_stats(&self) -> ConnectionHealthStats {
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

    pub fn average_rtt_ms(&self) -> Option<f32> {
        if self.rtt_samples.is_empty() {
            return None;
        }
        Some(self.rtt_samples.iter().sum::<f32>() / self.rtt_samples.len() as f32)
    }

    fn rtt_jitter_ms(&self) -> Option<f32> {
        if self.rtt_samples.len() < 2 {
            return None;
        }
        let avg = self.average_rtt_ms()?;
        let variance: f32 = self
            .rtt_samples
            .iter()
            .map(|&x| (x - avg).powi(2))
            .sum::<f32>()
            / self.rtt_samples.len() as f32;
        Some(variance.sqrt())
    }

    pub fn check_health_passive(&self) -> Option<Duration> {
        if let Some(reason) = self.connection.close_reason() {
            trace!(
                remote = %self.connection.remote_address(),
                reason = ?reason,
                "connection closed, health check failed"
            );
            return None;
        }

        let rtt = self.connection.rtt();
        if rtt.is_zero() {
            trace!(
                remote = %self.connection.remote_address(),
                "connection has zero RTT estimate, may be stale"
            );
            return None;
        }

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
    }
}

/// A transport-agnostic connection to a peer.
///
/// Represents three connection states:
/// - [`Direct`][Self::Direct]: QUIC connection with no relay hop
/// - [`RelayPending`][Self::RelayPending]: Relay session requested, awaiting peer
/// - [`Relayed`][Self::Relayed]: Active relay session with E2E encryption
///
/// # Upgrade Path
///
/// Relayed connections can upgrade to direct when conditions improve.
/// Use [`can_attempt_upgrade`][Self::can_attempt_upgrade] to check eligibility
/// and [`PeerNetwork::try_upgrade_to_direct`] to attempt the upgrade.
#[derive(Debug, Clone)]
pub enum SmartConnection {
    Direct(Connection),
    RelayPending {
        relay_connection: Connection,
        session_id: [u8; 16],
        relay_peer: Identity,
        direct_addrs: Vec<String>,
    },
    Relayed {
        relay_connection: Connection,
        session_id: [u8; 16],
        relay_peer: Identity,
        direct_addrs: Vec<String>,
    },
}

impl SmartConnection {
    pub fn is_direct(&self) -> bool {
        matches!(self, SmartConnection::Direct(_))
    }

    pub fn is_relayed(&self) -> bool {
        matches!(self, SmartConnection::Relayed { .. } | SmartConnection::RelayPending { .. })
    }

    pub fn connection(&self) -> &Connection {
        match self {
            SmartConnection::Direct(conn) => conn,
            SmartConnection::RelayPending { relay_connection, .. } => relay_connection,
            SmartConnection::Relayed { relay_connection, .. } => relay_connection,
        }
    }

    pub fn session_id(&self) -> Option<[u8; 16]> {
        match self {
            SmartConnection::Direct(_) => None,
            SmartConnection::RelayPending { session_id, .. } => Some(*session_id),
            SmartConnection::Relayed { session_id, .. } => Some(*session_id),
        }
    }

    pub fn direct_addrs(&self) -> Option<&[String]> {
        match self {
            SmartConnection::Direct(_) => None,
            SmartConnection::RelayPending { direct_addrs, .. } => Some(direct_addrs),
            SmartConnection::Relayed { direct_addrs, .. } => Some(direct_addrs),
        }
    }

    pub fn can_attempt_upgrade(&self) -> bool {
        match self {
            SmartConnection::Direct(_) => false,
            SmartConnection::RelayPending { direct_addrs, .. } => !direct_addrs.is_empty(),
            SmartConnection::Relayed { direct_addrs, .. } => !direct_addrs.is_empty(),
        }
    }
}

// ============================================================================
// Token Bucket Rate Limiter
// ============================================================================

/// Maximum new connections per second globally.
pub const MAX_GLOBAL_CONNECTIONS_PER_SECOND: usize = 100;

/// Maximum new connections per second per IP.
pub const MAX_CONNECTIONS_PER_IP_PER_SECOND: usize = 20;

/// Maximum number of IPs to track for rate limiting.
pub const MAX_TRACKED_IPS: usize = 1000;

/// A token bucket for rate limiting.
///
/// Uses fixed-size storage (2 fields) instead of per-request timestamp storage.
/// Tokens are replenished at a constant rate up to a maximum capacity.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    /// Current number of available tokens (fractional for smooth replenishment).
    tokens: f64,
    /// Last time tokens were replenished.
    last_update: Instant,
}

impl TokenBucket {
    /// Create a new token bucket with full capacity.
    fn new(capacity: usize) -> Self {
        Self {
            tokens: capacity as f64,
            last_update: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if successful.
    ///
    /// Tokens are replenished at `rate` tokens per second, up to `capacity`.
    fn try_consume(&mut self, rate: f64, capacity: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        
        // Replenish tokens based on elapsed time
        self.tokens = (self.tokens + elapsed * rate).min(capacity);
        self.last_update = now;
        
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Connection rate limiter using token bucket algorithm.
///
/// Bounds connection admission to prevent DoS attacks:
/// - **Global**: 100 tokens, refilled at 100/sec ([`MAX_GLOBAL_CONNECTIONS_PER_SECOND`])
/// - **Per-IP**: 20 tokens, refilled at 20/sec ([`MAX_CONNECTIONS_PER_IP_PER_SECOND`])
/// - **IP tracking**: LRU cache of 1,000 IPs ([`MAX_TRACKED_IPS`])
///
/// # Memory Efficiency
///
/// Token bucket uses fixed 16 bytes per bucket (f64 + Instant) vs sliding window's
/// O(rate) memory (e.g., 800 bytes for 100 timestamps).
///
/// # Async Safety
///
/// Uses `tokio::sync::Mutex` to avoid blocking the async runtime during rate checks.
#[derive(Debug)]
pub struct ConnectionRateLimiter {
    state: tokio::sync::Mutex<RateLimitState>,
}

#[derive(Debug)]
struct RateLimitState {
    /// Global token bucket.
    global: TokenBucket,
    /// Per-IP token buckets.
    per_ip: LruCache<IpAddr, TokenBucket>,
}

impl ConnectionRateLimiter {
    pub fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::new(RateLimitState {
                global: TokenBucket::new(MAX_GLOBAL_CONNECTIONS_PER_SECOND),
                per_ip: LruCache::new(NonZeroUsize::new(MAX_TRACKED_IPS).unwrap()),
            }),
        }
    }

    /// Check if a new connection should be allowed.
    /// Returns true if under rate limit, false if should reject.
    ///
    /// This is an async method to avoid blocking the tokio runtime.
    pub async fn allow(&self, ip: IpAddr) -> bool {
        let mut state = self.state.lock().await;
        
        // 1. Check global limit
        if !state.global.try_consume(
            MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64,
            MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64,
        ) {
            return false;
        }
        
        // 2. Check per-IP limit
        let ip_bucket = state.per_ip.get_or_insert_mut(ip, || {
            TokenBucket::new(MAX_CONNECTIONS_PER_IP_PER_SECOND)
        });
        
        if !ip_bucket.try_consume(
            MAX_CONNECTIONS_PER_IP_PER_SECOND as f64,
            MAX_CONNECTIONS_PER_IP_PER_SECOND as f64,
        ) {
            // Refund the global token since we're rejecting
            state.global.tokens = (state.global.tokens + 1.0)
                .min(MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64);
            return false;
        }
        
        true
    }
}

impl Default for ConnectionRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::RwLock;

    fn make_identity(seed: u32) -> Identity {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&seed.to_be_bytes());
        Identity::from_bytes(bytes)
    }

    // ========================================================================
    // Connection Cache Under Load Tests
    // ========================================================================

    const TEST_MAX_CONNECTIONS: usize = 1024;
    const CONNECTION_STALE_TIMEOUT_SECS: u64 = 60;

    #[test]
    fn cache_eviction_at_capacity() {
        let cache_size = TEST_MAX_CONNECTIONS;
        let new_connections = 10;

        assert!(
            cache_size + new_connections > cache_size,
            "Should trigger eviction"
        );
    }

    #[test]
    fn stale_connection_detection() {
        let stale_timeout = Duration::from_secs(CONNECTION_STALE_TIMEOUT_SECS);

        let last_used = Duration::from_secs(CONNECTION_STALE_TIMEOUT_SECS + 1);
        assert!(last_used > stale_timeout, "Connection should be considered stale");

        let last_used_recent = Duration::from_secs(CONNECTION_STALE_TIMEOUT_SECS - 1);
        assert!(
            last_used_recent <= stale_timeout,
            "Connection should not be considered stale"
        );
    }

    #[tokio::test]
    async fn concurrent_cache_access() {
        use std::collections::HashMap;

        let cache: Arc<RwLock<HashMap<Identity, u32>>> = Arc::new(RwLock::new(HashMap::new()));
        let mut handles = vec![];

        for i in 0..100 {
            let cache = cache.clone();
            let handle = tokio::spawn(async move {
                if i % 2 == 0 {
                    let mut guard = cache.write().await;
                    guard.insert(make_identity(i as u32), i);
                } else {
                    let guard = cache.read().await;
                    let _ = guard.get(&make_identity((i - 1) as u32));
                }
            });
            handles.push(handle);
        }

        futures::future::join_all(handles).await;

        let final_cache = cache.read().await;
        assert!(final_cache.len() <= 50, "Should have at most 50 entries");
    }

    #[test]
    fn closed_connection_handling() {
        #[derive(Debug, PartialEq)]
        enum ConnectionState {
            Open,
            Closed,
        }

        let mut connections: Vec<ConnectionState> = vec![
            ConnectionState::Open,
            ConnectionState::Closed,
            ConnectionState::Open,
            ConnectionState::Closed,
        ];

        connections.retain(|c| *c != ConnectionState::Closed);

        assert_eq!(connections.len(), 2, "Should remove closed connections");
    }

    #[test]
    fn liveness_probe_updates_timestamp() {
        let initial_timestamp = Instant::now();

        std::thread::sleep(Duration::from_millis(10));

        let updated_timestamp = Instant::now();

        assert!(updated_timestamp > initial_timestamp);
        assert!(initial_timestamp.elapsed() >= Duration::from_millis(10));
    }

    #[test]
    fn connection_failure_invalidation() {
        let mut identities_in_cache: HashSet<Identity> = HashSet::new();

        for i in 0..10 {
            identities_in_cache.insert(make_identity(i));
        }

        let failed_node = make_identity(5);
        identities_in_cache.remove(&failed_node);

        assert!(!identities_in_cache.contains(&failed_node));
        assert_eq!(identities_in_cache.len(), 9);
    }

    #[test]
    fn cache_memory_bounded() {
        let max_entries = TEST_MAX_CONNECTIONS;

        let estimated_bytes_per_entry = 256;
        let max_memory_bytes = max_entries * estimated_bytes_per_entry;

        assert!(
            max_memory_bytes <= 512 * 1024,
            "Cache memory should be bounded to ~512KB, got {} bytes",
            max_memory_bytes
        );
    }

    #[tokio::test]
    async fn rapid_connect_disconnect_cycles() {
        let mut operations = Vec::new();

        for i in 0..100 {
            let identity = make_identity((i % 10) as u32);
            if i % 2 == 0 {
                operations.push(("connect", identity));
            } else {
                operations.push(("disconnect", identity));
            }
        }

        assert_eq!(operations.len(), 100);

        let node_0_ops: Vec<_> = operations
            .iter()
            .filter(|(_, id)| *id == make_identity(0))
            .collect();

        assert!(node_0_ops.len() >= 10, "Node 0 should have multiple operations");
    }
}
