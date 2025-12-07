//! GossipSub configuration parameters and constants.
//!
//! This module contains all the tunable parameters for GossipSub behavior,
//! including mesh sizes, rate limits, and flood protection constants.

use std::time::Duration;

// ============================================================================
// Mesh Configuration
// ============================================================================

/// Default mesh degree (number of peers per topic).
pub const DEFAULT_MESH_DEGREE: usize = 6;

/// Minimum mesh degree before seeking more peers.
pub const DEFAULT_MESH_DEGREE_LOW: usize = 4;

/// Maximum mesh degree before pruning excess peers.
pub const DEFAULT_MESH_DEGREE_HIGH: usize = 12;

// ============================================================================
// Cache Configuration
// ============================================================================

/// How long to cache messages for deduplication.
pub const DEFAULT_MESSAGE_CACHE_TTL: Duration = Duration::from_secs(120);

/// Maximum messages to cache for deduplication.
pub const DEFAULT_MESSAGE_CACHE_SIZE: usize = 10_000;

// ============================================================================
// Timing Configuration
// ============================================================================

/// Gossip interval for IHave messages.
pub const DEFAULT_GOSSIP_INTERVAL: Duration = Duration::from_secs(1);

/// Heartbeat interval for mesh maintenance.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// How long to keep fanout peers cached.
pub const DEFAULT_FANOUT_TTL: Duration = Duration::from_secs(60);

/// Maximum number of IHave messages to include in gossip.
pub const DEFAULT_MAX_IHAVE_LENGTH: usize = 100;

// ============================================================================
// Flood Protection Constants
// ============================================================================

/// Maximum size of a single pubsub message payload (64 KB).
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Default publish rate limit (messages per second for local publishes).
pub const DEFAULT_PUBLISH_RATE_LIMIT: usize = 100;

/// Default forward rate limit (messages per second for relayed messages).
pub const DEFAULT_FORWARD_RATE_LIMIT: usize = 1000;

/// Default per-peer rate limit (messages per second from any single peer).
pub const DEFAULT_PER_PEER_RATE_LIMIT: usize = 50;

/// Time window for rate limiting.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);

/// Maximum topic name length.
pub const MAX_TOPIC_LENGTH: usize = 256;

/// Maximum number of topics to track state for.
/// Prevents memory exhaustion from topic count explosion.
pub const MAX_TOPICS: usize = 10_000;

/// Validate a topic name.
/// 
/// Returns true if the topic is valid (non-empty, within length limit, printable ASCII).
/// This is used for incoming message validation.
#[inline]
pub fn is_valid_topic(topic: &str) -> bool {
    !topic.is_empty() 
        && topic.len() <= MAX_TOPIC_LENGTH 
        && topic.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

/// Maximum topics a peer can subscribe to.
pub const MAX_SUBSCRIPTIONS_PER_PEER: usize = 100;

/// Maximum number of peers tracked per topic (mesh + peers combined).
///
/// # Security
///
/// Limits the total number of peers tracked for any single topic.
/// This prevents Sybil attacks where an attacker creates many fake
/// identities to exhaust memory via topic peer tracking.
///
/// Set to 1000 which is far more than needed for efficient gossip
/// (mesh typically has 6-12 peers, gossip needs ~50-100 more).
pub const MAX_PEERS_PER_TOPIC: usize = 1000;

/// Maximum number of message IDs in a single IHave.
pub const DEFAULT_MAX_IHAVE_MESSAGES: usize = 10;

/// Maximum number of message IDs in a single IWant request.
/// Limits amplification attacks where small IWant triggers large data responses.
pub const DEFAULT_MAX_IWANT_MESSAGES: usize = 10;

/// Default IWant rate limit (requests per second per peer).
/// Prevents amplification attacks via rapid IWant requests.
pub const DEFAULT_IWANT_RATE_LIMIT: usize = 5;

/// Maximum total bytes sent in response to a single IWant request.
/// Even with MAX_IWANT_MESSAGES messages, we won't exceed this byte budget.
/// Limits amplification to ~256KB per request regardless of message count.
pub const MAX_IWANT_RESPONSE_BYTES: usize = 256 * 1024;

/// Maximum pending outbound messages per peer before dropping.
/// Prevents memory exhaustion from disconnected peers.
pub const MAX_OUTBOUND_PER_PEER: usize = 100;

/// Maximum total outbound messages across all peers.
/// Prevents memory exhaustion from many peers with queued messages.
pub const MAX_TOTAL_OUTBOUND_MESSAGES: usize = 50_000;

/// Maximum number of peers with outbound queues.
/// Prevents memory exhaustion from peer count multiplication.
pub const MAX_OUTBOUND_PEERS: usize = 1000;

/// Maximum number of peers tracked in rate limiting state.
/// Oldest entries are evicted when limit is reached.
pub const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;

/// Maximum age of rate limit entries before cleanup (5 minutes).
pub const RATE_LIMIT_ENTRY_MAX_AGE: Duration = Duration::from_secs(300);

// ============================================================================
// GossipConfig
// ============================================================================

/// GossipSub configuration parameters.
#[derive(Clone, Debug)]
pub struct GossipConfig {
    /// Target number of peers per topic mesh.
    pub mesh_degree: usize,
    /// Minimum peers before seeking more.
    pub mesh_degree_low: usize,
    /// Maximum peers before pruning.
    pub mesh_degree_high: usize,
    /// Message cache size for deduplication.
    pub message_cache_size: usize,
    /// Message cache TTL.
    pub message_cache_ttl: Duration,
    /// Gossip interval.
    pub gossip_interval: Duration,
    /// Heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Fanout cache TTL.
    pub fanout_ttl: Duration,
    /// Maximum IHave messages per gossip round.
    pub max_ihave_length: usize,
    /// Maximum message payload size in bytes.
    pub max_message_size: usize,
    /// Maximum publish rate (messages per second) for local publishes.
    pub publish_rate_limit: usize,
    /// Maximum forward rate (messages per second) for relayed messages.
    pub forward_rate_limit: usize,
    /// Maximum rate per peer (messages per second).
    pub per_peer_rate_limit: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            mesh_degree: DEFAULT_MESH_DEGREE,
            mesh_degree_low: DEFAULT_MESH_DEGREE_LOW,
            mesh_degree_high: DEFAULT_MESH_DEGREE_HIGH,
            message_cache_size: DEFAULT_MESSAGE_CACHE_SIZE,
            message_cache_ttl: DEFAULT_MESSAGE_CACHE_TTL,
            gossip_interval: DEFAULT_GOSSIP_INTERVAL,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            fanout_ttl: DEFAULT_FANOUT_TTL,
            max_ihave_length: DEFAULT_MAX_IHAVE_LENGTH,
            max_message_size: MAX_MESSAGE_SIZE,
            publish_rate_limit: DEFAULT_PUBLISH_RATE_LIMIT,
            forward_rate_limit: DEFAULT_FORWARD_RATE_LIMIT,
            per_peer_rate_limit: DEFAULT_PER_PEER_RATE_LIMIT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_sane() {
        let config = GossipConfig::default();
        assert!(config.mesh_degree_low < config.mesh_degree);
        assert!(config.mesh_degree < config.mesh_degree_high);
        assert!(config.message_cache_size > 0);
        assert!(config.max_message_size > 0);
        assert!(config.publish_rate_limit > 0);
        assert!(config.per_peer_rate_limit > 0);
    }

    #[test]
    fn flood_protection_constants() {
        // Verify constants are reasonable
        assert!(MAX_MESSAGE_SIZE >= 1024, "max message size too small");
        assert!(MAX_MESSAGE_SIZE <= 1024 * 1024, "max message size too large");
        assert!(MAX_TOPIC_LENGTH >= 32, "max topic length too small");
        assert!(DEFAULT_PUBLISH_RATE_LIMIT > 0);
        assert!(DEFAULT_FORWARD_RATE_LIMIT >= DEFAULT_PUBLISH_RATE_LIMIT);
        assert!(DEFAULT_PER_PEER_RATE_LIMIT > 0);
        assert!(RATE_LIMIT_WINDOW.as_secs() >= 1);
    }

    #[test]
    fn config_custom_values() {
        let config = GossipConfig {
            mesh_degree: 8,
            mesh_degree_low: 6,
            mesh_degree_high: 16,
            max_message_size: 1024,
            publish_rate_limit: 50,
            forward_rate_limit: 500,
            per_peer_rate_limit: 25,
            ..Default::default()
        };
        
        assert_eq!(config.mesh_degree, 8);
        assert_eq!(config.max_message_size, 1024);
        assert_eq!(config.publish_rate_limit, 50);
        assert_eq!(config.per_peer_rate_limit, 25);
    }

    // ========================================================================
    // Config Security Tests (from tests/security_pubsub.rs)
    // ========================================================================

    #[test]
    fn default_config_has_security_limits() {
        let config = GossipConfig::default();

        assert!(
            config.max_message_size >= 1024 && config.max_message_size <= 1024 * 1024,
            "max_message_size should be between 1KB and 1MB, got {}",
            config.max_message_size
        );

        assert!(
            config.publish_rate_limit >= 1 && config.publish_rate_limit <= 10000,
            "publish_rate_limit should be reasonable, got {}",
            config.publish_rate_limit
        );
        assert!(
            config.forward_rate_limit >= 1 && config.forward_rate_limit <= 100000,
            "forward_rate_limit should be reasonable, got {}",
            config.forward_rate_limit
        );
        assert!(
            config.per_peer_rate_limit >= 1 && config.per_peer_rate_limit <= 1000,
            "per_peer_rate_limit should be reasonable, got {}",
            config.per_peer_rate_limit
        );

        assert!(
            config.mesh_degree >= 2 && config.mesh_degree <= 20,
            "mesh_degree should be between 2 and 20, got {}",
            config.mesh_degree
        );
        assert!(
            config.mesh_degree_low < config.mesh_degree,
            "mesh_degree_low ({}) should be less than mesh_degree ({})",
            config.mesh_degree_low,
            config.mesh_degree
        );
        assert!(
            config.mesh_degree < config.mesh_degree_high,
            "mesh_degree ({}) should be less than mesh_degree_high ({})",
            config.mesh_degree,
            config.mesh_degree_high
        );

        assert!(
            config.message_cache_size >= 100 && config.message_cache_size <= 1_000_000,
            "message_cache_size should be reasonable, got {}",
            config.message_cache_size
        );

        assert!(
            config.message_cache_ttl >= Duration::from_secs(10)
                && config.message_cache_ttl <= Duration::from_secs(3600),
            "message_cache_ttl should be reasonable, got {:?}",
            config.message_cache_ttl
        );
    }

    #[test]
    fn rate_limits_balanced() {
        let config = GossipConfig::default();

        assert!(
            config.per_peer_rate_limit <= config.forward_rate_limit,
            "per_peer ({}) should be <= forward_rate ({})",
            config.per_peer_rate_limit,
            config.forward_rate_limit
        );
    }

    #[test]
    fn message_cache_configuration() {
        let config = GossipConfig::default();

        assert!(config.message_cache_size > 0);
        assert!(config.message_cache_size <= 1_000_000);

        assert!(config.message_cache_ttl >= Duration::from_secs(30));
        assert!(config.message_cache_ttl <= Duration::from_secs(3600));
    }

    #[test]
    fn fanout_ttl_configuration() {
        let config = GossipConfig::default();

        assert!(config.fanout_ttl >= Duration::from_secs(10));
        assert!(config.fanout_ttl <= Duration::from_secs(300));
    }

    #[test]
    fn heartbeat_interval_configuration() {
        let config = GossipConfig::default();

        assert!(config.heartbeat_interval >= Duration::from_millis(100));
        assert!(config.heartbeat_interval <= Duration::from_secs(10));
    }

    #[test]
    fn gossip_interval_configuration() {
        let config = GossipConfig::default();

        assert!(config.gossip_interval >= Duration::from_millis(100));
        assert!(config.gossip_interval <= Duration::from_secs(10));
    }
}
