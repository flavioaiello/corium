//! # GossipSub Epidemic Broadcast
//!
//! This module implements the GossipSub protocol for reliable pub/sub messaging.
//! GossipSub builds an efficient broadcast tree while maintaining reliability
//! through lazy push repair.
//!
//! ## Protocol Overview
//!
//! GossipSub maintains two peer sets per topic:
//!
//! | Set | Purpose | Message Type |
//! |-----|---------|-------------|
//! | Eager | Immediate message forwarding | Full messages |
//! | Lazy | Backup for missed messages | IHave announcements |
//!
//! ## Message Flow
//!
//! 1. **Publish**: Message sent to all eager peers
//! 2. **IHave**: Lazy peers receive message ID announcements
//! 3. **IWant**: Peer requests missing message
//! 4. **Graft**: Promotes lazy peer to eager after repair
//! 5. **Prune**: Demotes eager peer to lazy (tree optimization)
//!
//! ## Tree Optimization
//!
//! The eager peer set naturally forms a spanning tree:
//! - First peer to deliver message becomes/stays eager
//! - Duplicate deliveries trigger Prune (demote to lazy)
//! - Missing messages trigger Graft (promote to eager)
//!
//! ## Security Measures
//!
//! - Message signatures verified before forwarding
//! - Per-peer and global rate limiting
//! - Bounded caches with LRU eviction
//! - Sequence number tracking for replay detection
//!
//! ## References
//!
//! Leitão, J., Pereira, J., & Rodrigues, L. (2007). "Epidemic Broadcast Trees"

use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use blake3::hash;
use lru::LruCache;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, trace, warn};

use crate::crypto::{SignatureError, GOSSIPSUB_SIGNATURE_DOMAIN, verify_with_domain};
use crate::dht::DhtNode;
use crate::identity::{Contact, Identity, Keypair};
use crate::messages::{MessageId, GossipSubRequest};
use crate::protocols::GossipSubRpc;
use crate::rpc::RpcNode;

// ============================================================================
// Relay Signal (mesh-mediated signaling)
// ============================================================================

/// A relay signal received through the GossipSub mesh.
/// 
/// This is used for mesh-mediated signaling: relays can send connection
/// notifications through mesh connections instead of dedicated signaling streams.
#[derive(Debug, Clone)]
pub struct RelaySignal {
    /// The peer requesting connection (initiator).
    pub from_peer: Identity,
    /// Session ID for the relay connection.
    pub session_id: [u8; 16],
    /// Address to send relay data packets to.
    pub relay_data_addr: String,
}

// ============================================================================
// Configuration Constants
// ============================================================================

/// Timeout for IWant requests before trying another peer.
pub const DEFAULT_IHAVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Default message cache size (number of messages).
pub const DEFAULT_MESSAGE_CACHE_SIZE: usize = 10_000;

/// Time-to-live for cached messages.
pub const DEFAULT_MESSAGE_CACHE_TTL: Duration = Duration::from_secs(120);

/// Interval between heartbeat rounds (maintenance tasks).
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum IHave message IDs per announcement.
pub const DEFAULT_MAX_IHAVE_LENGTH: usize = 100;

// ============================================================================
// Security Limits
// ============================================================================

/// Maximum message payload size (64 KiB).
/// SECURITY: Prevents memory exhaustion from large messages.
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Rate limit for local publishes per second.
pub const DEFAULT_PUBLISH_RATE_LIMIT: usize = 100;

/// Rate limit for messages received per peer per second.
pub const DEFAULT_PER_PEER_RATE_LIMIT: usize = 50;

/// Time window for rate limiting.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);

/// Maximum topic name length.
pub const MAX_TOPIC_LENGTH: usize = 256;

/// Maximum number of topics a node can track.
/// SCALABILITY: 10K topics is the per-node limit (see README Scaling Boundaries).
/// SECURITY: Prevents memory exhaustion from topic proliferation.
pub const MAX_TOPICS: usize = 10_000;

#[inline]
pub fn is_valid_topic(topic: &str) -> bool {
    !topic.is_empty() 
        && topic.len() <= MAX_TOPIC_LENGTH 
        && topic.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

pub const MAX_SUBSCRIPTIONS_PER_PEER: usize = 100;

/// Maximum peers tracked per topic.
/// SCALABILITY: 1,000 peers/topic maintains gossip efficiency (see README).
/// SECURITY: Bounds topic data structure growth.
pub const MAX_PEERS_PER_TOPIC: usize = 1000;

/// Maximum pending IWant requests per peer.
pub const DEFAULT_MAX_IWANT_MESSAGES: usize = 10;

/// Rate limit for IWant requests per peer per second.
pub const DEFAULT_IWANT_RATE_LIMIT: usize = 5;

/// Maximum bytes in an IWant batch response.
pub const MAX_IWANT_RESPONSE_BYTES: usize = 256 * 1024;

/// Maximum outbound queue size per peer.
/// SECURITY: Prevents memory exhaustion from slow receivers.
pub const MAX_OUTBOUND_PER_PEER: usize = 100;

/// Maximum total outbound messages across all peers.
/// SECURITY: Global memory bound for outbound queues.
pub const MAX_TOTAL_OUTBOUND_MESSAGES: usize = 50_000;

/// Maximum peers in the outbound queue map.
pub const MAX_OUTBOUND_PEERS: usize = 1000;

/// Maximum number of known peers to track.
/// This bounds memory usage from peer notifications.
pub const MAX_KNOWN_PEERS: usize = 1000;

/// Maximum entries in the rate limit tracker.
/// SECURITY: Bounds the rate limiter itself to prevent memory leaks.
pub const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;

/// Maximum IDONTWANT entries to track per peer.
/// Per GossipSub v1.2: tracks messages peers don't want to receive.
/// SECURITY: Prevents memory exhaustion from excessive IDontWant messages.
pub const MAX_IDONTWANT_PER_PEER: usize = 1000;

/// TTL for IDontWant entries before expiration.
/// Per GossipSub v1.2: entries should expire after a reasonable time.
pub const IDONTWANT_TTL: Duration = Duration::from_secs(30);

/// Maximum message sources to track sequence numbers for.
/// SCALABILITY: 10K sources × 128-bit window = ~2 MB (constant, not O(N)).
/// SECURITY: Limits replay tracking table size.
pub const MAX_SEQNO_TRACKING_SOURCES: usize = 10_000;

/// Window size for sequence number tracking (replay detection).
/// A sliding window allows out-of-order delivery within bounds.
pub const SEQNO_WINDOW_SIZE: usize = 128;

/// Maximum total bytes for message cache (64 MiB).
/// SECURITY: Hard limit on message cache memory usage.
pub const MAX_MESSAGE_CACHE_BYTES: usize = 64 * 1024 * 1024;

// ============================================================================
// GossipSub v1.1 Peer Scoring Parameters
// ============================================================================

/// Default score threshold for graylist (don't accept messages from).
pub const DEFAULT_GRAYLIST_THRESHOLD: f64 = -100.0;

/// Default score threshold for publish (don't publish to).
pub const DEFAULT_PUBLISH_THRESHOLD: f64 = -50.0;

/// Default score threshold for gossip (don't gossip to).
pub const DEFAULT_GOSSIP_THRESHOLD: f64 = -25.0;

/// Default decay interval for peer scores.
pub const DEFAULT_DECAY_INTERVAL: Duration = Duration::from_secs(1);

/// Default decay to zero threshold.
/// Scores below this absolute value decay to exactly zero.
pub const DEFAULT_DECAY_TO_ZERO: f64 = 0.01;

/// Default P1 weight (time in mesh).
pub const DEFAULT_P1_WEIGHT: f64 = 1.0;

/// Default P2 weight (first message deliveries).
pub const DEFAULT_P2_WEIGHT: f64 = 1.0;

/// Default P3 weight (mesh message delivery rate).
pub const DEFAULT_P3_WEIGHT: f64 = 0.0;

/// Default P3b weight (mesh failure penalty).
pub const DEFAULT_P3B_WEIGHT: f64 = 0.0;

/// Default P4 weight (invalid messages).
pub const DEFAULT_P4_WEIGHT: f64 = -100.0;

/// Default P5 weight (application-specific score).
pub const DEFAULT_P5_WEIGHT: f64 = 1.0;

/// Default P6 weight (IP colocation factor).
pub const DEFAULT_P6_WEIGHT: f64 = 0.0;

/// Default P7 weight (behavioural penalty).
pub const DEFAULT_P7_WEIGHT: f64 = -10.0;

/// Default time in mesh quantum for P1 scoring.
pub const DEFAULT_TIME_IN_MESH_QUANTUM: Duration = Duration::from_millis(100);

/// Default cap for P1 score contribution.
pub const DEFAULT_TIME_IN_MESH_CAP: f64 = 3600.0;

/// Default cap for first message deliveries (P2).
pub const DEFAULT_FIRST_MESSAGE_DELIVERIES_CAP: f64 = 100.0;

/// Maximum peers to track scores for.
/// SECURITY: Bounds the peer scoring table size.
pub const MAX_SCORED_PEERS: usize = 10_000;

// ============================================================================
// GossipSub v1.1 Mesh Parameters
// ============================================================================

/// D - Target number of peers in the mesh per topic.
pub const DEFAULT_MESH_N: usize = 6;

/// D_lo - Minimum mesh size before adding peers.
pub const DEFAULT_MESH_N_LOW: usize = 5;

/// D_hi - Maximum mesh size before pruning.
pub const DEFAULT_MESH_N_HIGH: usize = 12;

/// D_out - Minimum outbound peers in mesh (connection direction matters).
/// SECURITY: Prevents eclipse attacks by requiring outbound connections.
pub const DEFAULT_MESH_OUTBOUND_MIN: usize = 2;

/// D_lazy - Number of peers to gossip IHAVE to during heartbeat.
pub const DEFAULT_GOSSIP_LAZY: usize = 6;

/// Default PRUNE backoff duration in seconds.
pub const DEFAULT_PRUNE_BACKOFF_SECS: u64 = 60;

/// GossipSub configuration.
/// 
/// Contains all tunable parameters per the GossipSub v1.1 spec.
/// Some fields may not be read internally but are exposed for library users
/// to configure when building custom implementations.
#[derive(Clone, Debug)]
#[allow(dead_code)] // Config fields are public API for library users
pub struct GossipSubConfig {
    // ========================================================================
    // GossipSub v1.1 Mesh Parameters
    // ========================================================================
    
    /// D - Target number of peers in the mesh per topic.
    pub mesh_n: usize,
    /// D_lo - Minimum mesh peers before grafting more.
    pub mesh_n_low: usize,
    /// D_hi - Maximum mesh peers before pruning excess.
    pub mesh_n_high: usize,
    /// D_out - Minimum outbound peers in mesh.
    pub mesh_outbound_min: usize,
    /// D_lazy - Number of peers to gossip IHAVE to.
    pub gossip_lazy: usize,
    /// PRUNE backoff duration before re-grafting.
    pub prune_backoff: Duration,
    
    // ========================================================================
    // Peer Scoring Configuration (GossipSub v1.1)
    // ========================================================================
    
    /// Enable peer scoring. When disabled, all peers score 0.
    pub peer_scoring_enabled: bool,
    /// Score threshold below which we won't accept messages.
    pub graylist_threshold: f64,
    /// Score threshold below which we won't publish to peer.
    pub publish_threshold: f64,
    /// Score threshold below which we won't gossip to peer.
    pub gossip_threshold: f64,
    /// Interval between score decay applications.
    pub decay_interval: Duration,
    /// Threshold below which scores decay to exactly zero.
    pub decay_to_zero: f64,
    
    // ========================================================================
    // Timing and Caching
    // ========================================================================
    
    /// Timeout for IHave/IWant exchanges.
    pub ihave_timeout: Duration,
    /// Interval between heartbeat rounds (gossip emission, mesh maintenance).
    pub heartbeat_interval: Duration,
    /// Maximum number of messages in cache.
    pub message_cache_size: usize,
    /// Time-to-live for cached messages.
    pub message_cache_ttl: Duration,
    
    // ========================================================================
    // Size and Rate Limits
    // ========================================================================
    
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Maximum IHave message IDs per notification.
    pub max_ihave_length: usize,
    /// Rate limit for publishing messages per second.
    pub publish_rate_limit: usize,
    /// Rate limit for messages received per peer per second.
    pub per_peer_rate_limit: usize,
}

impl Default for GossipSubConfig {
    fn default() -> Self {
        Self {
            // GossipSub v1.1 mesh parameters
            mesh_n: DEFAULT_MESH_N,
            mesh_n_low: DEFAULT_MESH_N_LOW,
            mesh_n_high: DEFAULT_MESH_N_HIGH,
            mesh_outbound_min: DEFAULT_MESH_OUTBOUND_MIN,
            gossip_lazy: DEFAULT_GOSSIP_LAZY,
            prune_backoff: Duration::from_secs(DEFAULT_PRUNE_BACKOFF_SECS),
            
            // Peer scoring (disabled by default for backward compat)
            peer_scoring_enabled: false,
            graylist_threshold: DEFAULT_GRAYLIST_THRESHOLD,
            publish_threshold: DEFAULT_PUBLISH_THRESHOLD,
            gossip_threshold: DEFAULT_GOSSIP_THRESHOLD,
            decay_interval: DEFAULT_DECAY_INTERVAL,
            decay_to_zero: DEFAULT_DECAY_TO_ZERO,
            
            // Timing and caching
            ihave_timeout: DEFAULT_IHAVE_TIMEOUT,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            message_cache_size: DEFAULT_MESSAGE_CACHE_SIZE,
            message_cache_ttl: DEFAULT_MESSAGE_CACHE_TTL,
            
            // Size and rate limits
            max_message_size: MAX_MESSAGE_SIZE,
            max_ihave_length: DEFAULT_MAX_IHAVE_LENGTH,
            publish_rate_limit: DEFAULT_PUBLISH_RATE_LIMIT,
            per_peer_rate_limit: DEFAULT_PER_PEER_RATE_LIMIT,
        }
    }
}

// ============================================================================
// Peer Scoring (GossipSub v1.1 Spec)
// ============================================================================

/// Topic-specific score parameters.
/// 
/// Some fields may not be read internally but are exposed for library users
/// to configure custom scoring policies.
#[derive(Clone, Debug)]
#[allow(dead_code)] // Config fields are public API for library users
pub struct TopicScoreParams {
    /// Weight of this topic in overall peer score.
    pub topic_weight: f64,
    
    // P1: Time in mesh
    /// Weight for time-in-mesh score component.
    pub time_in_mesh_weight: f64,
    /// Quantum for time-in-mesh calculation.
    pub time_in_mesh_quantum: Duration,
    /// Cap for time-in-mesh contribution.
    pub time_in_mesh_cap: f64,
    
    // P2: First message deliveries
    /// Weight for first-message-deliveries score component.
    pub first_message_deliveries_weight: f64,
    /// Decay factor for first message deliveries counter.
    pub first_message_deliveries_decay: f64,
    /// Cap for first message deliveries contribution.
    pub first_message_deliveries_cap: f64,
    
    // P3: Mesh message delivery rate (optional, complex)
    /// Weight for mesh message delivery rate (0 = disabled).
    pub mesh_message_deliveries_weight: f64,
    /// Decay for mesh message delivery counter.
    pub mesh_message_deliveries_decay: f64,
    /// Threshold for satisfactory delivery rate.
    pub mesh_message_deliveries_threshold: f64,
    /// Activation window for mesh delivery scoring.
    pub mesh_message_deliveries_activation: Duration,
    
    // P3b: Mesh failure penalty
    /// Weight for mesh failure penalty (0 = disabled).
    pub mesh_failure_penalty_weight: f64,
    /// Decay for mesh failure penalty.
    pub mesh_failure_penalty_decay: f64,
    
    // P4: Invalid messages
    /// Weight for invalid message score (should be negative).
    pub invalid_message_deliveries_weight: f64,
    /// Decay for invalid message counter.
    pub invalid_message_deliveries_decay: f64,
}

impl Default for TopicScoreParams {
    fn default() -> Self {
        Self {
            topic_weight: 1.0,
            
            // P1: Time in mesh (simple, always on)
            time_in_mesh_weight: DEFAULT_P1_WEIGHT,
            time_in_mesh_quantum: DEFAULT_TIME_IN_MESH_QUANTUM,
            time_in_mesh_cap: DEFAULT_TIME_IN_MESH_CAP,
            
            // P2: First message deliveries (simple, always on)
            first_message_deliveries_weight: DEFAULT_P2_WEIGHT,
            first_message_deliveries_decay: 0.5,
            first_message_deliveries_cap: DEFAULT_FIRST_MESSAGE_DELIVERIES_CAP,
            
            // P3: Mesh delivery rate (disabled by default)
            mesh_message_deliveries_weight: DEFAULT_P3_WEIGHT,
            mesh_message_deliveries_decay: 0.5,
            mesh_message_deliveries_threshold: 1.0,
            mesh_message_deliveries_activation: Duration::from_secs(60),
            
            // P3b: Mesh failure penalty (disabled by default)
            mesh_failure_penalty_weight: DEFAULT_P3B_WEIGHT,
            mesh_failure_penalty_decay: 0.5,
            
            // P4: Invalid messages (always on, negative weight)
            invalid_message_deliveries_weight: DEFAULT_P4_WEIGHT,
            invalid_message_deliveries_decay: 0.5,
        }
    }
}

/// Per-peer score tracking for a specific topic.
#[derive(Debug, Clone, Default)]
struct TopicScore {
    /// Time this peer was added to the mesh for this topic.
    mesh_time: Option<Instant>,
    /// Counter for first message deliveries (P2).
    first_message_deliveries: f64,
    /// Counter for mesh message deliveries (P3).
    mesh_message_deliveries: f64,
    /// Accumulated mesh failure penalty (P3b).
    mesh_failure_penalty: f64,
    /// Counter for invalid message deliveries (P4).
    invalid_message_deliveries: f64,
}

impl TopicScore {
    /// Calculate this topic's contribution to the peer score.
    fn calculate(&self, params: &TopicScoreParams) -> f64 {
        let mut score = 0.0;
        
        // P1: Time in mesh
        if let Some(mesh_time) = self.mesh_time {
            let time_in_mesh = mesh_time.elapsed();
            let p1_value = (time_in_mesh.as_secs_f64() / params.time_in_mesh_quantum.as_secs_f64())
                .min(params.time_in_mesh_cap);
            score += params.time_in_mesh_weight * p1_value;
        }
        
        // P2: First message deliveries
        let p2_value = self.first_message_deliveries.min(params.first_message_deliveries_cap);
        score += params.first_message_deliveries_weight * p2_value;
        
        // P3: Mesh message delivery rate (only if in mesh and activated)
        if let Some(mesh_time) = self.mesh_time
            && mesh_time.elapsed() >= params.mesh_message_deliveries_activation
        {
            let deficit = params.mesh_message_deliveries_threshold - self.mesh_message_deliveries;
            if deficit > 0.0 {
                // Below threshold = penalty (squared deficit)
                let p3_value = deficit * deficit;
                score += params.mesh_message_deliveries_weight * p3_value;
            }
        }
        
        // P3b: Mesh failure penalty
        score += params.mesh_failure_penalty_weight * self.mesh_failure_penalty;
        
        // P4: Invalid message deliveries (always negative contribution)
        let p4_value = self.invalid_message_deliveries * self.invalid_message_deliveries;
        score += params.invalid_message_deliveries_weight * p4_value;
        
        // Apply topic weight
        params.topic_weight * score
    }
    
    /// Apply decay to all counters.
    fn decay(&mut self, params: &TopicScoreParams) {
        self.first_message_deliveries *= params.first_message_deliveries_decay;
        self.mesh_message_deliveries *= params.mesh_message_deliveries_decay;
        self.mesh_failure_penalty *= params.mesh_failure_penalty_decay;
        self.invalid_message_deliveries *= params.invalid_message_deliveries_decay;
    }
}

/// Complete peer score state per GossipSub v1.1 spec.
#[derive(Debug, Clone)]
struct PeerScore {
    /// Per-topic score components.
    topic_scores: HashMap<String, TopicScore>,
    /// P5: Application-specific score (set externally).
    app_specific_score: f64,
    /// P6: IP colocation factor (simplified: count of peers with same IP).
    ip_colocation_factor: f64,
    /// P7: Behavioural penalty counter.
    behaviour_penalty: f64,
    /// Last time decay was applied.
    last_decay: Instant,
}

impl Default for PeerScore {
    fn default() -> Self {
        Self {
            topic_scores: HashMap::new(),
            app_specific_score: 0.0,
            ip_colocation_factor: 0.0,
            behaviour_penalty: 0.0,
            last_decay: Instant::now(),
        }
    }
}

impl PeerScore {
    /// Calculate the total peer score.
    fn calculate(&self, topic_params: &HashMap<String, TopicScoreParams>) -> f64 {
        let mut score = 0.0;
        
        // Sum topic-specific scores
        for (topic, topic_score) in &self.topic_scores {
            if let Some(params) = topic_params.get(topic) {
                score += topic_score.calculate(params);
            }
        }
        
        // P5: Application-specific score
        score += DEFAULT_P5_WEIGHT * self.app_specific_score;
        
        // P6: IP colocation factor (simplified)
        score += DEFAULT_P6_WEIGHT * self.ip_colocation_factor;
        
        // P7: Behavioural penalty (squared)
        score += DEFAULT_P7_WEIGHT * self.behaviour_penalty * self.behaviour_penalty;
        
        score
    }
    
    /// Apply decay to all score components.
    fn decay(&mut self, topic_params: &HashMap<String, TopicScoreParams>, decay_to_zero: f64) {
        for (topic, topic_score) in self.topic_scores.iter_mut() {
            if let Some(params) = topic_params.get(topic) {
                topic_score.decay(params);
            }
        }
        
        // Decay behaviour penalty
        self.behaviour_penalty *= 0.99; // Fixed decay for P7
        
        // Zero out very small values
        if self.behaviour_penalty.abs() < decay_to_zero {
            self.behaviour_penalty = 0.0;
        }
        
        self.last_decay = Instant::now();
    }
    
    /// Record joining mesh for a topic.
    fn mesh_joined(&mut self, topic: &str) {
        let topic_score = self.topic_scores.entry(topic.to_string()).or_default();
        topic_score.mesh_time = Some(Instant::now());
    }
    
    /// Record leaving mesh for a topic.
    fn mesh_left(&mut self, topic: &str, params: &TopicScoreParams) {
        if let Some(topic_score) = self.topic_scores.get_mut(topic) {
            // If we left mesh before activation, no penalty
            if let Some(mesh_time) = topic_score.mesh_time
                && mesh_time.elapsed() >= params.mesh_message_deliveries_activation
            {
                // Below threshold at mesh exit = mesh failure penalty
                let deficit = params.mesh_message_deliveries_threshold 
                    - topic_score.mesh_message_deliveries;
                if deficit > 0.0 {
                    topic_score.mesh_failure_penalty += deficit * deficit;
                }
            }
            topic_score.mesh_time = None;
            topic_score.mesh_message_deliveries = 0.0;
        }
    }
    
    /// Record first message delivery (P2).
    fn first_message_delivered(&mut self, topic: &str) {
        let topic_score = self.topic_scores.entry(topic.to_string()).or_default();
        topic_score.first_message_deliveries += 1.0;
    }
    
    /// Record mesh message delivery (P3, only counts if in mesh).
    fn mesh_message_delivered(&mut self, topic: &str) {
        if let Some(topic_score) = self.topic_scores.get_mut(topic)
            && topic_score.mesh_time.is_some()
        {
            topic_score.mesh_message_deliveries += 1.0;
        }
    }
    
    /// Record invalid message (P4).
    fn invalid_message(&mut self, topic: &str) {
        let topic_score = self.topic_scores.entry(topic.to_string()).or_default();
        topic_score.invalid_message_deliveries += 1.0;
    }
    
    /// Add a behavioural penalty (P7).
    fn add_behaviour_penalty(&mut self, penalty: f64) {
        self.behaviour_penalty += penalty;
    }
}


// ============================================================================
// GossipSub Message Signing
// ============================================================================

/// Build the payload that gets signed for a GossipSub message.
/// 
/// This constructs the canonical byte representation that is signed.
/// The actual signing uses domain separation via `crypto::sign_with_domain()`.
/// 
/// Format: source(32) || topic_len(4) || topic || seqno(8) || data_len(4) || data
fn build_gossipsub_signed_payload(source: &Identity, topic: &str, seqno: u64, data: &[u8]) -> Vec<u8> {
    let topic_bytes = topic.as_bytes();
    let mut payload = Vec::with_capacity(32 + 4 + topic_bytes.len() + 8 + 4 + data.len());
    
    // Source identity (CRITICAL: prevents source spoofing)
    payload.extend_from_slice(source.as_bytes());
    
    // Topic (length-prefixed)
    payload.extend_from_slice(&(topic_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(topic_bytes);
    
    // Sequence number
    payload.extend_from_slice(&seqno.to_le_bytes());
    
    // Data payload (length-prefixed)
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    
    payload
}

/// Sign a GossipSub message.
/// 
/// Uses domain separation to prevent cross-protocol signature replay.
fn sign_gossipsub_message(keypair: &Keypair, topic: &str, seqno: u64, data: &[u8]) -> Vec<u8> {
    let source = keypair.identity();
    let payload = build_gossipsub_signed_payload(&source, topic, seqno, data);
    crate::crypto::sign_with_domain(keypair, GOSSIPSUB_SIGNATURE_DOMAIN, &payload)
}

/// Verify a GossipSub message signature.
/// 
/// Uses domain separation to prevent cross-protocol signature replay.
fn verify_gossipsub_signature(
    source: &Identity,
    topic: &str,
    seqno: u64,
    data: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let payload = build_gossipsub_signed_payload(source, topic, seqno, data);
    verify_with_domain(source, GOSSIPSUB_SIGNATURE_DOMAIN, &payload, signature)
}


const MAX_PENDING_IWANTS: usize = 100;

/// Global limit on pending IWants across all topics to prevent memory exhaustion.
const MAX_GLOBAL_PENDING_IWANTS: usize = 1000;

#[derive(Clone, Debug, Default)]
struct SeqnoTracker {
    highest_seen: u64,
    recent_seqnos: VecDeque<u64>,
}

impl SeqnoTracker {
    fn check_and_record(&mut self, seqno: u64) -> bool {
        if seqno > self.highest_seen {
            self.highest_seen = seqno;
            self.record_recent(seqno);
            return true;
        }
        
        if self.recent_seqnos.contains(&seqno) {
            return false;
        }
        
        if seqno + SEQNO_WINDOW_SIZE as u64 >= self.highest_seen {
            self.record_recent(seqno);
            return true;
        }
        
        false
    }
    
    fn record_recent(&mut self, seqno: u64) {
        if self.recent_seqnos.len() >= SEQNO_WINDOW_SIZE {
            self.recent_seqnos.pop_front();
        }
        self.recent_seqnos.push_back(seqno);
    }
}

/// Tracks messages a peer has indicated they don't want to receive (IDONTWANT).
/// Per GossipSub v1.2, this is an optimization to reduce redundant message delivery.
#[derive(Debug, Default, Clone)]
struct IDontWantTracker {
    /// Message IDs the peer doesn't want, with timestamps for expiration.
    entries: VecDeque<(MessageId, Instant)>,
}

impl IDontWantTracker {
    /// Add a message ID that the peer doesn't want.
    fn add(&mut self, msg_id: MessageId) {
        // Check if already present
        if self.entries.iter().any(|(id, _)| *id == msg_id) {
            return;
        }
        
        // Enforce max entries limit by evicting oldest
        while self.entries.len() >= MAX_IDONTWANT_PER_PEER {
            self.entries.pop_front();
        }
        
        self.entries.push_back((msg_id, Instant::now()));
    }
    
    /// Check if the peer doesn't want a message.
    fn contains(&self, msg_id: &MessageId) -> bool {
        self.entries.iter().any(|(id, _)| id == msg_id)
    }
    
    /// Remove expired entries (older than IDONTWANT_TTL).
    fn expire_old(&mut self) {
        let now = Instant::now();
        while let Some((_, timestamp)) = self.entries.front() {
            if now.duration_since(*timestamp) > IDONTWANT_TTL {
                self.entries.pop_front();
            } else {
                break; // Entries are in order, so stop at first non-expired
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    pub topic: String,
    pub source: Identity,
    pub seqno: u64,
    pub data: Vec<u8>,
    pub msg_id: MessageId,
    pub received_at: Instant,
}

#[derive(Clone)]
pub(crate) struct CachedMessage {
    pub topic: String,
    pub source: Identity,
    pub seqno: u64,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    pub cached_at: Instant,
}

impl CachedMessage {
    pub fn size_bytes(&self) -> usize {
        self.topic.len() + self.data.len() + self.signature.len() + 64
    }
}

#[derive(Debug)]
pub(crate) struct TopicState {
    pub eager_peers: HashSet<Identity>,
    pub lazy_peers: HashSet<Identity>,
    /// Peers where we initiated the GRAFT (outbound connections).
    /// SECURITY: Used for D_out enforcement to prevent eclipse attacks.
    pub outbound_peers: HashSet<Identity>,
    pub recent_messages: VecDeque<MessageId>,
    pub pending_iwants: HashMap<MessageId, (Instant, Vec<Identity>)>,
    pub last_lazy_push: Instant,
}

impl Default for TopicState {
    fn default() -> Self {
        Self {
            eager_peers: HashSet::new(),
            lazy_peers: HashSet::new(),
            outbound_peers: HashSet::new(),
            recent_messages: VecDeque::new(),
            pending_iwants: HashMap::new(),
            last_lazy_push: Instant::now(),
        }
    }
}

impl TopicState {
    pub fn total_peers(&self) -> usize {
        self.eager_peers.len() + self.lazy_peers.len()
    }

    /// Add a peer as eager. If eager count exceeds target, demotes oldest eager to lazy.
    /// Returns true if peer was added (as eager or lazy), false if at MAX_PEERS_PER_TOPIC.
    #[cfg(test)]
    pub fn add_eager(&mut self, peer: Identity) -> bool {
        self.add_peer_with_limits(peer, usize::MAX, usize::MAX)
    }

    /// Add a peer with enforcement of eager/lazy target limits.
    /// If eager count would exceed target, adds as lazy instead.
    pub fn add_peer_with_limits(&mut self, peer: Identity, eager_target: usize, lazy_target: usize) -> bool {
        if self.contains(&peer) {
            return true; // Already present
        }
        if self.total_peers() >= MAX_PEERS_PER_TOPIC {
            return false;
        }
        
        // Add as eager if under target, otherwise as lazy
        if self.eager_peers.len() < eager_target {
            self.eager_peers.insert(peer);
        } else if self.lazy_peers.len() < lazy_target {
            self.lazy_peers.insert(peer);
        } else {
            // Both at target, add as lazy anyway (will be rebalanced)
            self.lazy_peers.insert(peer);
        }
        true
    }

    pub fn demote_to_lazy(&mut self, peer: Identity) {
        if self.eager_peers.remove(&peer) {
            self.lazy_peers.insert(peer);
        }
    }

    /// Promote a peer to eager if under target, otherwise add as lazy.
    #[cfg(test)]
    pub fn promote_to_eager(&mut self, peer: Identity) {
        self.promote_to_eager_with_limit(peer, usize::MAX)
    }

    /// Promote a peer to eager only if under the target limit.
    pub fn promote_to_eager_with_limit(&mut self, peer: Identity, eager_target: usize) {
        let was_lazy = self.lazy_peers.remove(&peer);
        let is_eager = self.eager_peers.contains(&peer);
        
        if is_eager {
            return; // Already eager
        }
        
        if self.eager_peers.len() < eager_target {
            // Under target, promote to eager
            self.eager_peers.insert(peer);
        } else if was_lazy {
            // At target, keep as lazy
            self.lazy_peers.insert(peer);
        } else if self.total_peers() < MAX_PEERS_PER_TOPIC {
            // New peer, add as lazy since eager is at target
            self.lazy_peers.insert(peer);
        }
    }

    pub fn contains(&self, peer: &Identity) -> bool {
        self.eager_peers.contains(peer) || self.lazy_peers.contains(peer)
    }

    pub fn remove_peer(&mut self, peer: &Identity) {
        self.eager_peers.remove(peer);
        self.lazy_peers.remove(peer);
        self.outbound_peers.remove(peer);
    }

    /// Count outbound peers currently in the mesh (eager).
    /// SECURITY: Used for D_out enforcement to prevent eclipse attacks.
    pub fn outbound_mesh_count(&self) -> usize {
        self.eager_peers.intersection(&self.outbound_peers).count()
    }

    /// Check if a peer is an outbound connection.
    pub fn is_outbound(&self, peer: &Identity) -> bool {
        self.outbound_peers.contains(peer)
    }

    /// Mark a peer as outbound (we initiated the GRAFT).
    pub fn mark_outbound(&mut self, peer: Identity) {
        self.outbound_peers.insert(peer);
    }

    pub fn should_lazy_push(&self, lazy_push_interval: Duration) -> bool {
        self.last_lazy_push.elapsed() >= lazy_push_interval && !self.lazy_peers.is_empty()
    }

    /// Record a pending IWant for a message. Returns the delta to apply to the global count:
    /// +1 if a new entry was added, 0 if updated existing, -1 if an old entry was evicted.
    pub fn record_iwant(&mut self, msg_id: MessageId, peer: Identity) -> i32 {
        let mut delta = 0i32;
        
        // If entry already exists, just return 0 (no change to global count)
        if self.pending_iwants.contains_key(&msg_id) {
            return 0;
        }
        
        if self.pending_iwants.len() >= MAX_PENDING_IWANTS
            && let Some(oldest) = self.pending_iwants
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(id, _)| *id)
        {
            self.pending_iwants.remove(&oldest);
            delta -= 1; // Evicted one
        }
        self.pending_iwants.insert(msg_id, (Instant::now(), vec![peer]));
        delta += 1; // Added one
        delta
    }

    /// Check for timed out IWant requests and retry with different peers.
    /// Returns (retries, completed_count) where completed_count is the number of
    /// IWants that exhausted all retry options and were removed.
    pub fn check_iwant_timeouts(&mut self, ihave_timeout: Duration) -> (Vec<(MessageId, Identity)>, usize) {
        let now = Instant::now();
        let mut retries = Vec::new();
        let mut completed = Vec::new();

        for (msg_id, (requested_at, tried_peers)) in self.pending_iwants.iter_mut() {
            if now.duration_since(*requested_at) > ihave_timeout {
                if let Some(next_peer) = self.lazy_peers.iter()
                    .find(|p| !tried_peers.contains(p))
                    .copied()
                {
                    tried_peers.push(next_peer);
                    *requested_at = now;
                    retries.push((*msg_id, next_peer));
                } else {
                    completed.push(*msg_id);
                }
            }
        }

        let completed_count = completed.len();
        for msg_id in completed {
            self.pending_iwants.remove(&msg_id);
        }

        (retries, completed_count)
    }

    /// Remove a pending IWant when message is received. Returns true if an entry was removed.
    pub fn message_received(&mut self, msg_id: &MessageId) -> bool {
        self.pending_iwants.remove(msg_id).is_some()
    }
}

#[derive(Debug)]
pub(crate) struct PeerRateLimit {
    pub publish_times: VecDeque<Instant>,
    pub iwant_times: VecDeque<Instant>,
    pub last_active: Instant,
}

impl Default for PeerRateLimit {
    fn default() -> Self {
        Self {
            publish_times: VecDeque::new(),
            iwant_times: VecDeque::new(),
            last_active: Instant::now(),
        }
    }
}

impl PeerRateLimit {
    pub fn check_and_record(&mut self, max_rate: usize) -> bool {
        self.check_and_record_generic(&mut self.publish_times.clone(), max_rate)
    }
    
    pub fn check_and_record_iwant(&mut self, max_rate: usize) -> bool {
        let now = Instant::now();
        self.last_active = now;
        
        while let Some(front) = self.iwant_times.front() {
            if now.duration_since(*front) > RATE_LIMIT_WINDOW {
                self.iwant_times.pop_front();
            } else {
                break;
            }
        }
        
        if self.iwant_times.len() >= max_rate {
            return true;
        }
        
        self.iwant_times.push_back(now);
        false
    }
    
    fn check_and_record_generic(&mut self, _times: &mut VecDeque<Instant>, max_rate: usize) -> bool {
        let now = Instant::now();
        self.last_active = now;
        
        while let Some(front) = self.publish_times.front() {
            if now.duration_since(*front) > RATE_LIMIT_WINDOW {
                self.publish_times.pop_front();
            } else {
                break;
            }
        }
        
        if self.publish_times.len() >= max_rate {
            return true;
        }
        
        self.publish_times.push_back(now);
        false
    }
}

/// Structured error type for message publication failures.
/// 
/// Used by `GossipSub::publish()` to indicate why a message was rejected.
/// Callers can match on this to handle specific rejection reasons programmatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRejection {
    /// Message payload exceeds `GossipSubConfig::max_message_size`.
    MessageTooLarge,
    /// Topic name exceeds `MAX_TOPIC_LENGTH` (256 bytes).
    TopicTooLong,
    /// Topic name contains invalid characters or is empty.
    InvalidTopic,
    /// Local publish rate limit exceeded (per `GossipSubConfig::publish_rate_limit`).
    RateLimited,
}

impl std::fmt::Display for MessageRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageTooLarge => write!(f, "message size exceeds maximum allowed"),
            Self::TopicTooLong => write!(f, "topic name exceeds maximum length"),
            Self::InvalidTopic => write!(f, "topic name is invalid (empty or contains non-ASCII characters)"),
            Self::RateLimited => write!(f, "local publish rate limit exceeded"),
        }
    }
}

impl std::error::Error for MessageRejection {}


// ============================================================================
// Commands sent from Handle to Actor
// ============================================================================

enum Command {
    Subscribe(String, oneshot::Sender<anyhow::Result<()>>),
    Unsubscribe(String, oneshot::Sender<anyhow::Result<()>>),
    Publish(String, Vec<u8>, oneshot::Sender<anyhow::Result<MessageId>>),
    HandleMessage(Contact, GossipSubRequest, oneshot::Sender<anyhow::Result<()>>),
    GetSubscriptions(oneshot::Sender<Vec<String>>),
    /// Get all mesh peer contacts (for relay discovery).
    GetMeshPeers(oneshot::Sender<Vec<Contact>>),
    /// Send a relay signal to a specific peer via mesh (mesh-mediated signaling).
    SendRelaySignal {
        target: Identity,
        from_peer: Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    Quit,
}


// ============================================================================
// GossipSub Handle (public API - cheap to clone)
// ============================================================================

#[derive(Clone)]
pub struct GossipSub<N: GossipSubRpc> {
    cmd_tx: mpsc::Sender<Command>,
    // We keep phantom data to satisfy the generic parameter, though it's not strictly needed for the handle
    _phantom: std::marker::PhantomData<N>,
}

impl<N: GossipSubRpc + Send + Sync + 'static> GossipSub<N> {
    /// Spawn GossipSub with DHT integration and mesh relay signaling.
    /// 
    /// DHT integration provides:
    /// - Mesh peer contact notification (refreshes routing table)
    /// - Unknown peer resolution via DHT lookup
    /// 
    /// Relay signaling provides:
    /// - RelaySignal messages addressed to us forwarded through channel
    /// - Mesh-mediated signaling for relay connections
    pub fn spawn(
        network: Arc<N>,
        keypair: Keypair,
        config: GossipSubConfig,
        dht: DhtNode<RpcNode>,
        relay_signal_tx: mpsc::Sender<RelaySignal>,
    ) -> (Self, mpsc::Receiver<ReceivedMessage>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(1000);
        let (msg_tx, msg_rx) = mpsc::channel(1000);
        
        let actor = GossipSubActor::new(network, keypair, config, msg_tx, Some(dht), Some(relay_signal_tx));
        tokio::spawn(actor.run(cmd_rx));
        
        (
            Self {
                cmd_tx,
                _phantom: std::marker::PhantomData,
            },
            msg_rx,
        )
    }

    pub async fn subscribe(&self, topic: &str) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::Subscribe(topic.to_string(), tx)).await
            .map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?
    }

    pub async fn unsubscribe(&self, topic: &str) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::Unsubscribe(topic.to_string(), tx)).await
            .map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?
    }

    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> anyhow::Result<MessageId> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::Publish(topic.to_string(), data, tx)).await
            .map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?
    }

    pub async fn subscriptions(&self) -> Vec<String> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetSubscriptions(tx)).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Get all unique mesh peer contacts across all subscribed topics.
    /// 
    /// This is useful for relay discovery: mesh peers are pre-connected,
    /// pre-authenticated, and RTT-known, making them ideal relay candidates.
    pub async fn mesh_peers(&self) -> Vec<Contact> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetMeshPeers(tx)).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn quit(&self) {
        let _ = self.cmd_tx.send(Command::Quit).await;
    }

    /// Send a relay signal to a target peer via the GossipSub mesh.
    /// 
    /// This enables mesh-mediated signaling: instead of maintaining dedicated
    /// signaling connections, relay signals can be forwarded through existing
    /// mesh connections. The target must be reachable via mesh peers.
    /// 
    /// # Arguments
    /// * `target` - Identity of the peer to receive the signal
    /// * `from_peer` - Identity of the connecting peer (initiator)
    /// * `session_id` - Relay session identifier
    /// * `relay_data_addr` - Address for relay data packets
    /// 
    /// # Security
    /// - Only forwards to mesh peers (no gossip flooding)
    /// - Target must be directly connected or one hop away
    pub async fn send_relay_signal(
        &self,
        target: Identity,
        from_peer: Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
    ) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::SendRelaySignal {
            target,
            from_peer,
            session_id,
            relay_data_addr,
            reply: tx,
        }).await.map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?
    }

    /// Handle an incoming GossipSub message from a peer.
    pub async fn handle_message(&self, from: &Contact, message: GossipSubRequest) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::HandleMessage(from.clone(), message, tx)).await
            .map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("GossipSub actor closed"))?
    }
}


// ============================================================================
// GossipSub Actor (owns state)
// ============================================================================

/// Key for backoff tracking: (peer, topic).
type BackoffKey = (Identity, String);

/// Maximum entries in backoff tracker.
/// SECURITY: Bounds memory usage from PRUNE backoff tracking.
const MAX_BACKOFF_ENTRIES: usize = 10_000;

struct GossipSubActor<N: GossipSubRpc> {
    network: Arc<N>,
    keypair: Keypair,
    local_identity: Identity,
    config: GossipSubConfig,
    subscriptions: HashSet<String>,
    topics: HashMap<String, TopicState>,
    message_cache: LruCache<MessageId, CachedMessage>,
    message_cache_bytes: usize,
    seqno: u64,
    /// Per-source sequence number tracking to detect replays.
    /// Uses LruCache to enforce MAX_SEQNO_TRACKING_SOURCES bound.
    seqno_tracker: LruCache<Identity, SeqnoTracker>,
    message_tx: mpsc::Sender<ReceivedMessage>,
    outbound: HashMap<Identity, Vec<GossipSubRequest>>,
    /// Per-peer rate limiting.
    /// Uses LruCache to enforce MAX_RATE_LIMIT_ENTRIES bound.
    rate_limits: LruCache<Identity, PeerRateLimit>,
    /// Known peers with their contacts.
    /// Uses LruCache to enforce MAX_KNOWN_PEERS bound as defense-in-depth.
    contacts: LruCache<Identity, Contact>,
    /// Global count of pending IWants across all topics.
    global_pending_iwants: usize,
    /// Per-peer IDONTWANT tracking (GossipSub v1.2 optimization).
    /// Tracks messages peers don't want to reduce redundant delivery.
    idontwant: HashMap<Identity, IDontWantTracker>,
    /// Per-peer score tracking (GossipSub v1.1).
    /// Uses LruCache to enforce MAX_SCORED_PEERS bound.
    peer_scores: LruCache<Identity, PeerScore>,
    /// Per-topic score parameters for scoring calculations.
    topic_score_params: HashMap<String, TopicScoreParams>,
    /// Last time score decay was applied globally.
    last_score_decay: Instant,
    /// PRUNE backoff tracking: (peer, topic) -> expiry time.
    /// Per GossipSub v1.1: must not GRAFT to a peer during backoff period.
    /// Uses LruCache to bound memory usage.
    prune_backoff: LruCache<BackoffKey, Instant>,
    /// Optional DHT integration for peer resolution and routing updates.
    /// When present, mesh peer contacts are reported to DHT during heartbeat.
    dht: Option<DhtNode<RpcNode>>,
    /// Optional relay signal sender for mesh-mediated signaling.
    /// When present, RelaySignal messages addressed to us are forwarded here.
    relay_signal_tx: Option<mpsc::Sender<RelaySignal>>,
}

impl<N: GossipSubRpc + Send + Sync + 'static> GossipSubActor<N> {
    fn new(
        network: Arc<N>,
        keypair: Keypair,
        config: GossipSubConfig,
        message_tx: mpsc::Sender<ReceivedMessage>,
        dht: Option<DhtNode<RpcNode>>,
        relay_signal_tx: Option<mpsc::Sender<RelaySignal>>,
    ) -> Self {
        let cache_size = NonZeroUsize::new(config.message_cache_size)
            .unwrap_or(NonZeroUsize::new(1).expect("1 is non-zero"));
        let local_identity = keypair.identity();
        
        // SECURITY: Bounded LRU caches to prevent memory exhaustion attacks
        let seqno_tracker_cap = NonZeroUsize::new(MAX_SEQNO_TRACKING_SOURCES)
            .expect("MAX_SEQNO_TRACKING_SOURCES must be non-zero");
        let rate_limits_cap = NonZeroUsize::new(MAX_RATE_LIMIT_ENTRIES)
            .expect("MAX_RATE_LIMIT_ENTRIES must be non-zero");
        let contacts_cap = NonZeroUsize::new(MAX_KNOWN_PEERS)
            .expect("MAX_KNOWN_PEERS must be non-zero");
        let peer_scores_cap = NonZeroUsize::new(MAX_SCORED_PEERS)
            .expect("MAX_SCORED_PEERS must be non-zero");
        let backoff_cap = NonZeroUsize::new(MAX_BACKOFF_ENTRIES)
            .expect("MAX_BACKOFF_ENTRIES must be non-zero");
        
        Self {
            network,
            keypair,
            local_identity,
            config,
            subscriptions: HashSet::new(),
            topics: HashMap::new(),
            message_cache: LruCache::new(cache_size),
            message_cache_bytes: 0,
            seqno: 0,
            seqno_tracker: LruCache::new(seqno_tracker_cap),
            message_tx,
            outbound: HashMap::new(),
            rate_limits: LruCache::new(rate_limits_cap),
            contacts: LruCache::new(contacts_cap),
            global_pending_iwants: 0,
            idontwant: HashMap::new(),
            peer_scores: LruCache::new(peer_scores_cap),
            topic_score_params: HashMap::new(),
            last_score_decay: Instant::now(),
            prune_backoff: LruCache::new(backoff_cap),
            dht,
            relay_signal_tx,
        }
    }

    /// Get the contact for a peer, if known.
    fn get_contact(&mut self, identity: &Identity) -> Option<&Contact> {
        self.contacts.get(identity)
    }

    /// Store a contact for a peer.
    fn store_contact(&mut self, contact: Contact) {
        self.contacts.put(contact.identity, contact);
    }

    /// Get all unique mesh peer contacts across all subscribed topics.
    /// 
    /// Used by relay discovery: mesh peers are pre-connected and RTT-known,
    /// making them ideal relay candidates.
    fn get_mesh_peer_contacts(&mut self) -> Vec<Contact> {
        let mut seen = HashSet::new();
        let mut contacts = Vec::new();
        
        for state in self.topics.values() {
            // Collect from eager peers (active mesh)
            for peer_id in &state.eager_peers {
                if seen.insert(*peer_id)
                    && let Some(contact) = self.contacts.peek(peer_id)
                {
                    contacts.push(contact.clone());
                }
            }
            // Also include lazy peers (connected but not in mesh)
            for peer_id in &state.lazy_peers {
                if seen.insert(*peer_id)
                    && let Some(contact) = self.contacts.peek(peer_id)
                {
                    contacts.push(contact.clone());
                }
            }
        }
        
        contacts
    }

    // ========================================================================
    // Peer Scoring Methods
    // ========================================================================

    /// Get the current score for a peer.
    fn get_peer_score(&mut self, peer: &Identity) -> f64 {
        if !self.config.peer_scoring_enabled {
            return 0.0;
        }
        
        if let Some(score) = self.peer_scores.get(peer) {
            score.calculate(&self.topic_score_params)
        } else {
            0.0
        }
    }

    /// Check if a peer is below the graylist threshold.
    /// Peers below this threshold should have their messages rejected.
    fn is_peer_graylisted(&mut self, peer: &Identity) -> bool {
        if !self.config.peer_scoring_enabled {
            return false;
        }
        self.get_peer_score(peer) < self.config.graylist_threshold
    }

    /// Check if a peer is below the publish threshold.
    /// Peers below this threshold should not receive published messages.
    fn is_peer_below_publish_threshold(&mut self, peer: &Identity) -> bool {
        if !self.config.peer_scoring_enabled {
            return false;
        }
        self.get_peer_score(peer) < self.config.publish_threshold
    }

    /// Check if a peer is below the gossip threshold.
    /// Peers below this threshold should not receive IHAVE gossip.
    fn is_peer_below_gossip_threshold(&mut self, peer: &Identity) -> bool {
        if !self.config.peer_scoring_enabled {
            return false;
        }
        self.get_peer_score(peer) < self.config.gossip_threshold
    }

    /// Record that a peer joined the mesh for a topic.
    fn score_mesh_joined(&mut self, peer: &Identity, topic: &str) {
        if !self.config.peer_scoring_enabled {
            return;
        }
        let score = self.peer_scores.get_or_insert_mut(*peer, PeerScore::default);
        score.mesh_joined(topic);
    }

    /// Record that a peer left the mesh for a topic.
    fn score_mesh_left(&mut self, peer: &Identity, topic: &str) {
        if !self.config.peer_scoring_enabled {
            return;
        }
        let params = self.topic_score_params.get(topic)
            .cloned()
            .unwrap_or_default();
        if let Some(score) = self.peer_scores.get_mut(peer) {
            score.mesh_left(topic, &params);
        }
    }

    /// Record a first message delivery from a peer.
    fn score_first_message_delivered(&mut self, peer: &Identity, topic: &str) {
        if !self.config.peer_scoring_enabled {
            return;
        }
        let score = self.peer_scores.get_or_insert_mut(*peer, PeerScore::default);
        score.first_message_delivered(topic);
        score.mesh_message_delivered(topic);
    }

    /// Record an invalid message from a peer.
    fn score_invalid_message(&mut self, peer: &Identity, topic: &str) {
        if !self.config.peer_scoring_enabled {
            return;
        }
        let score = self.peer_scores.get_or_insert_mut(*peer, PeerScore::default);
        score.invalid_message(topic);
    }

    /// Add a behavioural penalty to a peer (P7).
    fn score_add_penalty(&mut self, peer: &Identity, penalty: f64) {
        if !self.config.peer_scoring_enabled {
            return;
        }
        let score = self.peer_scores.get_or_insert_mut(*peer, PeerScore::default);
        score.add_behaviour_penalty(penalty);
    }

    /// Apply decay to all peer scores (called from heartbeat).
    fn decay_scores(&mut self) {
        if !self.config.peer_scoring_enabled {
            return;
        }
        
        if self.last_score_decay.elapsed() < self.config.decay_interval {
            return;
        }
        
        // Collect peer IDs to avoid borrow conflict
        let peers: Vec<Identity> = self.peer_scores.iter().map(|(id, _)| *id).collect();
        
        for peer in peers {
            if let Some(score) = self.peer_scores.get_mut(&peer) {
                score.decay(&self.topic_score_params, self.config.decay_to_zero);
            }
        }
        
        self.last_score_decay = Instant::now();
    }

    // ========================================================================
    // PRUNE Backoff Methods (GossipSub v1.1)
    // ========================================================================

    /// Record backoff when we receive a PRUNE from a peer.
    /// Per GossipSub v1.1: must not GRAFT to peer during backoff.
    fn record_backoff(&mut self, peer: &Identity, topic: &str, backoff_secs: Option<u64>) {
        let backoff_duration = backoff_secs
            .map(Duration::from_secs)
            .unwrap_or(self.config.prune_backoff);
        
        let expiry = Instant::now() + backoff_duration;
        let key = (*peer, topic.to_string());
        self.prune_backoff.put(key, expiry);
        
        trace!(
            peer = %hex::encode(&peer.as_bytes()[..8]),
            topic = %topic,
            backoff_secs = backoff_duration.as_secs(),
            "recorded PRUNE backoff"
        );
    }

    /// Check if we are in backoff period for a peer on a topic.
    fn is_in_backoff(&mut self, peer: &Identity, topic: &str) -> bool {
        let key = (*peer, topic.to_string());
        if let Some(expiry) = self.prune_backoff.get(&key) {
            if Instant::now() < *expiry {
                return true;
            }
            // Expired, clean up
            self.prune_backoff.pop(&key);
        }
        false
    }

    /// Clean up expired backoff entries (called from heartbeat).
    fn cleanup_backoff(&mut self) {
        let now = Instant::now();
        
        // Collect expired keys to avoid borrow issues
        let expired_keys: Vec<BackoffKey> = self.prune_backoff
            .iter()
            .filter(|(_, expiry)| now >= **expiry)
            .map(|(key, _)| key.clone())
            .collect();
        
        for key in expired_keys {
            self.prune_backoff.pop(&key);
        }
    }

    // ========================================================================
    // Peer Exchange Methods (GossipSub v1.1)
    // ========================================================================

    /// Maximum peers to include in peer exchange (PX) field.
    const MAX_PX_PEERS: usize = 16;

    /// Get peer suggestions for peer exchange when sending PRUNE.
    /// Returns other mesh peers that the pruned peer could connect to.
    fn get_peer_exchange_suggestions(&mut self, topic: &str, exclude_peer: &Identity) -> Vec<Identity> {
        // Collect candidate peers first to avoid borrow conflicts
        let candidates: Vec<Identity> = if let Some(state) = self.topics.get(topic) {
            state.eager_peers
                .iter()
                .filter(|p| **p != *exclude_peer && **p != self.local_identity)
                .take(Self::MAX_PX_PEERS * 2) // Take extra in case some have negative scores
                .copied()
                .collect()
        } else {
            Vec::new()
        };
        
        // Now filter by score
        let mut suggestions = Vec::new();
        for peer in candidates {
            let score = self.get_peer_score(&peer);
            if score >= 0.0 {
                suggestions.push(peer);
            }
            if suggestions.len() >= Self::MAX_PX_PEERS {
                break;
            }
        }
        
        suggestions
    }

    /// Send a GossipSub message to a peer by identity.
    /// Returns Ok if sent, Err if contact not known.
    /// Also records RTT to DHT tiering if DHT is available.
    async fn send_to_peer(&mut self, to: &Identity, message: GossipSubRequest) -> anyhow::Result<()> {
        let contact = match self.get_contact(to) {
            Some(c) => c.clone(),
            None => anyhow::bail!("no contact for peer {}", hex::encode(&to.as_bytes()[..8])),
        };
        
        let start = Instant::now();
        let result = self.network.send_gossipsub(&contact, message).await;
        let elapsed = start.elapsed();
        
        // Report RTT to DHT tiering (fire-and-forget, only on success)
        if result.is_ok()
            && let Some(dht) = &self.dht
        {
            dht.record_rtt(&contact, elapsed).await;
        }
        
        result
    }

    async fn run(mut self, mut cmd_rx: mpsc::Receiver<Command>) {
        let mut heartbeat_interval = tokio::time::interval(self.config.heartbeat_interval);
        
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(Command::Subscribe(topic, reply)) => {
                            let _ = reply.send(self.handle_subscribe_cmd(&topic).await);
                        }
                        Some(Command::Unsubscribe(topic, reply)) => {
                            let _ = reply.send(self.handle_unsubscribe_cmd(&topic).await);
                        }
                        Some(Command::Publish(topic, data, reply)) => {
                            let _ = reply.send(self.handle_publish_cmd(&topic, data).await);
                        }
                        Some(Command::HandleMessage(from, msg, reply)) => {
                            // Store the contact for future messages
                            self.store_contact(from.clone());
                            let _ = reply.send(self.handle_message_internal(&from.identity, msg).await);
                        }
                        Some(Command::GetSubscriptions(reply)) => {
                            let _ = reply.send(self.subscriptions.iter().cloned().collect());
                        }
                        Some(Command::GetMeshPeers(reply)) => {
                            let _ = reply.send(self.get_mesh_peer_contacts());
                        }
                        Some(Command::SendRelaySignal {
                            target, from_peer, session_id, relay_data_addr, reply
                        }) => {
                            let _ = reply.send(
                                self.send_relay_signal_internal(target, from_peer, session_id, relay_data_addr).await
                            );
                        }
                        Some(Command::Quit) => {
                            debug!("GossipSub actor quitting");
                            break;
                        }
                        None => {
                            debug!("GossipSub handle dropped, actor quitting");
                            break;
                        }
                    }
                }
                _ = heartbeat_interval.tick() => {
                    self.heartbeat().await;
                }
            }
        }
    }

    async fn handle_subscribe_cmd(&mut self, topic: &str) -> anyhow::Result<()> {
        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!("topic length {} exceeds maximum {}", topic.len(), MAX_TOPIC_LENGTH);
        }
        if topic.is_empty() {
            anyhow::bail!("topic name cannot be empty");
        }
        if !is_valid_topic(topic) {
            anyhow::bail!("topic name contains invalid characters");
        }

        if self.subscriptions.contains(topic) {
            return Ok(());
        }
        if self.subscriptions.len() >= MAX_SUBSCRIPTIONS_PER_PEER {
            anyhow::bail!("subscription limit reached (max {})", MAX_SUBSCRIPTIONS_PER_PEER);
        }
        self.subscriptions.insert(topic.to_string());

        if !self.topics.contains_key(topic) && self.topics.len() >= MAX_TOPICS {
            let empty = self.topics.iter()
                .find(|(_, s)| s.eager_peers.is_empty() && s.lazy_peers.is_empty())
                .map(|(t, _)| t.clone());
            if let Some(t) = empty {
                self.topics.remove(&t);
                debug!(evicted_topic = %t, new_topic = %topic, "evicted empty topic to make room");
            } else {
                self.subscriptions.remove(topic);
                anyhow::bail!("topic limit reached (max {})", MAX_TOPICS);
            }
        }

        // Create topic state and add known contacts
        let state = self.topics.entry(topic.to_string()).or_default();
        
        for (peer, _) in self.contacts.iter() {
            if *peer != self.local_identity {
                state.add_peer_with_limits(*peer, self.config.mesh_n, self.config.gossip_lazy);
            }
        }
        
        // Check if we need DHT bootstrap (capture before releasing borrow)
        let needs_bootstrap = state.eager_peers.is_empty() && state.lazy_peers.is_empty();
        
        // DHT bootstrap: if no peers known for this topic, discover via DHT
        if needs_bootstrap {
            self.bootstrap_mesh_from_dht(topic).await;
        }

        // Re-borrow to get final peer list
        let peers: Vec<Identity> = self.topics.get(topic)
            .map(|s| s.eager_peers.iter().chain(s.lazy_peers.iter()).copied().collect())
            .unwrap_or_default();

        for peer in peers {
            self.queue_message(&peer, GossipSubRequest::Subscribe {
                topic: topic.to_string(),
            }).await;
        }

        debug!(topic = %topic, "subscribed to topic (GossipSub)");
        Ok(())
    }

    async fn handle_unsubscribe_cmd(&mut self, topic: &str) -> anyhow::Result<()> {
        if !self.subscriptions.remove(topic) {
            return Ok(());
        }

        let all_peers: Vec<Identity> = if let Some(state) = self.topics.remove(topic) {
            state.eager_peers.into_iter()
                .chain(state.lazy_peers.into_iter())
                .collect()
        } else {
            Vec::new()
        };

        for peer in all_peers {
            self.queue_message(&peer, GossipSubRequest::Unsubscribe {
                topic: topic.to_string(),
            }).await;
        }

        debug!(topic = %topic, "unsubscribed from topic");
        Ok(())
    }

    async fn handle_publish_cmd(&mut self, topic: &str, data: Vec<u8>) -> anyhow::Result<MessageId> {
        // Validate message size
        if data.len() > self.config.max_message_size {
            return Err(MessageRejection::MessageTooLarge.into());
        }
        
        // Validate topic name
        if topic.len() > MAX_TOPIC_LENGTH {
            return Err(MessageRejection::TopicTooLong.into());
        }
        if !is_valid_topic(topic) {
            return Err(MessageRejection::InvalidTopic.into());
        }

        // Check local publish rate limit
        {
            let limiter = self.rate_limits.get_or_insert_mut(self.local_identity, PeerRateLimit::default);
            if limiter.check_and_record(self.config.publish_rate_limit) {
                return Err(MessageRejection::RateLimited.into());
            }
        }

        self.seqno = self.seqno.wrapping_add(1);
        let seqno = self.seqno;
        
        let signature = sign_gossipsub_message(&self.keypair, topic, seqno, &data);
        
        let mut id_input = Vec::new();
        id_input.extend_from_slice(self.local_identity.as_bytes());
        id_input.extend_from_slice(&seqno.to_le_bytes());
        id_input.extend_from_slice(&data);
        let msg_id = *hash(&id_input).as_bytes();

        self.cache_message(msg_id, CachedMessage {
            topic: topic.to_string(),
            source: self.local_identity,
            seqno,
            data: data.clone(),
            signature: signature.clone(),
            cached_at: Instant::now(),
        });

        if let Some(state) = self.topics.get_mut(topic) {
            state.recent_messages.push_back(msg_id);
            if state.recent_messages.len() > self.config.max_ihave_length {
                state.recent_messages.pop_front();
            }
        }

        let publish_msg = GossipSubRequest::Publish {
            topic: topic.to_string(),
            msg_id,
            source: self.local_identity,
            seqno,
            data: data.clone(),
            signature,
        };

        let eager_peers: Vec<Identity> = self.topics.get(topic)
            .map(|s| s.eager_peers.iter().copied().collect())
            .unwrap_or_default();

        let eager_count = eager_peers.len();
        for peer in eager_peers {
            self.queue_message(&peer, publish_msg.clone()).await;
        }

        // NOTE: We do NOT deliver to local subscriber here.
        // GossipSub semantics: publishers do not receive their own messages.
        // The message is only forwarded to eager peers for network delivery.

        debug!(
            topic = %topic,
            msg_id = %hex::encode(&msg_id[..8]),
            eager_peers = eager_count,
            "published message (GossipSub)"
        );

        Ok(msg_id)
    }

    async fn handle_message_internal(&mut self, from: &Identity, msg: GossipSubRequest) -> anyhow::Result<()> {
        if let Some(topic) = msg.topic()
            && !is_valid_topic(topic)
        {
            anyhow::bail!("invalid topic name from peer");
        }
        
        match msg {
            GossipSubRequest::Subscribe { topic } => {
                self.handle_subscribe(from, &topic).await;
            }
            GossipSubRequest::Unsubscribe { topic } => {
                self.handle_unsubscribe(from, &topic).await;
            }
            GossipSubRequest::Graft { topic } => {
                self.handle_graft(from, &topic).await;
            }
            GossipSubRequest::Prune { topic, peers, backoff_secs } => {
                self.handle_prune(from, &topic, peers, backoff_secs).await;
            }
            GossipSubRequest::Publish { topic, msg_id, source, seqno, data, signature } => {
                self.handle_publish(from, &topic, msg_id, source, seqno, data, signature).await?;
            }
            GossipSubRequest::IHave { topic, msg_ids } => {
                self.handle_ihave(from, &topic, msg_ids).await;
            }
            GossipSubRequest::IWant { msg_ids } => {
                self.handle_iwant(from, msg_ids).await;
            }
            GossipSubRequest::IDontWant { msg_ids } => {
                self.handle_idontwant(from, msg_ids);
            }
            GossipSubRequest::RelaySignal { target, from_peer, session_id, relay_data_addr } => {
                self.handle_relay_signal(from, target, from_peer, session_id, relay_data_addr).await;
            }
        }
        Ok(())
    }

    fn cache_message(&mut self, msg_id: MessageId, message: CachedMessage) {
        let message_size = message.size_bytes();
        
        if let Some(existing) = self.message_cache.peek(&msg_id) {
            self.message_cache_bytes = self.message_cache_bytes.saturating_sub(existing.size_bytes());
        }
        
        while self.message_cache_bytes + message_size > MAX_MESSAGE_CACHE_BYTES && !self.message_cache.is_empty() {
            if let Some((_, evicted)) = self.message_cache.pop_lru() {
                self.message_cache_bytes = self.message_cache_bytes.saturating_sub(evicted.size_bytes());
                trace!(
                    evicted_bytes = evicted.size_bytes(),
                    cache_bytes = self.message_cache_bytes,
                    "evicted message from cache due to memory pressure"
                );
            } else {
                break;
            }
        }
        
        self.message_cache.put(msg_id, message);
        self.message_cache_bytes = self.message_cache_bytes.saturating_add(message_size);
    }

    async fn handle_subscribe(&mut self, from: &Identity, topic: &str) {
        if !self.subscriptions.contains(topic) {
            return;
        }

        if let Some(state) = self.topics.get_mut(topic) {
            state.add_peer_with_limits(*from, self.config.mesh_n, self.config.gossip_lazy);
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "peer subscribed, added to topic"
            );
        }
    }

    async fn handle_unsubscribe(&mut self, from: &Identity, topic: &str) {
        if let Some(state) = self.topics.get_mut(topic) {
            state.remove_peer(from);
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "peer unsubscribed"
            );
        }
    }

    async fn handle_graft(&mut self, from: &Identity, topic: &str) {
        if !self.subscriptions.contains(topic) {
            self.queue_message(from, GossipSubRequest::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
                backoff_secs: None, // Use default backoff (60s per spec)
            }).await;
            return;
        }

        // SECURITY: Only modify existing TopicState for subscribed topics.
        // TopicState is created by handle_subscribe_cmd when we subscribe.
        // This prevents attackers from creating orphan topic entries via Graft.
        let Some(state) = self.topics.get_mut(topic) else {
            // This should not happen: we're subscribed but no TopicState exists.
            // Log and reject rather than creating state from untrusted input.
            warn!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "graft received for subscribed topic without TopicState, rejecting"
            );
            return;
        };
        state.promote_to_eager_with_limit(*from, self.config.mesh_n);
        
        // GossipSub v1.1: Record mesh join for peer scoring (P1)
        self.score_mesh_joined(from, topic);
        
        debug!(
            peer = %hex::encode(&from.as_bytes()[..8]),
            topic = %topic,
            "peer grafted, promoted to eager"
        );
    }

    async fn handle_prune(&mut self, from: &Identity, topic: &str, peers: Vec<Identity>, backoff_secs: Option<u64>) {
        if let Some(state) = self.topics.get_mut(topic) {
            state.demote_to_lazy(*from);
            
            // GossipSub v1.1: Record mesh leave for peer scoring (P3b penalty)
            self.score_mesh_left(from, topic);
            
            debug!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "peer sent prune, demoted to lazy"
            );
        }
        
        // GossipSub v1.1: Record backoff - must not GRAFT during this period
        self.record_backoff(from, topic, backoff_secs);
        
        // GossipSub v1.1: Process peer exchange (PX) - resolve unknown peers via DHT
        if !peers.is_empty() {
            self.process_peer_exchange(topic, peers).await;
        }
    }
    
    /// Process peer exchange from PRUNE message.
    /// Resolves unknown peer identities via DHT lookup.
    async fn process_peer_exchange(&mut self, topic: &str, peer_ids: Vec<Identity>) {
        // Limit how many peers we resolve to avoid excessive DHT lookups
        const MAX_PX_RESOLVE: usize = 5;
        
        let dht = match &self.dht {
            Some(d) => d.clone(),
            None => return, // No DHT, can't resolve
        };
        
        let mut resolved = 0;
        for peer_id in peer_ids.into_iter().take(MAX_PX_RESOLVE * 2) {
            // Skip self and already-known peers
            if peer_id == self.local_identity {
                continue;
            }
            if self.contacts.contains(&peer_id) {
                continue;
            }
            
            // Try to resolve via DHT routing table first (fast, local)
            if let Some(contact) = dht.lookup_contact(&peer_id).await {
                self.store_contact(contact.clone());
                
                // Add to topic as lazy peer (can be promoted via GRAFT later)
                if let Some(state) = self.topics.get_mut(topic) {
                    state.add_peer_with_limits(peer_id, self.config.mesh_n, self.config.gossip_lazy);
                }
                
                trace!(
                    peer = %hex::encode(&peer_id.as_bytes()[..8]),
                    topic = %topic,
                    "resolved peer from PRUNE PX via DHT"
                );
                
                resolved += 1;
                if resolved >= MAX_PX_RESOLVE {
                    break;
                }
            }
        }
        
        if resolved > 0 {
            debug!(
                topic = %topic,
                resolved = resolved,
                "processed PRUNE peer exchange via DHT"
            );
        }
    }
    
    /// Bootstrap mesh from DHT when subscribing to a topic with no known peers.
    /// Discovers peers close to our identity and adds them as potential mesh members.
    async fn bootstrap_mesh_from_dht(&mut self, topic: &str) {
        let dht = match &self.dht {
            Some(d) => d.clone(),
            None => return,
        };
        
        // Find peers close to our identity
        let closest = match dht.iterative_find_node(self.local_identity).await {
            Ok(peers) => peers,
            Err(e) => {
                debug!(topic = %topic, error = %e, "DHT bootstrap failed");
                return;
            }
        };
        
        if closest.is_empty() {
            return;
        }
        
        // Add discovered peers to topic (limit to mesh target)
        let mut added = 0;
        for contact in closest.into_iter().take(self.config.mesh_n * 2) {
            if contact.identity == self.local_identity {
                continue;
            }
            
            // Store contact for future use
            self.store_contact(contact.clone());
            
            // Add to topic state
            if let Some(state) = self.topics.get_mut(topic)
                && state.add_peer_with_limits(contact.identity, self.config.mesh_n, self.config.gossip_lazy)
            {
                added += 1;
            }
        }
        
        if added > 0 {
            debug!(
                topic = %topic,
                peers_added = added,
                "bootstrapped mesh from DHT"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_publish(
        &mut self,
        from: &Identity,
        topic: &str,
        msg_id: MessageId,
        source: Identity,
        seqno: u64,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> anyhow::Result<()> {
        // SECURITY: Check peer score threshold (GossipSub v1.1)
        // Reject messages from graylisted peers
        if self.is_peer_graylisted(from) {
            debug!(
                from = %hex::encode(&from.as_bytes()[..8]),
                "rejecting message from graylisted peer"
            );
            return Ok(());
        }

        if data.len() > self.config.max_message_size {
            debug!(from = %hex::encode(&from.as_bytes()[..8]), "rejecting oversized message");
            return Ok(());
        }

        if let Err(e) = verify_gossipsub_signature(&source, topic, seqno, &data, &signature) {
            debug!(
                from = %hex::encode(&from.as_bytes()[..8]),
                error = ?e,
                "rejecting message with invalid signature"
            );
            // Score penalty for invalid signature (P4)
            self.score_invalid_message(from, topic);
            return Ok(());
        }

        {
            // LruCache automatically enforces MAX_SEQNO_TRACKING_SOURCES bound
            // by evicting least-recently-used entries when capacity is reached.
            let source_tracker = self.seqno_tracker.get_or_insert_mut(source, SeqnoTracker::default);
            if !source_tracker.check_and_record(seqno) {
                debug!(
                    from = %hex::encode(&from.as_bytes()[..8]),
                    source = %hex::encode(&source.as_bytes()[..8]),
                    seqno = seqno,
                    "rejecting replayed message (seqno already seen)"
                );
                return Ok(());
            }
        }

        {
            // LruCache automatically enforces MAX_RATE_LIMIT_ENTRIES bound
            // by evicting least-recently-used entries when capacity is reached.
            let limiter = self.rate_limits.get_or_insert_mut(*from, PeerRateLimit::default);
            if limiter.check_and_record(self.config.per_peer_rate_limit) {
                debug!(from = %hex::encode(&from.as_bytes()[..8]), "peer rate limited");
                // Score penalty for excessive messages (P7)
                self.score_add_penalty(from, 1.0);
                return Ok(());
            }
        }

        let is_duplicate = self.message_cache.contains(&msg_id);

        if is_duplicate {
            if let Some(state) = self.topics.get_mut(topic) {
                state.demote_to_lazy(*from);
            }
            
            self.queue_message(from, GossipSubRequest::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
                backoff_secs: None, // Use default backoff (60s per spec)
            }).await;

            trace!(
                msg_id = %hex::encode(&msg_id[..8]),
                from = %hex::encode(&from.as_bytes()[..8]),
                "duplicate message, demoted sender to lazy"
            );
            return Ok(());
        }

        // Score reward for first message delivery (P2)
        self.score_first_message_delivered(from, topic);

        self.cache_message(msg_id, CachedMessage {
            topic: topic.to_string(),
            source,
            seqno,
            data: data.clone(),
            signature: signature.clone(),
            cached_at: Instant::now(),
        });

        if let Some(state) = self.topics.get_mut(topic) {
            // Update global pending IWant counter when message is received
            if state.message_received(&msg_id) {
                self.global_pending_iwants = self.global_pending_iwants.saturating_sub(1);
            }
            
            state.recent_messages.push_back(msg_id);
            if state.recent_messages.len() > self.config.max_ihave_length {
                state.recent_messages.pop_front();
            }
        }

        if self.subscriptions.contains(topic) {
            let received = ReceivedMessage {
                topic: topic.to_string(),
                source,
                seqno,
                data: data.clone(),
                msg_id,
                received_at: Instant::now(),
            };
            trace!(
                topic = %received.topic,
                source = %hex::encode(&received.source.as_bytes()[..8]),
                seqno = received.seqno,
                msg_id = %hex::encode(&received.msg_id[..8]),
                data_len = received.data.len(),
                latency_us = received.received_at.elapsed().as_micros(),
                "delivering forwarded message to subscriber"
            );
            if self.message_tx.send(received).await.is_err() {
                warn!("message channel closed");
            }
        }

        let eager_peers: Vec<Identity> = self.topics.get(topic)
            .map(|s| s.eager_peers.iter().filter(|p| **p != *from).copied().collect())
            .unwrap_or_default();

        let forward_msg = GossipSubRequest::Publish {
            topic: topic.to_string(),
            msg_id,
            source,
            seqno,
            data,
            signature,
        };

        for peer in eager_peers {
            // GossipSub v1.2: Check IDontWant before forwarding
            if self.peer_wants_message(&peer, &msg_id) {
                self.queue_message(&peer, forward_msg.clone()).await;
            } else {
                trace!(
                    peer = %hex::encode(&peer.as_bytes()[..8]),
                    msg_id = %hex::encode(&msg_id[..8]),
                    "skipped forwarding to peer due to IDontWant"
                );
            }
        }

        debug!(
            msg_id = %hex::encode(&msg_id[..8]),
            topic = %topic,
            "handled publish (GossipSub), forwarded to eager peers"
        );

        Ok(())
    }

    async fn handle_ihave(&mut self, from: &Identity, topic: &str, msg_ids: Vec<MessageId>) {
        let missing: Vec<MessageId> = msg_ids.into_iter()
            .filter(|id| !self.message_cache.contains(id))
            .collect();

        if missing.is_empty() {
            return;
        }

        // Track which message IDs we actually record for IWant requests.
        // SECURITY: Only request messages we've tracked to prevent unbounded state.
        let mut recorded_ids: Vec<MessageId> = Vec::with_capacity(missing.len());

        if let Some(state) = self.topics.get_mut(topic) {
            state.promote_to_eager_with_limit(*from, self.config.mesh_n);
            
            for msg_id in &missing {
                // SECURITY: Enforce global pending IWant limit to prevent memory exhaustion
                if self.global_pending_iwants >= MAX_GLOBAL_PENDING_IWANTS {
                    debug!(
                        global_pending = self.global_pending_iwants,
                        max = MAX_GLOBAL_PENDING_IWANTS,
                        "global pending IWant limit reached, dropping IWant request"
                    );
                    break;
                }
                let delta = state.record_iwant(*msg_id, *from);
                self.global_pending_iwants = (self.global_pending_iwants as i32 + delta).max(0) as usize;
                recorded_ids.push(*msg_id);
            }
        }

        // Only send IWant for messages we actually recorded
        if recorded_ids.is_empty() {
            return;
        }

        // GossipSub v1.1: Only GRAFT if not in backoff period
        if !self.is_in_backoff(from, topic) {
            self.queue_message(from, GossipSubRequest::Graft {
                topic: topic.to_string(),
            }).await;
        } else {
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "skipping GRAFT due to backoff period"
            );
        }

        self.queue_message(from, GossipSubRequest::IWant { 
            msg_ids: recorded_ids.clone() 
        }).await;

        debug!(
            from = %hex::encode(&from.as_bytes()[..8]),
            topic = %topic,
            missing = recorded_ids.len(),
            "IHave received, promoted sender to eager and requested missing"
        );
    }

    async fn handle_iwant(&mut self, from: &Identity, msg_ids: Vec<MessageId>) {
        if msg_ids.len() > DEFAULT_MAX_IWANT_MESSAGES * 2 {
            warn!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                count = msg_ids.len(),
                "IWant request too large"
            );
            return;
        }

        {
            let limiter = self.rate_limits.get_or_insert_mut(*from, PeerRateLimit::default);
            if limiter.check_and_record_iwant(DEFAULT_IWANT_RATE_LIMIT) {
                warn!(peer = %hex::encode(&from.as_bytes()[..8]), "IWant rate limited");
                return;
            }
        }

        let mut bytes_sent = 0usize;

        for msg_id in msg_ids.into_iter().take(DEFAULT_MAX_IWANT_MESSAGES) {
            if let Some(cached) = self.message_cache.peek(&msg_id) {
                if bytes_sent.saturating_add(cached.data.len()) > MAX_IWANT_RESPONSE_BYTES {
                    break;
                }
                bytes_sent = bytes_sent.saturating_add(cached.data.len());

                self.queue_message(from, GossipSubRequest::Publish {
                    topic: cached.topic.clone(),
                    msg_id,
                    source: cached.source,
                    seqno: cached.seqno,
                    data: cached.data.clone(),
                    signature: cached.signature.clone(),
                }).await;
            }
        }
    }

    /// Handle IDONTWANT message - peer indicates they don't want certain messages.
    /// Per GossipSub v1.2: optimization to reduce bandwidth by tracking what peers
    /// have already received via other paths.
    fn handle_idontwant(&mut self, from: &Identity, msg_ids: Vec<MessageId>) {
        // SECURITY: Limit how many IDontWant entries we process per message
        let msg_ids = if msg_ids.len() > MAX_IDONTWANT_PER_PEER {
            warn!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                count = msg_ids.len(),
                "IDontWant request truncated to max entries"
            );
            msg_ids.into_iter().take(MAX_IDONTWANT_PER_PEER).collect()
        } else {
            msg_ids
        };

        let tracker = self.idontwant.entry(*from).or_default();
        for msg_id in msg_ids {
            tracker.add(msg_id);
        }

        trace!(
            peer = %hex::encode(&from.as_bytes()[..8]),
            "processed IDontWant message"
        );
    }

    /// Check if a peer has indicated they don't want a specific message.
    fn peer_wants_message(&mut self, peer: &Identity, msg_id: &MessageId) -> bool {
        if let Some(tracker) = self.idontwant.get(peer) {
            !tracker.contains(msg_id)
        } else {
            true // No tracker = wants all messages
        }
    }

    /// Handle RelaySignal - mesh-mediated relay signaling.
    /// 
    /// This allows relay signals to be forwarded through the GossipSub mesh
    /// instead of requiring a dedicated signaling connection to the relay.
    /// 
    /// Security: Only forwards to relay_signal_tx if target matches our identity.
    /// The sender must be a mesh peer to prevent amplification attacks.
    async fn handle_relay_signal(
        &mut self,
        from: &Identity,
        target: Identity,
        from_peer: Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
    ) {
        // Only process signals intended for us
        if target != self.local_identity {
            trace!(
                from = %hex::encode(&from.as_bytes()[..8]),
                target = %hex::encode(&target.as_bytes()[..8]),
                "ignoring relay signal not addressed to us"
            );
            return;
        }

        // Verify sender is in our mesh (prevents relay signal amplification)
        let is_mesh_peer = self.topics.values().any(|state| state.eager_peers.contains(from));
        if !is_mesh_peer {
            warn!(
                from = %hex::encode(&from.as_bytes()[..8]),
                "rejecting relay signal from non-mesh peer"
            );
            return;
        }

        // Forward to relay client via channel
        if let Some(ref tx) = self.relay_signal_tx {
            let signal = RelaySignal {
                from_peer,
                session_id,
                relay_data_addr,
            };
            if let Err(e) = tx.send(signal).await {
                debug!("relay signal channel closed: {}", e);
            } else {
                debug!(
                    from_peer = %hex::encode(&from_peer.as_bytes()[..8]),
                    session_id = %hex::encode(&session_id[..8]),
                    "forwarded relay signal to relay client"
                );
            }
        } else {
            trace!("received relay signal but no relay_signal_tx configured");
        }
    }

    /// Send a relay signal to a target peer via mesh.
    /// 
    /// Looks up the target in mesh peers or known contacts and sends directly.
    /// This is the sending side of mesh-mediated signaling.
    /// 
    /// # Security
    /// - Only sends to known mesh peers or peers we have contact info for
    /// - No gossip flooding - direct unicast to target or mesh neighbors
    async fn send_relay_signal_internal(
        &mut self,
        target: Identity,
        from_peer: Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
    ) -> anyhow::Result<()> {
        let msg = GossipSubRequest::RelaySignal {
            target,
            from_peer,
            session_id,
            relay_data_addr,
        };
        
        // Check if target is a direct mesh peer
        let is_mesh_peer = self.topics.values()
            .any(|state| state.eager_peers.contains(&target));
        
        if is_mesh_peer {
            // Direct send to mesh peer
            if let Some(contact) = self.contacts.get(&target) {
                let contact = contact.clone();
                if let Err(e) = self.network.send_gossipsub(&contact, msg).await {
                    debug!(
                        target = %hex::encode(&target.as_bytes()[..8]),
                        error = %e,
                        "failed to send relay signal to mesh peer"
                    );
                    anyhow::bail!("failed to send relay signal: {}", e);
                }
                debug!(
                    target = %hex::encode(&target.as_bytes()[..8]),
                    "sent relay signal directly to mesh peer"
                );
                return Ok(());
            }
        }
        
        // Target not in our mesh - try to forward via mesh peers who might know them
        // This is a limited fan-out to immediate mesh peers only (not full gossip)
        let mesh_contacts = self.get_mesh_peer_contacts();
        if mesh_contacts.is_empty() {
            anyhow::bail!("no mesh peers available to forward relay signal");
        }
        
        // Send to a subset of mesh peers (limit fan-out to prevent amplification)
        const MAX_RELAY_SIGNAL_FANOUT: usize = 3;
        let targets: Vec<_> = mesh_contacts.into_iter()
            .filter(|c| c.identity != target) // Don't send back to target
            .take(MAX_RELAY_SIGNAL_FANOUT)
            .collect();
        
        let mut sent = 0;
        for contact in targets {
            if self.network.send_gossipsub(&contact, msg.clone()).await.is_ok() {
                sent += 1;
            }
        }
        
        if sent == 0 {
            anyhow::bail!("failed to forward relay signal to any mesh peer");
        }
        
        debug!(
            target = %hex::encode(&target.as_bytes()[..8]),
            fanout = sent,
            "forwarded relay signal to mesh peers"
        );
        Ok(())
    }

    async fn heartbeat(&mut self) {
        let subscribed_topics: Vec<String> = self.subscriptions.iter().cloned().collect();

        for topic in subscribed_topics {
            // GossipSub v1.1: Mesh maintenance
            self.mesh_maintenance(&topic).await;
            
            self.lazy_push(&topic).await;
            self.check_timeouts(&topic).await;
        }

        // GossipSub v1.1: Apply score decay
        self.decay_scores();
        
        // GossipSub v1.1: Clean up expired backoff entries
        self.cleanup_backoff();

        // GossipSub v1.2: Clean up expired IDontWant entries
        self.cleanup_idontwant();

        self.cleanup_stale_state();
        self.flush_pending_queues().await;
        
        // DHT integration: notify DHT of active mesh peer contacts
        self.notify_dht_of_mesh_peers().await;
    }
    
    /// Notify DHT of mesh peer contacts (fire-and-forget).
    /// This keeps the DHT routing table fresh with actively-used peers.
    async fn notify_dht_of_mesh_peers(&mut self) {
        let dht = match &self.dht {
            Some(d) => d,
            None => return,
        };
        
        // Collect a sample of mesh peers to report (limit to avoid overhead)
        let mut peers_to_report: Vec<Contact> = Vec::with_capacity(5);
        
        for state in self.topics.values() {
            for peer_id in state.eager_peers.iter().take(2) {
                if let Some(contact) = self.contacts.peek(peer_id)
                    && peers_to_report.len() < 5
                {
                    peers_to_report.push(contact.clone());
                }
            }
            if peers_to_report.len() >= 5 {
                break;
            }
        }
        
        // Fire-and-forget: notify DHT of these contacts
        for contact in peers_to_report {
            dht.observe_contact(contact).await;
        }
    }

    /// GossipSub v1.1 mesh maintenance per heartbeat.
    /// - GRAFT when mesh < D_lo
    /// - PRUNE when mesh > D_hi  
    /// - Skip peers with low scores or in backoff
    /// - SECURITY: Maintains D_out outbound peers to prevent eclipse attacks
    async fn mesh_maintenance(&mut self, topic: &str) {
        // Collect current mesh state
        let (mesh_count, lazy_peers, outbound_count) = if let Some(state) = self.topics.get(topic) {
            let lazy: Vec<Identity> = state.lazy_peers.iter().copied().collect();
            (state.eager_peers.len(), lazy, state.outbound_mesh_count())
        } else {
            return;
        };
        
        // GRAFT: Add peers if mesh is too small
        if mesh_count < self.config.mesh_n_low && !lazy_peers.is_empty() {
            let needed = self.config.mesh_n.saturating_sub(mesh_count);
            let mut grafted = 0;
            
            for peer in lazy_peers {
                if grafted >= needed {
                    break;
                }
                
                // Skip peers in backoff
                if self.is_in_backoff(&peer, topic) {
                    continue;
                }
                
                // Skip low-score peers
                if self.is_peer_below_publish_threshold(&peer) {
                    continue;
                }
                
                // Send GRAFT
                self.queue_message(&peer, GossipSubRequest::Graft {
                    topic: topic.to_string(),
                }).await;
                
                // Move to mesh and mark as outbound (we initiated GRAFT)
                if let Some(state) = self.topics.get_mut(topic)
                    && state.lazy_peers.remove(&peer)
                {
                    state.eager_peers.insert(peer);
                    state.mark_outbound(peer); // SECURITY: Track outbound for D_out
                    self.score_mesh_joined(&peer, topic);
                    grafted += 1;
                    
                    trace!(
                        peer = %hex::encode(&peer.as_bytes()[..8]),
                        topic = %topic,
                        "GRAFT sent during mesh maintenance (outbound)"
                    );
                }
            }
            
            if grafted > 0 {
                debug!(
                    topic = %topic,
                    grafted = grafted,
                    mesh_size = mesh_count + grafted,
                    outbound = outbound_count + grafted,
                    "mesh maintenance: added peers via GRAFT"
                );
            }
        }
        
        // PRUNE: Remove peers if mesh is too large
        let (mesh_count, outbound_count) = if let Some(state) = self.topics.get(topic) {
            (state.eager_peers.len(), state.outbound_mesh_count())
        } else {
            return;
        };
        
        if mesh_count > self.config.mesh_n_high {
            let excess = mesh_count - self.config.mesh_n;
            
            // First collect peers and their outbound status (requires topics borrow)
            let peers_with_outbound: Vec<(Identity, bool)> = {
                if let Some(state) = self.topics.get(topic) {
                    state.eager_peers.iter()
                        .map(|p| (*p, state.is_outbound(p)))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            
            // Now compute scores (requires mutable self borrow for LRU access)
            let peer_info: Vec<(Identity, f64, bool)> = peers_with_outbound.into_iter()
                .map(|(p, is_outbound)| {
                    let score = self.get_peer_score(&p);
                    (p, score, is_outbound)
                })
                .collect();
            
            // Sort by: inbound first, then by score ascending (prune low-score inbound first)
            // SECURITY: This ensures we prune inbound peers before outbound peers
            let mut sorted_peers = peer_info;
            sorted_peers.sort_by(|a, b| {
                // Inbound (false) sorts before outbound (true)
                match (a.2, b.2) {
                    (false, true) => std::cmp::Ordering::Less,
                    (true, false) => std::cmp::Ordering::Greater,
                    _ => a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal),
                }
            });
            
            // SECURITY: Count how many outbound we can prune while maintaining D_out
            let outbound_to_keep = self.config.mesh_outbound_min;
            let mut current_outbound = outbound_count;
            let mut pruned_count = 0;
            let mut peers_to_prune = Vec::new();
            
            for (peer, _score, is_outbound) in sorted_peers {
                if pruned_count >= excess {
                    break;
                }
                
                // SECURITY: Don't prune outbound peers if we'd fall below D_out
                if is_outbound && current_outbound <= outbound_to_keep {
                    trace!(
                        peer = %hex::encode(&peer.as_bytes()[..8]),
                        topic = %topic,
                        outbound_count = current_outbound,
                        d_out = outbound_to_keep,
                        "skipping outbound peer to maintain D_out"
                    );
                    continue;
                }
                
                peers_to_prune.push(peer);
                if is_outbound {
                    current_outbound = current_outbound.saturating_sub(1);
                }
                pruned_count += 1;
            }
            
            for peer in &peers_to_prune {
                // Get peer exchange suggestions (other mesh peers)
                let px_peers = self.get_peer_exchange_suggestions(topic, peer);
                
                // Send PRUNE with backoff and peer exchange
                self.queue_message(peer, GossipSubRequest::Prune {
                    topic: topic.to_string(),
                    peers: px_peers,
                    backoff_secs: Some(DEFAULT_PRUNE_BACKOFF_SECS),
                }).await;
                
                // Move to lazy
                if let Some(state) = self.topics.get_mut(topic)
                    && state.eager_peers.remove(peer)
                {
                    state.lazy_peers.insert(*peer);
                    self.score_mesh_left(peer, topic);
                    
                    trace!(
                        peer = %hex::encode(&peer.as_bytes()[..8]),
                        topic = %topic,
                        "PRUNE sent during mesh maintenance"
                    );
                }
            }
            
            if !peers_to_prune.is_empty() {
                debug!(
                    topic = %topic,
                    pruned = peers_to_prune.len(),
                    mesh_size = mesh_count - peers_to_prune.len(),
                    outbound_remaining = current_outbound,
                    "mesh maintenance: removed excess peers via PRUNE (D_out protected)"
                );
            }
        }
    }

    /// Clean up expired IDontWant entries and remove empty trackers.
    fn cleanup_idontwant(&mut self) {
        // Expire old entries in each tracker
        for tracker in self.idontwant.values_mut() {
            tracker.expire_old();
        }
        // Remove empty trackers
        self.idontwant.retain(|_, tracker| !tracker.entries.is_empty());
    }

    async fn flush_pending_queues(&mut self) {
        let peers_with_pending: Vec<Identity> = self.outbound.keys().copied().collect();

        for peer in peers_with_pending {
            let messages = self.outbound.remove(&peer).unwrap_or_default();
            for msg in messages {
                if let Err(e) = self.send_to_peer(&peer, msg).await {
                    trace!(
                        peer = %hex::encode(&peer.as_bytes()[..8]),
                        error = %e,
                        "failed to flush pending GossipSub message"
                    );
                }
            }
        }
    }

    async fn lazy_push(&mut self, topic: &str) {
        let (should_push, msg_ids, lazy_peers) = if let Some(state) = self.topics.get_mut(topic) {
            if state.should_lazy_push(self.config.heartbeat_interval) {
                state.last_lazy_push = Instant::now();
                let ids: Vec<MessageId> = state.recent_messages.iter().copied().collect();
                let peers: Vec<Identity> = state.lazy_peers.iter().copied().collect();
                (true, ids, peers)
            } else {
                (false, Vec::new(), Vec::new())
            }
        } else {
            (false, Vec::new(), Vec::new())
        };

        if should_push && !msg_ids.is_empty() && !lazy_peers.is_empty() {
            let ihave = GossipSubRequest::IHave {
                topic: topic.to_string(),
                msg_ids,
            };

            for peer in lazy_peers {
                // GossipSub v1.1: Don't gossip to peers below gossip threshold
                if self.is_peer_below_gossip_threshold(&peer) {
                    continue;
                }
                self.queue_message(&peer, ihave.clone()).await;
            }
        }
    }

    async fn check_timeouts(&mut self, topic: &str) {
        let (retries, completed_count): (Vec<(MessageId, Identity)>, usize) = if let Some(state) = self.topics.get_mut(topic) {
            state.check_iwant_timeouts(self.config.ihave_timeout)
        } else {
            (Vec::new(), 0)
        };
        
        // Update global pending IWant count for completed (timed out) entries
        self.global_pending_iwants = self.global_pending_iwants.saturating_sub(completed_count);

        for (msg_id, peer) in retries {
            self.queue_message(&peer, GossipSubRequest::IWant {
                msg_ids: vec![msg_id],
            }).await;
            trace!(
                msg_id = %hex::encode(&msg_id[..8]),
                peer = %hex::encode(&peer.as_bytes()[..8]),
                "retrying IWant with different lazy peer"
            );
        }
    }

    fn cleanup_stale_state(&mut self) {
        // Note: rate_limits is now an LruCache that auto-evicts oldest entries.
        // We don't need to explicitly clean stale entries as the LRU policy
        // handles memory bounding, but we clear outbound buffers and cache.
        self.outbound.retain(|_, msgs| !msgs.is_empty());
        self.evict_expired_cache_entries();
    }

    /// Evict cache entries that have exceeded message_cache_ttl.
    fn evict_expired_cache_entries(&mut self) {
        let ttl = self.config.message_cache_ttl;
        let mut expired_ids = Vec::new();
        
        // Collect expired message IDs
        for (msg_id, cached) in self.message_cache.iter() {
            if cached.cached_at.elapsed() > ttl {
                expired_ids.push(*msg_id);
            }
        }
        
        // Remove expired entries
        for msg_id in &expired_ids {
            if let Some(evicted) = self.message_cache.pop(msg_id) {
                self.message_cache_bytes = self.message_cache_bytes.saturating_sub(evicted.size_bytes());
            }
        }
        
        if !expired_ids.is_empty() {
            trace!(
                evicted = expired_ids.len(),
                cache_size = self.message_cache.len(),
                cache_bytes = self.message_cache_bytes,
                "evicted expired messages from cache"
            );
        }
    }


    async fn queue_message(&mut self, peer: &Identity, msg: GossipSubRequest) {
        if let Err(e) = self.send_to_peer(peer, msg.clone()).await {
            trace!(
                peer = %hex::encode(&peer.as_bytes()[..8]),
                error = %e,
                "failed to send GossipSub message, queueing for later"
            );
        } else {
            return;
        }
        
        if !self.outbound.contains_key(peer) && self.outbound.len() >= MAX_OUTBOUND_PEERS {
            let smallest = self.outbound.iter()
                .min_by_key(|(_, msgs)| msgs.len())
                .map(|(id, _)| *id);
            if let Some(evict) = smallest {
                self.outbound.remove(&evict);
            }
        }
        
        let total: usize = self.outbound.values().map(|v| v.len()).sum();
        if total >= MAX_TOTAL_OUTBOUND_MESSAGES
            && let Some(largest) = self.outbound.iter()
                .max_by_key(|(_, msgs)| msgs.len())
                .map(|(id, _)| *id)
            && let Some(queue) = self.outbound.get_mut(&largest)
        {
            let drain = (queue.len() / 2).max(1);
            queue.drain(0..drain);
        }
        
        let queue = self.outbound.entry(*peer).or_default();
        
        if queue.len() >= MAX_OUTBOUND_PER_PEER {
            let drain = queue.len() / 2;
            queue.drain(0..drain);
        }
        
        queue.push(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_sane() {
        let config = GossipSubConfig::default();
        assert!(config.mesh_n > 0);
        assert!(config.gossip_lazy > 0);
        assert!(config.message_cache_size > 0);
        assert!(config.message_cache_ttl.as_secs() > 0);
        assert!(config.max_message_size > 0);
        assert!(config.publish_rate_limit > 0);
        assert!(config.per_peer_rate_limit > 0);
        // Verify mesh bounds are consistent
        assert!(config.mesh_n_low <= config.mesh_n);
        assert!(config.mesh_n <= config.mesh_n_high);
        assert!(config.mesh_outbound_min <= config.mesh_n_low);
    }

    #[test]
    fn flood_protection_constants() {
        const _: () = assert!(MAX_MESSAGE_SIZE >= 1024, "max message size too small");
        const _: () = assert!(MAX_MESSAGE_SIZE <= 1024 * 1024, "max message size too large");
        const _: () = assert!(MAX_TOPIC_LENGTH >= 32, "max topic length too small");
        const _: () = assert!(DEFAULT_PUBLISH_RATE_LIMIT > 0);
        const _: () = assert!(DEFAULT_PER_PEER_RATE_LIMIT > 0);
        assert!(RATE_LIMIT_WINDOW.as_secs() >= 1);
    }

    #[test]
    fn config_custom_values() {
        #[allow(deprecated)]
        let config = GossipSubConfig {
            mesh_n: 8,
            gossip_lazy: 12,
            max_message_size: 1024,
            publish_rate_limit: 50,
            per_peer_rate_limit: 25,
            ..Default::default()
        };
        
        assert_eq!(config.mesh_n, 8);
        assert_eq!(config.gossip_lazy, 12);
        assert_eq!(config.max_message_size, 1024);
        assert_eq!(config.publish_rate_limit, 50);
        assert_eq!(config.per_peer_rate_limit, 25);
    }

    #[test]
    fn default_config_has_security_limits() {
        let config = GossipSubConfig::default();

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
            config.per_peer_rate_limit >= 1 && config.per_peer_rate_limit <= 1000,
            "per_peer_rate_limit should be reasonable, got {}",
            config.per_peer_rate_limit
        );

        assert!(
            config.mesh_n >= 1 && config.mesh_n <= 20,
            "mesh_n should be between 1 and 20, got {}",
            config.mesh_n
        );

        assert!(
            config.gossip_lazy >= 1 && config.gossip_lazy <= 50,
            "gossip_lazy should be between 1 and 50, got {}",
            config.gossip_lazy
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
    fn message_cache_configuration() {
        let config = GossipSubConfig::default();

        assert!(config.message_cache_size > 0);
        assert!(config.message_cache_size <= 1_000_000);

        assert!(config.message_cache_ttl >= Duration::from_secs(30));
        assert!(config.message_cache_ttl <= Duration::from_secs(3600));
    }

    #[test]
    fn heartbeat_interval_configuration() {
        let config = GossipSubConfig::default();

        assert!(config.heartbeat_interval >= Duration::from_millis(100));
        assert!(config.heartbeat_interval <= Duration::from_secs(10));
    }

    #[test]
    fn gossip_interval_configuration() {
        let config = GossipSubConfig::default();

        // Gossip emission now happens on heartbeat interval
        assert!(config.heartbeat_interval >= Duration::from_millis(100));
        assert!(config.heartbeat_interval <= Duration::from_secs(10));
    }

    #[test]
    fn ihave_timeout_configuration() {
        let config = GossipSubConfig::default();

        assert!(config.ihave_timeout >= Duration::from_millis(500));
        assert!(config.ihave_timeout <= Duration::from_secs(30));
    }

    #[test]
    fn message_id_is_deterministic() {
        let data = b"hello world";
        let source = Identity::from_bytes([1u8; 32]);
        let seqno: u64 = 42;

        let mut input = Vec::new();
        input.extend_from_slice(source.as_bytes());
        input.extend_from_slice(&seqno.to_le_bytes());
        input.extend_from_slice(data);

        let id1 = *hash(&input).as_bytes();
        let id2 = *hash(&input).as_bytes();

        assert_eq!(id1, id2);
    }

    #[test]
    fn topic_state_eager_lazy_operations() {
        let mut state = TopicState::default();
        let peer1 = Identity::from_bytes([1u8; 32]);
        let peer2 = Identity::from_bytes([2u8; 32]);
        let peer3 = Identity::from_bytes([3u8; 32]);

        assert!(state.add_eager(peer1));
        assert!(state.add_eager(peer2));
        assert_eq!(state.eager_peers.len(), 2);
        assert_eq!(state.lazy_peers.len(), 0);

        state.demote_to_lazy(peer1);
        assert_eq!(state.eager_peers.len(), 1);
        assert_eq!(state.lazy_peers.len(), 1);
        assert!(!state.eager_peers.contains(&peer1));
        assert!(state.lazy_peers.contains(&peer1));

        state.promote_to_eager(peer1);
        assert_eq!(state.eager_peers.len(), 2);
        assert_eq!(state.lazy_peers.len(), 0);
        assert!(state.eager_peers.contains(&peer1));

        state.promote_to_eager(peer3);
        assert_eq!(state.eager_peers.len(), 3);

        state.remove_peer(&peer2);
        assert_eq!(state.total_peers(), 2);
        assert!(!state.contains(&peer2));
    }

    #[test]
    fn topic_state_iwant_tracking() {
        let mut state = TopicState::default();
        let peer1 = Identity::from_bytes([1u8; 32]);
        let msg_id = [0xABu8; 32];

        state.record_iwant(msg_id, peer1);
        assert_eq!(state.pending_iwants.len(), 1);
        assert!(state.pending_iwants.contains_key(&msg_id));

        state.message_received(&msg_id);
        assert!(state.pending_iwants.is_empty());
    }

    #[test]
    fn topic_state_respects_peer_limit() {
        let mut state = TopicState::default();

        for i in 0..MAX_PEERS_PER_TOPIC {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let peer = Identity::from_bytes(bytes);
            assert!(state.add_eager(peer), "should add peer {}", i);
        }

        assert_eq!(state.total_peers(), MAX_PEERS_PER_TOPIC);

        let mut overflow_bytes = [0xFFu8; 32];
        overflow_bytes[0..4].copy_from_slice(&(MAX_PEERS_PER_TOPIC as u32).to_le_bytes());
        let overflow_peer = Identity::from_bytes(overflow_bytes);
        assert!(!state.add_eager(overflow_peer), "should not exceed limit");
        assert_eq!(state.total_peers(), MAX_PEERS_PER_TOPIC);
    }

    #[test]
    fn gossipsub_config_all_fields_accessible() {
        let config = GossipSubConfig::default();
        
        // New GossipSub v1.1 mesh parameters
        assert!(config.mesh_n > 0);
        assert!(config.mesh_n_low > 0);
        assert!(config.mesh_n_high > 0);
        assert!(config.mesh_outbound_min > 0);
        assert!(config.gossip_lazy > 0);
        assert!(config.prune_backoff.as_secs() > 0);
        
        // Timing and caching
        assert!(config.ihave_timeout.as_secs() > 0);
        assert!(config.heartbeat_interval.as_millis() > 0);
        assert!(config.message_cache_size > 0);
        assert!(config.message_cache_ttl.as_secs() > 0);
        
        // Size and rate limits
        assert!(config.max_message_size > 0);
        assert!(config.max_ihave_length > 0);
        assert!(config.publish_rate_limit > 0);
        assert!(config.per_peer_rate_limit > 0);
        
        let cloned = config.clone();
        let _debug = format!("{:?}", cloned);
    }

    #[test]
    fn received_message_all_fields_accessible() {
        let msg = ReceivedMessage {
            topic: "test".into(),
            source: Identity::from_bytes([1u8; 32]),
            seqno: 42,
            data: vec![1, 2, 3],
            msg_id: [0xABu8; 32],
            received_at: Instant::now(),
        };
        
        assert_eq!(msg.topic, "test");
        assert_eq!(msg.seqno, 42);
        assert_eq!(msg.data, vec![1, 2, 3]);
        assert_eq!(msg.msg_id, [0xABu8; 32]);
        let _ = msg.source;
        let _ = msg.received_at;
        
        let cloned = msg.clone();
        let _debug = format!("{:?}", cloned);
    }

    #[test]
    fn topic_state_should_lazy_push() {
        let mut state = TopicState::default();
        let peer = Identity::from_bytes([1u8; 32]);
        
        state.add_eager(peer);
        state.demote_to_lazy(peer);
        
        let _ = state.should_lazy_push(DEFAULT_HEARTBEAT_INTERVAL);
        
        let (retries, _completed) = state.check_iwant_timeouts(DEFAULT_IHAVE_TIMEOUT);
        assert!(retries.is_empty());
    }

    #[test]
    fn message_rejection_variants_and_display() {
        let variants = [
            (MessageRejection::MessageTooLarge, "message size exceeds maximum allowed"),
            (MessageRejection::TopicTooLong, "topic name exceeds maximum length"),
            (MessageRejection::InvalidTopic, "topic name is invalid (empty or contains non-ASCII characters)"),
            (MessageRejection::RateLimited, "local publish rate limit exceeded"),
        ];
        
        for (v, expected_msg) in &variants {
            // Test Clone + Copy
            let cloned = *v;
            assert_eq!(*v, cloned);
            
            // Test Debug
            let _debug = format!("{:?}", cloned);
            
            // Test Display
            let display = format!("{}", v);
            assert_eq!(&display, *expected_msg);
            
            // Test Error trait (can convert to anyhow::Error)
            let err: anyhow::Error = (*v).into();
            assert!(err.to_string().contains(expected_msg));
        }
    }
}
