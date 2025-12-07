//! GossipSub-style publish/subscribe for Corium.
//!
//! This module implements a gossip-based pubsub system inspired by libp2p's GossipSub.
//! Messages propagate through the network via epidemic broadcast, achieving O(log n)
//! hop delivery with high reliability.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Application                             │
//! │              subscribe(), publish(), on_message()           │
//! ├─────────────────────────────────────────────────────────────┤
//! │                      GossipSub                              │
//! │         Topic meshes, message routing, deduplication        │
//! ├─────────────────────────────────────────────────────────────┤
//! │                       DhtNode                               │
//! │              Peer discovery, DHT, connections               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Concepts
//!
//! - **Topic**: A named channel for messages (e.g., "chat/lobby", "sensors/temperature")
//! - **Mesh**: For each topic, maintain connections to `mesh_degree` peers (default: 6)
//! - **Fanout**: When publishing to a topic we're not subscribed to, use cached peers
//! - **Gossip**: Periodically exchange "I have" metadata to repair mesh gaps
//!
//! # Security
//!
//! All published messages are cryptographically signed by the source's private key.
//! This prevents:
//! - **Identity spoofing**: Cannot claim to be someone else
//! - **Message forgery**: Cannot create messages on behalf of others  
//! - **Dedup cache poisoning**: Cannot inject fake seqnos for other identities
//!
//! Every node verifies signatures before accepting or forwarding messages.
//!
//! # Example
//!
//! ```ignore
//! use corium::pubsub::{GossipSub, GossipConfig};
//! use corium::identity::Keypair;
//!
//! // Create pubsub layer on top of discovery node
//! let keypair = Keypair::generate();
//! let config = GossipConfig::default();
//! let mut pubsub = GossipSub::new(node.clone(), keypair, config);
//!
//! // Subscribe to a topic
//! pubsub.subscribe("chat/lobby").await?;
//!
//! // Publish a message (automatically signed)
//! pubsub.publish("chat/lobby", b"Hello, world!").await?;
//!
//! // Handle incoming messages (signatures already verified)
//! while let Some(msg) = pubsub.next_message().await {
//!     println!("[{}] {}: {:?}", msg.topic, msg.source, msg.data);
//! }
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, trace, warn};

use crate::core::{hash_content, DhtNetwork, DhtNode};
use crate::identity::{Identity, Keypair};
use crate::node::PubSubHandler;

// ============================================================================
// Type Aliases
// ============================================================================

/// Fanout cache: topic -> (peers, creation time)
type FanoutCache = HashMap<String, (HashSet<Identity>, Instant)>;

// ============================================================================
// Message Authentication
// ============================================================================

/// Reason why a message signature verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature is missing (empty).
    Missing,
    /// Signature has invalid length (must be 64 bytes).
    InvalidLength,
    /// Signature verification failed (wrong key or tampered data).
    VerificationFailed,
    /// Source identity has invalid public key bytes.
    InvalidPublicKey,
}

/// Build the data to sign for a pubsub message.
///
/// The signed data is: topic || seqno (le bytes) || data
/// Using length prefixes to prevent malleability attacks.
fn build_signed_data(topic: &str, seqno: u64, data: &[u8]) -> Vec<u8> {
    let mut signed_data = Vec::new();
    // Length-prefix topic to prevent concatenation attacks
    let topic_bytes = topic.as_bytes();
    signed_data.extend_from_slice(&(topic_bytes.len() as u32).to_le_bytes());
    signed_data.extend_from_slice(topic_bytes);
    // Sequence number
    signed_data.extend_from_slice(&seqno.to_le_bytes());
    // Length-prefix data
    signed_data.extend_from_slice(&(data.len() as u32).to_le_bytes());
    signed_data.extend_from_slice(data);
    signed_data
}

/// Sign a pubsub message.
///
/// Returns the Ed25519 signature over (topic || seqno || data).
pub fn sign_pubsub_message(keypair: &Keypair, topic: &str, seqno: u64, data: &[u8]) -> Vec<u8> {
    let signed_data = build_signed_data(topic, seqno, data);
    keypair.sign(&signed_data).to_bytes().to_vec()
}

/// Verify a pubsub message signature.
///
/// Checks that the signature is valid for the given source identity.
/// Returns `Ok(())` if valid, or `Err(SignatureError)` if invalid.
pub fn verify_pubsub_signature(
    source: &Identity,
    topic: &str,
    seqno: u64,
    data: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    // Check signature length
    if signature.is_empty() {
        return Err(SignatureError::Missing);
    }
    if signature.len() != 64 {
        return Err(SignatureError::InvalidLength);
    }

    // Parse the public key from source identity
    let verifying_key = VerifyingKey::try_from(source.as_bytes().as_slice())
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    // Parse the signature
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignatureError::InvalidLength)?;
    let signature = Signature::from_bytes(&sig_bytes);

    // Build the signed data and verify
    let signed_data = build_signed_data(topic, seqno, data);
    verifying_key
        .verify_strict(&signed_data, &signature)
        .map_err(|_| SignatureError::VerificationFailed)
}

// ============================================================================
// Configuration
// ============================================================================

/// Default mesh degree (number of peers per topic).
pub const DEFAULT_MESH_DEGREE: usize = 6;

/// Minimum mesh degree before seeking more peers.
pub const DEFAULT_MESH_DEGREE_LOW: usize = 4;

/// Maximum mesh degree before pruning excess peers.
pub const DEFAULT_MESH_DEGREE_HIGH: usize = 12;

/// How long to cache messages for deduplication.
pub const DEFAULT_MESSAGE_CACHE_TTL: Duration = Duration::from_secs(120);

/// Maximum messages to cache for deduplication.
pub const DEFAULT_MESSAGE_CACHE_SIZE: usize = 10_000;

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
const MAX_OUTBOUND_PEERS: usize = 1000;

/// Maximum number of peers tracked in rate limiting state.
/// Oldest entries are evicted when limit is reached.
pub const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;

/// Maximum age of rate limit entries before cleanup (5 minutes).
pub const RATE_LIMIT_ENTRY_MAX_AGE: Duration = Duration::from_secs(300);

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

// ============================================================================
// Protocol Messages
// ============================================================================

/// Unique identifier for a pubsub message.
pub type MessageId = [u8; 32];

/// A pubsub protocol message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PubSubMessage {
    /// Subscribe to a topic (join mesh).
    Subscribe {
        /// The topic to subscribe to.
        topic: String,
    },
    /// Unsubscribe from a topic (leave mesh).
    Unsubscribe {
        /// The topic to unsubscribe from.
        topic: String,
    },
    /// Request to join a peer's mesh for a topic.
    Graft {
        /// The topic to graft into.
        topic: String,
    },
    /// Notification that we're leaving a peer's mesh.
    Prune {
        /// The topic to prune from.
        topic: String,
        /// Optional: suggest other peers for the topic.
        peers: Vec<Identity>,
    },
    /// Publish a message to a topic.
    Publish {
        /// The topic to publish to.
        topic: String,
        /// Unique message identifier (hash of data).
        msg_id: MessageId,
        /// The message originator.
        source: Identity,
        /// Sequence number from source.
        seqno: u64,
        /// The message payload.
        data: Vec<u8>,
        /// Ed25519 signature over (topic || seqno || data) by source's private key.
        /// This proves the message was created by the claimed source identity.
        signature: Vec<u8>,
    },
    /// Gossip: "I have these messages" (lazy push).
    IHave {
        /// The topic these messages belong to.
        topic: String,
        /// Message IDs we have.
        msg_ids: Vec<MessageId>,
    },
    /// Request: "Send me these messages".
    IWant {
        /// Message IDs we want.
        msg_ids: Vec<MessageId>,
    },
}

impl PubSubMessage {
    /// Get the topic this message relates to, if any.
    pub fn topic(&self) -> Option<&str> {
        match self {
            PubSubMessage::Subscribe { topic } => Some(topic),
            PubSubMessage::Unsubscribe { topic } => Some(topic),
            PubSubMessage::Graft { topic } => Some(topic),
            PubSubMessage::Prune { topic, .. } => Some(topic),
            PubSubMessage::Publish { topic, .. } => Some(topic),
            PubSubMessage::IHave { topic, .. } => Some(topic),
            PubSubMessage::IWant { .. } => None,
        }
    }
}

// ============================================================================
// Message Types
// ============================================================================

/// A received pubsub message.
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// The topic this message was published to.
    pub topic: String,
    /// The original publisher's identity.
    pub source: Identity,
    /// Sequence number from the source.
    pub seqno: u64,
    /// The message payload.
    pub data: Vec<u8>,
    /// Message ID (hash).
    pub msg_id: MessageId,
    /// When this message was received.
    pub received_at: Instant,
}

/// Cached message for deduplication and IWant fulfillment.
#[derive(Clone)]
struct CachedMessage {
    topic: String,
    source: Identity,
    seqno: u64,
    data: Vec<u8>,
    /// The signature from the original publisher.
    signature: Vec<u8>,
}

// ============================================================================
// Topic State
// ============================================================================

/// State for a single topic.
#[derive(Debug, Default)]
struct TopicState {
    /// Peers in our mesh for this topic (full message push).
    mesh: HashSet<Identity>,
    /// Peers we know are subscribed but not in our mesh (for gossip).
    peers: HashSet<Identity>,
    /// Recent message IDs for IHave gossip.
    recent_messages: VecDeque<MessageId>,
}

impl TopicState {
    /// Total number of peers tracked for this topic.
    fn total_peers(&self) -> usize {
        self.mesh.len() + self.peers.len()
    }

    /// Try to insert a peer into the peers set with bounds checking.
    ///
    /// # Security
    ///
    /// Returns false if the topic is at capacity, preventing Sybil attacks
    /// where an attacker creates many fake identities to exhaust memory.
    fn try_insert_peer(&mut self, peer: Identity) -> bool {
        // Already in mesh or peers - no capacity impact
        if self.mesh.contains(&peer) || self.peers.contains(&peer) {
            return true;
        }

        // Check capacity before inserting
        if self.total_peers() >= MAX_PEERS_PER_TOPIC {
            return false;
        }

        self.peers.insert(peer);
        true
    }
}

// ============================================================================
// Rate Limiting
// ============================================================================

/// Per-peer rate limiting state.
#[derive(Debug)]
struct PeerRateLimit {
    /// Timestamps of recent publish requests.
    publish_times: VecDeque<Instant>,
    /// Timestamps of recent IWant requests (separate limit for amplification protection).
    iwant_times: VecDeque<Instant>,
    /// Last activity time for cleanup.
    last_active: Instant,
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
    /// Check if a peer is rate limited for publish and record the request if not.
    fn check_and_record(&mut self, max_rate: usize) -> bool {
        self.check_and_record_generic(&mut self.publish_times.clone(), max_rate)
    }
    
    /// Check if a peer is rate limited for IWant and record the request if not.
    ///
    /// IWant has a separate rate limit because it can trigger amplification:
    /// a small IWant request can result in large Publish responses.
    fn check_and_record_iwant(&mut self, max_rate: usize) -> bool {
        let now = Instant::now();
        self.last_active = now;
        
        // Remove timestamps older than 1 second
        while let Some(front) = self.iwant_times.front() {
            if now.duration_since(*front) > RATE_LIMIT_WINDOW {
                self.iwant_times.pop_front();
            } else {
                break;
            }
        }
        
        // Check if over limit
        if self.iwant_times.len() >= max_rate {
            return true; // Rate limited
        }
        
        // Record this request
        self.iwant_times.push_back(now);
        false
    }
    
    /// Generic rate limit check helper.
    fn check_and_record_generic(&mut self, _times: &mut VecDeque<Instant>, max_rate: usize) -> bool {
        let now = Instant::now();
        self.last_active = now;
        
        // Remove timestamps older than 1 second
        while let Some(front) = self.publish_times.front() {
            if now.duration_since(*front) > RATE_LIMIT_WINDOW {
                self.publish_times.pop_front();
            } else {
                break;
            }
        }
        
        // Check if over limit
        if self.publish_times.len() >= max_rate {
            return true; // Rate limited
        }
        
        // Record this request
        self.publish_times.push_back(now);
        false
    }
    
    /// Check if this entry is stale and can be cleaned up.
    fn is_stale(&self, now: Instant) -> bool {
        now.duration_since(self.last_active) > RATE_LIMIT_ENTRY_MAX_AGE
    }
}

/// Reason why a message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRejection {
    /// Message payload is too large.
    MessageTooLarge,
    /// Topic name is too long.
    TopicTooLong,
    /// Peer is sending too many messages.
    RateLimited,
    /// Message is a duplicate.
    Duplicate,
    /// Invalid message ID.
    InvalidMessageId,
}

// ============================================================================
// Topic Subscription Record (for DHT storage)
// ============================================================================

/// Maximum subscribers to track per topic in DHT.
const MAX_TOPIC_SUBSCRIBERS: usize = 50;

/// A single subscriber entry in a topic record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriberEntry {
    /// The subscriber's identity.
    pub identity: Identity,
    /// Timestamp when this entry was created/updated.
    pub timestamp: u64,
}

impl SubscriberEntry {
    /// Create a new subscriber entry with current timestamp.
    pub fn new(identity: Identity) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self { identity, timestamp }
    }
}

/// A topic subscription record stored in the DHT.
/// Contains a list of all known subscribers for a topic.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TopicSubscribers {
    /// List of subscribers with their timestamps.
    pub subscribers: Vec<SubscriberEntry>,
}

// Custom deserialization to validate and truncate subscriber list
// This prevents memory spikes from malicious/corrupted DHT data
impl<'de> serde::Deserialize<'de> for TopicSubscribers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize to a raw representation first
        #[derive(serde::Deserialize)]
        struct RawTopicSubscribers {
            subscribers: Vec<SubscriberEntry>,
        }
        
        let raw = RawTopicSubscribers::deserialize(deserializer)?;
        
        // Truncate to MAX_TOPIC_SUBSCRIBERS to prevent memory exhaustion
        let subscribers = if raw.subscribers.len() > MAX_TOPIC_SUBSCRIBERS {
            raw.subscribers.into_iter().take(MAX_TOPIC_SUBSCRIBERS).collect()
        } else {
            raw.subscribers
        };
        
        Ok(TopicSubscribers { subscribers })
    }
}

impl TopicSubscribers {
    /// Create a new empty subscriber list.
    pub fn new() -> Self {
        Self { subscribers: Vec::new() }
    }

    /// Add or update a subscriber in the list.
    pub fn add_subscriber(&mut self, identity: Identity) {
        // Remove existing entry for this identity if present
        self.subscribers.retain(|e| e.identity != identity);
        
        // Add new entry
        self.subscribers.push(SubscriberEntry::new(identity));
        
        // Limit size by removing oldest entries
        while self.subscribers.len() > MAX_TOPIC_SUBSCRIBERS {
            // Find and remove oldest
            if let Some(oldest_idx) = self.subscribers
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(i, _)| i)
            {
                self.subscribers.remove(oldest_idx);
            }
        }
    }

    /// Remove a subscriber from the list.
    pub fn remove_subscriber(&mut self, identity: &Identity) {
        self.subscribers.retain(|e| &e.identity != identity);
    }

    /// Merge another subscriber list into this one (keeps newest entries).
    pub fn merge(&mut self, other: TopicSubscribers) {
        for entry in other.subscribers {
            // Only add if newer than existing or not present
            if let Some(existing) = self.subscribers.iter_mut().find(|e| e.identity == entry.identity) {
                if entry.timestamp > existing.timestamp {
                    existing.timestamp = entry.timestamp;
                }
            } else {
                self.subscribers.push(entry);
            }
        }
        
        // Limit size
        while self.subscribers.len() > MAX_TOPIC_SUBSCRIBERS {
            if let Some(oldest_idx) = self.subscribers
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(i, _)| i)
            {
                self.subscribers.remove(oldest_idx);
            }
        }
    }

    /// Get list of subscriber identities.
    pub fn get_subscribers(&self) -> Vec<Identity> {
        self.subscribers
            .iter()
            .map(|e| e.identity)
            .collect()
    }
}

/// Legacy single-subscriber record (kept for backward compatibility).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopicSubscription {
    /// The subscriber's identity.
    pub subscriber: Identity,
    /// Topics subscribed to.
    pub topics: Vec<String>,
    /// Timestamp when record was created.
    pub timestamp: u64,
}

impl TopicSubscription {
    /// Create a new subscription record.
    pub fn new(subscriber: Identity, topics: Vec<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            subscriber,
            topics,
            timestamp,
        }
    }
}

// ============================================================================
// GossipSub Implementation
// ============================================================================

/// GossipSub pubsub router.
///
/// Manages topic subscriptions, message routing, and mesh maintenance.
pub struct GossipSub<N: DhtNetwork> {
    /// The underlying DHT node.
    node: DhtNode<N>,
    /// Our keypair for signing messages.
    keypair: Keypair,
    /// Our identity.
    local_identity: Identity,
    /// Configuration.
    config: GossipConfig,
    /// Topics we're subscribed to.
    subscriptions: Arc<RwLock<HashSet<String>>>,
    /// Per-topic state (mesh, peers, recent messages).
    topics: Arc<RwLock<HashMap<String, TopicState>>>,
    /// Fanout cache for topics we publish to but aren't subscribed to.
    fanout: Arc<RwLock<FanoutCache>>,
    /// Message cache for deduplication.
    message_cache: Arc<RwLock<LruCache<MessageId, CachedMessage>>>,
    /// Message sequence number.
    seqno: Arc<RwLock<u64>>,
    /// Channel for received messages.
    message_tx: mpsc::Sender<ReceivedMessage>,
    /// Receiver for messages (given to caller).
    message_rx: Option<mpsc::Receiver<ReceivedMessage>>,
    /// Pending outbound messages.
    outbound: Arc<RwLock<HashMap<Identity, Vec<PubSubMessage>>>>,
    /// Per-peer rate limiting state.
    rate_limits: Arc<RwLock<HashMap<Identity, PeerRateLimit>>>,
}

impl<N: DhtNetwork> GossipSub<N> {
    /// Create a new GossipSub router.
    ///
    /// # Arguments
    /// * `node` - The underlying DHT node for DHT operations
    /// * `keypair` - The keypair for signing published messages
    /// * `config` - GossipSub configuration parameters
    ///
    /// # Panics
    ///
    /// This function will not panic. If `message_cache_size` is 0, it defaults to 1.
    pub fn new(node: DhtNode<N>, keypair: Keypair, config: GossipConfig) -> Self {
        // Use unwrap_or with sensible default instead of unwrap
        let cache_size = NonZeroUsize::new(config.message_cache_size)
            .unwrap_or(NonZeroUsize::new(1).expect("1 is non-zero"));
        let (tx, rx) = mpsc::channel(1000);
        let local_identity = keypair.identity();
        
        Self {
            node,
            keypair,
            local_identity,
            config,
            subscriptions: Arc::new(RwLock::new(HashSet::new())),
            topics: Arc::new(RwLock::new(HashMap::new())),
            fanout: Arc::new(RwLock::new(HashMap::new())),
            message_cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            seqno: Arc::new(RwLock::new(0)),
            message_tx: tx,
            message_rx: Some(rx),
            outbound: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Take the message receiver channel.
    ///
    /// Can only be called once; subsequent calls return None.
    pub fn take_message_receiver(&mut self) -> Option<mpsc::Receiver<ReceivedMessage>> {
        self.message_rx.take()
    }

    /// Subscribe to a topic.
    ///
    /// This will:
    /// 1. Add the topic to our subscriptions
    /// 2. Announce our subscription to the DHT
    /// 3. Find peers subscribed to this topic via DHT
    /// 4. Graft into the mesh with `mesh_degree` peers
    pub async fn subscribe(&self, topic: &str) -> anyhow::Result<()> {
        // Validate topic length
        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!(
                "topic length {} exceeds maximum {}",
                topic.len(),
                MAX_TOPIC_LENGTH
            );
        }
        
        // Validate topic content: only allow printable ASCII, no control chars
        if topic.is_empty() {
            anyhow::bail!("topic name cannot be empty");
        }
        if !topic.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            anyhow::bail!("topic name contains invalid characters (only printable ASCII allowed)");
        }

        // Add to subscriptions
        {
            let mut subs = self.subscriptions.write().await;
            if subs.contains(topic) {
                return Ok(()); // Already subscribed
            }
            // Check subscription limit
            if subs.len() >= MAX_SUBSCRIPTIONS_PER_PEER {
                anyhow::bail!(
                    "subscription limit reached (max {})",
                    MAX_SUBSCRIPTIONS_PER_PEER
                );
            }
            subs.insert(topic.to_string());
        }

        // Initialize topic state with limit check
        {
            let mut topics = self.topics.write().await;
            if !topics.contains_key(topic) && topics.len() >= MAX_TOPICS {
                // Remove a topic with empty mesh to make room
                let empty_topic = topics
                    .iter()
                    .find(|(_, state)| state.mesh.is_empty())
                    .map(|(t, _)| t.clone());
                if let Some(t) = empty_topic {
                    topics.remove(&t);
                } else {
                    // All topics have peers, reject new subscription
                    // (rollback the subscription we just added)
                    let mut subs = self.subscriptions.write().await;
                    subs.remove(topic);
                    anyhow::bail!("topic limit reached (max {})", MAX_TOPICS);
                }
            }
            topics.entry(topic.to_string()).or_default();
        }

        // Announce subscription to DHT
        self.announce_subscription(topic).await;

        // Check if we have fanout peers for this topic
        let fanout_peers: Vec<Identity> = {
            let mut fanout = self.fanout.write().await;
            if let Some((peers, _)) = fanout.remove(topic) {
                peers.into_iter().collect()
            } else {
                Vec::new()
            }
        };

        // Graft fanout peers into mesh
        if !fanout_peers.is_empty() {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                for peer in fanout_peers.iter().take(self.config.mesh_degree) {
                    state.mesh.insert(*peer);
                    self.queue_message(peer, PubSubMessage::Graft {
                        topic: topic.to_string(),
                    }).await;
                }
            }
        }

        // Find more peers via DHT if needed
        let current_mesh_size = {
            let topics = self.topics.read().await;
            topics.get(topic).map(|s| s.mesh.len()).unwrap_or(0)
        };

        if current_mesh_size < self.config.mesh_degree {
            self.discover_topic_peers(topic).await?;
        }

        debug!(topic = %topic, "subscribed to topic");
        Ok(())
    }

    /// Unsubscribe from a topic.
    ///
    /// Prunes all mesh connections, removes ourselves from the DHT subscriber
    /// list, and stops receiving messages.
    pub async fn unsubscribe(&self, topic: &str) -> anyhow::Result<()> {
        // Remove from subscriptions
        {
            let mut subs = self.subscriptions.write().await;
            if !subs.remove(topic) {
                return Ok(()); // Wasn't subscribed
            }
        }

        // Prune all mesh peers
        let mesh_peers: Vec<Identity> = {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                let peers: Vec<_> = state.mesh.drain().collect();
                peers
            } else {
                Vec::new()
            }
        };

        for peer in mesh_peers {
            self.queue_message(&peer, PubSubMessage::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
            }).await;
        }

        // Remove ourselves from DHT subscriber list
        self.remove_peer_from_dht(topic, &self.local_identity).await;

        debug!(topic = %topic, "unsubscribed from topic");
        Ok(())
    }

    /// Publish a message to a topic.
    ///
    /// The message will be:
    /// 1. Sent to all mesh peers (if subscribed)
    /// 2. Sent to fanout peers (if not subscribed)
    /// 3. Cached for IWant requests
    ///
    /// # Errors
    /// Returns an error if:
    /// - The message exceeds the maximum allowed size
    /// - The topic name exceeds the maximum allowed length
    /// - Local rate limit is exceeded
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> anyhow::Result<MessageId> {
        // Validate message size
        if data.len() > self.config.max_message_size {
            anyhow::bail!(
                "message size {} exceeds maximum {}",
                data.len(),
                self.config.max_message_size
            );
        }

        // Validate topic length
        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!(
                "topic length {} exceeds maximum {}",
                topic.len(),
                MAX_TOPIC_LENGTH
            );
        }

        // Check local publish rate limit
        {
            let mut rate_limits = self.rate_limits.write().await;
            let limiter = rate_limits.entry(self.local_identity).or_default();
            if limiter.check_and_record(self.config.publish_rate_limit) {
                anyhow::bail!("local publish rate limit exceeded");
            }
        }

        // Generate message ID and sequence number
        let seqno = {
            let mut seq = self.seqno.write().await;
            // Use wrapping_add - seqno overflow is acceptable as message IDs include source identity
            *seq = seq.wrapping_add(1);
            *seq
        };
        
        // Sign the message (topic || seqno || data)
        let signature = sign_pubsub_message(&self.keypair, topic, seqno, &data);
        
        // Message ID = hash(source || seqno || data)
        let mut id_input = Vec::new();
        id_input.extend_from_slice(self.local_identity.as_bytes());
        id_input.extend_from_slice(&seqno.to_le_bytes());
        id_input.extend_from_slice(&data);
        let msg_id = hash_content(&id_input);

        // Cache the message
        {
            let mut cache = self.message_cache.write().await;
            cache.put(msg_id, CachedMessage {
                topic: topic.to_string(),
                source: self.local_identity,
                seqno,
                data: data.clone(),
                signature: signature.clone(),
            });
        }

        // Add to recent messages for gossip
        {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                state.recent_messages.push_back(msg_id);
                if state.recent_messages.len() > self.config.max_ihave_length {
                    state.recent_messages.pop_front();
                }
            }
        }

        let publish_msg = PubSubMessage::Publish {
            topic: topic.to_string(),
            msg_id,
            source: self.local_identity,
            seqno,
            data,
            signature,
        };

        // Get peers to publish to
        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        let peers: Vec<Identity> = if is_subscribed {
            // Use mesh peers
            let topics = self.topics.read().await;
            topics.get(topic)
                .map(|s| s.mesh.iter().copied().collect())
                .unwrap_or_default()
        } else {
            // Use fanout peers
            self.get_or_create_fanout(topic).await
        };

        // Send to all peers
        for peer in peers {
            self.queue_message(&peer, publish_msg.clone()).await;
        }

        debug!(
            topic = %topic,
            msg_id = %hex::encode(&msg_id[..8]),
            "published message"
        );

        Ok(msg_id)
    }

    /// Handle an incoming pubsub message from a peer.
    pub async fn handle_message(&self, from: &Identity, msg: PubSubMessage) -> anyhow::Result<()> {
        // Extract and validate topic for messages that have one
        let topic_opt = match &msg {
            PubSubMessage::Subscribe { topic } 
            | PubSubMessage::Unsubscribe { topic }
            | PubSubMessage::Graft { topic }
            | PubSubMessage::Prune { topic, .. }
            | PubSubMessage::Publish { topic, .. }
            | PubSubMessage::IHave { topic, .. } => Some(topic.as_str()),
            PubSubMessage::IWant { .. } => None,
        };
        
        if let Some(topic) = topic_opt {
            if !is_valid_topic(topic) {
                anyhow::bail!("invalid topic name from peer");
            }
        }
        
        match msg {
            PubSubMessage::Subscribe { topic } => {
                self.handle_subscribe(from, &topic).await;
            }
            PubSubMessage::Unsubscribe { topic } => {
                self.handle_unsubscribe(from, &topic).await;
            }
            PubSubMessage::Graft { topic } => {
                self.handle_graft(from, &topic).await;
            }
            PubSubMessage::Prune { topic, peers } => {
                self.handle_prune(from, &topic, peers).await;
            }
            PubSubMessage::Publish { topic, msg_id, source, seqno, data, signature } => {
                self.handle_publish(from, &topic, msg_id, source, seqno, data, signature).await?;
            }
            PubSubMessage::IHave { topic, msg_ids } => {
                self.handle_ihave(from, &topic, msg_ids).await;
            }
            PubSubMessage::IWant { msg_ids } => {
                self.handle_iwant(from, msg_ids).await;
            }
        }
        Ok(())
    }

    /// Get list of topics we're subscribed to.
    pub async fn subscriptions(&self) -> Vec<String> {
        self.subscriptions.read().await.iter().cloned().collect()
    }

    /// Get mesh peers for a topic.
    pub async fn mesh_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| s.mesh.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get all known peers for a topic.
    pub async fn topic_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| {
                s.mesh.iter()
                    .chain(s.peers.iter())
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    // ========================================================================
    // Internal Handlers
    // ========================================================================

    async fn handle_subscribe(&self, from: &Identity, topic: &str) {
        let mut topics = self.topics.write().await;
        
        // Check topic limit before creating new entries from peer messages
        // Only add new topic if we have room, or if topic already exists
        if !topics.contains_key(topic) && topics.len() >= MAX_TOPICS {
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "rejecting subscribe: topic limit reached"
            );
            return;
        }
        
        let state = topics.entry(topic.to_string()).or_default();
        // Use bounded insertion to prevent Sybil memory exhaustion
        if !state.try_insert_peer(*from) {
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                total_peers = state.total_peers(),
                "rejecting subscribe: topic peer limit reached"
            );
            return;
        }
        trace!(peer = %hex::encode(&from.as_bytes()[..8]), topic = %topic, "peer subscribed");
    }

    async fn handle_unsubscribe(&self, from: &Identity, topic: &str) {
        let mut topics = self.topics.write().await;
        if let Some(state) = topics.get_mut(topic) {
            state.mesh.remove(from);
            state.peers.remove(from);
        }
        trace!(peer = %hex::encode(&from.as_bytes()[..8]), topic = %topic, "peer unsubscribed");
    }

    async fn handle_graft(&self, from: &Identity, topic: &str) {
        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        if !is_subscribed {
            // We're not subscribed, send prune
            self.queue_message(from, PubSubMessage::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
            }).await;
            return;
        }

        let mut topics = self.topics.write().await;
        
        // Check topic limit before creating new entries from peer messages
        if !topics.contains_key(topic) && topics.len() >= MAX_TOPICS {
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "rejecting graft: topic limit reached"
            );
            self.queue_message(from, PubSubMessage::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
            }).await;
            return;
        }
        
        let state = topics.entry(topic.to_string()).or_default();
        
        // Check if we have room in mesh
        if state.mesh.len() < self.config.mesh_degree_high {
            // Check total peer capacity before adding to mesh
            if state.total_peers() >= MAX_PEERS_PER_TOPIC && !state.mesh.contains(from) && !state.peers.contains(from) {
                trace!(
                    peer = %hex::encode(&from.as_bytes()[..8]),
                    topic = %topic,
                    "rejecting graft: topic peer limit reached"
                );
                self.queue_message(from, PubSubMessage::Prune {
                    topic: topic.to_string(),
                    peers: Vec::new(),
                }).await;
                return;
            }
            state.mesh.insert(*from);
            state.peers.remove(from);
            debug!(peer = %hex::encode(&from.as_bytes()[..8]), topic = %topic, "grafted peer into mesh");
        } else {
            // Mesh is full, prune
            self.queue_message(from, PubSubMessage::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
            }).await;
        }
    }

    async fn handle_prune(&self, from: &Identity, topic: &str, suggested_peers: Vec<Identity>) {
        let mut topics = self.topics.write().await;
        if let Some(state) = topics.get_mut(topic) {
            state.mesh.remove(from);
            // Use bounded insertion when moving from mesh to peers
            state.try_insert_peer(*from);
            
            // Add suggested peers for future grafting (with bounds)
            for peer in suggested_peers {
                if peer != self.local_identity {
                    // Use bounded insertion for suggested peers
                    if !state.try_insert_peer(peer) {
                        // Stop adding if at capacity
                        break;
                    }
                }
            }
        }
        debug!(peer = %hex::encode(&from.as_bytes()[..8]), topic = %topic, "pruned from mesh");
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_publish(
        &self,
        from: &Identity,
        topic: &str,
        msg_id: MessageId,
        source: Identity,
        seqno: u64,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> anyhow::Result<()> {
        // Validate message size
        if data.len() > self.config.max_message_size {
            debug!(
                from = %hex::encode(&from.as_bytes()[..8]),
                size = data.len(),
                max = self.config.max_message_size,
                "rejecting oversized message"
            );
            return Ok(()); // Silently drop
        }

        // ================================================================
        // Message Authentication (Security Critical)
        // ================================================================
        // 
        // A message is authentic if:
        // 1. The source matches the TLS-verified connection identity (first hop),
        //    which means the sender is the original publisher, OR
        // 2. The message has a valid signature from the claimed source identity
        //    (forwarded messages from other hops).
        //
        // This prevents:
        // - Identity spoofing: Cannot claim to be someone else
        // - Message forgery: Cannot create messages on behalf of others
        // - Dedup cache poisoning: Cannot inject fake seqnos for other identities
        
        let is_first_hop = source == *from;
        
        if !is_first_hop {
            // Message is being forwarded - verify the signature
            if let Err(e) = verify_pubsub_signature(&source, topic, seqno, &data, &signature) {
                debug!(
                    from = %hex::encode(&from.as_bytes()[..8]),
                    source = %hex::encode(&source.as_bytes()[..8]),
                    error = ?e,
                    "rejecting message with invalid signature"
                );
                return Ok(()); // Drop messages with invalid signatures
            }
        } else {
            // First hop - the sender claims to be the source
            // Verify they actually signed it (prevents replay attacks where
            // someone intercepts and resends another's signed message)
            if let Err(e) = verify_pubsub_signature(&source, topic, seqno, &data, &signature) {
                debug!(
                    from = %hex::encode(&from.as_bytes()[..8]),
                    error = ?e,
                    "rejecting first-hop message with invalid signature"
                );
                return Ok(()); // Drop - even first hop must have valid signature
            }
        }

        // Check per-peer rate limit
        {
            let mut rate_limits = self.rate_limits.write().await;
            
            // Proactive cleanup when approaching limit
            if rate_limits.len() >= MAX_RATE_LIMIT_ENTRIES {
                let now = Instant::now();
                rate_limits.retain(|_, limiter| !limiter.is_stale(now));
            }
            
            let limiter = rate_limits.entry(*from).or_default();
            if limiter.check_and_record(self.config.per_peer_rate_limit) {
                debug!(
                    from = %hex::encode(&from.as_bytes()[..8]),
                    "peer rate limited, dropping message"
                );
                return Ok(()); // Drop messages from rate-limited peers
            }
        }

        // Check if we've seen this message
        {
            let cache = self.message_cache.read().await;
            if cache.contains(&msg_id) {
                trace!(msg_id = %hex::encode(&msg_id[..8]), "duplicate message, ignoring");
                return Ok(());
            }
        }

        // Cache the message (including signature for IWant responses)
        {
            let mut cache = self.message_cache.write().await;
            cache.put(msg_id, CachedMessage {
                topic: topic.to_string(),
                source,
                seqno,
                data: data.clone(),
                signature: signature.clone(),
            });
        }

        // Check if we're subscribed
        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        if is_subscribed {
            // Deliver to application
            let received = ReceivedMessage {
                topic: topic.to_string(),
                source,
                seqno,
                data: data.clone(),
                msg_id,
                received_at: Instant::now(),
            };
            
            if self.message_tx.send(received).await.is_err() {
                warn!("message channel closed");
            }

            // Add to recent messages for gossip
            {
                let mut topics = self.topics.write().await;
                if let Some(state) = topics.get_mut(topic) {
                    state.recent_messages.push_back(msg_id);
                    if state.recent_messages.len() > self.config.max_ihave_length {
                        state.recent_messages.pop_front();
                    }
                }
            }
        }

        // Forward to mesh peers (except sender)
        // The signature is included so downstream peers can verify
        let mesh_peers: Vec<Identity> = {
            let topics = self.topics.read().await;
            topics.get(topic)
                .map(|s| s.mesh.iter().filter(|p| *p != from).copied().collect())
                .unwrap_or_default()
        };

        let forward_msg = PubSubMessage::Publish {
            topic: topic.to_string(),
            msg_id,
            source,
            seqno,
            data,
            signature,
        };

        for peer in mesh_peers {
            self.queue_message(&peer, forward_msg.clone()).await;
        }

        debug!(
            msg_id = %hex::encode(&msg_id[..8]),
            topic = %topic,
            source = %hex::encode(&source.as_bytes()[..8]),
            "handled publish"
        );

        Ok(())
    }

    /// Handle IHave gossip - peer announces message IDs they have.
    ///
    /// Note: The `_topic` parameter is currently unused because IWant requests
    /// are topic-agnostic (we request by message ID). Kept for future topic-scoped
    /// optimizations or logging.
    async fn handle_ihave(&self, from: &Identity, _topic: &str, msg_ids: Vec<MessageId>) {
        // Check which messages we don't have
        let missing: Vec<MessageId> = {
            let cache = self.message_cache.read().await;
            msg_ids.into_iter()
                .filter(|id| !cache.contains(id))
                .collect()
        };

        if !missing.is_empty() {
            self.queue_message(from, PubSubMessage::IWant { msg_ids: missing }).await;
        }
    }

    /// Handle an IWant request from a peer.
    ///
    /// # Security
    ///
    /// This method implements rate limiting and size limiting to prevent
    /// amplification attacks where an attacker sends small IWant requests
    /// to trigger large Publish responses.
    async fn handle_iwant(&self, from: &Identity, msg_ids: Vec<MessageId>) {
        // Early validation of message count before any processing
        // Reject obviously malicious requests with too many IDs
        if msg_ids.len() > DEFAULT_MAX_IWANT_MESSAGES * 2 {
            warn!(
                peer = ?hex::encode(&from.as_bytes()[..8]),
                count = msg_ids.len(),
                limit = DEFAULT_MAX_IWANT_MESSAGES,
                "IWant request rejected: too many message IDs"
            );
            return;
        }
        
        // Rate limit IWant requests per peer to prevent amplification attacks
        {
            let mut rate_limits = self.rate_limits.write().await;
            
            // Check rate limit entry count and cleanup if needed
            if rate_limits.len() >= MAX_RATE_LIMIT_ENTRIES {
                // Remove stale entries immediately
                let now = Instant::now();
                rate_limits.retain(|_, limiter| !limiter.is_stale(now));
            }
            
            let peer_limit = rate_limits.entry(*from).or_default();
            if peer_limit.check_and_record_iwant(DEFAULT_IWANT_RATE_LIMIT) {
                warn!(
                    peer = ?hex::encode(&from.as_bytes()[..8]),
                    "IWant rate limited - possible amplification attack"
                );
                return;
            }
        }
        
        // Limit the number of message IDs we'll process per request
        // to prevent a single request from triggering excessive responses
        let msg_ids_to_process: Vec<_> = msg_ids
            .into_iter()
            .take(DEFAULT_MAX_IWANT_MESSAGES)
            .collect();
        
        let cache = self.message_cache.read().await;
        
        // Track total bytes sent and enforce bandwidth limit
        // This prevents amplification even if all requested messages are large
        let mut bytes_sent: usize = 0;
        let mut messages_sent: usize = 0;
        
        for msg_id in msg_ids_to_process {
            if let Some(cached) = cache.peek(&msg_id) {
                // Check byte budget before sending
                let msg_size = cached.data.len();
                if bytes_sent.saturating_add(msg_size) > MAX_IWANT_RESPONSE_BYTES {
                    debug!(
                        peer = ?hex::encode(&from.as_bytes()[..8]),
                        bytes_sent,
                        messages_sent,
                        limit = MAX_IWANT_RESPONSE_BYTES,
                        "IWant response byte limit reached, stopping early"
                    );
                    break;
                }
                
                bytes_sent = bytes_sent.saturating_add(msg_size);
                messages_sent += 1;
                
                self.queue_message(from, PubSubMessage::Publish {
                    topic: cached.topic.clone(),
                    msg_id,
                    source: cached.source,
                    seqno: cached.seqno,
                    data: cached.data.clone(),
                    signature: cached.signature.clone(),
                }).await;
            }
        }
        
        if messages_sent > 0 {
            trace!(
                peer = ?hex::encode(&from.as_bytes()[..8]),
                messages_sent,
                bytes_sent,
                "Responded to IWant request"
            );
        }
    }

    // ========================================================================
    // Mesh Maintenance
    // ========================================================================

    /// Run the heartbeat loop for mesh maintenance.
    ///
    /// This should be spawned as a background task.
    pub async fn run_heartbeat(&self) {
        let mut interval = tokio::time::interval(self.config.heartbeat_interval);
        
        loop {
            interval.tick().await;
            self.heartbeat().await;
        }
    }

    /// Perform one heartbeat cycle.
    async fn heartbeat(&self) {
        let subscribed_topics: Vec<String> = {
            self.subscriptions.read().await.iter().cloned().collect()
        };

        for topic in subscribed_topics {
            self.maintain_mesh(&topic).await;
            self.emit_gossip(&topic).await;
        }

        // Clean up expired fanout entries
        self.cleanup_fanout().await;
        
        // Clean up stale rate limit entries and orphaned outbound queues
        self.cleanup_stale_state().await;
    }

    /// Maintain mesh for a topic (graft/prune as needed).
    async fn maintain_mesh(&self, topic: &str) {
        let (mesh_size, available_peers) = {
            let topics = self.topics.read().await;
            if let Some(state) = topics.get(topic) {
                (state.mesh.len(), state.peers.iter().copied().collect::<Vec<_>>())
            } else {
                return;
            }
        };

        // Graft if mesh is too small
        if mesh_size < self.config.mesh_degree_low {
            let needed = self.config.mesh_degree - mesh_size;
            let to_graft: Vec<Identity> = available_peers.into_iter().take(needed).collect();
            
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                for peer in to_graft {
                    state.mesh.insert(peer);
                    state.peers.remove(&peer);
                    self.queue_message(&peer, PubSubMessage::Graft {
                        topic: topic.to_string(),
                    }).await;
                }
            }
        }

        // Prune if mesh is too large
        if mesh_size > self.config.mesh_degree_high {
            let excess = mesh_size - self.config.mesh_degree;
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                let to_prune: Vec<Identity> = state.mesh.iter().copied().take(excess).collect();
                for peer in to_prune {
                    state.mesh.remove(&peer);
                    // Use bounded insertion when pruning from mesh
                    state.try_insert_peer(peer);
                    self.queue_message(&peer, PubSubMessage::Prune {
                        topic: topic.to_string(),
                        peers: Vec::new(),
                    }).await;
                }
            }
        }
    }

    /// Emit IHave gossip for a topic.
    async fn emit_gossip(&self, topic: &str) {
        let (msg_ids, gossip_peers) = {
            let topics = self.topics.read().await;
            if let Some(state) = topics.get(topic) {
                let ids: Vec<MessageId> = state.recent_messages.iter().copied().collect();
                let peers: Vec<Identity> = state.peers.iter().copied().collect();
                (ids, peers)
            } else {
                return;
            }
        };

        if msg_ids.is_empty() || gossip_peers.is_empty() {
            return;
        }

        // Send IHave to a subset of peers not in mesh
        let gossip_target = (gossip_peers.len() / 2).clamp(1, DEFAULT_MAX_IHAVE_MESSAGES);
        for peer in gossip_peers.into_iter().take(gossip_target) {
            self.queue_message(&peer, PubSubMessage::IHave {
                topic: topic.to_string(),
                msg_ids: msg_ids.clone(),
            }).await;
        }
    }

    /// Clean up expired fanout entries.
    async fn cleanup_fanout(&self) {
        let now = Instant::now();
        let mut fanout = self.fanout.write().await;
        fanout.retain(|_, (_, created)| now.duration_since(*created) < self.config.fanout_ttl);
    }
    
    /// Clean up stale rate limit entries to prevent unbounded growth.
    ///
    /// This should be called periodically (e.g., every minute).
    pub async fn cleanup_stale_state(&self) {
        let now = Instant::now();
        
        // Clean up stale rate limit entries
        {
            let mut rate_limits = self.rate_limits.write().await;
            rate_limits.retain(|_, limiter| !limiter.is_stale(now));
            
            // If still too many entries, remove oldest
            if rate_limits.len() > MAX_RATE_LIMIT_ENTRIES {
                // Find and remove stale entries (those with empty publish_times)
                rate_limits.retain(|_, limiter| !limiter.publish_times.is_empty());
            }
        }
        
        // Clean up empty outbound queues (peers that never collected their messages)
        {
            let mut outbound = self.outbound.write().await;
            outbound.retain(|_, msgs| !msgs.is_empty());
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /// Queue a message to be sent to a peer.
    ///
    /// If the queue for this peer exceeds MAX_OUTBOUND_PER_PEER, the oldest
    /// messages are dropped to prevent unbounded memory growth.
    ///
    /// Also enforces global limits on total messages and peer count.
    async fn queue_message(&self, peer: &Identity, msg: PubSubMessage) {
        let mut outbound = self.outbound.write().await;
        
        // Enforce global peer count limit to prevent memory exhaustion from many peers
        if !outbound.contains_key(peer) && outbound.len() >= MAX_OUTBOUND_PEERS {
            // Find and remove the peer with the smallest queue
            let smallest_peer = outbound
                .iter()
                .min_by_key(|(_, msgs)| msgs.len())
                .map(|(id, _)| *id);
            if let Some(evict_peer) = smallest_peer {
                debug!(
                    evicted = %hex::encode(&evict_peer.as_bytes()[..8]),
                    "evicted peer outbound queue due to peer count limit"
                );
                outbound.remove(&evict_peer);
            }
        }
        
        // Enforce global message count limit
        let total_messages: usize = outbound.values().map(|v| v.len()).sum();
        if total_messages >= MAX_TOTAL_OUTBOUND_MESSAGES {
            // Drop messages from largest queues until under limit
            let mut dropped = 0;
            while outbound.values().map(|v| v.len()).sum::<usize>() >= MAX_TOTAL_OUTBOUND_MESSAGES {
                // Find peer with largest queue
                let largest_peer = outbound
                    .iter()
                    .max_by_key(|(_, msgs)| msgs.len())
                    .map(|(id, _)| *id);
                if let Some(large_peer) = largest_peer {
                    if let Some(queue) = outbound.get_mut(&large_peer) {
                        if queue.is_empty() {
                            break;
                        }
                        // Drop half of their messages
                        let drain_count = (queue.len() / 2).max(1);
                        queue.drain(0..drain_count);
                        dropped += drain_count;
                    }
                } else {
                    break;
                }
            }
            if dropped > 0 {
                warn!(
                    dropped = dropped,
                    "dropped outbound messages due to global limit"
                );
            }
        }
        
        let queue = outbound.entry(*peer).or_default();
        
        // Enforce per-peer queue limit to prevent memory exhaustion
        if queue.len() >= MAX_OUTBOUND_PER_PEER {
            // Drop oldest messages (first half of queue) to make room
            let drain_count = queue.len() / 2;
            queue.drain(0..drain_count);
            debug!(
                peer = %hex::encode(&peer.as_bytes()[..8]),
                dropped = drain_count,
                "dropped oldest outbound messages due to per-peer queue limit"
            );
        }
        
        queue.push(msg);
    }

    /// Get pending messages for a peer and clear the queue.
    pub async fn take_pending_messages(&self, peer: &Identity) -> Vec<PubSubMessage> {
        let mut outbound = self.outbound.write().await;
        outbound.remove(peer).unwrap_or_default()
    }

    /// Get all peers with pending messages.
    pub async fn peers_with_pending(&self) -> Vec<Identity> {
        let outbound = self.outbound.read().await;
        outbound.keys().copied().collect()
    }

    /// Get or create fanout peers for a topic.
    async fn get_or_create_fanout(&self, topic: &str) -> Vec<Identity> {
        {
            let fanout = self.fanout.read().await;
            if let Some((peers, _)) = fanout.get(topic) {
                if !peers.is_empty() {
                    return peers.iter().copied().collect();
                }
            }
        }

        // Need to find peers for this topic
        let peers = self.discover_topic_peers_internal(topic).await;
        
        if !peers.is_empty() {
            let mut fanout = self.fanout.write().await;
            fanout.insert(topic.to_string(), (peers.iter().copied().collect(), Instant::now()));
        }

        peers
    }

    /// Announce our subscription to the DHT.
    ///
    /// Uses a CRDT-style merge to handle concurrent updates safely.
    /// Instead of read-modify-write, we:
    /// 1. Create our own subscription entry with current timestamp
    /// 2. Fetch existing list from DHT
    /// 3. Merge using LWW (Last-Writer-Wins) semantics per identity
    /// 4. Store the merged result
    ///
    /// This is safe because:
    /// - Each identity can only update its own entry (enforced by DHT verification)
    /// - Merge is commutative and idempotent (CRDT properties)
    /// - Timestamps ensure the latest subscription always wins
    async fn announce_subscription(&self, topic: &str) {
        // Topic key = hash("pubsub/topic:" + topic)
        let topic_key = hash_content(format!("pubsub/topic:{}", topic).as_bytes());
        
        // Create our subscription entry with current timestamp
        let our_entry = SubscriberEntry::new(self.local_identity);
        
        // Fetch existing subscriber list from DHT and merge
        // Retry up to 3 times to handle concurrent updates
        for attempt in 0..3 {
            let mut subscribers = match self.node.get(&topic_key).await {
                Ok(Some(data)) => {
                    // Try to parse as new format first
                    bincode::deserialize::<TopicSubscribers>(&data).unwrap_or_default()
                }
                _ => TopicSubscribers::new(),
            };
            
            // CRDT-style merge: add our entry using LWW semantics
            // This is idempotent - calling multiple times with same identity
            // will just update the timestamp if newer
            let mut our_subscribers = TopicSubscribers::new();
            our_subscribers.subscribers.push(our_entry.clone());
            subscribers.merge(our_subscribers);
            
            // Store merged list back to DHT
            match bincode::serialize(&subscribers) {
                Ok(data) => {
                    if let Err(e) = self.node.put_at(topic_key, data).await {
                        debug!(
                            topic = %topic, 
                            error = %e, 
                            attempt = attempt,
                            "failed to announce subscription to DHT, will retry"
                        );
                        // Small delay before retry to reduce contention
                        if attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1))).await;
                        }
                        continue;
                    } else {
                        trace!(
                            topic = %topic, 
                            subscriber_count = subscribers.subscribers.len(),
                            "announced subscription to DHT"
                        );
                        return; // Success
                    }
                }
                Err(e) => {
                    debug!(topic = %topic, error = %e, "failed to serialize subscription record");
                    return; // Serialization error, don't retry
                }
            }
        }
        debug!(topic = %topic, "exhausted retries for subscription announcement");
    }

    /// Discover peers for a topic via DHT.
    async fn discover_topic_peers(&self, topic: &str) -> anyhow::Result<()> {
        let peers = self.discover_topic_peers_internal(topic).await;
        
        let mut topics = self.topics.write().await;
        let state = topics.entry(topic.to_string()).or_default();
        
        let needed = self.config.mesh_degree.saturating_sub(state.mesh.len());
        for peer in peers.into_iter().take(needed) {
            if !state.mesh.contains(&peer) {
                state.mesh.insert(peer);
                self.queue_message(&peer, PubSubMessage::Graft {
                    topic: topic.to_string(),
                }).await;
            }
        }

        Ok(())
    }

    /// Internal helper to find peers for a topic.
    ///
    /// Uses the sloppy DHT to look up subscription records stored by other nodes.
    /// Returns all non-expired subscribers except ourselves.
    async fn discover_topic_peers_internal(&self, topic: &str) -> Vec<Identity> {
        // Topic key = hash("pubsub/topic:" + topic)
        let topic_key = hash_content(format!("pubsub/topic:{}", topic).as_bytes());
        
        // Look up subscription records from DHT
        match self.node.get(&topic_key).await {
            Ok(Some(data)) => {
                // Try to parse as new multi-subscriber format
                match bincode::deserialize::<TopicSubscribers>(&data) {
                    Ok(subscribers) => {
                        let peers: Vec<Identity> = subscribers
                            .get_subscribers()
                            .into_iter()
                            .filter(|id| *id != self.local_identity)
                            .collect();
                        
                        trace!(
                            topic = %topic,
                            peer_count = peers.len(),
                            "discovered topic peers from DHT"
                        );
                        
                        peers
                    }
                    Err(_) => {
                        // Try legacy single-subscriber format for backward compatibility
                        match bincode::deserialize::<TopicSubscription>(&data) {
                            Ok(record) => {
                                if record.subscriber != self.local_identity {
                                    vec![record.subscriber]
                                } else {
                                    Vec::new()
                                }
                            }
                            Err(e) => {
                                debug!(topic = %topic, error = %e, "failed to parse subscription record");
                                Vec::new()
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                trace!(topic = %topic, "no subscription records found in DHT");
                Vec::new()
            }
            Err(e) => {
                debug!(topic = %topic, error = %e, "failed to query DHT for subscribers");
                Vec::new()
            }
        }
    }

    /// Refresh our subscription announcements in the DHT.
    ///
    /// This is generally not needed for normal operation since subscriptions
    /// persist until explicitly removed or the 24-hour DHT TTL expires.
    /// Use this after network partitions or to update timestamps.
    pub async fn refresh_subscriptions(&self) {
        let topics: Vec<String> = {
            let subs = self.subscriptions.read().await;
            subs.iter().cloned().collect()
        };
        
        for topic in topics {
            self.announce_subscription(&topic).await;
        }
    }

    /// Add a known peer for a topic.
    ///
    /// Returns `true` if the peer was added, `false` if at capacity.
    pub async fn add_peer(&self, topic: &str, peer: Identity) -> bool {
        let mut topics = self.topics.write().await;
        let state = topics.entry(topic.to_string()).or_default();
        if state.mesh.contains(&peer) {
            return true; // Already in mesh
        }
        // Use bounded insertion to prevent Sybil attacks
        state.try_insert_peer(peer)
    }

    /// Remove a peer from all topics (e.g., on disconnect).
    ///
    /// This removes the peer from local mesh/peers state and also
    /// attempts to remove them from the DHT subscriber lists.
    pub async fn remove_peer(&self, peer: &Identity) {
        // Get topics this peer was in before removing
        let topics_with_peer: Vec<String> = {
            let topics = self.topics.read().await;
            topics.iter()
                .filter(|(_, state)| state.mesh.contains(peer) || state.peers.contains(peer))
                .map(|(topic, _)| topic.clone())
                .collect()
        };

        // Remove from local state
        {
            let mut topics = self.topics.write().await;
            for state in topics.values_mut() {
                state.mesh.remove(peer);
                state.peers.remove(peer);
            }
        }

        // Remove from DHT subscriber lists
        for topic in topics_with_peer {
            self.remove_peer_from_dht(&topic, peer).await;
        }
    }

    /// Remove a dead peer from the DHT subscriber list for a topic.
    ///
    /// This helps other nodes avoid trying to connect to dead peers.
    async fn remove_peer_from_dht(&self, topic: &str, peer: &Identity) {
        let topic_key = hash_content(format!("pubsub/topic:{}", topic).as_bytes());
        
        // Fetch existing subscriber list
        let mut subscribers = match self.node.get(&topic_key).await {
            Ok(Some(data)) => {
                bincode::deserialize::<TopicSubscribers>(&data).unwrap_or_default()
            }
            _ => return, // No list to update
        };
        
        // Remove the dead peer
        let original_len = subscribers.subscribers.len();
        subscribers.remove_subscriber(peer);
        
        // Only update if we actually removed something
        if subscribers.subscribers.len() < original_len {
            if let Ok(data) = bincode::serialize(&subscribers) {
                if let Err(e) = self.node.put_at(topic_key, data).await {
                    debug!(
                        topic = %topic,
                        peer = %hex::encode(&peer.as_bytes()[..8]),
                        error = %e,
                        "failed to remove dead peer from DHT"
                    );
                } else {
                    trace!(
                        topic = %topic,
                        peer = %hex::encode(&peer.as_bytes()[..8]),
                        "removed dead peer from DHT subscriber list"
                    );
                }
            }
        }
    }
}

// ============================================================================
// PubSubHandler Implementation
// ============================================================================

/// Implementation of PubSubHandler for GossipSub.
///
/// This allows GossipSub to receive incoming PubSub messages from MeshNode.
#[async_trait::async_trait]
impl<N: DhtNetwork + Send + Sync + 'static> PubSubHandler for GossipSub<N> {
    async fn handle_message(&self, from: &Identity, message: PubSubMessage) -> anyhow::Result<()> {
        // Delegate to the existing handle_message method
        GossipSub::handle_message(self, from, message).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_is_deterministic() {
        let data = b"hello world";
        let source = Identity::from_bytes([1u8; 32]);
        let seqno: u64 = 42;

        let mut input = Vec::new();
        input.extend_from_slice(source.as_bytes());
        input.extend_from_slice(&seqno.to_le_bytes());
        input.extend_from_slice(data);

        let id1 = hash_content(&input);
        let id2 = hash_content(&input);

        assert_eq!(id1, id2);
    }

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
    fn rate_limiter_allows_within_limit() {
        let mut limiter = PeerRateLimit::default();
        
        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(!limiter.check_and_record(10));
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let mut limiter = PeerRateLimit::default();
        
        // Fill up the limit
        for _ in 0..10 {
            let _ = limiter.check_and_record(10);
        }
        
        // Next request should be blocked
        assert!(limiter.check_and_record(10));
    }

    #[test]
    fn topic_subscription_serialization() {
        let identity = Identity::from_bytes([42u8; 32]);
        let topics = vec!["topic1".to_string(), "topic2".to_string()];
        let record = TopicSubscription::new(identity, topics.clone());
        
        // Serialize
        let data = bincode::serialize(&record).expect("serialization failed");
        
        // Deserialize
        let restored: TopicSubscription = bincode::deserialize(&data).expect("deserialization failed");
        
        assert_eq!(restored.subscriber, identity);
        assert_eq!(restored.topics, topics);
    }

    #[test]
    fn message_rejection_types_exist() {
        // Ensure all rejection types are usable
        let _ = MessageRejection::MessageTooLarge;
        let _ = MessageRejection::TopicTooLong;
        let _ = MessageRejection::RateLimited;
        let _ = MessageRejection::Duplicate;
        let _ = MessageRejection::InvalidMessageId;
    }

    #[test]
    fn pubsub_message_variants() {
        // Test Subscribe
        let sub = PubSubMessage::Subscribe { topic: "test".to_string() };
        assert_eq!(sub.topic(), Some("test"));
        
        // Test Unsubscribe
        let unsub = PubSubMessage::Unsubscribe { topic: "test".to_string() };
        assert_eq!(unsub.topic(), Some("test"));
        
        // Test Graft
        let graft = PubSubMessage::Graft { topic: "test".to_string() };
        assert_eq!(graft.topic(), Some("test"));
        
        // Test Prune
        let prune = PubSubMessage::Prune { 
            topic: "test".to_string(), 
            peers: vec![] 
        };
        assert_eq!(prune.topic(), Some("test"));
        
        // Test IHave
        let ihave = PubSubMessage::IHave { 
            topic: "test".to_string(), 
            msg_ids: vec![] 
        };
        assert_eq!(ihave.topic(), Some("test"));
        
        // Test IWant (no topic)
        let iwant = PubSubMessage::IWant { msg_ids: vec![] };
        assert_eq!(iwant.topic(), None);
    }

    #[test]
    fn pubsub_message_serialization() {
        let identity = Identity::from_bytes([1u8; 32]);
        let msg = PubSubMessage::Publish {
            topic: "test".to_string(),
            msg_id: [0u8; 32],
            source: identity,
            seqno: 1,
            data: b"hello".to_vec(),
            signature: vec![0u8; 64],
        };
        
        // Serialize and deserialize
        let encoded = bincode::serialize(&msg).expect("serialize failed");
        let decoded: PubSubMessage = bincode::deserialize(&encoded).expect("deserialize failed");
        
        match decoded {
            PubSubMessage::Publish { topic, seqno, data, .. } => {
                assert_eq!(topic, "test");
                assert_eq!(seqno, 1);
                assert_eq!(data, b"hello");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn topic_state_default() {
        let state = TopicState::default();
        assert!(state.mesh.is_empty());
        assert!(state.peers.is_empty());
        assert!(state.recent_messages.is_empty());
    }

    #[test]
    fn cached_message_fields() {
        let msg = CachedMessage {
            topic: "test".to_string(),
            source: Identity::from_bytes([1u8; 32]),
            seqno: 42,
            data: vec![1, 2, 3],
            signature: vec![0u8; 64],
        };
        
        assert_eq!(msg.topic, "test");
        assert_eq!(msg.seqno, 42);
        assert_eq!(msg.data, vec![1, 2, 3]);
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
    fn received_message_fields() {
        let msg = ReceivedMessage {
            topic: "test".to_string(),
            source: Identity::from_bytes([1u8; 32]),
            seqno: 1,
            data: vec![1, 2, 3],
            msg_id: [0u8; 32],
            received_at: Instant::now(),
        };
        
        assert_eq!(msg.topic, "test");
        assert_eq!(msg.seqno, 1);
        assert!(!msg.data.is_empty());
    }

    #[test]
    fn rate_limiter_window_expiration() {
        let mut limiter = PeerRateLimit::default();
        
        // Add an old timestamp manually
        limiter.publish_times.push_back(Instant::now() - Duration::from_secs(2));
        
        // Old entries should be cleaned up when checking
        assert!(!limiter.check_and_record(10));
        
        // Should only have the new timestamp now (old one cleaned up)
        assert_eq!(limiter.publish_times.len(), 1);
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
    // Multi-Subscriber DHT Tests
    // ========================================================================

    #[test]
    fn subscriber_entry_creation() {
        let identity = Identity::from_bytes([42u8; 32]);
        let entry = SubscriberEntry::new(identity);
        
        assert_eq!(entry.identity, identity);
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn topic_subscribers_add_and_get() {
        let mut subscribers = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        let id2 = Identity::from_bytes([2u8; 32]);
        let id3 = Identity::from_bytes([3u8; 32]);
        
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id2);
        subscribers.add_subscriber(id3);
        
        let result = subscribers.get_subscribers();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&id1));
        assert!(result.contains(&id2));
        assert!(result.contains(&id3));
    }

    #[test]
    fn topic_subscribers_remove() {
        let mut subscribers = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        let id2 = Identity::from_bytes([2u8; 32]);
        
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id2);
        
        subscribers.remove_subscriber(&id1);
        
        let result = subscribers.get_subscribers();
        assert_eq!(result.len(), 1);
        assert!(!result.contains(&id1));
        assert!(result.contains(&id2));
    }

    #[test]
    fn topic_subscribers_update_existing() {
        let mut subscribers = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        
        // Add same subscriber twice
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id1);
        
        // Should still only have one entry
        assert_eq!(subscribers.subscribers.len(), 1);
    }

    #[test]
    fn topic_subscribers_merge() {
        let mut subscribers1 = TopicSubscribers::new();
        let mut subscribers2 = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        let id2 = Identity::from_bytes([2u8; 32]);
        let id3 = Identity::from_bytes([3u8; 32]);
        
        subscribers1.add_subscriber(id1);
        subscribers1.add_subscriber(id2);
        
        subscribers2.add_subscriber(id2);
        subscribers2.add_subscriber(id3);
        
        subscribers1.merge(subscribers2);
        
        let result = subscribers1.get_subscribers();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&id1));
        assert!(result.contains(&id2));
        assert!(result.contains(&id3));
    }

    #[test]
    fn topic_subscribers_serialization() {
        let mut subscribers = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        let id2 = Identity::from_bytes([2u8; 32]);
        
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id2);
        
        // Serialize
        let data = bincode::serialize(&subscribers).expect("serialize failed");
        
        // Deserialize
        let restored: TopicSubscribers = bincode::deserialize(&data).expect("deserialize failed");
        
        let result = restored.get_subscribers();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&id1));
        assert!(result.contains(&id2));
    }

    #[test]
    fn topic_subscribers_limits_size() {
        let mut subscribers = TopicSubscribers::new();
        
        // Add more than MAX_TOPIC_SUBSCRIBERS
        for i in 0..60 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            subscribers.add_subscriber(Identity::from_bytes(bytes));
        }
        
        // Should be limited to MAX_TOPIC_SUBSCRIBERS
        assert!(subscribers.subscribers.len() <= MAX_TOPIC_SUBSCRIBERS);
    }

    // ========================================================================
    // Message Authentication Tests
    // ========================================================================

    #[test]
    fn sign_and_verify_message_valid() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        // Verify with the correct identity
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &signature,
        );
        assert!(result.is_ok(), "valid signature should verify");
    }

    #[test]
    fn verify_message_wrong_identity_fails() {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        // Sign with keypair1
        let signature = sign_pubsub_message(&keypair1, topic, seqno, data);
        
        // Try to verify with keypair2's identity - should fail
        let result = verify_pubsub_signature(
            &keypair2.identity(),
            topic,
            seqno,
            data,
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn verify_message_wrong_topic_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        // Verify with wrong topic
        let result = verify_pubsub_signature(
            &keypair.identity(),
            "different/topic",
            seqno,
            data,
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn verify_message_wrong_seqno_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        // Verify with wrong seqno
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            43, // different seqno
            data,
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn verify_message_wrong_data_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        // Verify with wrong data
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            b"different data",
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn verify_message_empty_signature_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &[], // empty signature
        );
        assert_eq!(result, Err(SignatureError::Missing));
    }

    #[test]
    fn verify_message_short_signature_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &[0u8; 32], // too short (should be 64)
        );
        assert_eq!(result, Err(SignatureError::InvalidLength));
    }

    #[test]
    fn verify_message_corrupted_signature_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let mut signature = sign_pubsub_message(&keypair, topic, seqno, data);
        // Corrupt the signature
        signature[0] ^= 0xFF;
        
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn signed_data_not_malleable() {
        // Prove that different messages produce different signed data
        let topic1 = "topic1";
        let topic2 = "topic2";
        let seqno = 42u64;
        let data = b"hello";
        
        let signed1 = build_signed_data(topic1, seqno, data);
        let signed2 = build_signed_data(topic2, seqno, data);
        
        assert_ne!(signed1, signed2, "different topics should produce different signed data");
        
        // Test seqno affects signed data
        let signed3 = build_signed_data(topic1, 43, data);
        assert_ne!(signed1, signed3, "different seqnos should produce different signed data");
        
        // Test data affects signed data
        let signed4 = build_signed_data(topic1, seqno, b"world");
        assert_ne!(signed1, signed4, "different data should produce different signed data");
    }

    #[test]
    fn pubsub_publish_message_includes_signature() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 1u64;
        let data = b"test data".to_vec();
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, &data);
        
        let msg = PubSubMessage::Publish {
            topic: topic.to_string(),
            msg_id: [0u8; 32],
            source: keypair.identity(),
            seqno,
            data: data.clone(),
            signature: signature.clone(),
        };
        
        // Serialize and deserialize to verify signature survives
        let bytes = bincode::serialize(&msg).expect("serialize failed");
        let decoded: PubSubMessage = bincode::deserialize(&bytes).expect("deserialize failed");
        
        if let PubSubMessage::Publish { signature: decoded_sig, source, .. } = decoded {
            assert_eq!(decoded_sig, signature);
            
            // Verify the signature is still valid after deserialization
            let result = verify_pubsub_signature(&source, topic, seqno, &data, &decoded_sig);
            assert!(result.is_ok(), "signature should still verify after roundtrip");
        } else {
            panic!("Expected Publish message");
        }
    }
}
