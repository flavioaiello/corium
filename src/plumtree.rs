//! # PlumTree Epidemic Broadcast
//!
//! This module implements the PlumTree protocol for reliable pub/sub messaging.
//! PlumTree builds an efficient broadcast tree while maintaining reliability
//! through lazy push repair.
//!
//! ## Protocol Overview
//!
//! PlumTree maintains two peer sets per topic:
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

use ed25519_dalek::{Signature, VerifyingKey};
use lru::LruCache;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, trace, warn};

use crate::hyparview::NeighborCallback;
use crate::identity::{Identity, Keypair};
use crate::messages::{MessageId, PlumTreeMessage};
use crate::rpc::PlumTreeRpc;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default number of eager peers per topic (tree fanout).
pub const DEFAULT_EAGER_PEERS: usize = 6;

/// Default number of lazy peers per topic (reliability mesh).
pub const DEFAULT_LAZY_PEERS: usize = 6;

/// Timeout for IWant requests before trying another peer.
pub const DEFAULT_IHAVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Interval between lazy push rounds (IHave announcements).
pub const DEFAULT_LAZY_PUSH_INTERVAL: Duration = Duration::from_secs(1);

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
/// This bounds memory usage even if HyParView misbehaves.
pub const MAX_KNOWN_PEERS: usize = 1000;

/// Maximum entries in the rate limit tracker.
/// SECURITY: Bounds the rate limiter itself to prevent memory leaks.
pub const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;

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

#[derive(Clone, Debug)]
pub struct PlumTreeConfig {
    /// Target number of eager peers per topic (gossip tree fanout).
    pub eager_peers: usize,
    /// Target number of lazy peers per topic (reliability mesh).
    pub lazy_peers: usize,
    /// Timeout for IHave/IWant exchanges.
    pub ihave_timeout: Duration,
    /// Interval between lazy push rounds.
    pub lazy_push_interval: Duration,
    /// Maximum number of messages in cache.
    pub message_cache_size: usize,
    /// Time-to-live for cached messages.
    pub message_cache_ttl: Duration,
    /// Interval between heartbeat rounds.
    pub heartbeat_interval: Duration,
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Maximum IHave message IDs per notification.
    pub max_ihave_length: usize,
    /// Rate limit for publishing messages per second.
    pub publish_rate_limit: usize,
    /// Rate limit for messages received per peer per second.
    pub per_peer_rate_limit: usize,
}

impl Default for PlumTreeConfig {
    fn default() -> Self {
        Self {
            eager_peers: DEFAULT_EAGER_PEERS,
            lazy_peers: DEFAULT_LAZY_PEERS,
            ihave_timeout: DEFAULT_IHAVE_TIMEOUT,
            lazy_push_interval: DEFAULT_LAZY_PUSH_INTERVAL,
            message_cache_size: DEFAULT_MESSAGE_CACHE_SIZE,
            message_cache_ttl: DEFAULT_MESSAGE_CACHE_TTL,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            max_message_size: MAX_MESSAGE_SIZE,
            max_ihave_length: DEFAULT_MAX_IHAVE_LENGTH,
            publish_rate_limit: DEFAULT_PUBLISH_RATE_LIMIT,
            per_peer_rate_limit: DEFAULT_PER_PEER_RATE_LIMIT,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    Missing,
    InvalidLength,
    VerificationFailed,
    InvalidPublicKey,
}

fn build_signed_data(topic: &str, seqno: u64, data: &[u8]) -> Vec<u8> {
    let mut signed_data = Vec::new();
    let topic_bytes = topic.as_bytes();
    signed_data.extend_from_slice(&(topic_bytes.len() as u32).to_le_bytes());
    signed_data.extend_from_slice(topic_bytes);
    signed_data.extend_from_slice(&seqno.to_le_bytes());
    signed_data.extend_from_slice(&(data.len() as u32).to_le_bytes());
    signed_data.extend_from_slice(data);
    signed_data
}

fn sign_plumtree_message(keypair: &Keypair, topic: &str, seqno: u64, data: &[u8]) -> Vec<u8> {
    let signed_data = build_signed_data(topic, seqno, data);
    keypair.sign(&signed_data).to_bytes().to_vec()
}

fn verify_plumtree_signature(
    source: &Identity,
    topic: &str,
    seqno: u64,
    data: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    if signature.is_empty() {
        return Err(SignatureError::Missing);
    }
    if signature.len() != 64 {
        return Err(SignatureError::InvalidLength);
    }

    let verifying_key = VerifyingKey::try_from(source.as_bytes().as_slice())
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignatureError::InvalidLength)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let signed_data = build_signed_data(topic, seqno, data);
    verifying_key
        .verify_strict(&signed_data, &signature)
        .map_err(|_| SignatureError::VerificationFailed)
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
    pub recent_messages: VecDeque<MessageId>,
    pub pending_iwants: HashMap<MessageId, (Instant, Vec<Identity>)>,
    pub last_lazy_push: Instant,
}

impl Default for TopicState {
    fn default() -> Self {
        Self {
            eager_peers: HashSet::new(),
            lazy_peers: HashSet::new(),
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

    /// Rebalance eager/lazy peers to match target counts.
    /// Demotes excess eager peers to lazy.
    pub fn rebalance(&mut self, eager_target: usize, _lazy_target: usize) {
        // Demote excess eager peers to lazy
        while self.eager_peers.len() > eager_target {
            // Pick a random eager peer to demote
            if let Some(peer) = self.eager_peers.iter().next().copied() {
                self.eager_peers.remove(&peer);
                self.lazy_peers.insert(peer);
            } else {
                break;
            }
        }
    }

    pub fn contains(&self, peer: &Identity) -> bool {
        self.eager_peers.contains(peer) || self.lazy_peers.contains(peer)
    }

    pub fn remove_peer(&mut self, peer: &Identity) {
        self.eager_peers.remove(peer);
        self.lazy_peers.remove(peer);
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
        
        if self.pending_iwants.len() >= MAX_PENDING_IWANTS {
            if let Some(oldest) = self.pending_iwants
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(id, _)| *id)
            {
                self.pending_iwants.remove(&oldest);
                delta -= 1; // Evicted one
            }
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
/// Used by `PlumTree::publish()` to indicate why a message was rejected.
/// Callers can match on this to handle specific rejection reasons programmatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRejection {
    /// Message payload exceeds `PlumTreeConfig::max_message_size`.
    MessageTooLarge,
    /// Topic name exceeds `MAX_TOPIC_LENGTH` (256 bytes).
    TopicTooLong,
    /// Topic name contains invalid characters or is empty.
    InvalidTopic,
    /// Local publish rate limit exceeded (per `PlumTreeConfig::publish_rate_limit`).
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


#[async_trait::async_trait]
pub trait PlumTreeHandler: Send + Sync {
    async fn handle_message(&self, from: &Identity, message: PlumTreeMessage) -> anyhow::Result<()>;
}


// ============================================================================
// Commands sent from Handle to Actor
// ============================================================================

enum Command {
    Subscribe(String, oneshot::Sender<anyhow::Result<()>>),
    Unsubscribe(String, oneshot::Sender<anyhow::Result<()>>),
    Publish(String, Vec<u8>, oneshot::Sender<anyhow::Result<MessageId>>),
    HandleMessage(Identity, PlumTreeMessage, oneshot::Sender<anyhow::Result<()>>),
    NeighborUp(Identity),
    NeighborDown(Identity),
    GetSubscriptions(oneshot::Sender<Vec<String>>),
    Quit,
}


// ============================================================================
// PlumTree Handle (public API - cheap to clone)
// ============================================================================

#[derive(Clone)]
pub struct PlumTree<N: PlumTreeRpc> {
    cmd_tx: mpsc::Sender<Command>,
    // We keep phantom data to satisfy the generic parameter, though it's not strictly needed for the handle
    _phantom: std::marker::PhantomData<N>,
}

impl<N: PlumTreeRpc + Send + Sync + 'static> PlumTree<N> {
    pub fn spawn(
        network: Arc<N>,
        keypair: Keypair,
        config: PlumTreeConfig,
    ) -> (Self, mpsc::Receiver<ReceivedMessage>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(1000);
        let (msg_tx, msg_rx) = mpsc::channel(1000);
        
        let actor = PlumTreeActor::new(network, keypair, config, msg_tx);
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
            .map_err(|_| anyhow::anyhow!("PlumTree actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("PlumTree actor closed"))?
    }

    pub async fn unsubscribe(&self, topic: &str) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::Unsubscribe(topic.to_string(), tx)).await
            .map_err(|_| anyhow::anyhow!("PlumTree actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("PlumTree actor closed"))?
    }

    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> anyhow::Result<MessageId> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::Publish(topic.to_string(), data, tx)).await
            .map_err(|_| anyhow::anyhow!("PlumTree actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("PlumTree actor closed"))?
    }

    pub async fn subscriptions(&self) -> Vec<String> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetSubscriptions(tx)).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn quit(&self) {
        let _ = self.cmd_tx.send(Command::Quit).await;
    }
}

#[async_trait::async_trait]
impl<N: PlumTreeRpc + Send + Sync + 'static> NeighborCallback for PlumTree<N> {
    async fn neighbor_up(&self, peer: Identity) {
        if self.cmd_tx.send(Command::NeighborUp(peer)).await.is_err() {
            warn!(
                peer = %hex::encode(&peer.as_bytes()[..8]),
                "failed to notify PlumTree of neighbor_up - actor closed"
            );
        }
    }

    async fn neighbor_down(&self, peer: &Identity) {
        if self.cmd_tx.send(Command::NeighborDown(*peer)).await.is_err() {
            warn!(
                peer = %hex::encode(&peer.as_bytes()[..8]),
                "failed to notify PlumTree of neighbor_down - actor closed"
            );
        }
    }
}

#[async_trait::async_trait]
impl<N: PlumTreeRpc + Send + Sync + 'static> PlumTreeHandler for PlumTree<N> {
    async fn handle_message(&self, from: &Identity, message: PlumTreeMessage) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::HandleMessage(*from, message, tx)).await
            .map_err(|_| anyhow::anyhow!("PlumTree actor closed"))?;
        rx.await.map_err(|_| anyhow::anyhow!("PlumTree actor closed"))?
    }
}


// ============================================================================
// PlumTree Actor (owns state)
// ============================================================================

struct PlumTreeActor<N: PlumTreeRpc> {
    network: Arc<N>,
    keypair: Keypair,
    local_identity: Identity,
    config: PlumTreeConfig,
    subscriptions: HashSet<String>,
    topics: HashMap<String, TopicState>,
    message_cache: LruCache<MessageId, CachedMessage>,
    message_cache_bytes: usize,
    seqno: u64,
    /// Per-source sequence number tracking to detect replays.
    /// Uses LruCache to enforce MAX_SEQNO_TRACKING_SOURCES bound.
    seqno_tracker: LruCache<Identity, SeqnoTracker>,
    message_tx: mpsc::Sender<ReceivedMessage>,
    outbound: HashMap<Identity, Vec<PlumTreeMessage>>,
    /// Per-peer rate limiting.
    /// Uses LruCache to enforce MAX_RATE_LIMIT_ENTRIES bound.
    rate_limits: LruCache<Identity, PeerRateLimit>,
    /// Known peers from HyParView membership.
    /// Uses LruCache to enforce MAX_KNOWN_PEERS bound as defense-in-depth.
    known_peers: LruCache<Identity, ()>,
    /// Global count of pending IWants across all topics.
    global_pending_iwants: usize,
}

impl<N: PlumTreeRpc + Send + Sync + 'static> PlumTreeActor<N> {
    fn new(
        network: Arc<N>,
        keypair: Keypair,
        config: PlumTreeConfig,
        message_tx: mpsc::Sender<ReceivedMessage>,
    ) -> Self {
        let cache_size = NonZeroUsize::new(config.message_cache_size)
            .unwrap_or(NonZeroUsize::new(1).expect("1 is non-zero"));
        let local_identity = keypair.identity();
        
        // SECURITY: Bounded LRU caches to prevent memory exhaustion attacks
        let seqno_tracker_cap = NonZeroUsize::new(MAX_SEQNO_TRACKING_SOURCES)
            .expect("MAX_SEQNO_TRACKING_SOURCES must be non-zero");
        let rate_limits_cap = NonZeroUsize::new(MAX_RATE_LIMIT_ENTRIES)
            .expect("MAX_RATE_LIMIT_ENTRIES must be non-zero");
        let known_peers_cap = NonZeroUsize::new(MAX_KNOWN_PEERS)
            .expect("MAX_KNOWN_PEERS must be non-zero");
        
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
            known_peers: LruCache::new(known_peers_cap),
            global_pending_iwants: 0,
        }
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
                            let _ = reply.send(self.handle_message_internal(&from, msg).await);
                        }
                        Some(Command::NeighborUp(peer)) => {
                            self.handle_neighbor_up(peer).await;
                        }
                        Some(Command::NeighborDown(peer)) => {
                            self.handle_neighbor_down(&peer).await;
                        }
                        Some(Command::GetSubscriptions(reply)) => {
                            let _ = reply.send(self.subscriptions.iter().cloned().collect());
                        }
                        Some(Command::Quit) => {
                            debug!("PlumTree actor quitting");
                            break;
                        }
                        None => {
                            debug!("PlumTree handle dropped, actor quitting");
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

        let state = self.topics.entry(topic.to_string()).or_default();
        
        for (peer, _) in self.known_peers.iter() {
            if *peer != self.local_identity {
                state.add_peer_with_limits(*peer, self.config.eager_peers, self.config.lazy_peers);
            }
        }

        let peers: Vec<Identity> = state.eager_peers.iter().chain(state.lazy_peers.iter()).copied().collect();

        for peer in peers {
            self.queue_message(&peer, PlumTreeMessage::Subscribe {
                topic: topic.to_string(),
            }).await;
        }

        debug!(topic = %topic, "subscribed to topic (PlumTree)");
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
            self.queue_message(&peer, PlumTreeMessage::Unsubscribe {
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
        
        let signature = sign_plumtree_message(&self.keypair, topic, seqno, &data);
        
        let mut id_input = Vec::new();
        id_input.extend_from_slice(self.local_identity.as_bytes());
        id_input.extend_from_slice(&seqno.to_le_bytes());
        id_input.extend_from_slice(&data);
        let msg_id = crate::dht::hash_content(&id_input);

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

        let publish_msg = PlumTreeMessage::Publish {
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

        if self.subscriptions.contains(topic) {
            let received = ReceivedMessage {
                topic: topic.to_string(),
                source: self.local_identity,
                seqno,
                data,
                msg_id,
                received_at: Instant::now(),
            };
            trace!(
                topic = %received.topic,
                seqno = received.seqno,
                msg_id = %hex::encode(&received.msg_id[..8]),
                data_len = received.data.len(),
                "delivering local message to subscriber"
            );
            if self.message_tx.send(received).await.is_err() {
                warn!("message channel closed during local delivery");
            }
        }

        debug!(
            topic = %topic,
            msg_id = %hex::encode(&msg_id[..8]),
            eager_peers = eager_count,
            "published message (PlumTree)"
        );

        Ok(msg_id)
    }

    async fn handle_message_internal(&mut self, from: &Identity, msg: PlumTreeMessage) -> anyhow::Result<()> {
        if let Some(topic) = msg.topic() {
            if !is_valid_topic(topic) {
                anyhow::bail!("invalid topic name from peer");
            }
        }
        
        match msg {
            PlumTreeMessage::Subscribe { topic } => {
                self.handle_subscribe(from, &topic).await;
            }
            PlumTreeMessage::Unsubscribe { topic } => {
                self.handle_unsubscribe(from, &topic).await;
            }
            PlumTreeMessage::Graft { topic } => {
                self.handle_graft(from, &topic).await;
            }
            PlumTreeMessage::Prune { topic, .. } => {
                self.handle_prune(from, &topic).await;
            }
            PlumTreeMessage::Publish { topic, msg_id, source, seqno, data, signature } => {
                self.handle_publish(from, &topic, msg_id, source, seqno, data, signature).await?;
            }
            PlumTreeMessage::IHave { topic, msg_ids } => {
                self.handle_ihave(from, &topic, msg_ids).await;
            }
            PlumTreeMessage::IWant { msg_ids } => {
                self.handle_iwant(from, msg_ids).await;
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

    async fn handle_neighbor_up(&mut self, peer: Identity) {
        if peer == self.local_identity {
            return;
        }
        
        // known_peers is bounded by LruCache with MAX_KNOWN_PEERS capacity.
        // LRU eviction provides defense-in-depth against HyParView bugs.
        self.known_peers.put(peer, ());
        
        if self.subscriptions.is_empty() {
            return;
        }
        
        for topic in self.subscriptions.iter() {
            if let Some(state) = self.topics.get_mut(topic) {
                state.add_peer_with_limits(peer, self.config.eager_peers, self.config.lazy_peers);
                debug!(
                    peer = %hex::encode(&peer.as_bytes()[..8]),
                    topic = %topic,
                    "added HyParView neighbor to topic"
                );
            }
        }
    }

    async fn handle_neighbor_down(&mut self, peer: &Identity) {
        if *peer == self.local_identity {
            return;
        }
        
        self.known_peers.pop(peer);
        self.outbound.remove(peer);
        
        for (topic, state) in self.topics.iter_mut() {
            let was_eager = state.eager_peers.contains(peer);
            let was_lazy = state.lazy_peers.contains(peer);
            state.remove_peer(peer);
            if was_eager || was_lazy {
                debug!(
                    peer = %hex::encode(&peer.as_bytes()[..8]),
                    topic = %topic,
                    "removed HyParView neighbor from topic"
                );
            }
        }
    }

    async fn handle_subscribe(&mut self, from: &Identity, topic: &str) {
        if !self.subscriptions.contains(topic) {
            return;
        }

        if let Some(state) = self.topics.get_mut(topic) {
            state.add_peer_with_limits(*from, self.config.eager_peers, self.config.lazy_peers);
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
            self.queue_message(from, PlumTreeMessage::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
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
        state.promote_to_eager_with_limit(*from, self.config.eager_peers);
        
        debug!(
            peer = %hex::encode(&from.as_bytes()[..8]),
            topic = %topic,
            "peer grafted, promoted to eager"
        );
    }

    async fn handle_prune(&mut self, from: &Identity, topic: &str) {
        if let Some(state) = self.topics.get_mut(topic) {
            state.demote_to_lazy(*from);
            debug!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "peer sent prune, demoted to lazy"
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
        if data.len() > self.config.max_message_size {
            debug!(from = %hex::encode(&from.as_bytes()[..8]), "rejecting oversized message");
            return Ok(());
        }

        if let Err(e) = verify_plumtree_signature(&source, topic, seqno, &data, &signature) {
            debug!(
                from = %hex::encode(&from.as_bytes()[..8]),
                error = ?e,
                "rejecting message with invalid signature"
            );
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
                return Ok(());
            }
        }

        let is_duplicate = self.message_cache.contains(&msg_id);

        if is_duplicate {
            if let Some(state) = self.topics.get_mut(topic) {
                state.demote_to_lazy(*from);
            }
            
            self.queue_message(from, PlumTreeMessage::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
            }).await;

            trace!(
                msg_id = %hex::encode(&msg_id[..8]),
                from = %hex::encode(&from.as_bytes()[..8]),
                "duplicate message, demoted sender to lazy"
            );
            return Ok(());
        }


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

        let forward_msg = PlumTreeMessage::Publish {
            topic: topic.to_string(),
            msg_id,
            source,
            seqno,
            data,
            signature,
        };

        for peer in eager_peers {
            self.queue_message(&peer, forward_msg.clone()).await;
        }

        debug!(
            msg_id = %hex::encode(&msg_id[..8]),
            topic = %topic,
            "handled publish (PlumTree), forwarded to eager peers"
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
            state.promote_to_eager_with_limit(*from, self.config.eager_peers);
            
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

        self.queue_message(from, PlumTreeMessage::Graft {
            topic: topic.to_string(),
        }).await;

        self.queue_message(from, PlumTreeMessage::IWant { 
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

                self.queue_message(from, PlumTreeMessage::Publish {
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

    async fn heartbeat(&mut self) {
        let subscribed_topics: Vec<String> = self.subscriptions.iter().cloned().collect();

        for topic in subscribed_topics {
            // Rebalance eager/lazy peers to respect target counts
            if let Some(state) = self.topics.get_mut(&topic) {
                state.rebalance(self.config.eager_peers, self.config.lazy_peers);
            }
            
            self.lazy_push(&topic).await;
            self.check_timeouts(&topic).await;
        }

        self.cleanup_stale_state();
        self.flush_pending_queues().await;
    }

    async fn flush_pending_queues(&mut self) {
        let peers_with_pending: Vec<Identity> = self.outbound.keys().copied().collect();

        for peer in peers_with_pending {
            if let Some(contact) = self.network.resolve_identity_to_contact(&peer).await {
                let messages = self.outbound.remove(&peer).unwrap_or_default();
                for msg in messages {
                    if let Err(e) = self.network.send_plumtree(&contact, self.local_identity, msg).await {
                        trace!(
                            peer = %hex::encode(&peer.as_bytes()[..8]),
                            error = %e,
                            "failed to flush pending PlumTree message"
                        );
                    }
                }
            }
        }
    }

    async fn lazy_push(&mut self, topic: &str) {
        let (should_push, msg_ids, lazy_peers) = if let Some(state) = self.topics.get_mut(topic) {
            if state.should_lazy_push(self.config.lazy_push_interval) {
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
            let ihave = PlumTreeMessage::IHave {
                topic: topic.to_string(),
                msg_ids,
            };

            for peer in lazy_peers {
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
            self.queue_message(&peer, PlumTreeMessage::IWant {
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


    async fn queue_message(&mut self, peer: &Identity, msg: PlumTreeMessage) {
        if let Some(contact) = self.network.resolve_identity_to_contact(peer).await {
            if let Err(e) = self.network.send_plumtree(&contact, self.local_identity, msg.clone()).await {
                trace!(
                    peer = %hex::encode(&peer.as_bytes()[..8]),
                    error = %e,
                    "failed to send PlumTree message, queueing for later"
                );
            } else {
                return;
            }
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
        if total >= MAX_TOTAL_OUTBOUND_MESSAGES {
            if let Some(largest) = self.outbound.iter()
                .max_by_key(|(_, msgs)| msgs.len())
                .map(|(id, _)| *id)
            {
                if let Some(queue) = self.outbound.get_mut(&largest) {
                    let drain = (queue.len() / 2).max(1);
                    queue.drain(0..drain);
                }
            }
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
        let config = PlumTreeConfig::default();
        assert!(config.eager_peers > 0);
        assert!(config.lazy_peers > 0);
        assert!(config.message_cache_size > 0);
        assert!(config.message_cache_ttl.as_secs() > 0);
        assert!(config.max_message_size > 0);
        assert!(config.publish_rate_limit > 0);
        assert!(config.per_peer_rate_limit > 0);
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
        let config = PlumTreeConfig {
            eager_peers: 8,
            lazy_peers: 12,
            max_message_size: 1024,
            publish_rate_limit: 50,
            per_peer_rate_limit: 25,
            ..Default::default()
        };
        
        assert_eq!(config.eager_peers, 8);
        assert_eq!(config.lazy_peers, 12);
        assert_eq!(config.max_message_size, 1024);
        assert_eq!(config.publish_rate_limit, 50);
        assert_eq!(config.per_peer_rate_limit, 25);
    }

    #[test]
    fn default_config_has_security_limits() {
        let config = PlumTreeConfig::default();

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
            config.eager_peers >= 1 && config.eager_peers <= 20,
            "eager_peers should be between 1 and 20, got {}",
            config.eager_peers
        );

        assert!(
            config.lazy_peers >= 1 && config.lazy_peers <= 50,
            "lazy_peers should be between 1 and 50, got {}",
            config.lazy_peers
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
        let config = PlumTreeConfig::default();

        assert!(config.message_cache_size > 0);
        assert!(config.message_cache_size <= 1_000_000);

        assert!(config.message_cache_ttl >= Duration::from_secs(30));
        assert!(config.message_cache_ttl <= Duration::from_secs(3600));
    }

    #[test]
    fn heartbeat_interval_configuration() {
        let config = PlumTreeConfig::default();

        assert!(config.heartbeat_interval >= Duration::from_millis(100));
        assert!(config.heartbeat_interval <= Duration::from_secs(10));
    }

    #[test]
    fn lazy_push_interval_configuration() {
        let config = PlumTreeConfig::default();

        assert!(config.lazy_push_interval >= Duration::from_millis(100));
        assert!(config.lazy_push_interval <= Duration::from_secs(10));
    }

    #[test]
    fn ihave_timeout_configuration() {
        let config = PlumTreeConfig::default();

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

        let id1 = crate::dht::hash_content(&input);
        let id2 = crate::dht::hash_content(&input);

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
    fn plumtree_config_all_fields_accessible() {
        let config = PlumTreeConfig::default();
        
        assert!(config.eager_peers > 0);
        assert!(config.lazy_peers > 0);
        assert!(config.ihave_timeout.as_secs() > 0);
        assert!(config.lazy_push_interval.as_millis() > 0);
        assert!(config.message_cache_size > 0);
        assert!(config.message_cache_ttl.as_secs() > 0);
        assert!(config.heartbeat_interval.as_millis() > 0);
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
        
        let _ = state.should_lazy_push(DEFAULT_LAZY_PUSH_INTERVAL);
        
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
