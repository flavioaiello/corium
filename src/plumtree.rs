use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use lru::LruCache;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, trace, warn};

use crate::hyparview::NeighborCallback;
use crate::identity::{Identity, Keypair};
use crate::messages::{MessageId, PlumTreeMessage};
use crate::rpc::PlumTreeRpc;

// ============================================================================
// PlumTree Configuration Constants
// ============================================================================

pub const DEFAULT_EAGER_PEERS: usize = 4;
pub const DEFAULT_LAZY_PEERS: usize = 6;
pub const DEFAULT_IHAVE_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_LAZY_PUSH_INTERVAL: Duration = Duration::from_secs(1);

pub const DEFAULT_MESSAGE_CACHE_TTL: Duration = Duration::from_secs(120);
pub const DEFAULT_MESSAGE_CACHE_SIZE: usize = 10_000;
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_MAX_IHAVE_LENGTH: usize = 100;

pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;
pub const DEFAULT_PUBLISH_RATE_LIMIT: usize = 100;
pub const DEFAULT_PER_PEER_RATE_LIMIT: usize = 50;
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);

pub const MAX_TOPIC_LENGTH: usize = 256;
pub const MAX_TOPICS: usize = 10_000;

#[inline]
pub fn is_valid_topic(topic: &str) -> bool {
    !topic.is_empty() 
        && topic.len() <= MAX_TOPIC_LENGTH 
        && topic.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

pub const MAX_SUBSCRIPTIONS_PER_PEER: usize = 100;
pub const MAX_PEERS_PER_TOPIC: usize = 1000;

pub const DEFAULT_MAX_IWANT_MESSAGES: usize = 10;
pub const DEFAULT_IWANT_RATE_LIMIT: usize = 5;
pub const MAX_IWANT_RESPONSE_BYTES: usize = 256 * 1024;

pub const MAX_OUTBOUND_PER_PEER: usize = 100;
pub const MAX_TOTAL_OUTBOUND_MESSAGES: usize = 50_000;
pub const MAX_OUTBOUND_PEERS: usize = 1000;

pub const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;
pub const RATE_LIMIT_ENTRY_MAX_AGE: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct PlumTreeConfig {
    pub eager_peers: usize,
    pub lazy_peers: usize,
    pub ihave_timeout: Duration,
    pub lazy_push_interval: Duration,
    pub message_cache_size: usize,
    pub message_cache_ttl: Duration,
    pub heartbeat_interval: Duration,
    pub max_message_size: usize,
    pub max_ihave_length: usize,
    pub publish_rate_limit: usize,
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

// ============================================================================
// Signature Types and Functions
// ============================================================================

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

// ============================================================================
// PlumTree Types
// ============================================================================

// PlumTree IWant handling
const MAX_PENDING_IWANTS: usize = 100;

#[derive(Clone, Debug)]
#[allow(dead_code)] // Fields used when receiving messages from channel
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
}

#[derive(Debug)]
#[allow(dead_code)] // Fields used by heartbeat/lazy push loop
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

#[allow(dead_code)] // Heartbeat loop infrastructure
impl TopicState {
    pub fn total_peers(&self) -> usize {
        self.eager_peers.len() + self.lazy_peers.len()
    }

    pub fn add_eager(&mut self, peer: Identity) -> bool {
        if self.total_peers() >= MAX_PEERS_PER_TOPIC && !self.contains(&peer) {
            return false;
        }
        self.lazy_peers.remove(&peer);
        self.eager_peers.insert(peer);
        true
    }

    pub fn demote_to_lazy(&mut self, peer: Identity) {
        if self.eager_peers.remove(&peer) {
            self.lazy_peers.insert(peer);
        }
    }

    pub fn promote_to_eager(&mut self, peer: Identity) {
        if self.lazy_peers.remove(&peer) {
            self.eager_peers.insert(peer);
        } else if !self.eager_peers.contains(&peer) {
            // New peer, add as eager
            if self.total_peers() < MAX_PEERS_PER_TOPIC {
                self.eager_peers.insert(peer);
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

    pub fn should_lazy_push(&self) -> bool {
        self.last_lazy_push.elapsed() >= DEFAULT_LAZY_PUSH_INTERVAL && !self.lazy_peers.is_empty()
    }

    pub fn record_iwant(&mut self, msg_id: MessageId, peer: Identity) {
        // Limit pending IWants to prevent memory growth
        if self.pending_iwants.len() >= MAX_PENDING_IWANTS {
            // Remove oldest
            if let Some(oldest) = self.pending_iwants
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(id, _)| *id)
            {
                self.pending_iwants.remove(&oldest);
            }
        }
        self.pending_iwants.insert(msg_id, (Instant::now(), vec![peer]));
    }

    pub fn check_iwant_timeouts(&mut self) -> Vec<(MessageId, Identity)> {
        let now = Instant::now();
        let mut retries = Vec::new();
        let mut completed = Vec::new();

        for (msg_id, (requested_at, tried_peers)) in self.pending_iwants.iter_mut() {
            if now.duration_since(*requested_at) > DEFAULT_IHAVE_TIMEOUT {
                // Find a lazy peer we haven't tried
                if let Some(next_peer) = self.lazy_peers.iter()
                    .find(|p| !tried_peers.contains(p))
                    .copied()
                {
                    tried_peers.push(next_peer);
                    *requested_at = now; // Reset timeout
                    retries.push((*msg_id, next_peer));
                } else {
                    // No more peers to try
                    completed.push(*msg_id);
                }
            }
        }

        for msg_id in completed {
            self.pending_iwants.remove(&msg_id);
        }

        retries
    }

    pub fn message_received(&mut self, msg_id: &MessageId) {
        self.pending_iwants.remove(msg_id);
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
            return true; // Rate limited
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
            return true; // Rate limited
        }
        
        self.publish_times.push_back(now);
        false
    }
    
    pub fn is_stale(&self, now: Instant) -> bool {
        now.duration_since(self.last_active) > RATE_LIMIT_ENTRY_MAX_AGE
    }
}

#[allow(dead_code)]  // Ready for future rejection handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRejection {
    MessageTooLarge,
    TopicTooLong,
    RateLimited,
    Duplicate,
    InvalidMessageId,
}

// ============================================================================
// PlumTree Handler Trait
// ============================================================================

#[async_trait::async_trait]
pub trait PlumTreeHandler: Send + Sync {
    async fn handle_message(&self, from: &Identity, message: PlumTreeMessage) -> anyhow::Result<()>;
}

// ============================================================================
// PlumTree Implementation
// ============================================================================

#[allow(dead_code)] // Infrastructure methods for heartbeat loop
pub struct PlumTree<N: PlumTreeRpc> {
    network: Arc<N>,
    keypair: Keypair,
    local_identity: Identity,
    config: PlumTreeConfig,
    subscriptions: Arc<RwLock<HashSet<String>>>,
    topics: Arc<RwLock<HashMap<String, TopicState>>>,
    message_cache: Arc<RwLock<LruCache<MessageId, CachedMessage>>>,
    seqno: Arc<RwLock<u64>>,
    message_tx: mpsc::Sender<ReceivedMessage>,
    message_rx: Option<mpsc::Receiver<ReceivedMessage>>,
    outbound: Arc<RwLock<HashMap<Identity, Vec<PlumTreeMessage>>>>,
    rate_limits: Arc<RwLock<HashMap<Identity, PeerRateLimit>>>,
    known_peers: Arc<RwLock<HashSet<Identity>>>,
}

#[allow(dead_code)] // PlumTree infrastructure methods for heartbeat, diagnostics, and introspection
impl<N: PlumTreeRpc + Send + Sync + 'static> PlumTree<N> {
    pub fn new(network: Arc<N>, keypair: Keypair, config: PlumTreeConfig) -> Self {
        let cache_size = NonZeroUsize::new(config.message_cache_size)
            .unwrap_or(NonZeroUsize::new(1).expect("1 is non-zero"));
        let (tx, rx) = mpsc::channel(1000);
        let local_identity = keypair.identity();
        
        Self {
            network,
            keypair,
            local_identity,
            config,
            subscriptions: Arc::new(RwLock::new(HashSet::new())),
            topics: Arc::new(RwLock::new(HashMap::new())),
            message_cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            seqno: Arc::new(RwLock::new(0)),
            message_tx: tx,
            message_rx: Some(rx),
            outbound: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            known_peers: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn take_message_receiver(&mut self) -> Option<mpsc::Receiver<ReceivedMessage>> {
        self.message_rx.take()
    }

    // ========================================================================
    // HYPARVIEW INTEGRATION
    // ========================================================================

    pub async fn handle_neighbor_up(&self, peer: Identity) {
        if peer == self.local_identity {
            return;
        }
        
        // Add to known peers
        {
            let mut known = self.known_peers.write().await;
            known.insert(peer);
        }
        
        // Add as eager peer to all subscribed topics
        let subs = self.subscriptions.read().await;
        if subs.is_empty() {
            return;
        }
        
        let mut topics = self.topics.write().await;
        for topic in subs.iter() {
            if let Some(state) = topics.get_mut(topic) {
                // Add as eager - tree will optimize via duplicate detection
                state.add_eager(peer);
                debug!(
                    peer = %hex::encode(&peer.as_bytes()[..8]),
                    topic = %topic,
                    "added HyParView neighbor as eager peer"
                );
            }
        }
    }

    pub async fn handle_neighbor_down(&self, peer: &Identity) {
        if *peer == self.local_identity {
            return;
        }
        
        // Remove from known peers
        {
            let mut known = self.known_peers.write().await;
            known.remove(peer);
        }
        
        // Remove from all topics
        let mut topics = self.topics.write().await;
        for (topic, state) in topics.iter_mut() {
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
}

// ============================================================================
// NeighborCallback Implementation for PlumTree
// ============================================================================

#[async_trait::async_trait]
impl<N: PlumTreeRpc + Send + Sync + 'static> NeighborCallback for PlumTree<N> {
    async fn neighbor_up(&self, peer: Identity) {
        self.handle_neighbor_up(peer).await;
    }

    async fn neighbor_down(&self, peer: &Identity) {
        self.handle_neighbor_down(peer).await;
    }
}

impl<N: PlumTreeRpc + Send + Sync + 'static> PlumTree<N> {
    // ========================================================================
    // SUBSCRIPTION MANAGEMENT (No DHT involvement)
    // ========================================================================

    pub async fn subscribe(&self, topic: &str) -> anyhow::Result<()> {
        // Validate topic
        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!("topic length {} exceeds maximum {}", topic.len(), MAX_TOPIC_LENGTH);
        }
        if topic.is_empty() {
            anyhow::bail!("topic name cannot be empty");
        }
        if !is_valid_topic(topic) {
            anyhow::bail!("topic name contains invalid characters");
        }

        // Check subscription limits
        {
            let mut subs = self.subscriptions.write().await;
            if subs.contains(topic) {
                return Ok(()); // Already subscribed
            }
            if subs.len() >= MAX_SUBSCRIPTIONS_PER_PEER {
                anyhow::bail!("subscription limit reached (max {})", MAX_SUBSCRIPTIONS_PER_PEER);
            }
            subs.insert(topic.to_string());
        }

        // Initialize topic state with known peers as eager
        {
            let known = self.known_peers.read().await;
            let mut topics = self.topics.write().await;
            
            if !topics.contains_key(topic) && topics.len() >= MAX_TOPICS {
                // Try to remove an empty topic
                let empty = topics.iter()
                    .find(|(_, s)| s.eager_peers.is_empty() && s.lazy_peers.is_empty())
                    .map(|(t, _)| t.clone());
                if let Some(t) = empty {
                    topics.remove(&t);
                } else {
                    let mut subs = self.subscriptions.write().await;
                    subs.remove(topic);
                    anyhow::bail!("topic limit reached (max {})", MAX_TOPICS);
                }
            }

            let state = topics.entry(topic.to_string()).or_default();
            
            // Add all known peers as eager (PlumTree starts optimistic)
            for peer in known.iter() {
                if *peer != self.local_identity {
                    state.add_eager(*peer);
                }
            }
        }

        // Notify peers of our subscription
        let peers: Vec<Identity> = {
            let topics = self.topics.read().await;
            topics.get(topic)
                .map(|s| s.eager_peers.iter().chain(s.lazy_peers.iter()).copied().collect())
                .unwrap_or_default()
        };

        for peer in peers {
            self.queue_message(&peer, PlumTreeMessage::Subscribe {
                topic: topic.to_string(),
            }).await;
        }

        debug!(topic = %topic, "subscribed to topic (PlumTree)");
        Ok(())
    }

    pub async fn unsubscribe(&self, topic: &str) -> anyhow::Result<()> {
        {
            let mut subs = self.subscriptions.write().await;
            if !subs.remove(topic) {
                return Ok(()); // Wasn't subscribed
            }
        }

        // Notify all peers and clean up
        let all_peers: Vec<Identity> = {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.remove(topic) {
                state.eager_peers.into_iter()
                    .chain(state.lazy_peers.into_iter())
                    .collect()
            } else {
                Vec::new()
            }
        };

        for peer in all_peers {
            self.queue_message(&peer, PlumTreeMessage::Unsubscribe {
                topic: topic.to_string(),
            }).await;
        }

        debug!(topic = %topic, "unsubscribed from topic");
        Ok(())
    }

    // ========================================================================
    // PUBLISHING
    // ========================================================================

    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> anyhow::Result<MessageId> {
        // Validate
        if data.len() > self.config.max_message_size {
            anyhow::bail!("message size {} exceeds maximum {}", data.len(), self.config.max_message_size);
        }
        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!("topic length {} exceeds maximum {}", topic.len(), MAX_TOPIC_LENGTH);
        }

        // Rate limit check
        {
            let mut rate_limits = self.rate_limits.write().await;
            let limiter = rate_limits.entry(self.local_identity).or_default();
            if limiter.check_and_record(self.config.publish_rate_limit) {
                anyhow::bail!("local publish rate limit exceeded");
            }
        }

        // Generate message ID
        let seqno = {
            let mut seq = self.seqno.write().await;
            *seq = seq.wrapping_add(1);
            *seq
        };
        
        let signature = sign_plumtree_message(&self.keypair, topic, seqno, &data);
        
        let mut id_input = Vec::new();
        id_input.extend_from_slice(self.local_identity.as_bytes());
        id_input.extend_from_slice(&seqno.to_le_bytes());
        id_input.extend_from_slice(&data);
        let msg_id = crate::dht::hash_content(&id_input);

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

        // Track in recent messages for lazy push
        {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                state.recent_messages.push_back(msg_id);
                if state.recent_messages.len() > self.config.max_ihave_length {
                    state.recent_messages.pop_front();
                }
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

        // PlumTree: Send to EAGER peers only (tree edges)
        let eager_peers: Vec<Identity> = {
            let topics = self.topics.read().await;
            topics.get(topic)
                .map(|s| s.eager_peers.iter().copied().collect())
                .unwrap_or_default()
        };

        let eager_count = eager_peers.len();
        for peer in eager_peers {
            self.queue_message(&peer, publish_msg.clone()).await;
        }

        // Deliver locally if subscribed
        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        if is_subscribed {
            let received = ReceivedMessage {
                topic: topic.to_string(),
                source: self.local_identity,
                seqno,
                data,
                msg_id,
                received_at: Instant::now(),
            };
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

    // ========================================================================
    // MESSAGE HANDLING (PlumTree Core Logic)
    // ========================================================================

    pub async fn handle_message(&self, from: &Identity, msg: PlumTreeMessage) -> anyhow::Result<()> {
        // Validate topic
        let topic_opt = match &msg {
            PlumTreeMessage::Subscribe { topic } 
            | PlumTreeMessage::Unsubscribe { topic }
            | PlumTreeMessage::Graft { topic }
            | PlumTreeMessage::Prune { topic, .. }
            | PlumTreeMessage::Publish { topic, .. }
            | PlumTreeMessage::IHave { topic, .. } => Some(topic.as_str()),
            PlumTreeMessage::IWant { .. } => None,
        };
        
        if let Some(topic) = topic_opt {
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

    async fn handle_subscribe(&self, from: &Identity, topic: &str) {
        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        if !is_subscribed {
            return; // We're not subscribed, ignore
        }

        let mut topics = self.topics.write().await;
        if let Some(state) = topics.get_mut(topic) {
            // New subscriber joins as eager (optimistic)
            state.add_eager(*from);
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "peer subscribed, added as eager"
            );
        }
    }

    async fn handle_unsubscribe(&self, from: &Identity, topic: &str) {
        let mut topics = self.topics.write().await;
        if let Some(state) = topics.get_mut(topic) {
            state.remove_peer(from);
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "peer unsubscribed"
            );
        }
    }

    async fn handle_graft(&self, from: &Identity, topic: &str) {
        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        if !is_subscribed {
            // We're not subscribed, send Prune
            self.queue_message(from, PlumTreeMessage::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
            }).await;
            return;
        }

        let mut topics = self.topics.write().await;
        let state = topics.entry(topic.to_string()).or_default();
        state.promote_to_eager(*from);
        
        debug!(
            peer = %hex::encode(&from.as_bytes()[..8]),
            topic = %topic,
            "peer grafted, promoted to eager"
        );
    }

    async fn handle_prune(&self, from: &Identity, topic: &str) {
        let mut topics = self.topics.write().await;
        if let Some(state) = topics.get_mut(topic) {
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
        &self,
        from: &Identity,
        topic: &str,
        msg_id: MessageId,
        source: Identity,
        seqno: u64,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> anyhow::Result<()> {
        // Size check
        if data.len() > self.config.max_message_size {
            debug!(from = %hex::encode(&from.as_bytes()[..8]), "rejecting oversized message");
            return Ok(());
        }

        // Signature verification
        if let Err(e) = verify_plumtree_signature(&source, topic, seqno, &data, &signature) {
            debug!(
                from = %hex::encode(&from.as_bytes()[..8]),
                error = ?e,
                "rejecting message with invalid signature"
            );
            return Ok(());
        }

        // Rate limiting
        {
            let mut rate_limits = self.rate_limits.write().await;
            if rate_limits.len() >= MAX_RATE_LIMIT_ENTRIES {
                let now = Instant::now();
                rate_limits.retain(|_, limiter| !limiter.is_stale(now));
            }
            let limiter = rate_limits.entry(*from).or_default();
            if limiter.check_and_record(self.config.per_peer_rate_limit) {
                debug!(from = %hex::encode(&from.as_bytes()[..8]), "peer rate limited");
                return Ok(());
            }
        }

        // PLUMTREE CORE: Check if duplicate
        let is_duplicate = {
            let cache = self.message_cache.read().await;
            cache.contains(&msg_id)
        };

        if is_duplicate {
            // DUPLICATE RECEIPT: Demote sender to lazy, send Prune
            {
                let mut topics = self.topics.write().await;
                if let Some(state) = topics.get_mut(topic) {
                    state.demote_to_lazy(*from);
                }
            }
            
            // Send Prune to tell sender to stop sending us full messages
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

        // FIRST RECEIPT: Cache, deliver, forward to eager peers

        // Cache the message
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

        // Clear from pending IWants
        {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                state.message_received(&msg_id);
                
                // Track in recent messages for lazy push
                state.recent_messages.push_back(msg_id);
                if state.recent_messages.len() > self.config.max_ihave_length {
                    state.recent_messages.pop_front();
                }
            }
        }

        // Deliver to application if subscribed
        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        if is_subscribed {
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
        }

        // PLUMTREE: Forward to EAGER peers only (not sender)
        let eager_peers: Vec<Identity> = {
            let topics = self.topics.read().await;
            topics.get(topic)
                .map(|s| s.eager_peers.iter().filter(|p| *p != from).copied().collect())
                .unwrap_or_default()
        };

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

    async fn handle_ihave(&self, from: &Identity, topic: &str, msg_ids: Vec<MessageId>) {
        let missing: Vec<MessageId> = {
            let cache = self.message_cache.read().await;
            msg_ids.into_iter()
                .filter(|id| !cache.contains(id))
                .collect()
        };

        if missing.is_empty() {
            return;
        }

        // PLUMTREE REPAIR: Promote sender to eager (they have messages we need)
        {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                state.promote_to_eager(*from);
                
                // Track pending IWants
                for msg_id in &missing {
                    state.record_iwant(*msg_id, *from);
                }
            }
        }

        // Send Graft to tell sender we want full messages now
        self.queue_message(from, PlumTreeMessage::Graft {
            topic: topic.to_string(),
        }).await;

        // Request the missing messages
        self.queue_message(from, PlumTreeMessage::IWant { 
            msg_ids: missing.clone() 
        }).await;

        debug!(
            from = %hex::encode(&from.as_bytes()[..8]),
            topic = %topic,
            missing = missing.len(),
            "IHave received, promoted sender to eager and requested missing"
        );
    }

    async fn handle_iwant(&self, from: &Identity, msg_ids: Vec<MessageId>) {
        if msg_ids.len() > DEFAULT_MAX_IWANT_MESSAGES * 2 {
            warn!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                count = msg_ids.len(),
                "IWant request too large"
            );
            return;
        }

        // Rate limit IWant
        {
            let mut rate_limits = self.rate_limits.write().await;
            let limiter = rate_limits.entry(*from).or_default();
            if limiter.check_and_record_iwant(DEFAULT_IWANT_RATE_LIMIT) {
                warn!(peer = %hex::encode(&from.as_bytes()[..8]), "IWant rate limited");
                return;
            }
        }

        let cache = self.message_cache.read().await;
        let mut bytes_sent = 0usize;

        for msg_id in msg_ids.into_iter().take(DEFAULT_MAX_IWANT_MESSAGES) {
            if let Some(cached) = cache.peek(&msg_id) {
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

    // ========================================================================
    // HEARTBEAT / MAINTENANCE
    // ========================================================================

    pub async fn run_heartbeat(&self) {
        let mut interval = tokio::time::interval(self.config.heartbeat_interval);
        
        loop {
            interval.tick().await;
            self.heartbeat().await;
        }
    }

    async fn heartbeat(&self) {
        let subscribed_topics: Vec<String> = {
            self.subscriptions.read().await.iter().cloned().collect()
        };

        for topic in subscribed_topics {
            self.lazy_push(&topic).await;
            self.check_timeouts(&topic).await;
        }

        self.cleanup_stale_state().await;
    }

    async fn lazy_push(&self, topic: &str) {
        let (should_push, msg_ids, lazy_peers) = {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                if state.should_lazy_push() {
                    state.last_lazy_push = Instant::now();
                    let ids: Vec<MessageId> = state.recent_messages.iter().copied().collect();
                    let peers: Vec<Identity> = state.lazy_peers.iter().copied().collect();
                    (true, ids, peers)
                } else {
                    (false, Vec::new(), Vec::new())
                }
            } else {
                (false, Vec::new(), Vec::new())
            }
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

    async fn check_timeouts(&self, topic: &str) {
        let retries: Vec<(MessageId, Identity)> = {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                state.check_iwant_timeouts()
            } else {
                Vec::new()
            }
        };

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

    async fn cleanup_stale_state(&self) {
        let now = Instant::now();
        
        let mut rate_limits = self.rate_limits.write().await;
        rate_limits.retain(|_, limiter| !limiter.is_stale(now));
        
        let mut outbound = self.outbound.write().await;
        outbound.retain(|_, msgs| !msgs.is_empty());
    }

    // ========================================================================
    // OUTBOUND QUEUE
    // ========================================================================

    async fn queue_message(&self, peer: &Identity, msg: PlumTreeMessage) {
        let mut outbound = self.outbound.write().await;
        
        // Limit total peers
        if !outbound.contains_key(peer) && outbound.len() >= MAX_OUTBOUND_PEERS {
            let smallest = outbound.iter()
                .min_by_key(|(_, msgs)| msgs.len())
                .map(|(id, _)| *id);
            if let Some(evict) = smallest {
                outbound.remove(&evict);
            }
        }
        
        // Limit total messages
        let total: usize = outbound.values().map(|v| v.len()).sum();
        if total >= MAX_TOTAL_OUTBOUND_MESSAGES {
            if let Some(largest) = outbound.iter()
                .max_by_key(|(_, msgs)| msgs.len())
                .map(|(id, _)| *id)
            {
                if let Some(queue) = outbound.get_mut(&largest) {
                    let drain = (queue.len() / 2).max(1);
                    queue.drain(0..drain);
                }
            }
        }
        
        let queue = outbound.entry(*peer).or_default();
        
        // Limit per-peer queue
        if queue.len() >= MAX_OUTBOUND_PER_PEER {
            let drain = queue.len() / 2;
            queue.drain(0..drain);
        }
        
        queue.push(msg);
    }

    pub async fn take_pending_messages(&self, peer: &Identity) -> Vec<PlumTreeMessage> {
        let mut outbound = self.outbound.write().await;
        outbound.remove(peer).unwrap_or_default()
    }

    pub async fn peers_with_pending(&self) -> Vec<Identity> {
        let outbound = self.outbound.read().await;
        outbound.keys().copied().collect()
    }

    // ========================================================================
    // PUBLIC ACCESSORS
    // ========================================================================

    pub async fn subscriptions(&self) -> Vec<String> {
        self.subscriptions.read().await.iter().cloned().collect()
    }

    pub async fn eager_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| s.eager_peers.iter().copied().collect())
            .unwrap_or_default()
    }

    pub async fn lazy_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| s.lazy_peers.iter().copied().collect())
            .unwrap_or_default()
    }

    pub async fn topic_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| s.eager_peers.iter().chain(s.lazy_peers.iter()).copied().collect())
            .unwrap_or_default()
    }

    pub fn local_identity(&self) -> Identity {
        self.local_identity
    }
}

#[async_trait::async_trait]
impl<N: PlumTreeRpc + Send + Sync + 'static> PlumTreeHandler for PlumTree<N> {
    async fn handle_message(&self, from: &Identity, message: PlumTreeMessage) -> anyhow::Result<()> {
        PlumTree::handle_message(self, from, message).await
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
        assert!(config.max_message_size > 0);
        assert!(config.publish_rate_limit > 0);
        assert!(config.per_peer_rate_limit > 0);
    }

    #[test]
    fn flood_protection_constants() {
        assert!(MAX_MESSAGE_SIZE >= 1024, "max message size too small");
        assert!(MAX_MESSAGE_SIZE <= 1024 * 1024, "max message size too large");
        assert!(MAX_TOPIC_LENGTH >= 32, "max topic length too small");
        assert!(DEFAULT_PUBLISH_RATE_LIMIT > 0);
        assert!(DEFAULT_PER_PEER_RATE_LIMIT > 0);
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

        // Add peers as eager
        assert!(state.add_eager(peer1));
        assert!(state.add_eager(peer2));
        assert_eq!(state.eager_peers.len(), 2);
        assert_eq!(state.lazy_peers.len(), 0);

        // Demote peer1 to lazy (simulating duplicate receipt)
        state.demote_to_lazy(peer1);
        assert_eq!(state.eager_peers.len(), 1);
        assert_eq!(state.lazy_peers.len(), 1);
        assert!(!state.eager_peers.contains(&peer1));
        assert!(state.lazy_peers.contains(&peer1));

        // Promote peer1 back to eager (simulating IHave receipt)
        state.promote_to_eager(peer1);
        assert_eq!(state.eager_peers.len(), 2);
        assert_eq!(state.lazy_peers.len(), 0);
        assert!(state.eager_peers.contains(&peer1));

        // New peer added directly as eager
        state.promote_to_eager(peer3);
        assert_eq!(state.eager_peers.len(), 3);

        // Remove peer
        state.remove_peer(&peer2);
        assert_eq!(state.total_peers(), 2);
        assert!(!state.contains(&peer2));
    }

    #[test]
    fn topic_state_iwant_tracking() {
        let mut state = TopicState::default();
        let peer1 = Identity::from_bytes([1u8; 32]);
        let msg_id = [0xABu8; 32];

        // Record pending IWant
        state.record_iwant(msg_id, peer1);
        assert_eq!(state.pending_iwants.len(), 1);
        assert!(state.pending_iwants.contains_key(&msg_id));

        // Message received - clear pending
        state.message_received(&msg_id);
        assert!(state.pending_iwants.is_empty());
    }

    #[test]
    fn topic_state_respects_peer_limit() {
        let mut state = TopicState::default();

        // Add peers up to the limit (use unique identities)
        for i in 0..MAX_PEERS_PER_TOPIC {
            // Create unique 32-byte identity by encoding i into first 4 bytes
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let peer = Identity::from_bytes(bytes);
            assert!(state.add_eager(peer), "should add peer {}", i);
        }

        assert_eq!(state.total_peers(), MAX_PEERS_PER_TOPIC);

        // Adding one more should fail (use a unique identity that wasn't added)
        let mut overflow_bytes = [0xFFu8; 32];
        overflow_bytes[0..4].copy_from_slice(&(MAX_PEERS_PER_TOPIC as u32).to_le_bytes());
        let overflow_peer = Identity::from_bytes(overflow_bytes);
        assert!(!state.add_eager(overflow_peer), "should not exceed limit");
        assert_eq!(state.total_peers(), MAX_PEERS_PER_TOPIC);
    }
}
