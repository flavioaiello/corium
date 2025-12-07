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

pub const MAX_SEQNO_TRACKING_SOURCES: usize = 10_000;
pub const SEQNO_WINDOW_SIZE: usize = 128;

pub const MAX_MESSAGE_CACHE_BYTES: usize = 64 * 1024 * 1024;

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


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SignatureError {
    Missing,
    InvalidLength,
    VerificationFailed,
    InvalidPublicKey,
    ReplayDetected,
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
#[allow(dead_code)]
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
        let was_lazy = self.lazy_peers.remove(&peer);
        let is_eager = self.eager_peers.contains(&peer);
        
        if was_lazy || (!is_eager && self.total_peers() < MAX_PEERS_PER_TOPIC) {
            self.eager_peers.insert(peer);
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

    pub fn record_iwant(&mut self, msg_id: MessageId, peer: Identity) {
        if self.pending_iwants.len() >= MAX_PENDING_IWANTS {
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

    pub fn check_iwant_timeouts(&mut self, ihave_timeout: Duration) -> Vec<(MessageId, Identity)> {
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
                    *requested_at = now;                    retries.push((*msg_id, next_peer));
                } else {
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
            return true;        }
        
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
            return true;        }
        
        self.publish_times.push_back(now);
        false
    }
    
    pub fn is_stale(&self, now: Instant) -> bool {
        now.duration_since(self.last_active) > RATE_LIMIT_ENTRY_MAX_AGE
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRejection {
    MessageTooLarge,
    TopicTooLong,
    RateLimited,
    Duplicate,
    InvalidMessageId,
}


#[async_trait::async_trait]
pub trait PlumTreeHandler: Send + Sync {
    async fn handle_message(&self, from: &Identity, message: PlumTreeMessage) -> anyhow::Result<()>;
}


pub struct PlumTree<N: PlumTreeRpc> {
    network: Arc<N>,
    keypair: Keypair,
    local_identity: Identity,
    config: PlumTreeConfig,
    subscriptions: Arc<RwLock<HashSet<String>>>,
    topics: Arc<RwLock<HashMap<String, TopicState>>>,
    message_cache: Arc<RwLock<LruCache<MessageId, CachedMessage>>>,
    message_cache_bytes: Arc<RwLock<usize>>,
    seqno: Arc<RwLock<u64>>,
    seqno_tracker: Arc<RwLock<HashMap<Identity, SeqnoTracker>>>,
    message_tx: mpsc::Sender<ReceivedMessage>,
    message_rx: Option<mpsc::Receiver<ReceivedMessage>>,
    outbound: Arc<RwLock<HashMap<Identity, Vec<PlumTreeMessage>>>>,
    rate_limits: Arc<RwLock<HashMap<Identity, PeerRateLimit>>>,
    known_peers: Arc<RwLock<HashSet<Identity>>>,
}

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
            message_cache_bytes: Arc::new(RwLock::new(0)),
            seqno: Arc::new(RwLock::new(0)),
            seqno_tracker: Arc::new(RwLock::new(HashMap::new())),
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

    async fn cache_message(&self, msg_id: MessageId, message: CachedMessage) {
        let message_size = message.size_bytes();
        
        let mut cache = self.message_cache.write().await;
        let mut cache_bytes = self.message_cache_bytes.write().await;
        
        if let Some(existing) = cache.peek(&msg_id) {
            *cache_bytes = cache_bytes.saturating_sub(existing.size_bytes());
        }
        
        while *cache_bytes + message_size > MAX_MESSAGE_CACHE_BYTES && !cache.is_empty() {
            if let Some((_, evicted)) = cache.pop_lru() {
                *cache_bytes = cache_bytes.saturating_sub(evicted.size_bytes());
                trace!(
                    evicted_bytes = evicted.size_bytes(),
                    cache_bytes = *cache_bytes,
                    "evicted message from cache due to memory pressure"
                );
            } else {
                break;
            }
        }
        
        cache.put(msg_id, message);
        *cache_bytes = cache_bytes.saturating_add(message_size);
    }


    pub async fn handle_neighbor_up(&self, peer: Identity) {
        if peer == self.local_identity {
            return;
        }
        
        {
            let mut known = self.known_peers.write().await;
            known.insert(peer);
        }
        
        let subs = self.subscriptions.read().await;
        if subs.is_empty() {
            return;
        }
        
        let mut topics = self.topics.write().await;
        for topic in subs.iter() {
            if let Some(state) = topics.get_mut(topic) {
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
        
        {
            let mut known = self.known_peers.write().await;
            known.remove(peer);
        }
        
        {
            let mut outbound = self.outbound.write().await;
            outbound.remove(peer);
        }
        
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

    pub async fn subscribe(&self, topic: &str) -> anyhow::Result<()> {
        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!("topic length {} exceeds maximum {}", topic.len(), MAX_TOPIC_LENGTH);
        }
        if topic.is_empty() {
            anyhow::bail!("topic name cannot be empty");
        }
        if !is_valid_topic(topic) {
            anyhow::bail!("topic name contains invalid characters");
        }

        {
            let mut subs = self.subscriptions.write().await;
            if subs.contains(topic) {
                return Ok(());            }
            if subs.len() >= MAX_SUBSCRIPTIONS_PER_PEER {
                anyhow::bail!("subscription limit reached (max {})", MAX_SUBSCRIPTIONS_PER_PEER);
            }
            subs.insert(topic.to_string());
        }

        {
            let known = self.known_peers.read().await;
            let mut topics = self.topics.write().await;
            
            if !topics.contains_key(topic) && topics.len() >= MAX_TOPICS {
                let empty = topics.iter()
                    .find(|(_, s)| s.eager_peers.is_empty() && s.lazy_peers.is_empty())
                    .map(|(t, _)| t.clone());
                if let Some(t) = empty {
                    topics.remove(&t);
                    debug!(evicted_topic = %t, new_topic = %topic, "evicted empty topic to make room");
                } else {
                    let mut subs = self.subscriptions.write().await;
                    subs.remove(topic);
                    anyhow::bail!("topic limit reached (max {})", MAX_TOPICS);
                }
            }

            let state = topics.entry(topic.to_string()).or_default();
            
            for peer in known.iter() {
                if *peer != self.local_identity {
                    state.add_eager(*peer);
                }
            }
        }

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
                return Ok(());            }
        }

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


    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> anyhow::Result<MessageId> {
        if data.len() > self.config.max_message_size {
            anyhow::bail!("message size {} exceeds maximum {}", data.len(), self.config.max_message_size);
        }
        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!("topic length {} exceeds maximum {}", topic.len(), MAX_TOPIC_LENGTH);
        }

        {
            let mut rate_limits = self.rate_limits.write().await;
            let limiter = rate_limits.entry(self.local_identity).or_default();
            if limiter.check_and_record(self.config.publish_rate_limit) {
                anyhow::bail!("local publish rate limit exceeded");
            }
        }

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

        self.cache_message(msg_id, CachedMessage {
            topic: topic.to_string(),
            source: self.local_identity,
            seqno,
            data: data.clone(),
            signature: signature.clone(),
        }).await;

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


    pub async fn handle_message(&self, from: &Identity, msg: PlumTreeMessage) -> anyhow::Result<()> {
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

    async fn handle_subscribe(&self, from: &Identity, topic: &str) {
        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        if !is_subscribed {
            return;        }

        let mut topics = self.topics.write().await;
        if let Some(state) = topics.get_mut(topic) {
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
            let mut tracker = self.seqno_tracker.write().await;
            
            if tracker.len() >= MAX_SEQNO_TRACKING_SOURCES && !tracker.contains_key(&source) {
                let oldest = tracker.iter()
                    .min_by_key(|(_, t)| t.highest_seen)
                    .map(|(id, _)| *id);
                if let Some(id) = oldest {
                    tracker.remove(&id);
                }
            }
            
            let source_tracker = tracker.entry(source).or_default();
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

        let is_duplicate = {
            let cache = self.message_cache.read().await;
            cache.contains(&msg_id)
        };

        if is_duplicate {
            {
                let mut topics = self.topics.write().await;
                if let Some(state) = topics.get_mut(topic) {
                    state.demote_to_lazy(*from);
                }
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
        }).await;

        {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                state.message_received(&msg_id);
                
                state.recent_messages.push_back(msg_id);
                if state.recent_messages.len() > self.config.max_ihave_length {
                    state.recent_messages.pop_front();
                }
            }
        }

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

        {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                state.promote_to_eager(*from);
                
                for msg_id in &missing {
                    state.record_iwant(*msg_id, *from);
                }
            }
        }

        self.queue_message(from, PlumTreeMessage::Graft {
            topic: topic.to_string(),
        }).await;

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
        self.flush_pending_queues().await;
    }

    async fn flush_pending_queues(&self) {
        let peers_with_pending: Vec<Identity> = {
            let outbound = self.outbound.read().await;
            outbound.keys().copied().collect()
        };

        for peer in peers_with_pending {
            if let Some(contact) = self.network.resolve_identity_to_contact(&peer).await {
                let messages = self.take_pending_messages(&peer).await;
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

    async fn lazy_push(&self, topic: &str) {
        let (should_push, msg_ids, lazy_peers) = {
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
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
                state.check_iwant_timeouts(self.config.ihave_timeout)
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


    async fn queue_message(&self, peer: &Identity, msg: PlumTreeMessage) {
        if let Some(contact) = self.network.resolve_identity_to_contact(peer).await {
            if let Err(e) = self.network.send_plumtree(&contact, self.local_identity, msg.clone()).await {
                trace!(
                    peer = %hex::encode(&peer.as_bytes()[..8]),
                    error = %e,
                    "failed to send PlumTree message, queueing for later"
                );
            } else {
                return;            }
        }
        
        let mut outbound = self.outbound.write().await;
        
        if !outbound.contains_key(peer) && outbound.len() >= MAX_OUTBOUND_PEERS {
            let smallest = outbound.iter()
                .min_by_key(|(_, msgs)| msgs.len())
                .map(|(id, _)| *id);
            if let Some(evict) = smallest {
                outbound.remove(&evict);
            }
        }
        
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

    #[allow(dead_code)]
    pub async fn peers_with_pending(&self) -> Vec<Identity> {
        let outbound = self.outbound.read().await;
        outbound.keys().copied().collect()
    }

    pub async fn subscriptions(&self) -> Vec<String> {
        self.subscriptions.read().await.iter().cloned().collect()
    }

    #[allow(dead_code)]
    pub async fn eager_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| s.eager_peers.iter().copied().collect())
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub async fn lazy_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| s.lazy_peers.iter().copied().collect())
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub async fn topic_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| s.eager_peers.iter().chain(s.lazy_peers.iter()).copied().collect())
            .unwrap_or_default()
    }

    #[allow(dead_code)]
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
        
        let retries = state.check_iwant_timeouts(DEFAULT_IHAVE_TIMEOUT);
        assert!(retries.is_empty());
    }

    #[test]
    fn message_rejection_variants() {
        let variants = [
            MessageRejection::MessageTooLarge,
            MessageRejection::TopicTooLong,
            MessageRejection::RateLimited,
            MessageRejection::Duplicate,
            MessageRejection::InvalidMessageId,
        ];
        
        for v in &variants {
            let cloned = *v;
            let _debug = format!("{:?}", cloned);
            assert_eq!(*v, cloned);
        }
    }
}
