use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use lru::LruCache;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, trace, warn};

use crate::dht::{hash_content, Dht, DhtNetwork};
use crate::identity::{Identity, Keypair};

use super::config::*;
use super::message::{MessageId, PubSubMessage};
use super::network::GossipSubNetwork;
use super::signature::{sign_pubsub_message, verify_pubsub_signature};
use super::subscription::{SubscriberEntry, TopicSubscribers, TopicSubscription};
use super::types::{CachedMessage, PeerRateLimit, ReceivedMessage, TopicState};

type FanoutCache = HashMap<String, (HashSet<Identity>, Instant)>;

#[async_trait::async_trait]
pub trait PubSubHandler: Send + Sync {
    async fn handle_message(&self, from: &Identity, message: PubSubMessage) -> anyhow::Result<()>;
}

pub struct GossipSub<N: DhtNetwork + GossipSubNetwork> {
    dht: Dht<N>,
    keypair: Keypair,
    local_identity: Identity,
    config: GossipConfig,
    subscriptions: Arc<RwLock<HashSet<String>>>,
    topics: Arc<RwLock<HashMap<String, TopicState>>>,
    fanout: Arc<RwLock<FanoutCache>>,
    message_cache: Arc<RwLock<LruCache<MessageId, CachedMessage>>>,
    seqno: Arc<RwLock<u64>>,
    message_tx: mpsc::Sender<ReceivedMessage>,
    message_rx: Option<mpsc::Receiver<ReceivedMessage>>,
    outbound: Arc<RwLock<HashMap<Identity, Vec<PubSubMessage>>>>,
    rate_limits: Arc<RwLock<HashMap<Identity, PeerRateLimit>>>,
}

impl<N: DhtNetwork + GossipSubNetwork> GossipSub<N> {
    pub fn new(dht: Dht<N>, keypair: Keypair, config: GossipConfig) -> Self {
        let cache_size = NonZeroUsize::new(config.message_cache_size)
            .unwrap_or(NonZeroUsize::new(1).expect("1 is non-zero"));
        let (tx, rx) = mpsc::channel(1000);
        let local_identity = keypair.identity();
        
        Self {
            dht,
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

    pub fn take_message_receiver(&mut self) -> Option<mpsc::Receiver<ReceivedMessage>> {
        self.message_rx.take()
    }

    pub async fn subscribe(&self, topic: &str) -> anyhow::Result<()> {
        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!(
                "topic length {} exceeds maximum {}",
                topic.len(),
                MAX_TOPIC_LENGTH
            );
        }
        
        if topic.is_empty() {
            anyhow::bail!("topic name cannot be empty");
        }
        if !topic.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            anyhow::bail!("topic name contains invalid characters (only printable ASCII allowed)");
        }

        {
            let mut subs = self.subscriptions.write().await;
            if subs.contains(topic) {
                return Ok(()); // Already subscribed
            }
            if subs.len() >= MAX_SUBSCRIPTIONS_PER_PEER {
                anyhow::bail!(
                    "subscription limit reached (max {})",
                    MAX_SUBSCRIPTIONS_PER_PEER
                );
            }
            subs.insert(topic.to_string());
        }

        {
            let mut topics = self.topics.write().await;
            if !topics.contains_key(topic) && topics.len() >= MAX_TOPICS {
                let empty_topic = topics
                    .iter()
                    .find(|(_, state)| state.mesh.is_empty())
                    .map(|(t, _)| t.clone());
                if let Some(t) = empty_topic {
                    topics.remove(&t);
                } else {
                    let mut subs = self.subscriptions.write().await;
                    subs.remove(topic);
                    anyhow::bail!("topic limit reached (max {})", MAX_TOPICS);
                }
            }
            topics.entry(topic.to_string()).or_default();
        }

        self.announce_subscription(topic).await;

        let fanout_peers: Vec<Identity> = {
            let mut fanout = self.fanout.write().await;
            if let Some((peers, _)) = fanout.remove(topic) {
                peers.into_iter().collect()
            } else {
                Vec::new()
            }
        };

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

    pub async fn unsubscribe(&self, topic: &str) -> anyhow::Result<()> {
        {
            let mut subs = self.subscriptions.write().await;
            if !subs.remove(topic) {
                return Ok(()); // Wasn't subscribed
            }
        }

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

        self.remove_peer_from_dht(topic, &self.local_identity).await;

        debug!(topic = %topic, "unsubscribed from topic");
        Ok(())
    }

    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> anyhow::Result<MessageId> {
        if data.len() > self.config.max_message_size {
            anyhow::bail!(
                "message size {} exceeds maximum {}",
                data.len(),
                self.config.max_message_size
            );
        }

        if topic.len() > MAX_TOPIC_LENGTH {
            anyhow::bail!(
                "topic length {} exceeds maximum {}",
                topic.len(),
                MAX_TOPIC_LENGTH
            );
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
        
        let signature = sign_pubsub_message(&self.keypair, topic, seqno, &data);
        
        let mut id_input = Vec::new();
        id_input.extend_from_slice(self.local_identity.as_bytes());
        id_input.extend_from_slice(&seqno.to_le_bytes());
        id_input.extend_from_slice(&data);
        let msg_id = hash_content(&id_input);

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

        let is_subscribed = {
            let subs = self.subscriptions.read().await;
            subs.contains(topic)
        };

        let peers: Vec<Identity> = if is_subscribed {
            let topics = self.topics.read().await;
            topics.get(topic)
                .map(|s| s.mesh.iter().copied().collect())
                .unwrap_or_default()
        } else {
            self.get_or_create_fanout(topic).await
        };

        for peer in peers {
            self.queue_message(&peer, publish_msg.clone()).await;
        }

        if is_subscribed {
            let received = ReceivedMessage {
                topic: topic.to_string(),
                source: self.local_identity,
                seqno,
                data: match &publish_msg {
                    PubSubMessage::Publish { data, .. } => data.clone(),
                    _ => unreachable!(),
                },
                msg_id,
                received_at: std::time::Instant::now(),
            };
            
            if self.message_tx.send(received).await.is_err() {
                warn!("message channel closed during local delivery");
            }
        }

        debug!(
            topic = %topic,
            msg_id = %hex::encode(&msg_id[..8]),
            "published message"
        );

        Ok(msg_id)
    }

    pub async fn handle_message(&self, from: &Identity, msg: PubSubMessage) -> anyhow::Result<()> {
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

    pub async fn subscriptions(&self) -> Vec<String> {
        self.subscriptions.read().await.iter().cloned().collect()
    }

    pub async fn mesh_peers(&self, topic: &str) -> Vec<Identity> {
        let topics = self.topics.read().await;
        topics.get(topic)
            .map(|s| s.mesh.iter().copied().collect())
            .unwrap_or_default()
    }

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

    async fn handle_subscribe(&self, from: &Identity, topic: &str) {
        let mut topics = self.topics.write().await;
        
        if !topics.contains_key(topic) && topics.len() >= MAX_TOPICS {
            trace!(
                peer = %hex::encode(&from.as_bytes()[..8]),
                topic = %topic,
                "rejecting subscribe: topic limit reached"
            );
            return;
        }
        
        let state = topics.entry(topic.to_string()).or_default();
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
            self.queue_message(from, PubSubMessage::Prune {
                topic: topic.to_string(),
                peers: Vec::new(),
            }).await;
            return;
        }

        let mut topics = self.topics.write().await;
        
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
        
        if state.mesh.len() < self.config.mesh_degree_high {
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
            state.try_insert_peer(*from);
            
            for peer in suggested_peers {
                if peer != self.local_identity {
                    if !state.try_insert_peer(peer) {
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
        if data.len() > self.config.max_message_size {
            debug!(
                from = %hex::encode(&from.as_bytes()[..8]),
                size = data.len(),
                max = self.config.max_message_size,
                "rejecting oversized message"
            );
            return Ok(()); // Silently drop
        }

        
        let is_first_hop = source == *from;
        
        if !is_first_hop {
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
            if let Err(e) = verify_pubsub_signature(&source, topic, seqno, &data, &signature) {
                debug!(
                    from = %hex::encode(&from.as_bytes()[..8]),
                    error = ?e,
                    "rejecting first-hop message with invalid signature"
                );
                return Ok(()); // Drop - even first hop must have valid signature
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
                debug!(
                    from = %hex::encode(&from.as_bytes()[..8]),
                    "peer rate limited, dropping message"
                );
                return Ok(()); // Drop messages from rate-limited peers
            }
        }

        {
            let cache = self.message_cache.read().await;
            if cache.contains(&msg_id) {
                trace!(msg_id = %hex::encode(&msg_id[..8]), "duplicate message, ignoring");
                return Ok(());
            }
        }

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

    async fn handle_ihave(&self, from: &Identity, _topic: &str, msg_ids: Vec<MessageId>) {
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

    async fn handle_iwant(&self, from: &Identity, msg_ids: Vec<MessageId>) {
        if msg_ids.len() > DEFAULT_MAX_IWANT_MESSAGES * 2 {
            warn!(
                peer = ?hex::encode(&from.as_bytes()[..8]),
                count = msg_ids.len(),
                limit = DEFAULT_MAX_IWANT_MESSAGES,
                "IWant request rejected: too many message IDs"
            );
            return;
        }
        
        {
            let mut rate_limits = self.rate_limits.write().await;
            
            if rate_limits.len() >= MAX_RATE_LIMIT_ENTRIES {
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
        
        let msg_ids_to_process: Vec<_> = msg_ids
            .into_iter()
            .take(DEFAULT_MAX_IWANT_MESSAGES)
            .collect();
        
        let cache = self.message_cache.read().await;
        
        let mut bytes_sent: usize = 0;
        let mut messages_sent: usize = 0;
        
        for msg_id in msg_ids_to_process {
            if let Some(cached) = cache.peek(&msg_id) {
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
            self.maintain_mesh(&topic).await;
            self.emit_gossip(&topic).await;
        }

        self.cleanup_fanout().await;
        
        self.cleanup_stale_state().await;
    }

    async fn maintain_mesh(&self, topic: &str) {
        let (mesh_size, available_peers) = {
            let topics = self.topics.read().await;
            if let Some(state) = topics.get(topic) {
                (state.mesh.len(), state.peers.iter().copied().collect::<Vec<_>>())
            } else {
                return;
            }
        };

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

        if mesh_size > self.config.mesh_degree_high {
            let excess = mesh_size - self.config.mesh_degree;
            let mut topics = self.topics.write().await;
            if let Some(state) = topics.get_mut(topic) {
                let to_prune: Vec<Identity> = state.mesh.iter().copied().take(excess).collect();
                for peer in to_prune {
                    state.mesh.remove(&peer);
                    state.try_insert_peer(peer);
                    self.queue_message(&peer, PubSubMessage::Prune {
                        topic: topic.to_string(),
                        peers: Vec::new(),
                    }).await;
                }
            }
        }
    }

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

        let gossip_target = (gossip_peers.len() / 2).clamp(1, DEFAULT_MAX_IHAVE_MESSAGES);
        for peer in gossip_peers.into_iter().take(gossip_target) {
            self.queue_message(&peer, PubSubMessage::IHave {
                topic: topic.to_string(),
                msg_ids: msg_ids.clone(),
            }).await;
        }
    }

    async fn cleanup_fanout(&self) {
        let now = Instant::now();
        let mut fanout = self.fanout.write().await;
        fanout.retain(|_, (_, created)| now.duration_since(*created) < self.config.fanout_ttl);
    }
    
    pub async fn cleanup_stale_state(&self) {
        let now = Instant::now();
        
        {
            let mut rate_limits = self.rate_limits.write().await;
            rate_limits.retain(|_, limiter| !limiter.is_stale(now));
            
            if rate_limits.len() > MAX_RATE_LIMIT_ENTRIES {
                rate_limits.retain(|_, limiter| !limiter.publish_times.is_empty());
            }
        }
        
        {
            let mut outbound = self.outbound.write().await;
            outbound.retain(|_, msgs| !msgs.is_empty());
        }
    }

    async fn queue_message(&self, peer: &Identity, msg: PubSubMessage) {
        let mut outbound = self.outbound.write().await;
        
        if !outbound.contains_key(peer) && outbound.len() >= MAX_OUTBOUND_PEERS {
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
        
        let total_messages: usize = outbound.values().map(|v| v.len()).sum();
        if total_messages >= MAX_TOTAL_OUTBOUND_MESSAGES {
            let mut dropped = 0;
            while outbound.values().map(|v| v.len()).sum::<usize>() >= MAX_TOTAL_OUTBOUND_MESSAGES {
                let largest_peer = outbound
                    .iter()
                    .max_by_key(|(_, msgs)| msgs.len())
                    .map(|(id, _)| *id);
                if let Some(large_peer) = largest_peer {
                    if let Some(queue) = outbound.get_mut(&large_peer) {
                        if queue.is_empty() {
                            break;
                        }
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
        
        if queue.len() >= MAX_OUTBOUND_PER_PEER {
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

    pub async fn take_pending_messages(&self, peer: &Identity) -> Vec<PubSubMessage> {
        let mut outbound = self.outbound.write().await;
        outbound.remove(peer).unwrap_or_default()
    }

    pub async fn peers_with_pending(&self) -> Vec<Identity> {
        let outbound = self.outbound.read().await;
        outbound.keys().copied().collect()
    }

    async fn get_or_create_fanout(&self, topic: &str) -> Vec<Identity> {
        {
            let fanout = self.fanout.read().await;
            if let Some((peers, _)) = fanout.get(topic) {
                if !peers.is_empty() {
                    return peers.iter().copied().collect();
                }
            }
        }

        let peers = self.discover_topic_peers_internal(topic).await;
        
        if !peers.is_empty() {
            let mut fanout = self.fanout.write().await;
            fanout.insert(topic.to_string(), (peers.iter().copied().collect(), Instant::now()));
        }

        peers
    }

    async fn announce_subscription(&self, topic: &str) {
        let topic_key = hash_content(format!("pubsub/topic:{}", topic).as_bytes());
        
        let our_entry = SubscriberEntry::new(self.local_identity);
        
        for attempt in 0..3 {
            let mut subscribers = match self.dht.get(&topic_key).await {
                Ok(Some(data)) => {
                    bincode::deserialize::<TopicSubscribers>(&data).unwrap_or_default()
                }
                _ => TopicSubscribers::new(),
            };
            
            let mut our_subscribers = TopicSubscribers::new();
            our_subscribers.subscribers.push(our_entry.clone());
            subscribers.merge(our_subscribers);
            
            match bincode::serialize(&subscribers) {
                Ok(data) => {
                    if let Err(e) = self.dht.put_at(topic_key, data).await {
                        debug!(
                            topic = %topic, 
                            error = %e, 
                            attempt = attempt,
                            "failed to announce subscription to DHT, will retry"
                        );
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

    async fn discover_topic_peers_internal(&self, topic: &str) -> Vec<Identity> {
        let topic_key = hash_content(format!("pubsub/topic:{}", topic).as_bytes());
        
        match self.dht.get(&topic_key).await {
            Ok(Some(data)) => {
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

    pub async fn refresh_subscriptions(&self) {
        let topics: Vec<String> = {
            let subs = self.subscriptions.read().await;
            subs.iter().cloned().collect()
        };
        
        for topic in topics {
            self.announce_subscription(&topic).await;
        }
    }

    pub async fn add_peer(&self, topic: &str, peer: Identity) -> bool {
        let mut topics = self.topics.write().await;
        let state = topics.entry(topic.to_string()).or_default();
        if state.mesh.contains(&peer) {
            return true; // Already in mesh
        }
        state.try_insert_peer(peer)
    }

    pub async fn remove_peer(&self, peer: &Identity) {
        let topics_with_peer: Vec<String> = {
            let topics = self.topics.read().await;
            topics.iter()
                .filter(|(_, state)| state.mesh.contains(peer) || state.peers.contains(peer))
                .map(|(topic, _)| topic.clone())
                .collect()
        };

        {
            let mut topics = self.topics.write().await;
            for state in topics.values_mut() {
                state.mesh.remove(peer);
                state.peers.remove(peer);
            }
        }

        for topic in topics_with_peer {
            self.remove_peer_from_dht(&topic, peer).await;
        }
    }

    async fn remove_peer_from_dht(&self, topic: &str, peer: &Identity) {
        let topic_key = hash_content(format!("pubsub/topic:{}", topic).as_bytes());
        
        let mut subscribers = match self.dht.get(&topic_key).await {
            Ok(Some(data)) => {
                bincode::deserialize::<TopicSubscribers>(&data).unwrap_or_default()
            }
            _ => return, // No list to update
        };
        
        let original_len = subscribers.subscribers.len();
        subscribers.remove_subscriber(peer);
        
        if subscribers.subscribers.len() < original_len {
            if let Ok(data) = bincode::serialize(&subscribers) {
                if let Err(e) = self.dht.put_at(topic_key, data).await {
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

#[async_trait::async_trait]
impl<N: DhtNetwork + GossipSubNetwork + Send + Sync + 'static> PubSubHandler for GossipSub<N> {
    async fn handle_message(&self, from: &Identity, message: PubSubMessage) -> anyhow::Result<()> {
        GossipSub::handle_message(self, from, message).await
    }
}

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
}
