//! GossipSub implementation.
//!
//! This module contains the main GossipSub router that manages topic subscriptions,
//! message routing, and mesh maintenance.
//!
//! # Security Model
//!
//! ## Message Authentication Flow
//!
//! ```text
//! Publisher                    Forwarder                    Subscriber
//!     |                            |                            |
//!     |-- sign(topic||seqno||data) |                            |
//!     |-- Publish{sig, ...} ------>|                            |
//!     |                            |-- verify(sig, source) ---->|
//!     |                            |-- Publish{sig, ...} ------>|
//!     |                            |                            |-- verify(sig, source)
//! ```
//!
//! Every node verifies the Ed25519 signature before accepting or forwarding.
//!
//! ## Rate Limiting Layers
//!
//! ```text
//! Incoming Message
//!       |
//!       v
//! [1] Per-Peer Rate Check (50 msg/s) --> DROP if exceeded
//!       |
//!       v
//! [2] Signature Verification --> DROP if invalid
//!       |
//!       v
//! [3] Deduplication Check --> DROP if seen
//!       |
//!       v
//! [4] Message Size Check --> DROP if > 64KB
//!       |
//!       v
//! ACCEPT and Forward
//! ```
//!
//! ## IWant Amplification Prevention
//!
//! ```text
//! Attacker                     Victim
//!     |                            |
//!     |-- IWant{1000 msg_ids} ---->| [1] Reject: > MAX_IWANT_MESSAGES * 2
//!     |                            |
//!     |-- IWant{10 msg_ids} x100 ->| [2] Rate limit: > IWANT_RATE_LIMIT/s
//!     |                            |
//!     |-- IWant{10 large msgs} --->| [3] Byte limit: stop at MAX_IWANT_RESPONSE_BYTES
//! ```
//!
//! ## Bounded State Growth
//!
//! | Operation | Bound Enforced |
//! |-----------|----------------|
//! | Topic creation | `MAX_TOPICS` check, evict empty topics |
//! | Peer insertion | `try_insert_peer()` capacity check |
//! | Subscribe | `MAX_SUBSCRIPTIONS_PER_PEER` check |
//! | Queue message | `MAX_OUTBOUND_PER_PEER`, drop oldest half |
//! | Global queue | `MAX_TOTAL_OUTBOUND_MESSAGES`, evict largest |
//! | Rate limit entry | `MAX_RATE_LIMIT_ENTRIES`, stale cleanup |

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use lru::LruCache;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, trace, warn};

use crate::dht::{hash_content, DhtNetwork, DhtNode};
use crate::identity::{Identity, Keypair};

use super::config::*;
use super::message::{MessageId, PubSubMessage};
use super::signature::{sign_pubsub_message, verify_pubsub_signature};
use super::subscription::{SubscriberEntry, TopicSubscribers, TopicSubscription};
use super::types::{CachedMessage, PeerRateLimit, ReceivedMessage, TopicState};

/// Fanout cache: topic -> (peers, creation time)
type FanoutCache = HashMap<String, (HashSet<Identity>, Instant)>;

// ============================================================================
// PubSub Handler Trait
// ============================================================================

/// Trait for handling incoming PubSub messages.
///
/// Implement this trait to receive and process GossipSub messages.
/// The [`GossipSub`] struct implements this trait.
#[async_trait::async_trait]
pub trait PubSubHandler: Send + Sync {
    /// Handle an incoming pubsub message from a peer.
    ///
    /// # Arguments
    /// * `from` - The TLS-verified identity of the peer who sent this message
    /// * `message` - The pubsub protocol message
    ///
    /// # Returns
    /// * `Ok(())` if the message was processed (may have been dropped due to dedup, etc.)
    /// * `Err(_)` if there was an error processing the message
    async fn handle_message(&self, from: &Identity, message: PubSubMessage) -> anyhow::Result<()>;
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

        // Deliver locally if subscribed (self-delivery)
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
