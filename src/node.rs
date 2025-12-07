//! Unified node facade for mesh networking.
//!
//! This module provides [`Node`], the primary public API for Corium.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::Endpoint;
use tracing::{info, warn};

use crate::dht::{Contact, DhtNode, Key, TelemetrySnapshot};
use crate::identity::{EndpointRecord, Identity, Keypair};
use crate::net::{PeerNetwork, smartsock::SmartSock};
use crate::pubsub::{GossipConfig, GossipSub, ReceivedMessage};
use crate::net::UdpRelayForwarder;
use crate::server::Server;

// Re-export PubSubHandler for users who want to implement custom handlers
pub use crate::pubsub::PubSubHandler;

/// Default Kademlia bucket size / replication factor.
const DEFAULT_K: usize = 20;
/// Default lookup parallelism.
const DEFAULT_ALPHA: usize = 3;

/// Unified node for mesh networking.
///
/// `Node` is the primary public API for Corium. It provides a simple, high-level
/// interface for mesh networking with automatic NAT traversal, distributed hash
/// table (DHT) operations, and optional pub/sub messaging.
///
/// # Quick Start
///
/// ```ignore
/// use corium::{Node, Keypair};
///
/// // Generate or load identity
/// let keypair = Keypair::generate();
///
/// // Start the node
/// let node = Node::bind("0.0.0.0:0", keypair).await?;
///
/// // Store and retrieve data
/// let key = node.put(b"hello world".to_vec()).await?;
/// let value = node.get(&key).await?;
///
/// // Connect to peers
/// let record = node.resolve_peer(&peer_identity).await?;
/// let conn = node.connect(&record).await?;
/// ```
///
/// # With PubSub
///
/// ```ignore
/// // Enable pub/sub messaging
/// let node = Node::bind_with_pubsub("0.0.0.0:0", keypair).await?;
///
/// // Subscribe and publish
/// node.subscribe("my-topic").await?;
/// let mut rx = node.take_message_receiver().await?;
/// node.publish("my-topic", b"hello!".to_vec()).await?;
/// ```
///
/// # Architecture
///
/// Internally, `Node` wires together:
/// - **PeerNetwork**: QUIC transport with connection caching
/// - **DhtNode**: Kademlia DHT for peer discovery and storage
/// - **Server**: RPC handler for incoming connections
/// - **GossipSub** (optional): Pub/sub messaging layer
///
/// All these components are hidden from the consumer. You interact with the
/// mesh network through the methods on `Node`.
pub struct Node {
    /// The node's Ed25519 keypair for signing operations.
    keypair: Keypair,
    /// The QUIC endpoint for connections.
    endpoint: Endpoint,
    /// SmartSock for seamless path switching (relay↔direct).
    smartsock: Arc<SmartSock>,
    /// Our contact information.
    contact: Contact,
    /// The underlying DHT node.
    dht: DhtNode<PeerNetwork>,
    /// The network transport layer.
    network: PeerNetwork,
    /// Optional GossipSub pubsub handler.
    pubsub: Option<Arc<GossipSub<PeerNetwork>>>,
    /// Message receiver for pubsub (taken from GossipSub at construction).
    pubsub_receiver: Option<tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ReceivedMessage>>>>,
    /// Handle to the server task.
    _server_handle: tokio::task::JoinHandle<Result<()>>,
}

impl Node {
    /// Bind to a socket address and start the node.
    ///
    /// Uses default configuration (k=20, alpha=3, no pubsub).
    /// For pub/sub support, use [`Node::bind_with_pubsub`].
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind to (e.g., "0.0.0.0:0" for random port)
    /// * `keypair` - Ed25519 keypair for node identity and signing
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keypair = Keypair::generate();
    /// let node = Node::bind("0.0.0.0:0", keypair).await?;
    /// ```
    pub async fn bind(addr: &str, keypair: Keypair) -> Result<Self> {
        Self::create(addr, keypair, false).await
    }

    /// Bind to a socket address and start the node with pub/sub enabled.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind to (e.g., "0.0.0.0:0" for random port)
    /// * `keypair` - Ed25519 keypair for node identity and signing
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keypair = Keypair::generate();
    /// let node = Node::bind_with_pubsub("0.0.0.0:0", keypair).await?;
    /// node.subscribe("my-topic").await?;
    /// ```
    pub async fn bind_with_pubsub(addr: &str, keypair: Keypair) -> Result<Self> {
        Self::create(addr, keypair, true).await
    }

    /// Internal constructor.
    async fn create(addr: &str, keypair: Keypair, enable_pubsub: bool) -> Result<Self> {
        let addr: SocketAddr = addr.parse()
            .context("invalid socket address")?;
        
        let identity = keypair.identity();
        
        // Generate TLS certificates
        let (server_certs, server_key) = crate::net::generate_ed25519_cert(&keypair)?;
        let (client_certs, client_key) = crate::net::generate_ed25519_cert(&keypair)?;
        
        let server_config = crate::net::create_server_config(server_certs, server_key)?;
        let client_config = crate::net::create_client_config(client_certs, client_key)?;
        
        // Create QUIC endpoint with SmartSock for seamless path switching
        let (endpoint, smartsock) = SmartSock::bind_endpoint(addr, server_config)
            .await
            .context("failed to bind SmartSock endpoint")?;
        let local_addr = endpoint.local_addr()?;
        
        // Create contact info
        let contact = Contact {
            identity,
            addr: local_addr.to_string(),
        };
        
        // Create network with SmartSock for seamless path switching
        let network = PeerNetwork::with_identity(
            endpoint.clone(),
            contact.clone(),
            client_config,
            identity,
        ).with_smartsock(smartsock.clone());
        
        let dht = DhtNode::new(
            identity,
            contact.clone(),
            network.clone(),
            DEFAULT_K,
            DEFAULT_ALPHA,
        );
        
        // Create server
        let mut server = Server::new(dht.clone())
            .map_err(|e| anyhow::anyhow!("failed to initialize server: {}", e))?;
        
        // Setup UDP relay forwarder on port+1 for CRLY frame forwarding
        // This enables true E2E encryption over relay without RPC overhead
        let forwarder_addr = SocketAddr::new(local_addr.ip(), local_addr.port() + 1);
        match UdpRelayForwarder::bind(forwarder_addr).await {
            Ok(forwarder) => {
                let forwarder = Arc::new(forwarder);
                let actual_addr = forwarder.local_addr().unwrap_or(forwarder_addr);
                info!("UDP relay forwarder on {}", actual_addr);
                server = server.with_udp_forwarder(forwarder, actual_addr);
            }
            Err(e) => {
                // Non-fatal: fall back to RPC-based relay
                warn!("failed to bind UDP relay forwarder on {}: {}", forwarder_addr, e);
            }
        }
        
        // Setup pubsub if enabled
        let (pubsub, pubsub_receiver) = if enable_pubsub {
            let mut gossip = GossipSub::new(dht.clone(), keypair.clone(), GossipConfig::default());
            // Take the message receiver before wrapping in Arc
            let receiver = gossip.take_message_receiver();
            let gossip = Arc::new(gossip);
            server = server.with_pubsub(gossip.clone());
            (
                Some(gossip),
                Some(tokio::sync::Mutex::new(receiver)),
            )
        } else {
            (None, None)
        };
        
        // Spawn server
        let server_handle = server.spawn(endpoint.clone());
        
        info!("Node {}/{}", local_addr, hex::encode(identity));
        
        Ok(Self {
            keypair,
            endpoint,
            smartsock,
            contact,
            dht,
            network,
            pubsub,
            pubsub_receiver,
            _server_handle: server_handle,
        })
    }
    
    // =========================================================================
    // Identity & Info
    // =========================================================================
    
    /// Get the node's Identity (Ed25519 public key).
    pub fn identity(&self) -> Identity {
        self.keypair.identity()
    }
    
    /// Get the node's keypair.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
    
    /// Get the node's contact information.
    pub fn contact(&self) -> &Contact {
        &self.contact
    }
    
    /// Get the local socket address the node is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr()
            .context("failed to get local address")
    }
    
    /// Get the QUIC endpoint for advanced usage.
    ///
    /// This is provided for power users who need direct endpoint access.
    /// Most users should not need this.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    
    /// Get the SmartSock for path management.
    ///
    /// SmartSock provides seamless relay↔direct path switching.
    /// Use this to register peers and update path preferences.
    pub fn smartsock(&self) -> &Arc<SmartSock> {
        &self.smartsock
    }

    // =========================================================================
    // DHT Operations
    // =========================================================================
    
    /// Store a value in the DHT.
    ///
    /// The key is derived from the BLAKE3 hash of the value (content-addressed).
    /// The value is stored locally and replicated to the k closest nodes.
    ///
    /// # Returns
    ///
    /// The content-addressed key for retrieving the value.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let key = node.put(b"hello world".to_vec()).await?;
    /// println!("Stored at key: {}", hex::encode(key));
    /// ```
    pub async fn put(&self, value: Vec<u8>) -> Result<Key> {
        self.dht.put(value).await
    }
    
    /// Store a value at a specific key in the DHT.
    ///
    /// Unlike `put()` which derives the key from the value's hash,
    /// this stores at an arbitrary key. Used for endpoint records
    /// where the key is derived from the Identity.
    pub async fn put_at(&self, key: Key, value: Vec<u8>) -> Result<()> {
        self.dht.put_at(key, value).await
    }
    
    /// Look up a value from the DHT by key.
    ///
    /// Returns the value if found, either locally or from the network.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(data) = node.get(&key).await? {
    ///     println!("Found: {:?}", data);
    /// }
    /// ```
    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.dht.get(key).await
    }
    
    /// Publish this node's current network addresses to the DHT.
    ///
    /// This creates a signed EndpointRecord and stores it in the DHT
    /// under the node's Identity. Other nodes can then resolve this
    /// peer's addresses by looking up its Identity.
    ///
    /// # Arguments
    ///
    /// * `addresses` - The current network addresses (e.g., ["192.168.1.100:4433"])
    ///
    /// # Example
    ///
    /// ```ignore
    /// node.publish_address(vec!["192.168.1.100:9000".to_string()]).await?;
    /// ```
    pub async fn publish_address(&self, addresses: Vec<String>) -> Result<()> {
        self.dht.publish_address(&self.keypair, addresses).await
    }
    
    /// Resolve a peer's current network addresses from the DHT.
    ///
    /// Looks up the EndpointRecord for the given Identity and verifies
    /// the signature and timestamp freshness before returning it.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(record))` - The verified endpoint record
    /// * `Ok(None)` - No record found for this peer
    /// * `Err(_)` - Lookup or verification failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(record) = node.resolve_peer(&peer_id).await? {
    ///     println!("Peer addresses: {:?}", record.addrs);
    /// }
    /// ```
    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        self.dht.resolve_peer(peer_id).await
    }
    
    /// Find the k closest nodes to a target identity.
    ///
    /// This performs an iterative Kademlia lookup.
    pub async fn find_peers(&self, target: Identity) -> Result<Vec<Contact>> {
        self.dht.iterative_find_node(target).await
    }
    
    /// Add a peer to the routing table.
    ///
    /// Use this to bootstrap the node by adding known peers.
    ///
    /// # Example
    ///
    /// ```ignore
    /// node.add_peer(Contact {
    ///     identity: peer_identity,
    ///     addr: "192.168.1.100:9000".to_string(),
    /// }).await;
    /// ```
    pub async fn add_peer(&self, contact: Contact) {
        self.dht.observe_contact(contact).await
    }
    
    /// Bootstrap from a list of known peers.
    ///
    /// This adds the peers to the routing table and performs an initial
    /// lookup to populate the routing table with additional nodes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// node.bootstrap(&[
    ///     Contact { identity: peer1, addr: "192.168.1.100:9000".to_string() },
    ///     Contact { identity: peer2, addr: "192.168.1.101:9000".to_string() },
    /// ]).await?;
    /// ```
    pub async fn bootstrap(&self, peers: &[Contact]) -> Result<Vec<Contact>> {
        for peer in peers {
            self.dht.observe_contact(peer.clone()).await;
        }
        
        // Automatically detect NAT type using bootstrap peers
        if peers.len() >= 2 {
            self.network.detect_nat(peers).await;
        }
        
        // Perform self-lookup to populate routing table
        self.dht.iterative_find_node(self.identity()).await
    }
    
    // =========================================================================
    // Connections
    // =========================================================================
    
    /// Connect to a peer using smart connectivity.
    ///
    /// This method abstracts all transport complexity:
    /// - Direct connection if possible
    /// - NAT traversal (hole punching) when needed
    /// - Relay fallback for CGNAT/Symmetric NAT
    ///
    /// # Arguments
    ///
    /// * `record` - The peer's endpoint record (from `resolve_peer`)
    ///
    /// # Returns
    ///
    /// A `SmartConnection` that works regardless of NAT topology.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let record = node.resolve_peer(&peer_id).await?.unwrap();
    /// let conn = node.connect(&record).await?;
    /// println!("Connected: direct={}", conn.is_direct());
    /// ```
    pub async fn connect(&self, record: &EndpointRecord) -> Result<crate::net::SmartConnection> {
        self.network.smart_connect(record).await
    }
    
    /// Get our public address (if detected).
    ///
    /// Returns the public IP:port as seen by external peers. This is
    /// discovered automatically during [`bootstrap`][Self::bootstrap].
    /// Useful for logging or displaying to users.
    pub async fn public_addr(&self) -> Option<SocketAddr> {
        self.network.public_addr().await
    }
    
    // =========================================================================
    // PubSub Operations
    // =========================================================================
    
    /// Subscribe to a topic.
    ///
    /// This registers interest in a topic. Messages for subscribed topics
    /// are received through the message receiver obtained from
    /// `take_message_receiver()`.
    ///
    /// # Errors
    ///
    /// Returns an error if pubsub is not enabled on this node.
    ///
    /// # Example
    ///
    /// ```ignore
    /// node.subscribe("my-topic").await?;
    /// ```
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        let pubsub = self.pubsub.as_ref()
            .context("pubsub not enabled - use Node::bind_with_pubsub")?;
        pubsub.subscribe(topic).await
    }
    
    /// Publish a message to a topic.
    ///
    /// The message will be signed with the node's keypair and propagated
    /// through the GossipSub mesh to all subscribers.
    ///
    /// # Returns
    ///
    /// The MessageId of the published message.
    ///
    /// # Errors
    ///
    /// Returns an error if pubsub is not enabled or message signing fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let msg_id = node.publish("my-topic", b"hello everyone!".to_vec()).await?;
    /// ```
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<crate::pubsub::MessageId> {
        let pubsub = self.pubsub.as_ref()
            .context("pubsub not enabled - use Node::bind_with_pubsub")?;
        pubsub.publish(topic, data).await
    }
    
    /// Unsubscribe from a topic.
    ///
    /// Stops receiving messages for this topic and leaves the mesh.
    ///
    /// # Errors
    ///
    /// Returns an error if pubsub is not enabled.
    pub async fn unsubscribe(&self, topic: &str) -> Result<()> {
        let pubsub = self.pubsub.as_ref()
            .context("pubsub not enabled - use Node::bind_with_pubsub")?;
        pubsub.unsubscribe(topic).await?;
        Ok(())
    }
    
    /// Take the pubsub message receiver.
    ///
    /// This can only be called once. The receiver will receive all messages
    /// for topics the node is subscribed to.
    ///
    /// # Errors
    ///
    /// Returns an error if pubsub is not enabled or if the receiver was
    /// already taken.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut rx = node.take_message_receiver().await?;
    /// tokio::spawn(async move {
    ///     while let Some(msg) = rx.recv().await {
    ///         println!("[{}] {}: {:?}", msg.topic, hex::encode(&msg.from.as_bytes()[..8]), msg.data);
    ///     }
    /// });
    /// ```
    pub async fn take_message_receiver(&self) -> Result<tokio::sync::mpsc::Receiver<ReceivedMessage>> {
        let receiver_mutex = self.pubsub_receiver.as_ref()
            .context("pubsub not enabled - use Node::bind_with_pubsub")?;
        let mut guard = receiver_mutex.lock().await;
        guard.take().context("message receiver already taken")
    }
    
    /// Check if pubsub is enabled on this node.
    pub fn has_pubsub(&self) -> bool {
        self.pubsub.is_some()
    }
    
    // =========================================================================
    // Telemetry
    // =========================================================================
    
    /// Get a snapshot of the node's current state for telemetry.
    pub async fn telemetry(&self) -> TelemetrySnapshot {
        self.dht.telemetry_snapshot().await
    }
}
