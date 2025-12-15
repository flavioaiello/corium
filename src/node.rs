use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};
use tracing::{debug, info, warn};

use crate::crypto::{generate_ed25519_cert, create_server_config, create_client_config};
use crate::dht::{DhtNode, TelemetrySnapshot, DEFAULT_ALPHA, DEFAULT_K};
use crate::storage::Key;
use crate::hyparview::{HyParView, HyParViewConfig};
use crate::identity::{EndpointRecord, Identity, Keypair};
use crate::messages::Message;
use crate::plumtree::{PlumTree, PlumTreeConfig, PlumTreeHandler, ReceivedMessage};
use crate::relay::{Relay, RelayClient, NatStatus};
use crate::transport::{Contact, SmartSock};
use crate::rpc::{self, RpcNode};

// Re-export from relay module for backwards compatibility
pub use crate::relay::IncomingConnection;


pub struct Node {
    keypair: Keypair,
    endpoint: Endpoint,
    smartsock: Arc<SmartSock>,
    contact: Contact,
    dhtnode: DhtNode<RpcNode>,
    rpcnode: RpcNode,
    hyparview: HyParView,
    plumtree: PlumTree<RpcNode>,
    relay_client: RelayClient,
    plumtree_receiver: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ReceivedMessage>>>,
    direct_receiver: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<(Identity, Vec<u8>)>>>,
    server_handle: tokio::task::JoinHandle<Result<()>>,
}

impl Node {
    pub async fn bind(addr: &str) -> Result<Self> {
        let keypair = Keypair::generate();
        Self::create(addr, keypair).await
    }

    pub async fn bind_with_keypair(addr: &str, keypair: Keypair) -> Result<Self> {
        Self::create(addr, keypair).await
    }

    async fn create(addr: &str, keypair: Keypair) -> Result<Self> {
        let addr: SocketAddr = addr.parse()
            .context("invalid socket address")?;
        
        let identity = keypair.identity();
        
        let (server_certs, server_key) = generate_ed25519_cert(&keypair)?;
        let (client_certs, client_key) = generate_ed25519_cert(&keypair)?;
        
        let server_config = create_server_config(server_certs, server_key)?;
        let client_config = create_client_config(client_certs, client_key)?;
        
        let (endpoint, smartsock) = SmartSock::bind_endpoint(addr, server_config)
            .await
            .context("failed to bind SmartSock endpoint")?;
        let local_addr = endpoint.local_addr()?;
        
        let contact = Contact {
            identity,
            addr: local_addr.to_string(),
            addrs: vec![],
        };
        
        let rpcnode = RpcNode::with_identity(
            endpoint.clone(),
            contact.clone(),
            client_config,
            identity,
        ).with_smartsock(smartsock.clone());
        
        let dhtnode = DhtNode::new(
            identity,
            contact.clone(),
            rpcnode.clone(),
            DEFAULT_K,
            DEFAULT_ALPHA,
        );
        
        // Initialize relay server (shares socket with SmartSock)
        let relay = Relay::with_socket(smartsock.inner_socket().clone());
        smartsock.set_udprelay(relay);
        info!("UDP relay server sharing port {}", local_addr);
        
        let hyparview = HyParView::spawn(identity, HyParViewConfig::default(), Arc::new(rpcnode.clone()));
        
        let (plumtree, plumtree_rx) = PlumTree::spawn(Arc::new(rpcnode.clone()), keypair.clone(), PlumTreeConfig::default());
        let plumtree_receiver = tokio::sync::Mutex::new(Some(plumtree_rx));
        
        hyparview.set_neighbor_callback(Arc::new(plumtree.clone())).await;
        
        // Create relay client for NAT traversal
        let relay_client = RelayClient::new(
            Arc::new(rpcnode.clone()),
            dhtnode.clone(),
            keypair.clone(),
            local_addr,
        );
        
        let server_handle = {
            let endpoint = endpoint.clone();
            let dhtnode = dhtnode.clone();
            let smartsock = smartsock.clone();
            let plumtree: Arc<dyn PlumTreeHandler + Send + Sync> = Arc::new(plumtree.clone());
            let hyparview = hyparview.clone();
            
            let (direct_tx, direct_rx) = tokio::sync::mpsc::channel::<(Identity, Vec<u8>)>(256);
            let direct_receiver = tokio::sync::Mutex::new(Some(direct_rx));
            
            let server_task = tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let node = dhtnode.clone();
                    let plumtree = Some(plumtree.clone());
                    let ss = Some(smartsock.clone());
                    let hv = hyparview.clone();
                    let direct_tx = Some(direct_tx.clone());
                    tokio::spawn(async move {
                        if let Err(e) = rpc::handle_connection(node, plumtree, ss, incoming, hv, direct_tx).await {
                            warn!("connection error: {:?}", e);
                        }
                    });
                }
                Ok(())
            });
            
            (server_task, direct_receiver)
        };
        
        info!("Node {}/{}", local_addr, hex::encode(identity));
        
        Ok(Self {
            keypair,
            endpoint,
            smartsock,
            contact,
            dhtnode,
            rpcnode,
            hyparview,
            plumtree,
            relay_client,
            plumtree_receiver,
            direct_receiver: server_handle.1,
            server_handle: server_handle.0,
        })
    }
    
    
    pub fn identity(&self) -> String {
        hex::encode(self.keypair.identity())
    }
    
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr()
            .context("failed to get local address")
    }
    
    
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
    
    pub fn peer_endpoint(&self) -> &Contact {
        &self.contact
    }
    
    pub fn quic_endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    
    pub fn smartsock(&self) -> &Arc<SmartSock> {
        &self.smartsock
    }

    /// Get the relay handle for this node.
    /// 
    /// All nodes run an embedded relay server that shares the QUIC socket.
    /// Use this to access relay telemetry, session counts, or to check
    /// if the relay is operational.
    /// 
    /// # Returns
    /// The Relay handle, or `None` if the relay hasn't been initialized.
    pub fn relay(&self) -> Option<crate::relay::Relay> {
        self.smartsock.relay()
    }

    
    pub async fn put(&self, value: Vec<u8>) -> Result<Key> {
        self.dhtnode.put(value).await
    }
    
    pub async fn put_at(&self, key: Key, value: Vec<u8>) -> Result<()> {
        self.dhtnode.put_at(key, value).await
    }
    
    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.dhtnode.get(key).await
    }
    
    pub async fn publish_address(&self, addresses: Vec<String>) -> Result<()> {
        self.dhtnode.publish_address(&self.keypair, addresses).await
    }
    
    pub async fn publish_address_with_relays(
        &self,
        addresses: Vec<String>,
        relays: Vec<Contact>,
    ) -> Result<()> {
        self.dhtnode
            .republish_on_network_change(&self.keypair, addresses, relays)
            .await
    }
    
    pub async fn relay_endpoint(&self) -> Option<Contact> {
        let local_addr = self.endpoint.local_addr().ok()?;
        
        Some(Contact {
            identity: self.keypair.identity(),
            addr: local_addr.to_string(),
            addrs: vec![],
        })
    }
    
    /// Register with a relay node for incoming connection notifications.
    /// 
    /// NAT-bound nodes should call this to maintain a signaling channel with
    /// their relay. When other peers want to connect via the relay, the node
    /// receives `IncomingConnection` notifications through the returned receiver.
    /// 
    /// # Arguments
    /// * `relay_identity` - Hex-encoded identity of the relay node
    /// * `relay_addr` - Address of the relay node
    /// 
    /// # Returns
    /// A receiver that yields incoming connection notifications. Each notification
    /// contains the connecting peer's identity and a session_id to use when
    /// completing the relay connection.
    /// 
    /// # Example
    /// ```ignore
    /// let mut rx = node.register_with_relay("abc123...", "1.2.3.4:5000").await?;
    /// while let Some(notification) = rx.recv().await {
    ///     match notification {
    ///         IncomingConnection { from_peer, session_id, relay_data_addr } => {
    ///             // Complete the relay connection...
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn register_with_relay(
        &self,
        relay_identity: &str,
        relay_addr: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<IncomingConnection>> {
        let relay_id = Identity::from_hex(relay_identity)
            .context("invalid relay identity: must be 64 hex characters")?;
        
        let relay_contact = Contact {
            identity: relay_id,
            addr: relay_addr.to_string(),
            addrs: vec![],
        };
        
        self.relay_client.register_with_relay(&relay_contact).await?;
        
        self.relay_client.take_incoming_receiver().await
            .context("incoming receiver not available")
    }
    
    /// Accept an incoming relay connection from a peer.
    /// 
    /// When a NAT-bound node receives an `IncomingConnection` notification
    /// (from the receiver returned by `register_with_relay`), call this method
    /// to complete the relay handshake and establish the tunnel.
    /// 
    /// After this returns successfully, the SmartSock is configured to route
    /// traffic to/from `from_peer` through the relay tunnel. The connecting
    /// peer's QUIC connection will arrive through the normal server accept loop.
    /// 
    /// # Flow
    /// 1. Peer A calls `connect_peer(B)` → triggers relay session
    /// 2. B receives `IncomingConnection` notification
    /// 3. B calls `accept_incoming()` → configures tunnel, sends probe
    /// 4. A's pending QUIC handshake now completes through the relay
    /// 5. B receives A's connection via the server accept loop (RPC handler)
    /// 
    /// # Example
    /// ```ignore
    /// let mut rx = node.register_with_relay("relay_id", "relay_addr").await?;
    /// tokio::spawn(async move {
    ///     while let Some(incoming) = rx.recv().await {
    ///         node.accept_incoming(&incoming).await?;
    ///         // A's connection will arrive via the server - nothing more to do
    ///     }
    /// });
    /// ```
    pub async fn accept_incoming(&self, incoming: &IncomingConnection) -> Result<()> {
        self.relay_client.accept_incoming(incoming).await
    }

    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        self.dhtnode.resolve_peer(peer_id).await
    }
    
    pub async fn find_peers(&self, target: Identity) -> Result<Vec<Contact>> {
        self.dhtnode.iterative_find_node(target).await
    }
    
    pub async fn add_peer(&self, endpoint: Contact) {
        self.rpcnode.cache_contact(&endpoint).await;
        self.dhtnode.observe_contact(endpoint).await
    }
    
    pub async fn bootstrap(&self, identity: &str, addr: &str) -> Result<()> {
        let peer_identity = Identity::from_hex(identity)
            .context("invalid identity: must be 64 hex characters")?;
        
        let contact = Contact {
            identity: peer_identity,
            addr: addr.to_string(),
            addrs: vec![],
        };
        
        self.rpcnode.cache_contact(&contact).await;
        self.dhtnode.observe_contact(contact.clone()).await;
        
        self.hyparview.request_join(peer_identity).await;
        
        let self_identity = self.keypair.identity();
        self.dhtnode.iterative_find_node(self_identity).await?;
        
        Ok(())
    }
    
    
    pub async fn connect(&self, identity: &str, addr: &str) -> Result<Connection> {
        let peer_identity = Identity::from_hex(identity)
            .context("invalid identity: must be 64 hex characters")?;
        
        let conn = self.rpcnode.connect_to_peer(&peer_identity, &[addr.to_string()]).await?;
        Ok(conn)
    }
    
    pub async fn connect_peer(&self, identity: &str) -> Result<Connection> {
        let peer_identity = Identity::from_hex(identity)
            .context("invalid identity: must be 64 hex characters")?;
        
        let record = self.dhtnode.resolve_peer(&peer_identity).await?
            .context("peer not found in DHT")?;
        
        debug!(
            peer = %identity,
            addrs = ?record.addrs,
            relays = record.relays.len(),
            is_relay = record.is_relay,
            "resolved peer endpoint, attempting smartconnect"
        );
        
        let conn = self.rpcnode.smartconnect(&record).await?;
        Ok(conn)
    }
    
    pub async fn send_direct(&self, identity: &str, data: Vec<u8>) -> Result<()> {
        let peer_identity = Identity::from_hex(identity)
            .context("invalid identity: must be 64 hex characters")?;
        
        let record = self.dhtnode.resolve_peer(&peer_identity).await?
            .context("peer not found in DHT")?;
        
        let contact = Contact {
            identity: peer_identity,
            addr: record.addrs.first().cloned().unwrap_or_default(),
            addrs: record.addrs.clone(),
        };
        
        self.rpcnode.send_direct(&contact, self.keypair.identity(), data).await
    }
    
    pub async fn direct_messages(&self) -> Result<tokio::sync::mpsc::Receiver<(String, Vec<u8>)>> {
        let mut guard = self.direct_receiver.lock().await;
        let internal_rx = guard.take().context("direct message receiver already taken")?;
        
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(async move {
            let mut internal_rx = internal_rx;
            while let Some((from, data)) = internal_rx.recv().await {
                let from_hex = hex::encode(from.as_bytes());
                if tx.send((from_hex, data)).await.is_err() {
                    break;
                }
            }
        });
        
        Ok(rx)
    }
    
    
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        self.plumtree.subscribe(topic).await
    }
    
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        self.plumtree.publish(topic, data).await?;
        Ok(())
    }
    
    pub async fn unsubscribe(&self, topic: &str) -> Result<()> {
        self.plumtree.unsubscribe(topic).await?;
        Ok(())
    }
    
    pub async fn subscriptions(&self) -> Result<Vec<String>> {
        Ok(self.plumtree.subscriptions().await)
    }
    
    pub async fn messages(&self) -> Result<tokio::sync::mpsc::Receiver<Message>> {
        let mut guard = self.plumtree_receiver.lock().await;
        let internal_rx = guard.take().context("message receiver already taken")?;
        
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(async move {
            let mut internal_rx = internal_rx;
            while let Some(msg) = internal_rx.recv().await {
                let public_msg = Message {
                    topic: msg.topic,
                    from: hex::encode(msg.source.as_bytes()),
                    data: msg.data,
                };
                if tx.send(public_msg).await.is_err() {
                    break;
                }
            }
        });
        
        Ok(rx)
    }
    
    pub fn is_running(&self) -> bool {
        !self.server_handle.is_finished()
    }
    
    pub async fn shutdown(&self) {
        self.hyparview.quit().await;
        self.plumtree.quit().await;
        self.dhtnode.quit().await;
        self.server_handle.abort();
    }
    
    
    pub async fn telemetry(&self) -> TelemetrySnapshot {
        self.dhtnode.telemetry_snapshot().await
    }

    // =========================================================================
    // NAT Detection and Relay Configuration
    // =========================================================================

    /// Check if this node is publicly reachable by asking a peer to connect back.
    /// 
    /// This performs a "self-probe" by requesting `helper` to attempt a connection
    /// to our local address. Returns `true` if we are publicly reachable.
    /// 
    /// # Arguments
    /// * `helper` - A known peer that will attempt to connect back to us
    /// 
    /// # Returns
    /// * `Ok(true)` - We are publicly reachable (can serve as relay)
    /// * `Ok(false)` - We are behind NAT (need to use a relay)
    /// * `Err(_)` - Could not complete the probe (helper unreachable, etc.)
    pub async fn probe_reachability(&self, helper: &Contact) -> Result<bool> {
        self.relay_client.probe_reachability(helper).await
    }

    /// Discover relay-capable nodes in the network.
    /// 
    /// Searches for peers with `is_relay: true` in their published EndpointRecords.
    /// This queries peers from the routing table and checks their relay capability.
    /// 
    /// # Returns
    /// A list of contacts that can serve as relays.
    pub async fn discover_relays(&self) -> Result<Vec<Contact>> {
        self.relay_client.discover_relays().await
    }

    /// Select the best relay from a list by measuring RTT.
    /// 
    /// Pings each relay and returns the one with the lowest round-trip time.
    /// 
    /// # Arguments
    /// * `candidates` - List of potential relay contacts
    /// 
    /// # Returns
    /// The relay with the lowest RTT, or `None` if all candidates are unreachable.
    pub async fn select_best_relay(&self, candidates: &[Contact]) -> Option<Contact> {
        self.relay_client.select_best_relay(candidates).await
    }

    /// Automatically configure NAT traversal for this node.
    /// 
    /// This performs the complete NAT configuration flow:
    /// 1. Probe reachability via a helper peer
    /// 2. If publicly reachable: publish address with `is_relay: true`
    /// 3. If NAT-bound: discover relays, select best one, register, and publish
    /// 
    /// # Arguments
    /// * `helper` - A known peer to use for the reachability probe
    /// * `addresses` - Our addresses to publish in the DHT
    /// 
    /// # Returns
    /// Configuration result indicating our NAT status and relay (if applicable).
    pub async fn configure_nat(
        &self,
        helper: &Contact,
        addresses: Vec<String>,
    ) -> Result<(bool, Option<Contact>, Option<tokio::sync::mpsc::Receiver<IncomingConnection>>)> {
        let status = self.relay_client.configure(helper, addresses).await?;
        
        match status {
            NatStatus::Public => Ok((true, None, None)),
            NatStatus::NatBound { relay } => {
                let incoming_rx = self.relay_client.take_incoming_receiver().await;
                Ok((false, Some(relay), incoming_rx))
            }
            NatStatus::Unknown => {
                anyhow::bail!("NAT configuration failed: status unknown")
            }
        }
    }

    /// Get the current NAT status.
    pub async fn nat_status(&self) -> NatStatus {
        self.relay_client.status().await
    }

    /// Get access to the relay client for advanced NAT management.
    pub fn relay_client(&self) -> &RelayClient {
        &self.relay_client
    }
}
