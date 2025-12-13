use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint, Incoming};
use tracing::{debug, info, trace, warn};

use crate::crypto::{extract_verified_identity, generate_ed25519_cert, create_server_config, create_client_config};
use crate::dht::{Dht, Key, TelemetrySnapshot, DEFAULT_ALPHA, DEFAULT_K};
use crate::hyparview::{HyParView, HyParViewConfig, HyParViewMessage};
use crate::identity::{EndpointRecord, Identity, Keypair};
use crate::messages::{DhtRequest, DhtResponse, Message, PlumTreeMessage, RpcRequest, RpcResponse};
use crate::plumtree::{PlumTree, PlumTreeConfig, PlumTreeHandler, ReceivedMessage};
use crate::ratelimit::ConnectionRateLimiter;
use crate::transport::{self, Contact, SmartSock, UdpRelayForwarder};
use crate::rpc::{DhtRpc, HyParViewRpc, PlumTreeRpc, RpcNode};

const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_SIZE: usize = 64 * 1024;

// ============================================================================
// Connection Handling
// ============================================================================

async fn handle_connection<N: DhtRpc + PlumTreeRpc + HyParViewRpc + Clone + Send + Sync + 'static>(
    node: Dht<N>,
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    smartsock: Option<Arc<SmartSock>>,
    incoming: Incoming,
    hyparview: Arc<HyParView<N>>,
    plumtree: Option<Arc<PlumTree<N>>>,
    _network: N,
    _local_identity: Identity,
) -> Result<()> {
    debug!("handle_connection: accepting incoming connection");
    let connection = incoming.await.context("failed to accept connection")?;
    let remote = connection.remote_address();

    let verified_identity = extract_verified_identity(&connection);
    if verified_identity.is_none() {
        warn!(remote = %remote, "rejecting connection: could not verify peer identity");
        return Err(anyhow::anyhow!("could not verify peer identity from certificate"));
    }
    let verified_identity = verified_identity.unwrap();

    // Register inbound peer with SmartSock for path multiplexing
    if let Some(ss) = &smartsock {
        ss.register_peer(verified_identity, vec![remote]).await;
        debug!(
            peer = hex::encode(verified_identity),
            addr = %remote,
            "registered inbound peer with SmartSock"
        );
    }

    info!("Peer {}/{}", remote, hex::encode(verified_identity));

    debug!(
        peer = hex::encode(verified_identity),
        addr = %remote,
        "New peer connected"
    );

    let result = loop {
        let stream = match connection.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!(remote = %remote, "connection closed");
                break Ok(());
            }
            Err(e) => {
                break Err(e.into());
            }
        };

        let node = node.clone();
        let plumtree_h = plumtree_handler.clone();
        let forwarder = udp_forwarder.clone();
        let forwarder_addr = udp_forwarder_addr;
        let remote_addr = remote;
        let verified_id = verified_identity;
        let hv = hyparview.clone();
        let ps = plumtree.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_stream(node, plumtree_h, forwarder, forwarder_addr, stream, remote_addr, verified_id, hv, ps).await
            {
                debug!(error = ?e, "stream error");
            }
        });
    };

    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream<N: DhtRpc + PlumTreeRpc + HyParViewRpc + Send + Sync + 'static>(
    node: Dht<N>,
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    remote_addr: SocketAddr,
    verified_identity: Identity,
    hyparview: Arc<HyParView<N>>,
    plumtree: Option<Arc<PlumTree<N>>>,
) -> Result<()> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(REQUEST_READ_TIMEOUT, recv.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow::anyhow!("request header read timed out"))??;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_REQUEST_SIZE {
        warn!(
            remote = %remote_addr,
            size = len,
            max = MAX_REQUEST_SIZE,
            "rejecting oversized request"
        );
        let error_response = DhtResponse::Error {
            message: format!("request too large: {} bytes (max {})", len, MAX_REQUEST_SIZE),
        };
        let response_bytes = bincode::serialize(&error_response)?;
        let response_len = response_bytes.len() as u32;
        send.write_all(&response_len.to_be_bytes()).await?;
        send.write_all(&response_bytes).await?;
        send.finish()?;
        return Ok(());
    }

    let mut request_bytes = vec![0u8; len];
    tokio::time::timeout(REQUEST_READ_TIMEOUT, recv.read_exact(&mut request_bytes))
        .await
        .map_err(|_| anyhow::anyhow!("request body read timed out"))??;

    let request: RpcRequest =
        crate::messages::deserialize_request(&request_bytes).context("failed to deserialize request")?;

    if let Some(claimed_id) = request.sender_identity() {
        if claimed_id != verified_identity {
            warn!(
                remote = %remote_addr,
                claimed = ?hex::encode(&claimed_id.as_bytes()[..8]),
                verified = ?hex::encode(&verified_identity.as_bytes()[..8]),
                "rejecting request: identity mismatch (possible Sybil attack)"
            );
            let error_response = RpcResponse::Error {
                message: "Identity does not match connection identity".to_string(),
            };
            let response_bytes = bincode::serialize(&error_response)?;
            let len = response_bytes.len() as u32;
            send.write_all(&len.to_be_bytes()).await?;
            send.write_all(&response_bytes).await?;
            send.finish()?;
            return Ok(());
        }
    }

    let response = handle_rpc_request(
        node,
        request,
        remote_addr,
        verified_identity,
        plumtree_handler,
        udp_forwarder,
        udp_forwarder_addr,
        hyparview,
        plumtree,
    )
    .await;

    let response_bytes = bincode::serialize(&response).context("failed to serialize response")?;
    let len = response_bytes.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&response_bytes).await?;
    send.finish()?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_rpc_request<N: DhtRpc + PlumTreeRpc + HyParViewRpc + Send + Sync + 'static>(
    node: Dht<N>,
    request: RpcRequest,
    remote_addr: SocketAddr,
    _verified_identity: Identity,
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    hyparview: Arc<HyParView<N>>,
    _plumtree: Option<Arc<PlumTree<N>>>,
) -> RpcResponse {
    match request {
        RpcRequest::Dht(dht_request) => {
            let dht_response = handle_dht_request(node, dht_request, remote_addr).await;
            RpcResponse::Dht(dht_response)
        }
        RpcRequest::Relay(relay_request) => {
            let relay_response = transport::handle_relay_request(
                relay_request,
                remote_addr,
                udp_forwarder.as_deref(),
                udp_forwarder_addr,
            ).await;
            RpcResponse::Relay(relay_response)
        }
        RpcRequest::PlumTree(req) => {
            handle_plumtree_request(req.from, req.message, plumtree_handler).await
        }
        RpcRequest::HyParView(req) => {
            handle_hyparview_request(req.from, req.message, hyparview).await
        }
    }
}

// ============================================================================
// DHT Request Handler
// ============================================================================

async fn handle_dht_request<N: DhtRpc>(
    node: Dht<N>,
    request: DhtRequest,
    remote_addr: SocketAddr,
) -> DhtResponse {
    match request {
        DhtRequest::Ping { from } => {
            trace!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                "handling PING request"
            );
            DhtResponse::Ack
        }
        DhtRequest::FindNode { from, target } => {
            trace!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                target = ?hex::encode(&target.as_bytes()[..8]),
                "handling FIND_NODE request"
            );
            let nodes = node.handle_find_node_request(&from, target).await;
            debug!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                returned = nodes.len(),
                "FIND_NODE response"
            );
            DhtResponse::Nodes(nodes)
        }
        DhtRequest::FindValue { from, key } => {
            trace!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                key = ?hex::encode(&key[..8]),
                "handling FIND_VALUE request"
            );
            let (value, closer) = node.handle_find_value_request(&from, key).await;
            let found = value.is_some();
            debug!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                found = found,
                closer_nodes = closer.len(),
                "FIND_VALUE response"
            );
            DhtResponse::Value { value, closer }
        }
        DhtRequest::Store { from, key, value } => {
            debug!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                key = ?hex::encode(&key[..8]),
                value_len = value.len(),
                "handling STORE request"
            );
            node.handle_store_request(&from, key, value).await;
            DhtResponse::Ack
        }
        DhtRequest::WhatIsMyAddr => {
            debug!("handling WHAT_IS_MY_ADDR request (STUN-like)");
            DhtResponse::YourAddr {
                addr: remote_addr.to_string(),
            }
        }
    }
}

// ============================================================================
// PlumTree Request Handler
// ============================================================================

async fn handle_plumtree_request(
    from: Identity,
    message: PlumTreeMessage,
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
) -> RpcResponse {
    if let Some(handler) = plumtree_handler {
        trace!(
            from = ?hex::encode(&from.as_bytes()[..8]),
            message = ?message,
            "dispatching PLUMTREE request to handler"
        );
        if let Err(e) = handler.handle_message(&from, message).await {
            warn!(from = ?hex::encode(&from.as_bytes()[..8]), error = %e, "PlumTree handler returned error");
            RpcResponse::Error {
                message: format!("PlumTree error: {}", e),
            }
        } else {
            RpcResponse::PlumTreeAck
        }
    } else {
        warn!(
            from = ?hex::encode(&from.as_bytes()[..8]),
            message = ?message,
            "received PLUMTREE request but no handler registered"
        );
        RpcResponse::Error {
            message: "PlumTree not enabled on this node".to_string(),
        }
    }
}

async fn handle_hyparview_request<N: HyParViewRpc + Send + Sync + 'static>(
    from: Identity,
    message: HyParViewMessage,
    hyparview: Arc<HyParView<N>>,
) -> RpcResponse {
    trace!(
        from = ?hex::encode(&from.as_bytes()[..8]),
        message = ?message,
        "handling HyParView request"
    );
    
    // Process the message through HyParView - it handles events internally
    hyparview.handle_message(from, message).await;
    
    RpcResponse::HyParViewAck
}

pub struct Node {
    keypair: Keypair,
    endpoint: Endpoint,
    smartsock: Arc<SmartSock>,
    contact: Contact,
    dht: Dht<RpcNode>,
    network: RpcNode,
    #[allow(dead_code)] // Used for connection rate limiting in server loop
    rate_limiter: Arc<ConnectionRateLimiter>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    #[allow(dead_code)] // HyParView state machine - used in RPC handlers
    hyparview: Arc<HyParView<RpcNode>>,
    plumtree: Option<Arc<PlumTree<RpcNode>>>,
    plumtree_receiver: Option<tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ReceivedMessage>>>>,
    _server_handle: tokio::task::JoinHandle<Result<()>>,
}

impl Node {
    pub async fn bind(addr: &str) -> Result<Self> {
        let keypair = Keypair::generate();
        Self::create(addr, keypair, true).await
    }

    pub async fn bind_with_keypair(addr: &str, keypair: Keypair) -> Result<Self> {
        Self::create(addr, keypair, true).await
    }

    async fn create(addr: &str, keypair: Keypair, enable_plumtree: bool) -> Result<Self> {
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
        
        // Start the path probing loop for automatic path switching
        let _probe_handle = smartsock.spawn_probe_loop();
        debug!("SmartSock probe loop started");
        
        let contact = Contact {
            identity,
            addr: local_addr.to_string(),
            addrs: vec![],
        };
        
        let network = RpcNode::with_identity(
            endpoint.clone(),
            contact.clone(),
            client_config,
            identity,
        ).with_smartsock(smartsock.clone());
        
        let dht = Dht::new(
            identity,
            contact.clone(),
            network.clone(),
            DEFAULT_K,
            DEFAULT_ALPHA,
        );
        
        let rate_limiter = Arc::new(ConnectionRateLimiter::new());
        
        let forwarder_addr = SocketAddr::new(local_addr.ip(), local_addr.port() + 1);
        let (udp_forwarder, udp_forwarder_addr) = match UdpRelayForwarder::bind(forwarder_addr).await {
            Ok(forwarder) => {
                let forwarder = Arc::new(forwarder);
                let actual_addr = forwarder.local_addr().unwrap_or(forwarder_addr);
                info!("UDP relay forwarder on {}", actual_addr);
                (Some(forwarder), Some(actual_addr))
            }
            Err(e) => {
                warn!("failed to bind UDP relay forwarder on {}: {}", forwarder_addr, e);
                (None, None)
            }
        };
        
        // Create HyParView membership manager
        let hyparview = Arc::new(
            HyParView::new(identity, HyParViewConfig::default(), Arc::new(network.clone()))
        );
        
        let (plumtree, plumtree_receiver) = if enable_plumtree {
            let mut plumtree = PlumTree::new(Arc::new(network.clone()), keypair.clone(), PlumTreeConfig::default());
            let receiver = plumtree.take_message_receiver();
            let plumtree = Arc::new(plumtree);
            
            // Connect HyParView neighbor events to PlumTree
            hyparview.set_neighbor_callback(plumtree.clone()).await;
            
            (
                Some(plumtree),
                Some(tokio::sync::Mutex::new(receiver)),
            )
        } else {
            (None, None)
        };
        
        // Start HyParView shuffle loop
        hyparview.spawn_shuffle_loop();
        
        let server_handle = {
            let endpoint = endpoint.clone();
            let dht = dht.clone();
            let rate_limiter = rate_limiter.clone();
            let udp_forwarder = udp_forwarder.clone();
            let smartsock_for_server = Some(smartsock.clone());
            let plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>> = 
                plumtree.clone().map(|p| p as Arc<dyn PlumTreeHandler + Send + Sync>);
            let hyparview_for_server = hyparview.clone();
            let plumtree_for_server = plumtree.clone();
            let network_for_server = network.clone();
            let identity_for_server = identity;
            
            tokio::spawn(async move {
                if let Some(forwarder) = &udp_forwarder {
                    info!(
                        addr = ?udp_forwarder_addr,
                        "starting UDP relay forwarder"
                    );
                    forwarder.clone().spawn();
                }

                while let Some(incoming) = endpoint.accept().await {
                    let remote_addr = incoming.remote_address();
                    if !rate_limiter.allow(remote_addr.ip()).await {
                        warn!(remote = %remote_addr, "rate limiting: rejecting connection");
                        continue;
                    }

                    let node = dht.clone();
                    let plumtree = plumtree_handler.clone();
                    let forwarder = udp_forwarder.clone();
                    let forwarder_addr = udp_forwarder_addr;
                    let ss = smartsock_for_server.clone();
                    let hv = hyparview_for_server.clone();
                    let ps = plumtree_for_server.clone();
                    let net = network_for_server.clone();
                    let me = identity_for_server;
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(node, plumtree, forwarder, forwarder_addr, ss, incoming, hv, ps, net, me).await
                        {
                            warn!("connection error: {:?}", e);
                        }
                    });
                }
                Ok(())
            })
        };
        
        info!("Node {}/{}", local_addr, hex::encode(identity));
        
        Ok(Self {
            keypair,
            endpoint,
            smartsock,
            contact,
            dht,
            network,
            rate_limiter,
            udp_forwarder,
            udp_forwarder_addr,
            hyparview,
            plumtree,
            plumtree_receiver,
            _server_handle: server_handle,
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
    
    /// Returns this node's endpoint information (identity + addresses).
    pub fn peer_endpoint(&self) -> &Contact {
        &self.contact
    }
    
    /// Returns the underlying QUIC endpoint.
    pub fn quic_endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    
    pub fn smartsock(&self) -> &Arc<SmartSock> {
        &self.smartsock
    }

    
    pub async fn put(&self, value: Vec<u8>) -> Result<Key> {
        self.dht.put(value).await
    }
    
    pub async fn put_at(&self, key: Key, value: Vec<u8>) -> Result<()> {
        self.dht.put_at(key, value).await
    }
    
    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.dht.get(key).await
    }
    
    pub async fn publish_address(&self, addresses: Vec<String>) -> Result<()> {
        self.dht.publish_address(&self.keypair, addresses).await
    }
    
    pub async fn publish_address_with_relays(
        &self,
        addresses: Vec<String>,
        relays: Vec<Contact>,
    ) -> Result<()> {
        self.dht.republish_on_network_change(&self.keypair, addresses, relays).await
    }
    
    pub fn is_relay_capable(&self) -> bool {
        self.udp_forwarder.is_some()
    }
    
    pub async fn relay_endpoint(&self) -> Option<Contact> {
        let forwarder_addr = self.udp_forwarder_addr?;
        let local_addr = self.endpoint.local_addr().ok()?;
        
        // Prefer public address if detected, otherwise use local
        let relay_addr = self.network.public_addr().await
            .map(|public| SocketAddr::new(public.ip(), forwarder_addr.port()))
            .unwrap_or(forwarder_addr);
        
        Some(Contact {
            identity: self.keypair.identity(),
            addr: relay_addr.to_string(),
            addrs: vec![local_addr.to_string()],
        })
    }
    
    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        self.dht.resolve_peer(peer_id).await
    }
    
    pub async fn find_peers(&self, target: Identity) -> Result<Vec<Contact>> {
        self.dht.iterative_find_node(target).await
    }
    
    /// Add a peer to this node's routing table.
    pub async fn add_peer(&self, endpoint: Contact) {
        self.dht.observe_contact(endpoint).await
    }
    
    pub async fn bootstrap(&self, identity: &str, addr: &str) -> Result<()> {
        let identity_bytes = hex::decode(identity)
            .context("invalid identity: must be 64 hex characters")?;
        if identity_bytes.len() != 32 {
            anyhow::bail!("invalid identity: must be 32 bytes (64 hex chars)");
        }
        let peer_identity = Identity::from_bytes(identity_bytes.try_into().unwrap());
        
        let contact = Contact {
            identity: peer_identity,
            addr: addr.to_string(),
            addrs: vec![],
        };
        
        self.dht.observe_contact(contact.clone()).await;
        
        self.network.detect_nat(&[contact]).await;
        
        let self_identity = self.keypair.identity();
        self.dht.iterative_find_node(self_identity).await?;
        
        Ok(())
    }
    
    
    pub async fn connect(&self, identity: &str, addr: &str) -> Result<Connection> {
        let identity_bytes = hex::decode(identity)
            .context("invalid identity: must be 64 hex characters")?;
        if identity_bytes.len() != 32 {
            anyhow::bail!("invalid identity: must be 32 bytes (64 hex chars)");
        }
        let peer_identity = Identity::from_bytes(identity_bytes.try_into().unwrap());
        
        let record = EndpointRecord {
            identity: peer_identity,
            addrs: vec![addr.to_string()],
            relays: vec![],
            timestamp: crate::now_ms(),
            signature: vec![], // Not needed for outbound connection
        };
        
        let conn = self.network.smart_connect(&record).await?;
        Ok(conn)
    }
    
    pub async fn connect_peer(&self, identity: &str) -> Result<Connection> {
        let identity_bytes = hex::decode(identity)
            .context("invalid identity: must be 64 hex characters")?;
        if identity_bytes.len() != 32 {
            anyhow::bail!("invalid identity: must be 32 bytes (64 hex chars)");
        }
        let peer_identity = Identity::from_bytes(identity_bytes.try_into().unwrap());
        
        // Resolve the peer's endpoint record from DHT
        let record = self.dht.resolve_peer(&peer_identity).await?
            .context("peer not found in DHT")?;
        
        debug!(
            peer = %identity,
            addrs = ?record.addrs,
            relays = record.relays.len(),
            "resolved peer endpoint, attempting smart_connect"
        );
        
        // Use smart_connect which handles direct + relay fallback
        let conn = self.network.smart_connect(&record).await?;
        Ok(conn)
    }
    
    pub async fn public_addr(&self) -> Option<SocketAddr> {
        self.network.public_addr().await
    }
    
    
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        let plumtree = self.plumtree.as_ref()
            .context("plumtree not enabled")?;
        plumtree.subscribe(topic).await
    }
    
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        let plumtree = self.plumtree.as_ref()
            .context("plumtree not enabled")?;
        plumtree.publish(topic, data).await?;
        Ok(())
    }
    
    pub async fn unsubscribe(&self, topic: &str) -> Result<()> {
        let plumtree = self.plumtree.as_ref()
            .context("plumtree not enabled")?;
        plumtree.unsubscribe(topic).await?;
        Ok(())
    }
    
    pub async fn messages(&self) -> Result<tokio::sync::mpsc::Receiver<Message>> {
        let receiver_mutex = self.plumtree_receiver.as_ref()
            .context("plumtree not enabled")?;
        let mut guard = receiver_mutex.lock().await;
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
    
    pub fn has_plumtree(&self) -> bool {
        self.plumtree.is_some()
    }
    
    
    pub async fn telemetry(&self) -> TelemetrySnapshot {
        self.dht.telemetry_snapshot().await
    }
}
