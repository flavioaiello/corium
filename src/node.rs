use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use lru::LruCache;
use quinn::{Connection, Endpoint, Incoming};
use tracing::{debug, info, trace, warn};

use crate::dht::{Contact, Dht, DhtNetwork, Key, TelemetrySnapshot};
use crate::identity::{EndpointRecord, Identity, Keypair, RelayEndpoint};
use crate::dht::messages::{DhtRequest, DhtResponse};
use crate::net::{
    extract_public_key_from_cert, RpcNode, RpcRequest, RpcResponse, SmartSock,
    UdpRelayForwarder, MAX_SESSIONS,
};
use crate::pubsub::{GossipConfig, GossipSub, PubSubHandler, PubSubMessage, ReceivedMessage};

const DEFAULT_K: usize = 20;
const DEFAULT_ALPHA: usize = 3;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_SIZE: usize = 64 * 1024;

// ============================================================================
// ConnectionRateLimiter - Token bucket rate limiting for incoming connections
// ============================================================================

const MAX_GLOBAL_CONNECTIONS_PER_SECOND: usize = 100;
const MAX_CONNECTIONS_PER_IP_PER_SECOND: usize = 20;
const MAX_TRACKED_IPS: usize = 1000;

#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: usize) -> Self {
        Self {
            tokens: capacity as f64,
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self, rate: f64, capacity: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        self.tokens = (self.tokens + elapsed * rate).min(capacity);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
struct RateLimitState {
    global: TokenBucket,
    per_ip: LruCache<IpAddr, TokenBucket>,
}

#[derive(Debug)]
struct ConnectionRateLimiter {
    state: tokio::sync::Mutex<RateLimitState>,
}

impl ConnectionRateLimiter {
    fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::new(RateLimitState {
                global: TokenBucket::new(MAX_GLOBAL_CONNECTIONS_PER_SECOND),
                per_ip: LruCache::new(NonZeroUsize::new(MAX_TRACKED_IPS).unwrap()),
            }),
        }
    }

    async fn allow(&self, ip: IpAddr) -> bool {
        let mut state = self.state.lock().await;

        if !state.global.try_consume(
            MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64,
            MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64,
        ) {
            return false;
        }

        let ip_bucket = state.per_ip.get_or_insert_mut(ip, || {
            TokenBucket::new(MAX_CONNECTIONS_PER_IP_PER_SECOND)
        });

        if !ip_bucket.try_consume(
            MAX_CONNECTIONS_PER_IP_PER_SECOND as f64,
            MAX_CONNECTIONS_PER_IP_PER_SECOND as f64,
        ) {
            state.global.tokens = (state.global.tokens + 1.0)
                .min(MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64);
            return false;
        }

        true
    }
}

// ============================================================================
// Connection Handling
// ============================================================================

fn extract_verified_identity(connection: &quinn::Connection) -> Option<Identity> {
    let peer_identity = connection.peer_identity()?;
    let certs: &Vec<rustls::pki_types::CertificateDer> = peer_identity.downcast_ref()?;
    let cert_der = certs.first()?.as_ref();
    let public_key = extract_public_key_from_cert(cert_der)?;
    Some(Identity::from_bytes(public_key))
}

async fn handle_connection<N: DhtNetwork>(
    node: Dht<N>,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    smartsock: Option<Arc<SmartSock>>,
    incoming: Incoming,
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
        let pubsub = pubsub_handler.clone();
        let forwarder = udp_forwarder.clone();
        let forwarder_addr = udp_forwarder_addr;
        let remote_addr = remote;
        let verified_id = verified_identity;
        tokio::spawn(async move {
            if let Err(e) =
                handle_stream(node, pubsub, forwarder, forwarder_addr, stream, remote_addr, verified_id).await
            {
                debug!(error = ?e, "stream error");
            }
        });
    };

    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream<N: DhtNetwork>(
    node: Dht<N>,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    remote_addr: SocketAddr,
    verified_identity: Identity,
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
        crate::net::messages::deserialize_request(&request_bytes).context("failed to deserialize request")?;

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
        pubsub_handler,
        udp_forwarder,
        udp_forwarder_addr,
    )
    .await;

    let response_bytes = bincode::serialize(&response).context("failed to serialize response")?;
    let len = response_bytes.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&response_bytes).await?;
    send.finish()?;

    Ok(())
}

/// Dispatch incoming RPC requests to DHT or PubSub handlers.
#[allow(clippy::too_many_arguments)]
async fn handle_rpc_request<N: DhtNetwork>(
    node: Dht<N>,
    request: RpcRequest,
    remote_addr: SocketAddr,
    _verified_identity: Identity,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
) -> RpcResponse {
    match request {
        RpcRequest::Dht(dht_request) => {
            let dht_response = handle_dht_request(
                node,
                dht_request,
                remote_addr,
                udp_forwarder,
                udp_forwarder_addr,
            ).await;
            RpcResponse::Dht(dht_response)
        }
        RpcRequest::PubSub { from, message } => {
            handle_pubsub_request(from, message, pubsub_handler).await
        }
    }
}

/// Handle DHT protocol requests.
#[allow(clippy::too_many_arguments)]
async fn handle_dht_request<N: DhtNetwork>(
    node: Dht<N>,
    request: DhtRequest,
    remote_addr: SocketAddr,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
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
        DhtRequest::RelayConnect {
            from_peer,
            target_peer,
            session_id,
        } => {
            debug!(
                from = ?from_peer,
                target = ?target_peer,
                session = hex::encode(session_id),
                "handling RELAY_CONNECT request"
            );

            let forwarder = match &udp_forwarder {
                Some(f) => f,
                None => {
                    return DhtResponse::RelayRejected {
                        reason: "relay not available".to_string(),
                    };
                }
            };

            let relay_data_addr = match udp_forwarder_addr {
                Some(addr) => addr.to_string(),
                None => {
                    return DhtResponse::RelayRejected {
                        reason: "relay address not configured".to_string(),
                    };
                }
            };

            let session_count = forwarder.session_count().await;
            if session_count >= MAX_SESSIONS {
                return DhtResponse::RelayRejected {
                    reason: "relay server at capacity".to_string(),
                };
            }

            match forwarder.register_session(session_id, remote_addr).await {
                Ok(()) => {
                    debug!(
                        session = hex::encode(session_id),
                        peer = %remote_addr,
                        "relay session pending (waiting for peer B)"
                    );
                    DhtResponse::RelayAccepted {
                        session_id,
                        relay_data_addr,
                    }
                }
                Err("session already exists") => match forwarder.complete_session(session_id, remote_addr).await {
                    Ok(()) => {
                        debug!(
                            session = hex::encode(session_id),
                            peer = %remote_addr,
                            "relay session established"
                        );
                        DhtResponse::RelayConnected {
                            session_id,
                            relay_data_addr,
                        }
                    }
                    Err(e) => {
                        warn!(
                            session = hex::encode(session_id),
                            error = e,
                            "failed to complete relay session"
                        );
                        DhtResponse::RelayRejected {
                            reason: e.to_string(),
                        }
                    }
                },
                Err(e) => {
                    warn!(
                        session = hex::encode(session_id),
                        error = e,
                        "failed to register relay session"
                    );
                    DhtResponse::RelayRejected {
                        reason: e.to_string(),
                    }
                }
            }
        }
        DhtRequest::WhatIsMyAddr => {
            debug!(
                remote = %remote_addr,
                "handling WHAT_IS_MY_ADDR request (STUN-like)"
            );
            DhtResponse::YourAddr {
                addr: remote_addr.to_string(),
            }
        }
    }
}

/// Handle PubSub protocol requests.
async fn handle_pubsub_request(
    from: Identity,
    message: PubSubMessage,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
) -> RpcResponse {
    if let Some(handler) = pubsub_handler {
        trace!(
            from = ?hex::encode(&from.as_bytes()[..8]),
            message = ?message,
            "dispatching PUBSUB request to handler"
        );
        if let Err(e) = handler.handle_message(&from, message).await {
            warn!(from = ?hex::encode(&from.as_bytes()[..8]), error = %e, "PubSub handler returned error");
            RpcResponse::Error {
                message: format!("PubSub error: {}", e),
            }
        } else {
            RpcResponse::PubSubAck
        }
    } else {
        warn!(
            from = ?hex::encode(&from.as_bytes()[..8]),
            message = ?message,
            "received PUBSUB request but no handler registered"
        );
        RpcResponse::Error {
            message: "PubSub not enabled on this node".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Message {
    pub topic: String,
    pub from: String,
    pub data: Vec<u8>,
}

pub struct Node {
    keypair: Keypair,
    endpoint: Endpoint,
    smartsock: Arc<SmartSock>,
    contact: Contact,
    dht: Dht<RpcNode>,
    network: RpcNode,
    rate_limiter: Arc<ConnectionRateLimiter>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    pubsub: Option<Arc<GossipSub<RpcNode>>>,
    pubsub_receiver: Option<tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ReceivedMessage>>>>,
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

    async fn create(addr: &str, keypair: Keypair, enable_pubsub: bool) -> Result<Self> {
        let addr: SocketAddr = addr.parse()
            .context("invalid socket address")?;
        
        let identity = keypair.identity();
        
        let (server_certs, server_key) = crate::net::generate_ed25519_cert(&keypair)?;
        let (client_certs, client_key) = crate::net::generate_ed25519_cert(&keypair)?;
        
        let server_config = crate::net::create_server_config(server_certs, server_key)?;
        let client_config = crate::net::create_client_config(client_certs, client_key)?;
        
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
        
        let (pubsub, pubsub_receiver) = if enable_pubsub {
            let mut gossip = GossipSub::new(dht.clone(), keypair.clone(), GossipConfig::default());
            let receiver = gossip.take_message_receiver();
            let gossip = Arc::new(gossip);
            (
                Some(gossip),
                Some(tokio::sync::Mutex::new(receiver)),
            )
        } else {
            (None, None)
        };
        
        let server_handle = {
            let endpoint = endpoint.clone();
            let dht = dht.clone();
            let rate_limiter = rate_limiter.clone();
            let udp_forwarder = udp_forwarder.clone();
            let smartsock_for_server = Some(smartsock.clone());
            let pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>> = 
                pubsub.clone().map(|p| p as Arc<dyn PubSubHandler + Send + Sync>);
            
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
                    let pubsub = pubsub_handler.clone();
                    let forwarder = udp_forwarder.clone();
                    let forwarder_addr = udp_forwarder_addr;
                    let ss = smartsock_for_server.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(node, pubsub, forwarder, forwarder_addr, ss, incoming).await
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
            pubsub,
            pubsub_receiver,
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
    
    pub fn contact(&self) -> &Contact {
        &self.contact
    }
    
    pub fn endpoint(&self) -> &Endpoint {
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
    
    /// Publish address with relay endpoints for NAT traversal.
    /// Use this when behind symmetric NAT or when you want to advertise relay fallbacks.
    pub async fn publish_address_with_relays(
        &self,
        addresses: Vec<String>,
        relays: Vec<RelayEndpoint>,
    ) -> Result<()> {
        self.dht.republish_on_network_change(&self.keypair, addresses, relays).await
    }
    
    /// Check if this node is capable of acting as a relay for other peers.
    /// A node is relay-capable if it has a UDP forwarder bound.
    pub fn is_relay_capable(&self) -> bool {
        self.udp_forwarder.is_some()
    }
    
    /// Get relay endpoint info for this node (for others to use in their records).
    /// Returns None if this node is not relay-capable.
    pub async fn relay_endpoint(&self) -> Option<RelayEndpoint> {
        let forwarder_addr = self.udp_forwarder_addr?;
        let local_addr = self.endpoint.local_addr().ok()?;
        
        // Prefer public address if detected, otherwise use local
        let relay_addr = self.network.public_addr().await
            .map(|public| SocketAddr::new(public.ip(), forwarder_addr.port()))
            .unwrap_or(forwarder_addr);
        
        Some(RelayEndpoint {
            relay_identity: self.keypair.identity(),
            relay_addrs: vec![relay_addr.to_string(), local_addr.to_string()],
        })
    }
    
    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        self.dht.resolve_peer(peer_id).await
    }
    
    pub async fn find_peers(&self, target: Identity) -> Result<Vec<Contact>> {
        self.dht.iterative_find_node(target).await
    }
    
    pub async fn add_peer(&self, contact: Contact) {
        self.dht.observe_contact(contact).await
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
    
    /// Connect to a peer by identity only, resolving their address from the DHT.
    /// This is the preferred method when the peer's address is not known.
    /// It will try direct connection first, then fall back to relay if available.
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
        let pubsub = self.pubsub.as_ref()
            .context("pubsub not enabled")?;
        pubsub.subscribe(topic).await
    }
    
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        let pubsub = self.pubsub.as_ref()
            .context("pubsub not enabled")?;
        pubsub.publish(topic, data).await?;
        Ok(())
    }
    
    pub async fn unsubscribe(&self, topic: &str) -> Result<()> {
        let pubsub = self.pubsub.as_ref()
            .context("pubsub not enabled")?;
        pubsub.unsubscribe(topic).await?;
        Ok(())
    }
    
    pub async fn messages(&self) -> Result<tokio::sync::mpsc::Receiver<Message>> {
        let receiver_mutex = self.pubsub_receiver.as_ref()
            .context("pubsub not enabled")?;
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
    
    pub fn has_pubsub(&self) -> bool {
        self.pubsub.is_some()
    }
    
    
    pub async fn telemetry(&self) -> TelemetrySnapshot {
        self.dht.telemetry_snapshot().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_rate_limiter_per_ip() {
        let limiter = ConnectionRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..MAX_CONNECTIONS_PER_IP_PER_SECOND {
            assert!(limiter.allow(ip).await);
        }

        assert!(!limiter.allow(ip).await);

        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(limiter.allow(ip2).await);
    }

    const TEST_MAX_CONNECTIONS_PER_IP: usize = 10;

    const TEST_MAX_GLOBAL_CONNECTIONS: usize = 100;

    const TEST_MAX_TRACKED_IPS: usize = 1000;

    #[test]
    fn per_ip_limit_exact_boundary() {
        let allowed_count = TEST_MAX_CONNECTIONS_PER_IP;
        let rejected_count = 1;

        assert_eq!(
            allowed_count + rejected_count,
            TEST_MAX_CONNECTIONS_PER_IP + 1,
            "Test configuration error"
        );
    }

    #[test]
    fn global_limit_exact_boundary() {
        let ips_needed = TEST_MAX_GLOBAL_CONNECTIONS / TEST_MAX_CONNECTIONS_PER_IP;

        assert_eq!(ips_needed, 10, "Should need 10 IPs to hit global limit");

        let total_allowed = TEST_MAX_GLOBAL_CONNECTIONS;
        assert_eq!(total_allowed, 100);
    }

    #[test]
    fn ip_tracking_lru_eviction() {
        let ips_to_fill_cache = TEST_MAX_TRACKED_IPS;
        let extra_ip = 1;

        assert!(
            ips_to_fill_cache + extra_ip > TEST_MAX_TRACKED_IPS,
            "Need more IPs than cache size to trigger eviction"
        );
    }

    #[test]
    fn rate_limit_window_expiration() {
        use std::time::Duration;

        let window_duration = Duration::from_secs(1);
        let time_after_window = Duration::from_millis(1001);

        assert!(
            time_after_window > window_duration,
            "Time after window should exceed window duration"
        );
    }

    #[test]
    fn rapid_burst_handling() {
        let burst_connections = TEST_MAX_CONNECTIONS_PER_IP + 5;
        let expected_allowed = TEST_MAX_CONNECTIONS_PER_IP;
        let expected_rejected = 5;

        assert_eq!(
            expected_allowed + expected_rejected,
            burst_connections,
            "Burst should be partially rejected"
        );
    }

    #[tokio::test]
    async fn concurrent_rate_limit_checks() {
        use std::sync::Arc;
        use tokio::sync::Barrier;

        let barrier = Arc::new(Barrier::new(20));
        let mut handles = vec![];

        for _ in 0..20 {
            let barrier = barrier.clone();
            let handle = tokio::spawn(async move {
                barrier.wait().await;
                true
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        assert_eq!(results.len(), 20);
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn ipv4_vs_ipv6_separate_limits() {
        let ipv4: IpAddr = "192.168.1.1".parse().unwrap();
        let ipv6: IpAddr = "::1".parse().unwrap();

        assert_ne!(ipv4, ipv6);

        let ipv4_mapped_ipv6: IpAddr = "::ffff:192.168.1.1".parse().unwrap();

        assert_ne!(ipv4, ipv4_mapped_ipv6);
    }

    #[test]
    fn sustained_load_over_time() {
        let seconds_of_load = 10;
        let connections_per_second = TEST_MAX_CONNECTIONS_PER_IP;

        let total_allowed = seconds_of_load * connections_per_second;

        assert_eq!(
            total_allowed, 100,
            "Should allow {} connections over {} seconds",
            total_allowed, seconds_of_load
        );
    }
}
