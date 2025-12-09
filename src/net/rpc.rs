use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;

use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::{ClientConfig, Connection, Endpoint};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use super::messages::{self, RpcRequest, RpcResponse};
use super::smartsock::SmartSock;
use super::tls::identity_to_sni;
use super::relay::{NatType, detect_nat_type, generate_session_id, DIRECT_CONNECT_TIMEOUT};
use super::network::{RelayNetwork, RelaySession};

use crate::dht::{Contact, DhtNetwork, Key};
use crate::dht::messages::{DhtRequest, DhtResponse};
use crate::identity::{EndpointRecord, Identity};
use crate::pubsub::{GossipSubNetwork, PubSubMessage};

const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

const MAX_CONTACTS_PER_RESPONSE: usize = 100;

const MAX_VALUE_SIZE: usize = crate::dht::messages::MAX_VALUE_SIZE;

const MAX_CACHED_CONNECTIONS: usize = 1000;

const CONNECTION_STALE_TIMEOUT: Duration = Duration::from_secs(60);

// ============================================================================
// CachedConnection - Minimal connection wrapper with staleness tracking
// ============================================================================

#[derive(Clone)]
struct CachedConnection {
    connection: Connection,
    last_success: Instant,
}

impl CachedConnection {
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            last_success: Instant::now(),
        }
    }

    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    fn is_stale(&self) -> bool {
        self.last_success.elapsed() > CONNECTION_STALE_TIMEOUT
    }

    fn mark_success(&mut self) {
        self.last_success = Instant::now();
    }

    fn check_health_passive(&self) -> bool {
        if self.connection.close_reason().is_some() {
            return false;
        }
        let rtt = self.connection.rtt();
        !rtt.is_zero()
    }
}

// ============================================================================
// RpcNode - RPC layer for DHT peer communication
// ============================================================================

/// RpcNode handles RPC communication with DHT peers.
/// 
/// Responsibilities:
/// - Connection caching and health tracking
/// - RPC request/response framing (length-prefixed serialization)
/// - DhtNetwork trait implementation (find_node, find_value, store, ping)
/// - NAT detection via STUN-like queries
/// - Smart connection with relay fallback
#[derive(Clone)]
pub struct RpcNode {
    pub endpoint: Endpoint,
    pub self_contact: Contact,
    client_config: ClientConfig,
    our_peer_id: Option<Identity>,
    nat_type: Arc<RwLock<NatType>>,
    public_addr: Arc<RwLock<Option<SocketAddr>>>,
    connections: Arc<RwLock<LruCache<Identity, CachedConnection>>>,
    smartsock: Option<Arc<SmartSock>>,
}

impl RpcNode {
    pub fn with_identity(
        endpoint: Endpoint,
        self_contact: Contact,
        client_config: ClientConfig,
        our_peer_id: Identity,
    ) -> Self {
        Self {
            endpoint,
            self_contact,
            client_config,
            our_peer_id: Some(our_peer_id),
            nat_type: Arc::new(RwLock::new(NatType::Unknown)),
            public_addr: Arc::new(RwLock::new(None)),
            connections: Arc::new(RwLock::new(LruCache::<Identity, CachedConnection>::new(
                NonZeroUsize::new(MAX_CACHED_CONNECTIONS).unwrap()
            ))),
            smartsock: None,
        }
    }

    pub fn with_smartsock(mut self, smartsock: Arc<SmartSock>) -> Self {
        self.smartsock = Some(smartsock);
        self
    }

    pub async fn public_addr(&self) -> Option<SocketAddr> {
        *self.public_addr.read().await
    }

    pub async fn detect_nat(&self, stun_contacts: &[Contact]) -> NatType {
        if stun_contacts.len() < 2 {
            debug!("not enough STUN contacts for NAT detection, need at least 2");
            return NatType::Unknown;
        }

        let mut mapped_addrs: Vec<SocketAddr> = Vec::new();
        
        for contact in stun_contacts.iter().take(2) {
            match self.what_is_my_addr(contact).await {
                Ok(addr) => {
                    mapped_addrs.push(addr);
                }
                Err(e) => {
                    debug!(contact = %contact.addr, error = %e, "STUN query failed");
                }
            }
        }

        let local_addr: SocketAddr = self.self_contact.addr.parse().unwrap_or_else(|_| {
            "0.0.0.0:0".parse().unwrap()
        });

        let report = detect_nat_type(
            mapped_addrs.first().copied(),
            mapped_addrs.get(1).copied(),
            local_addr,
        );

        {
            let mut nat_type = self.nat_type.write().await;
            *nat_type = report.nat_type;
        }
        
        if let Some(addr) = report.mapped_addr_1 {
            let mut public_addr = self.public_addr.write().await;
            *public_addr = Some(addr);
        }

        info!(
            nat_type = ?report.nat_type,
            public_addr = ?report.mapped_addr_1,
            "NAT detection complete"
        );

        report.nat_type
    }

    fn parse_addr(&self, contact: &Contact) -> Result<SocketAddr> {
        contact
            .addr
            .parse()
            .with_context(|| format!("invalid socket address: {}", contact.addr))
    }

    async fn connect(&self, contact: &Contact) -> Result<Connection> {
        let addr = self.parse_addr(contact)?;
        let sni = identity_to_sni(&contact.identity);
        
        let conn = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, &sni)
            .with_context(|| format!("failed to initiate connection to {}", addr))?
            .await
            .with_context(|| format!("failed to establish connection to {}", addr))?;
        
        Ok(conn)
    }

    async fn get_or_connect(&self, contact: &Contact) -> Result<Connection> {
        let peer_id = contact.identity;
        
        {
            let mut cache = self.connections.write().await;
            if let Some(cached) = cache.get_mut(&peer_id) {
                if cached.is_closed() {
                    trace!(
                        peer = hex::encode(&peer_id.as_bytes()[..8]),
                        "cached connection is closed, removing"
                    );
                    cache.pop(&peer_id);
                }
                else if !cached.is_stale() {
                    return Ok(cached.connection.clone());
                }
                else {
                    if cached.check_health_passive() {
                        cached.mark_success();
                        return Ok(cached.connection.clone());
                    } else {
                        debug!(
                            peer = hex::encode(&peer_id.as_bytes()[..8]),
                            "stale connection failed passive health check, removing"
                        );
                        cache.pop(&peer_id);
                    }
                }
            }
        }
        
        let conn = self.connect(contact).await?;
        
        {
            let mut cache = self.connections.write().await;
            cache.put(peer_id, CachedConnection::new(conn.clone()));
        }
        
        Ok(conn)
    }

    async fn invalidate_connection(&self, peer_id: &Identity) {
        let mut cache = self.connections.write().await;
        if cache.pop(peer_id).is_some() {
            debug!(
                peer = hex::encode(&peer_id.as_bytes()[..8]),
                "invalidated cached connection after failure"
            );
        }
    }

    async fn mark_connection_success(&self, peer_id: &Identity) {
        let mut cache = self.connections.write().await;
        if let Some(cached) = cache.get_mut(peer_id) {
            cached.mark_success();
        }
    }

    /// Send a DHT RPC request and return the DHT response.
    pub(crate) async fn rpc(&self, contact: &Contact, request: DhtRequest) -> Result<DhtResponse> {
        let rpc_request = RpcRequest::Dht(request);
        let rpc_response = self.rpc_raw(contact, rpc_request).await?;
        
        match rpc_response {
            RpcResponse::Dht(dht_response) => Ok(dht_response),
            RpcResponse::Error { message } => anyhow::bail!("RPC error: {}", message),
            other => anyhow::bail!("unexpected response type for DHT request: {:?}", other),
        }
    }

    /// Send a raw RPC request and return the raw response.
    async fn rpc_raw(&self, contact: &Contact, request: RpcRequest) -> Result<RpcResponse> {
        let peer_id = contact.identity;
        let conn = self.get_or_connect(contact).await?;
        
        let result = self.rpc_inner(&conn, contact, request).await;
        
        match &result {
            Ok(_) => {
                self.mark_connection_success(&peer_id).await;
            }
            Err(e) => {
                let error_str = format!("{:?}", e);
                if error_str.contains("connection") 
                    || error_str.contains("stream")
                    || error_str.contains("timeout")
                    || error_str.contains("reset")
                    || error_str.contains("closed")
                {
                    self.invalidate_connection(&peer_id).await;
                }
            }
        }
        
        result
    }

    async fn rpc_inner(&self, conn: &Connection, contact: &Contact, request: RpcRequest) -> Result<RpcResponse> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open bidirectional stream")?;

        let request_bytes = messages::serialize(&request).context("failed to serialize request")?;
        let len = request_bytes.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&request_bytes).await?;
        send.finish()?;

        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > MAX_RESPONSE_SIZE {
            warn!(
                peer = %contact.addr,
                size = len,
                max = MAX_RESPONSE_SIZE,
                "peer sent oversized response"
            );
            anyhow::bail!("response too large: {} bytes (max {})", len, MAX_RESPONSE_SIZE);
        }

        let mut response_bytes = vec![0u8; len];
        recv.read_exact(&mut response_bytes).await?;

        let response: RpcResponse =
            messages::deserialize_response(&response_bytes).context("failed to deserialize response")?;
        Ok(response)
    }

    pub async fn what_is_my_addr(&self, contact: &Contact) -> Result<SocketAddr> {
        let response = self.rpc(contact, DhtRequest::WhatIsMyAddr).await?;
        
        match response {
            DhtResponse::YourAddr { addr } => {
                addr.parse()
                    .with_context(|| format!("invalid address in response: {}", addr))
            }
            other => anyhow::bail!("unexpected response to WhatIsMyAddr: {:?}", other),
        }
    }

    pub async fn connect_to_peer(
        &self,
        peer_id: &Identity,
        addrs: &[String],
    ) -> Result<Connection> {
        let mut last_error = None;
        
        for addr_str in addrs {
            let addr: SocketAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    last_error = Some(anyhow::anyhow!("invalid address {}: {}", addr_str, e));
                    continue;
                }
            };
            
            match self.connect_and_verify(addr, peer_id).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no addresses provided for peer")))
    }

    async fn connect_and_verify(
        &self,
        addr: SocketAddr,
        expected_peer_id: &Identity,
    ) -> Result<Connection> {
        let sni = identity_to_sni(expected_peer_id);
        let conn = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, &sni)
            .with_context(|| format!("failed to initiate connection to {}", addr))?
            .await
            .with_context(|| format!("failed to establish connection to {}", addr))?;
        
        Ok(conn)
    }

    pub async fn smart_connect(&self, record: &EndpointRecord) -> Result<Connection> {
        let peer_id = &record.identity;
        
        let our_nat_type = *self.nat_type.read().await;
        let skip_direct = our_nat_type == NatType::Symmetric;
        
        if skip_direct {
            debug!(
                peer = ?peer_id,
                nat_type = ?our_nat_type,
                "Symmetric NAT detected, skipping direct connection (CGNAT mode)"
            );
        }

        if !record.addrs.is_empty() && !skip_direct {
            debug!(peer = ?peer_id, addrs = ?record.addrs, "trying direct connection");
            
            let direct_result = tokio::time::timeout(
                DIRECT_CONNECT_TIMEOUT,
                self.connect_to_peer(peer_id, &record.addrs),
            )
            .await;

            match direct_result {
                Ok(Ok(conn)) => {
                    debug!(peer = ?peer_id, "direct connection successful");
                    
                    if let Some(smartsock) = &self.smartsock {
                        let addrs: Vec<std::net::SocketAddr> = record.addrs.iter()
                            .filter_map(|a| a.parse().ok())
                            .collect();
                        smartsock.register_peer(*peer_id, addrs).await;
                        debug!(peer = ?peer_id, "registered peer with SmartSock (direct)");
                    }
                    
                    return Ok(conn);
                }
                Ok(Err(e)) => {
                    debug!(peer = ?peer_id, error = %e, "direct connection failed");
                }
                Err(_) => {
                    debug!(peer = ?peer_id, "direct connection timed out");
                }
            }
        }

        if record.has_relays() {
            debug!(peer = ?peer_id, relays = record.relays.len(), "trying relay connection");
            
            let our_peer_id = self.our_peer_id.as_ref()
                .context("cannot use relay without our_peer_id set")?;
            
            let relay = record.relays.first()
                .context("no relays available")?;
            
            let relay_peer_id = relay.relay_identity;
            let session_id = generate_session_id()
                .context("failed to generate session ID")?;
            
            let relay_conn = self.connect_to_peer(&relay_peer_id, &relay.relay_addrs).await
                .context("failed to connect to relay")?;
            
            let request = DhtRequest::RelayConnect {
                from_peer: *our_peer_id,
                target_peer: *peer_id,
                session_id,
            };
            
            let response = self.send_rpc(&relay_conn, request).await?;
            
            let direct_addrs = record.addrs.clone();
            
            match response {
                DhtResponse::RelayAccepted { session_id, relay_data_addr } => {
                    debug!(
                        peer = ?peer_id,
                        relay = ?relay_peer_id,
                        session = hex::encode(session_id),
                        relay_data = %relay_data_addr,
                        "relay session pending, waiting for peer"
                    );
                    
                    let data_addr: Option<std::net::SocketAddr> = relay_data_addr.parse().ok();
                    
                    if let (Some(smartsock), Some(relay_data)) = (&self.smartsock, data_addr) {
                        let addrs: Vec<std::net::SocketAddr> = direct_addrs.iter()
                            .filter_map(|a| a.parse().ok())
                            .collect();
                        smartsock.register_peer(*peer_id, addrs).await;
                        smartsock.add_relay_tunnel(peer_id, session_id, relay_data).await;
                        smartsock.use_relay_path(peer_id, session_id).await;
                        debug!(peer = ?peer_id, "registered peer with SmartSock (relay pending)");
                    }
                    
                    Ok(relay_conn)
                }
                DhtResponse::RelayConnected { session_id, relay_data_addr } => {
                    debug!(
                        peer = ?peer_id,
                        relay = ?relay_peer_id,
                        session = hex::encode(session_id),
                        relay_data = %relay_data_addr,
                        "relay session established"
                    );
                    
                    let data_addr: Option<std::net::SocketAddr> = relay_data_addr.parse().ok();
                    
                    if let (Some(smartsock), Some(relay_data)) = (&self.smartsock, data_addr) {
                        let addrs: Vec<std::net::SocketAddr> = direct_addrs.iter()
                            .filter_map(|a| a.parse().ok())
                            .collect();
                        smartsock.register_peer(*peer_id, addrs).await;
                        smartsock.add_relay_tunnel(peer_id, session_id, relay_data).await;
                        smartsock.use_relay_path(peer_id, session_id).await;
                        debug!(peer = ?peer_id, "registered peer with SmartSock (relay connected)");
                    }
                    
                    Ok(relay_conn)
                }
                DhtResponse::RelayRejected { reason } => {
                    anyhow::bail!("relay rejected: {}", reason);
                }
                _ => anyhow::bail!("unexpected relay response"),
            }
        } else {
            anyhow::bail!("direct connection failed and no relays available");
        }
    }

    /// Send a DHT RPC on an existing connection (used for relay handshake).
    async fn send_rpc(&self, conn: &Connection, request: DhtRequest) -> Result<DhtResponse> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open bidirectional stream")?;

        let rpc_request = RpcRequest::Dht(request);
        let request_bytes = messages::serialize(&rpc_request).context("failed to serialize request")?;
        let len = request_bytes.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&request_bytes).await?;
        send.finish()?;

        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > MAX_RESPONSE_SIZE {
            warn!(
                size = len,
                max = MAX_RESPONSE_SIZE,
                "peer sent oversized response on existing connection"
            );
            anyhow::bail!("response too large: {} bytes (max {})", len, MAX_RESPONSE_SIZE);
        }

        let mut response_bytes = vec![0u8; len];
        recv.read_exact(&mut response_bytes).await?;

        let rpc_response: RpcResponse =
            messages::deserialize_response(&response_bytes).context("failed to deserialize response")?;
        
        match rpc_response {
            RpcResponse::Dht(dht_response) => Ok(dht_response),
            RpcResponse::Error { message } => anyhow::bail!("RPC error: {}", message),
            other => anyhow::bail!("unexpected response type: {:?}", other),
        }
    }
}

#[async_trait]
impl DhtNetwork for RpcNode {
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>> {
        let request = DhtRequest::FindNode {
            from: self.self_contact.clone(),
            target,
        };
        match self.rpc(to, request).await? {
            DhtResponse::Nodes(nodes) => {
                if nodes.len() > MAX_CONTACTS_PER_RESPONSE {
                    warn!(
                        peer = %to.addr,
                        count = nodes.len(),
                        max = MAX_CONTACTS_PER_RESPONSE,
                        "peer returned too many contacts, truncating"
                    );
                    Ok(nodes.into_iter().take(MAX_CONTACTS_PER_RESPONSE).collect())
                } else {
                    Ok(nodes)
                }
            }
            other => anyhow::bail!("unexpected response to FindNode: {:?}", other),
        }
    }

    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)> {
        let request = DhtRequest::FindValue {
            from: self.self_contact.clone(),
            key,
        };
        match self.rpc(to, request).await? {
            DhtResponse::Value { value, closer } => {
                if let Some(ref v) = value {
                    if v.len() > MAX_VALUE_SIZE {
                        warn!(
                            peer = %to.addr,
                            size = v.len(),
                            max = MAX_VALUE_SIZE,
                            "peer returned oversized value, rejecting"
                        );
                        anyhow::bail!("value too large: {} bytes (max {})", v.len(), MAX_VALUE_SIZE);
                    }
                }
                
                let closer = if closer.len() > MAX_CONTACTS_PER_RESPONSE {
                    warn!(
                        peer = %to.addr,
                        count = closer.len(),
                        max = MAX_CONTACTS_PER_RESPONSE,
                        "peer returned too many contacts in FIND_VALUE, truncating"
                    );
                    closer.into_iter().take(MAX_CONTACTS_PER_RESPONSE).collect()
                } else {
                    closer
                };
                
                Ok((value, closer))
            }
            other => anyhow::bail!("unexpected response to FindValue: {:?}", other),
        }
    }

    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()> {
        let request = DhtRequest::Store {
            from: self.self_contact.clone(),
            key,
            value,
        };
        match self.rpc(to, request).await? {
            DhtResponse::Ack => Ok(()),
            other => anyhow::bail!("unexpected response to Store: {:?}", other),
        }
    }

    async fn ping(&self, to: &Contact) -> Result<()> {
        let request = DhtRequest::Ping {
            from: self.self_contact.clone(),
        };
        match self.rpc(to, request).await? {
            DhtResponse::Ack => Ok(()),
            other => anyhow::bail!("unexpected response to Ping: {:?}", other),
        }
    }
}

// ============================================================================
// GossipSubNetwork - PubSub message delivery for GossipSub
// ============================================================================

#[async_trait]
impl GossipSubNetwork for RpcNode {
    async fn send_pubsub(&self, to: &Contact, from: Identity, message: PubSubMessage) -> Result<()> {
        let request = RpcRequest::PubSub { from, message };
        match self.rpc_raw(to, request).await? {
            RpcResponse::PubSubAck => Ok(()),
            RpcResponse::Error { message } => anyhow::bail!("PubSub rejected: {}", message),
            other => anyhow::bail!("unexpected response to PubSub: {:?}", other),
        }
    }

    async fn send_pubsub_batch(&self, to: &Contact, from: Identity, messages: Vec<PubSubMessage>) -> Result<()> {
        // For now, send sequentially. Could be optimized with a batch RPC later.
        for msg in messages {
            self.send_pubsub(to, from, msg).await?;
        }
        Ok(())
    }
}

// ============================================================================
// RelayNetwork - Relay connection establishment
// ============================================================================

#[async_trait]
impl RelayNetwork for RpcNode {
    async fn request_relay(
        &self,
        relay: &Contact,
        target: Identity,
    ) -> Result<RelaySession> {
        let our_peer_id = self.our_peer_id.as_ref()
            .context("cannot use relay without our_peer_id set")?;
        
        let session_id = generate_session_id()
            .context("failed to generate session ID")?;
        
        let request = DhtRequest::RelayConnect {
            from_peer: *our_peer_id,
            target_peer: target,
            session_id,
        };
        
        match self.rpc(relay, request).await? {
            DhtResponse::RelayAccepted { session_id, relay_data_addr } => {
                debug!(
                    target = ?target,
                    relay = ?relay.identity,
                    session = hex::encode(session_id),
                    relay_data = %relay_data_addr,
                    "relay session pending, waiting for peer"
                );
                Ok(RelaySession {
                    session_id,
                    relay_data_addr,
                    relay_identity: relay.identity,
                })
            }
            DhtResponse::RelayConnected { session_id, relay_data_addr } => {
                debug!(
                    target = ?target,
                    relay = ?relay.identity,
                    session = hex::encode(session_id),
                    relay_data = %relay_data_addr,
                    "relay session established"
                );
                Ok(RelaySession {
                    session_id,
                    relay_data_addr,
                    relay_identity: relay.identity,
                })
            }
            DhtResponse::RelayRejected { reason } => {
                anyhow::bail!("relay rejected: {}", reason);
            }
            other => anyhow::bail!("unexpected relay response: {:?}", other),
        }
    }

    async fn join_relay(
        &self,
        relay: &Contact,
        session_id: [u8; 16],
    ) -> Result<RelaySession> {
        let our_peer_id = self.our_peer_id.as_ref()
            .context("cannot use relay without our_peer_id set")?;
        
        // When joining, we use a placeholder target - the relay will match by session_id
        let request = DhtRequest::RelayConnect {
            from_peer: *our_peer_id,
            target_peer: *our_peer_id, // Placeholder, relay matches by session_id
            session_id,
        };
        
        match self.rpc(relay, request).await? {
            DhtResponse::RelayConnected { session_id, relay_data_addr } => {
                debug!(
                    relay = ?relay.identity,
                    session = hex::encode(session_id),
                    relay_data = %relay_data_addr,
                    "joined relay session"
                );
                Ok(RelaySession {
                    session_id,
                    relay_data_addr,
                    relay_identity: relay.identity,
                })
            }
            DhtResponse::RelayRejected { reason } => {
                anyhow::bail!("relay rejected join: {}", reason);
            }
            other => anyhow::bail!("unexpected relay response: {:?}", other),
        }
    }
}
