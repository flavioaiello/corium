use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;

use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::{ClientConfig, Connection, Endpoint, Incoming};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::messages::{self as messages, DirectMessageSender, DirectRequest, DhtRequest, DhtResponse, HyParViewRequest, PlumTreeMessage, PlumTreeRequest, RelayRequest, RelayResponse, RpcRequest, RpcResponse};
use crate::transport::SmartSock;
use crate::crypto::{extract_verified_identity, identity_to_sni};
use crate::transport::{self, Contact, NatType, detect_nat_type, generate_session_id, DIRECT_CONNECT_TIMEOUT, UdpRelayForwarder};
use crate::dht::{Dht, Key};
use crate::identity::{EndpointRecord, Identity};
use crate::hyparview::{HyParView, HyParViewMessage};
use crate::plumtree::PlumTreeHandler;


#[async_trait]
pub trait DhtRpc: Send + Sync + 'static {
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>>;

    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)>;

    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()>;

    async fn ping(&self, to: &Contact) -> Result<()>;
}


#[async_trait]

pub trait PlumTreeRpc: Send + Sync {
    async fn send_plumtree(&self, to: &Contact, from: Identity, message: PlumTreeMessage)
        -> Result<()>;
    
    async fn resolve_identity_to_contact(&self, identity: &Identity) -> Option<Contact>;
}


#[async_trait]

pub trait HyParViewRpc: Send + Sync {
    async fn send_hyparview(
        &self,
        to: &Identity,
        from: Identity,
        message: HyParViewMessage,
    ) -> Result<()>;
}


const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

const MAX_CONTACTS_PER_RESPONSE: usize = 100;

const MAX_VALUE_SIZE: usize = crate::messages::MAX_VALUE_SIZE;

const MAX_CACHED_CONNECTIONS: usize = 1000;

const CONNECTION_STALE_TIMEOUT: Duration = Duration::from_secs(60);

const RPC_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

const RELAY_ASSISTED_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);



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


#[derive(Clone)]
pub struct RpcNode {
    pub endpoint: Endpoint,
    pub self_contact: Contact,
    client_config: ClientConfig,
    our_peer_id: Option<Identity>,
    nat_type: Arc<RwLock<NatType>>,
    public_addr: Arc<RwLock<Option<SocketAddr>>>,
    connections: Arc<RwLock<LruCache<Identity, CachedConnection>>>,
    contact_cache: Arc<RwLock<LruCache<Identity, Contact>>>,
    in_flight: Arc<tokio::sync::Mutex<std::collections::HashSet<Identity>>>,
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
            contact_cache: Arc::new(RwLock::new(LruCache::<Identity, Contact>::new(
                NonZeroUsize::new(MAX_CACHED_CONNECTIONS).unwrap()
            ))),
            in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            smartsock: None,
        }
    }

    pub fn with_smartsock(mut self, smartsock: Arc<SmartSock>) -> Self {
        self.smartsock = Some(smartsock);
        self
    }
    
    pub async fn resolve_identity_to_contact(&self, identity: &Identity) -> Option<Contact> {
        let mut cache = self.contact_cache.write().await;
        cache.get(identity).cloned()
    }

    pub async fn cache_contact(&self, contact: &Contact) {
        let mut cache = self.contact_cache.write().await;
        cache.put(contact.identity, contact.clone());
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
                } else if !cached.is_stale() {
                    return Ok(cached.connection.clone());
                } else if cached.check_health_passive() {
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
        
        const MAX_WAIT_RETRIES: usize = 10;
        const BASE_WAIT_INTERVAL_MS: u64 = 25;
        const MAX_TOTAL_WAIT_MS: u64 = 2000;
        
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(MAX_TOTAL_WAIT_MS);
        
        for retry in 0..=MAX_WAIT_RETRIES {
            {
                let mut in_flight = self.in_flight.lock().await;
                if !in_flight.contains(&peer_id) {
                    in_flight.insert(peer_id);
                    break;
                }
            }
            
            if retry == MAX_WAIT_RETRIES || std::time::Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for concurrent connection to peer");
            }
            
            let backoff_ms = BASE_WAIT_INTERVAL_MS * (1 << retry.min(5));
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            
            let cache = self.connections.read().await;
            if let Some(cached) = cache.peek(&peer_id) {
                if !cached.is_closed() {
                    return Ok(cached.connection.clone());
                }
            }
        }
        
        let result = self.connect(contact).await;
        
        {
            let mut in_flight = self.in_flight.lock().await;
            in_flight.remove(&peer_id);
        }
        
        let conn = result?;
        
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

    pub(crate) async fn rpc(&self, contact: &Contact, request: DhtRequest) -> Result<DhtResponse> {
        let rpc_request = RpcRequest::Dht(request);
        let rpc_response = self.rpc_raw(contact, rpc_request).await?;
        
        match rpc_response {
            RpcResponse::Dht(dht_response) => Ok(dht_response),
            RpcResponse::Error { message } => anyhow::bail!("RPC error: {}", message),
            other => anyhow::bail!("unexpected response type for DHT request: {:?}", other),
        }
    }

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
        tokio::time::timeout(RPC_STREAM_TIMEOUT, async {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .context("failed to open bidirectional stream")?;

            let request_bytes = messages::serialize_request(&request)
                .context("failed to serialize request")?;
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

            let response: RpcResponse = bincode::deserialize(&response_bytes)
                .context("failed to deserialize response")?;
            Ok(response)
        })
        .await
        .context("RPC timed out")?
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

    pub async fn request_relay_session(
        &self,
        relay: &Contact,
        from_peer: Identity,
        target_peer: Identity,
        session_id: [u8; 16],
    ) -> Result<(Connection, RelayResponse)> {
        let relay_addrs: Vec<String> = std::iter::once(relay.addr.clone())
            .chain(relay.addrs.iter().cloned())
            .collect();

        let relay_conn = self
            .connect_to_peer(&relay.identity, &relay_addrs)
            .await
            .context("failed to connect to relay")?;

        let request = RelayRequest::Connect {
            from_peer,
            target_peer,
            session_id,
        };

        let response = self.send_relay_rpc(&relay_conn, request).await?;
        Ok((relay_conn, response))
    }

    pub async fn configure_relay_path_for_peer(
        &self,
        peer_id: Identity,
        direct_addrs: &[String],
        session_id: [u8; 16],
        relay_data_addr: &str,
    ) -> Result<()> {
        let smartsock = self
            .smartsock
            .as_ref()
            .context("SmartSock not configured")?;

        let direct_socket_addrs: Vec<std::net::SocketAddr> = direct_addrs
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect();

        smartsock.register_peer(peer_id, direct_socket_addrs).await;

        let relay_data: std::net::SocketAddr = relay_data_addr
            .parse()
            .context("invalid relay data address")?;

        let added = smartsock
            .add_relay_tunnel(&peer_id, session_id, relay_data)
            .await
            .is_some();
        if !added {
            anyhow::bail!("failed to add relay tunnel (peer not registered)");
        }

        let switched = smartsock.use_relay_path(&peer_id, session_id).await;
        if !switched {
            anyhow::bail!("failed to activate relay path");
        }

        Ok(())
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

    pub async fn smartconnect(&self, record: &EndpointRecord) -> Result<Connection> {
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
            
            let relay_peer_id = relay.identity;
            let session_id = generate_session_id()
                .context("failed to generate session ID")?;
            
            let (relay_conn, response) = self
                .request_relay_session(relay, *our_peer_id, *peer_id, session_id)
                .await?;

            let direct_addrs = record.addrs.clone();
            if direct_addrs.is_empty() {
                anyhow::bail!("cannot use relay without at least one target address");
            }

            let (session_id, relay_data_addr) = match response {
                RelayResponse::Accepted {
                    session_id,
                    relay_data_addr,
                } => {
                    debug!(
                        peer = ?peer_id,
                        relay = ?relay_peer_id,
                        session = hex::encode(session_id),
                        relay_data = %relay_data_addr,
                        "relay session pending, attempting relay-assisted QUIC connect"
                    );
                    (session_id, relay_data_addr)
                }
                RelayResponse::Connected {
                    session_id,
                    relay_data_addr,
                } => {
                    debug!(
                        peer = ?peer_id,
                        relay = ?relay_peer_id,
                        session = hex::encode(session_id),
                        relay_data = %relay_data_addr,
                        "relay session established, attempting relay-assisted QUIC connect"
                    );
                    (session_id, relay_data_addr)
                }
                RelayResponse::Rejected { reason } => {
                    anyhow::bail!("relay rejected: {}", reason);
                }
            };

            self.configure_relay_path_for_peer(*peer_id, &direct_addrs, session_id, &relay_data_addr)
                .await?;

            let peer_conn = tokio::time::timeout(
                RELAY_ASSISTED_CONNECT_TIMEOUT,
                self.connect_to_peer(peer_id, &direct_addrs),
            )
            .await
            .context("relay-assisted connect timed out")?
            .context("relay-assisted connect failed")?;

            drop(relay_conn);

            Ok(peer_conn)
        } else {
            anyhow::bail!("direct connection failed and no relays available");
        }
    }

    async fn send_relay_rpc(&self, conn: &Connection, request: RelayRequest) -> Result<RelayResponse> {
        tokio::time::timeout(RPC_STREAM_TIMEOUT, async {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .context("failed to open bidirectional stream")?;

            let rpc_request = RpcRequest::Relay(request);
            let request_bytes = messages::serialize_request(&rpc_request)
                .context("failed to serialize request")?;
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

            let rpc_response: RpcResponse = bincode::deserialize(&response_bytes)
                .context("failed to deserialize response")?;
            
            match rpc_response {
                RpcResponse::Relay(relay_response) => Ok(relay_response),
                RpcResponse::Error { message } => anyhow::bail!("Relay RPC error: {}", message),
                other => anyhow::bail!("unexpected response type for Relay: {:?}", other),
            }
        })
        .await
        .context("RPC timed out")?
    }
}

#[async_trait]
impl DhtRpc for RpcNode {
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


#[async_trait]
impl PlumTreeRpc for RpcNode {
    async fn send_plumtree(&self, to: &Contact, from: Identity, message: PlumTreeMessage) -> Result<()> {
        let request = RpcRequest::PlumTree(PlumTreeRequest { from, message });
        match self.rpc_raw(to, request).await? {
            RpcResponse::PlumTreeAck => Ok(()),
            RpcResponse::Error { message } => anyhow::bail!("PlumTree rejected: {}", message),
            other => anyhow::bail!("unexpected response to PlumTree: {:?}", other),
        }
    }
    
    async fn resolve_identity_to_contact(&self, identity: &Identity) -> Option<Contact> {
        let mut cache = self.contact_cache.write().await;
        cache.get(identity).cloned()
    }
}


#[async_trait]
impl HyParViewRpc for RpcNode {
    async fn send_hyparview(&self, to: &Identity, from: Identity, message: HyParViewMessage) -> Result<()> {
        let contact = self.resolve_identity_to_contact(to).await
            .context("could not resolve identity to contact for HyParView message")?;
        
        let request = RpcRequest::HyParView(HyParViewRequest { from, message });
        match self.rpc_raw(&contact, request).await? {
            RpcResponse::HyParViewAck => Ok(()),
            RpcResponse::Error { message } => anyhow::bail!("HyParView rejected: {}", message),
            other => anyhow::bail!("unexpected response to HyParView: {:?}", other),
        }
    }
}


impl RpcNode {
    pub async fn send_direct(&self, to: &Contact, from: Identity, data: Vec<u8>) -> Result<()> {
        let request = RpcRequest::Direct(DirectRequest { from, data });
        match self.rpc_raw(to, request).await? {
            RpcResponse::DirectAck => Ok(()),
            RpcResponse::Error { message } => anyhow::bail!("Direct message rejected: {}", message),
            other => anyhow::bail!("unexpected response to Direct: {:?}", other),
        }
    }
}


const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_SIZE: usize = 64 * 1024;

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<N: DhtRpc + PlumTreeRpc + HyParViewRpc + Clone + Send + Sync + 'static>(
    node: Dht<N>,
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    smartsock: Option<Arc<SmartSock>>,
    incoming: Incoming,
    hyparview: Arc<HyParView<N>>,
    direct_tx: Option<DirectMessageSender>,
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
                hyparview.handle_peer_disconnected(verified_identity).await;
                break Ok(());
            }
            Err(e) => {
                hyparview.handle_peer_disconnected(verified_identity).await;
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
        let direct_sender = direct_tx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_stream(node, plumtree_h, forwarder, forwarder_addr, stream, remote_addr, verified_id, hv, direct_sender).await
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
    direct_tx: Option<DirectMessageSender>,
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

    let response = match tokio::time::timeout(
        REQUEST_PROCESS_TIMEOUT,
        handle_rpc_request(
            node,
            request,
            remote_addr,
            plumtree_handler,
            udp_forwarder,
            udp_forwarder_addr,
            hyparview,
            direct_tx,
        )
    ).await {
        Ok(resp) => resp,
        Err(_) => {
            warn!(remote = %remote_addr, "request processing timed out");
            RpcResponse::Error {
                message: "request processing timeout".to_string(),
            }
        }
    };

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
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<UdpRelayForwarder>>,
    udp_forwarder_addr: Option<SocketAddr>,
    hyparview: Arc<HyParView<N>>,
    direct_tx: Option<DirectMessageSender>,
) -> RpcResponse {
    match request {
        RpcRequest::Dht(dht_request) => {
            let dht_response = handle_dht_rpc(&node, dht_request, remote_addr).await;
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
            handle_plumtree_rpc(req.from, req.message, plumtree_handler).await
        }
        RpcRequest::HyParView(req) => {
            handle_hyparview_rpc(req.from, req.message, hyparview).await
        }
        RpcRequest::Direct(req) => {
            if let Some(tx) = direct_tx {
                let _ = tx.send((req.from, req.data)).await;
            }
            RpcResponse::DirectAck
        }
    }
}


async fn handle_dht_rpc<N: DhtRpc + Send + Sync + 'static>(
    node: &Dht<N>,
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

async fn handle_plumtree_rpc(
    from: Identity,
    message: PlumTreeMessage,
    handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
) -> RpcResponse {
    if let Some(h) = handler {
        trace!(
            from = ?hex::encode(&from.as_bytes()[..8]),
            message = ?message,
            "dispatching PLUMTREE request to handler"
        );
        if let Err(e) = h.handle_message(&from, message).await {
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

async fn handle_hyparview_rpc<N: HyParViewRpc + Send + Sync + 'static>(
    from: Identity,
    message: HyParViewMessage,
    hyparview: Arc<HyParView<N>>,
) -> RpcResponse {
    trace!(
        from = ?hex::encode(&from.as_bytes()[..8]),
        message = ?message,
        "handling HyParView request"
    );
    
    hyparview.handle_message(from, message).await;
    
    RpcResponse::HyParViewAck
}
