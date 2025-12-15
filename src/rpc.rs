use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;

use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::{ClientConfig, Connection, Endpoint, Incoming};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, trace, warn};

use crate::messages::{self as messages, DirectMessageSender, DirectRequest, DhtNodeRequest, DhtNodeResponse, HyParViewRequest, PlumTreeMessage, PlumTreeRequest, RelayRequest, RelayResponse, RpcRequest, RpcResponse};
use crate::transport::{SmartSock, Contact, DIRECT_CONNECT_TIMEOUT};
use crate::crypto::{extract_verified_identity, identity_to_sni};
use crate::relay::{Relay, generate_session_id, handle_relay_request};
use crate::dht::DhtNode;
use crate::storage::Key;
use crate::identity::{EndpointRecord, Identity};
use crate::hyparview::HyParView;
use crate::messages::HyParViewMessage;
use crate::plumtree::PlumTreeHandler;


#[async_trait]
pub trait DhtNodeRpc: Send + Sync + 'static {
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>>;

    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)>;

    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()>;

    async fn ping(&self, to: &Contact) -> Result<()>;
    
    /// Ask a peer to check if we are reachable by connecting back to the given address.
    /// Returns true if the peer successfully connected back.
    async fn check_reachability(&self, to: &Contact, probe_addr: &str) -> Result<bool>;
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

const MAX_CACHED_CONNECTIONS: usize = 1_000;

const CONNECTION_STALE_TIMEOUT: Duration = Duration::from_secs(60);

const RPC_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

const RELAY_ASSISTED_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Command channel capacity for the RPC actor.
const RPC_COMMAND_CHANNEL_SIZE: usize = 256;

/// Interval for cleaning up stale connections.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);


// ============================================================================
// Actor Commands
// ============================================================================

enum RpcCommand {
    /// Get a cached connection or establish a new one
    GetOrConnect {
        contact: Contact,
        reply: oneshot::Sender<Result<Connection>>,
    },
    /// Cache a contact for future resolution
    CacheContact {
        contact: Contact,
    },
    /// Resolve an identity to a cached contact
    ResolveContact {
        identity: Identity,
        reply: oneshot::Sender<Option<Contact>>,
    },
    /// Invalidate a connection after failure
    InvalidateConnection {
        peer_id: Identity,
    },
    /// Mark a connection as successfully used
    MarkSuccess {
        peer_id: Identity,
    },
    /// Shutdown the actor
    Quit,
}


// ============================================================================
// Actor (owns all mutable state)
// ============================================================================

struct RpcNodeActor {
    endpoint: Endpoint,
    client_config: ClientConfig,
    connections: LruCache<Identity, CachedConnection>,
    contact_cache: LruCache<Identity, Contact>,
    in_flight: std::collections::HashSet<Identity>,
}

impl RpcNodeActor {
    fn new(endpoint: Endpoint, client_config: ClientConfig) -> Self {
        Self {
            endpoint,
            client_config,
            connections: LruCache::new(NonZeroUsize::new(MAX_CACHED_CONNECTIONS).unwrap()),
            contact_cache: LruCache::new(NonZeroUsize::new(MAX_CACHED_CONNECTIONS).unwrap()),
            in_flight: std::collections::HashSet::new(),
        }
    }

    async fn run(mut self, mut cmd_rx: mpsc::Receiver<RpcCommand>) {
        let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);
        cleanup_interval.tick().await; // Skip initial tick

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(RpcCommand::GetOrConnect { contact, reply }) => {
                            let result = self.get_or_connect(contact).await;
                            let _ = reply.send(result);
                        }
                        Some(RpcCommand::CacheContact { contact }) => {
                            self.contact_cache.put(contact.identity, contact);
                        }
                        Some(RpcCommand::ResolveContact { identity, reply }) => {
                            let contact = self.contact_cache.get(&identity).cloned();
                            let _ = reply.send(contact);
                        }
                        Some(RpcCommand::InvalidateConnection { peer_id }) => {
                            if self.connections.pop(&peer_id).is_some() {
                                debug!(
                                    peer = hex::encode(&peer_id.as_bytes()[..8]),
                                    "invalidated cached connection after failure"
                                );
                            }
                        }
                        Some(RpcCommand::MarkSuccess { peer_id }) => {
                            if let Some(cached) = self.connections.get_mut(&peer_id) {
                                cached.mark_success();
                            }
                        }
                        Some(RpcCommand::Quit) | None => {
                            debug!("RpcNode actor shutting down");
                            break;
                        }
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_stale_connections();
                }
            }
        }
    }

    fn cleanup_stale_connections(&mut self) {
        // Collect keys to remove (can't mutate while iterating)
        let stale_peers: Vec<Identity> = self.connections
            .iter()
            .filter(|(_, cached)| cached.is_closed() || cached.is_stale())
            .map(|(id, _)| *id)
            .collect();

        for peer_id in stale_peers {
            self.connections.pop(&peer_id);
            trace!(
                peer = hex::encode(&peer_id.as_bytes()[..8]),
                "cleaned up stale connection"
            );
        }
    }

    async fn get_or_connect(&mut self, contact: Contact) -> Result<Connection> {
        let peer_id = contact.identity;

        // Check cache first
        if let Some(cached) = self.connections.get_mut(&peer_id) {
            if cached.is_closed() {
                trace!(
                    peer = hex::encode(&peer_id.as_bytes()[..8]),
                    "cached connection is closed, removing"
                );
                self.connections.pop(&peer_id);
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
                self.connections.pop(&peer_id);
            }
        }

        // Check if connection is already in flight
        if self.in_flight.contains(&peer_id) {
            // Wait and retry - but we need to release the lock
            // Use a bounded retry with backoff
            const MAX_WAIT_RETRIES: usize = 10;
            const BASE_WAIT_INTERVAL_MS: u64 = 25;
            
            for retry in 0..MAX_WAIT_RETRIES {
                let backoff_ms = BASE_WAIT_INTERVAL_MS * (1 << retry.min(5));
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                
                // Check if the connection appeared
                if let Some(cached) = self.connections.get(&peer_id) {
                    if !cached.is_closed() {
                        return Ok(cached.connection.clone());
                    }
                }
                
                // Check if in_flight cleared
                if !self.in_flight.contains(&peer_id) {
                    break;
                }
            }
            
            if self.in_flight.contains(&peer_id) {
                anyhow::bail!("timed out waiting for concurrent connection to peer");
            }
        }

        // Mark in-flight
        self.in_flight.insert(peer_id);

        // Establish connection
        let result = self.connect(&contact).await;

        // Clear in-flight
        self.in_flight.remove(&peer_id);

        let conn = result?;
        
        // Cache the connection
        self.connections.put(peer_id, CachedConnection::new(conn.clone()));
        
        Ok(conn)
    }

    async fn connect(&self, contact: &Contact) -> Result<Connection> {
        let primary = contact.primary_addr()
            .context("contact has no addresses")?;
        let addr: SocketAddr = primary.parse()
            .with_context(|| format!("invalid socket address: {}", primary))?;
        let sni = identity_to_sni(&contact.identity);
        
        let conn = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, &sni)
            .with_context(|| format!("failed to initiate connection to {}", addr))?
            .await
            .with_context(|| format!("failed to establish connection to {}", addr))?;
        
        Ok(conn)
    }
}



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
// RpcNode Handle (public API - cheap to clone)
// ============================================================================

#[derive(Clone)]
pub struct RpcNode {
    pub endpoint: Endpoint,
    pub self_contact: Contact,
    client_config: ClientConfig,
    our_peer_id: Option<Identity>,
    cmd_tx: mpsc::Sender<RpcCommand>,
    smartsock: Option<Arc<SmartSock>>,
}

impl RpcNode {
    pub fn with_identity(
        endpoint: Endpoint,
        self_contact: Contact,
        client_config: ClientConfig,
        our_peer_id: Identity,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(RPC_COMMAND_CHANNEL_SIZE);
        
        // Spawn the actor
        let actor = RpcNodeActor::new(endpoint.clone(), client_config.clone());
        tokio::spawn(actor.run(cmd_rx));
        
        Self {
            endpoint,
            self_contact,
            client_config,
            our_peer_id: Some(our_peer_id),
            cmd_tx,
            smartsock: None,
        }
    }

    pub fn with_smartsock(mut self, smartsock: Arc<SmartSock>) -> Self {
        self.smartsock = Some(smartsock);
        self
    }

    /// Shutdown the RPC actor gracefully.
    pub async fn quit(&self) {
        let _ = self.cmd_tx.send(RpcCommand::Quit).await;
    }
    
    pub async fn resolve_identity_to_contact(&self, identity: &Identity) -> Option<Contact> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        if self.cmd_tx.send(RpcCommand::ResolveContact {
            identity: *identity,
            reply: reply_tx,
        }).await.is_err() {
            return None;
        }
        
        reply_rx.await.ok().flatten()
    }

    pub async fn cache_contact(&self, contact: &Contact) {
        let _ = self.cmd_tx.send(RpcCommand::CacheContact {
            contact: contact.clone(),
        }).await;
    }

    async fn get_or_connect(&self, contact: &Contact) -> Result<Connection> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.cmd_tx.send(RpcCommand::GetOrConnect {
            contact: contact.clone(),
            reply: reply_tx,
        }).await.map_err(|_| anyhow::anyhow!("RPC actor closed"))?;
        
        reply_rx.await.map_err(|_| anyhow::anyhow!("RPC actor closed"))?
    }

    async fn invalidate_connection(&self, peer_id: &Identity) {
        let _ = self.cmd_tx.send(RpcCommand::InvalidateConnection {
            peer_id: *peer_id,
        }).await;
    }

    async fn mark_connection_success(&self, peer_id: &Identity) {
        let _ = self.cmd_tx.send(RpcCommand::MarkSuccess {
            peer_id: *peer_id,
        }).await;
    }

    pub(crate) async fn rpc(&self, contact: &Contact, request: DhtNodeRequest) -> Result<DhtNodeResponse> {
        let rpc_request = RpcRequest::DhtNode(request);
        let rpc_response = self.rpc_raw(contact, rpc_request).await?;
        
        match rpc_response {
            RpcResponse::DhtNode(dht_response) => Ok(dht_response),
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
                    peer = %contact.primary_addr().unwrap_or("<no addr>"),
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
        let relay_conn = self
            .connect_to_peer(&relay.identity, &relay.addrs)
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

    /// Complete a relay session as the receiving peer (B).
    /// 
    /// When a NAT-bound node receives an `IncomingConnection` notification,
    /// it calls this to complete the relay handshake with the relay server.
    /// 
    /// # Arguments
    /// * `relay_addr` - The relay's data address (from IncomingConnection.relay_data_addr)
    /// * `our_identity` - Our identity
    /// * `from_peer` - The identity of the peer who initiated the connection
    /// * `session_id` - The session ID (from IncomingConnection.session_id)
    /// 
    /// # Returns
    /// The relay data address to use for the tunnel on success.
    pub async fn complete_relay_session(
        &self,
        relay_addr: &str,
        _our_identity: Identity,
        from_peer: Identity,
        session_id: [u8; 16],
    ) -> Result<String> {
        // Parse relay address
        let relay_socket: std::net::SocketAddr = relay_addr.parse()
            .context("invalid relay address")?;
        
        // We just need to send an initial CRLY packet to the relay to register 
        // our address. The relay will auto-complete the session when it sees 
        // a packet from us.
        
        // Configure SmartSock to route traffic to from_peer through the relay
        let smartsock = self.smartsock.as_ref()
            .context("SmartSock not configured")?;
        
        // Register the peer (we may not know their direct addresses, use empty)
        smartsock.register_peer(from_peer, vec![]).await;
        
        // Add relay tunnel
        let added = smartsock
            .add_relay_tunnel(&from_peer, session_id, relay_socket)
            .await
            .is_some();
        if !added {
            anyhow::bail!("failed to add relay tunnel");
        }
        
        // Activate relay path
        let switched = smartsock.use_relay_path(&from_peer, session_id).await;
        if !switched {
            anyhow::bail!("failed to activate relay path");
        }
        
        // Send an initial probe packet to the relay to register our address
        // This completes the relay session (relay learns our address)
        smartsock.send_relay_probe(&from_peer, session_id).await?;
        
        debug!(
            session = hex::encode(session_id),
            from_peer = ?from_peer,
            relay = %relay_addr,
            "completed relay session as receiver"
        );
        
        Ok(relay_addr.to_string())
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
        debug!(addr = %addr, sni = %sni, "initiating connection");
        let connecting = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, &sni)
            .with_context(|| format!("failed to initiate connection to {}", addr))?;
        
        debug!(addr = %addr, "awaiting connection establishment");
        let conn = connecting
            .await
            .with_context(|| format!("failed to establish connection to {}", addr))?;
        
        debug!(addr = %addr, "connection established");
        Ok(conn)
    }

    /// Connect to a peer using their published EndpointRecord.
    /// 
    /// Strategy:
    /// 1. Try direct connection to advertised addresses
    /// 2. If direct fails and peer has designated relays, connect via relay
    pub async fn smartconnect(&self, record: &EndpointRecord) -> Result<Connection> {
        let peer_id = &record.identity;

        // Try direct connection first (SmartSock handles path probing and fallback)
        if !record.addrs.is_empty() {
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

        // Use the peer's designated relays from their published record
        if !record.relays.is_empty() {
            debug!(
                peer = ?peer_id,
                relay_count = record.relays.len(),
                "trying connection via peer's designated relays"
            );
            
            let our_peer_id = self.our_peer_id.as_ref()
                .context("cannot use relay without our_peer_id set")?;

            let direct_addrs = record.addrs.clone();
            if direct_addrs.is_empty() {
                anyhow::bail!("cannot use relay without at least one target address");
            }
            
            // Try each designated relay
            let mut last_error = None;
            for relay in &record.relays {
                let relay_peer_id = relay.identity;
                let session_id = match generate_session_id() {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                
                debug!(
                    peer = ?peer_id,
                    relay = ?relay_peer_id,
                    "attempting connection via designated relay"
                );
                
                let relay_result = self
                    .request_relay_session(relay, *our_peer_id, *peer_id, session_id)
                    .await;

                let (relay_conn, response) = match relay_result {
                    Ok((conn, resp)) => (conn, resp),
                    Err(e) => {
                        debug!(
                            relay = ?relay_peer_id,
                            error = %e,
                            "failed to request relay session, trying next"
                        );
                        last_error = Some(e);
                        continue;
                    }
                };

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
                            "relay session pending"
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
                            "relay session established"
                        );
                        (session_id, relay_data_addr)
                    }
                    RelayResponse::Rejected { reason } => {
                        debug!(
                            relay = ?relay_peer_id,
                            reason = %reason,
                            "relay rejected, trying next"
                        );
                        last_error = Some(anyhow::anyhow!("relay rejected: {}", reason));
                        continue;
                    }
                    RelayResponse::Registered => {
                        debug!(relay = ?relay_peer_id, "unexpected Registered response, trying next");
                        last_error = Some(anyhow::anyhow!("unexpected Registered response"));
                        continue;
                    }
                    RelayResponse::Incoming { .. } => {
                        debug!(relay = ?relay_peer_id, "unexpected Incoming response, trying next");
                        last_error = Some(anyhow::anyhow!("unexpected Incoming response"));
                        continue;
                    }
                };

                if let Err(e) = self.configure_relay_path_for_peer(
                    *peer_id,
                    &direct_addrs,
                    session_id,
                    &relay_data_addr,
                ).await {
                    debug!(
                        relay = ?relay_peer_id,
                        error = %e,
                        "failed to configure relay path, trying next"
                    );
                    last_error = Some(e);
                    continue;
                }

                let peer_conn_result = tokio::time::timeout(
                    RELAY_ASSISTED_CONNECT_TIMEOUT,
                    self.connect_to_peer(peer_id, &direct_addrs),
                )
                .await;

                drop(relay_conn);

                match peer_conn_result {
                    Ok(Ok(conn)) => {
                        info!(
                            peer = ?peer_id,
                            relay = ?relay_peer_id,
                            "connection successful via designated relay"
                        );
                        return Ok(conn);
                    }
                    Ok(Err(e)) => {
                        if let Some(smartsock) = &self.smartsock {
                            smartsock.remove_relay_tunnel(peer_id, &session_id).await;
                        }
                        debug!(
                            relay = ?relay_peer_id,
                            error = %e,
                            "relay-assisted connect failed, trying next"
                        );
                        last_error = Some(e);
                        continue;
                    }
                    Err(_) => {
                        if let Some(smartsock) = &self.smartsock {
                            smartsock.remove_relay_tunnel(peer_id, &session_id).await;
                        }
                        debug!(
                            relay = ?relay_peer_id,
                            "relay-assisted connect timed out, trying next"
                        );
                        last_error = Some(anyhow::anyhow!("relay-assisted connect timed out"));
                        continue;
                    }
                }
            }

            // All designated relays failed
            if let Some(e) = last_error {
                anyhow::bail!("all relay attempts failed, last error: {}", e);
            }
        }

        anyhow::bail!("direct connection failed and peer has no designated relays");
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
impl DhtNodeRpc for RpcNode {
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>> {
        let request = DhtNodeRequest::FindNode {
            from: self.self_contact.clone(),
            target,
        };
        match self.rpc(to, request).await? {
            DhtNodeResponse::Nodes(nodes) => {
                if nodes.len() > MAX_CONTACTS_PER_RESPONSE {
                    warn!(
                        peer = %to.primary_addr().unwrap_or("<no addr>"),
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
        let request = DhtNodeRequest::FindValue {
            from: self.self_contact.clone(),
            key,
        };
        match self.rpc(to, request).await? {
            DhtNodeResponse::Value { value, closer } => {
                if let Some(ref v) = value {
                    if v.len() > MAX_VALUE_SIZE {
                        warn!(
                            peer = %to.primary_addr().unwrap_or("<no addr>"),
                            size = v.len(),
                            max = MAX_VALUE_SIZE,
                            "peer returned oversized value, rejecting"
                        );
                        anyhow::bail!("value too large: {} bytes (max {})", v.len(), MAX_VALUE_SIZE);
                    }
                }
                
                let closer = if closer.len() > MAX_CONTACTS_PER_RESPONSE {
                    warn!(
                        peer = %to.primary_addr().unwrap_or("<no addr>"),
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
        let request = DhtNodeRequest::Store {
            from: self.self_contact.clone(),
            key,
            value,
        };
        match self.rpc(to, request).await? {
            DhtNodeResponse::Ack => Ok(()),
            other => anyhow::bail!("unexpected response to Store: {:?}", other),
        }
    }

    async fn ping(&self, to: &Contact) -> Result<()> {
        let request = DhtNodeRequest::Ping {
            from: self.self_contact.clone(),
        };
        match self.rpc(to, request).await? {
            DhtNodeResponse::Ack => Ok(()),
            other => anyhow::bail!("unexpected response to Ping: {:?}", other),
        }
    }

    async fn check_reachability(&self, to: &Contact, probe_addr: &str) -> Result<bool> {
        let request = DhtNodeRequest::CheckReachability {
            from: self.self_contact.clone(),
            probe_addr: probe_addr.to_string(),
        };
        match self.rpc(to, request).await? {
            DhtNodeResponse::Reachable { reachable } => Ok(reachable),
            other => anyhow::bail!("unexpected response to CheckReachability: {:?}", other),
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
        // Delegate to the existing method which uses the actor
        RpcNode::resolve_identity_to_contact(self, identity).await
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
    
    /// Register with a relay for incoming connection notifications.
    /// Returns a receiver that yields `RelayResponse::Incoming` messages when
    /// other peers want to connect via this relay.
    /// 
    /// The returned receiver must be polled continuously to receive notifications.
    /// When the receiver is dropped, the signaling connection is closed.
    pub async fn register_for_signaling(
        &self,
        relay: &Contact,
        our_identity: Identity,
    ) -> Result<tokio::sync::mpsc::Receiver<RelayResponse>> {
        let conn = self.get_or_connect(relay).await
            .context("failed to connect to relay")?;
        
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open bidirectional stream for signaling")?;
        
        // Send Register request
        let request = RpcRequest::Relay(RelayRequest::Register { from_peer: our_identity });
        let request_bytes = messages::serialize_request(&request)
            .context("failed to serialize Register request")?;
        let len = request_bytes.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&request_bytes).await?;
        // Note: NOT calling send.finish() - keep stream open
        
        // Read initial response (should be Registered)
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut len_buf))
            .await
            .context("timeout waiting for Registered response")??;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        if len > MAX_RESPONSE_SIZE {
            anyhow::bail!("response too large: {} bytes", len);
        }
        
        let mut response_bytes = vec![0u8; len];
        recv.read_exact(&mut response_bytes).await?;
        
        let rpc_response: RpcResponse = bincode::deserialize(&response_bytes)
            .context("failed to deserialize response")?;
        
        match rpc_response {
            RpcResponse::Relay(RelayResponse::Registered) => {
                debug!(relay = ?relay.identity, "successfully registered for signaling");
            }
            RpcResponse::Relay(RelayResponse::Rejected { reason }) => {
                anyhow::bail!("relay rejected registration: {}", reason);
            }
            other => {
                anyhow::bail!("unexpected response to Register: {:?}", other);
            }
        }
        
        // Create channel to forward incoming notifications
        let (tx, rx) = tokio::sync::mpsc::channel::<RelayResponse>(16);
        
        // Spawn task to read notifications and forward them
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 4];
                match recv.read_exact(&mut len_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        debug!(error = %e, "signaling stream closed");
                        break;
                    }
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                
                if len > MAX_RESPONSE_SIZE {
                    warn!(len = len, "oversized notification, dropping");
                    break;
                }
                
                let mut response_bytes = vec![0u8; len];
                if let Err(e) = recv.read_exact(&mut response_bytes).await {
                    debug!(error = %e, "failed to read notification body");
                    break;
                }
                
                let rpc_response: RpcResponse = match bincode::deserialize(&response_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "failed to deserialize notification");
                        continue;
                    }
                };
                
                if let RpcResponse::Relay(relay_response) = rpc_response {
                    if tx.send(relay_response).await.is_err() {
                        debug!("signaling receiver dropped, closing connection");
                        break;
                    }
                }
            }
            
            // Cleanup: close the stream
            let _ = send.finish();
        });
        
        Ok(rx)
    }
}


const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_SIZE: usize = 64 * 1024;

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<N: DhtNodeRpc + PlumTreeRpc + Clone + Send + Sync + 'static>(
    node: DhtNode<N>,
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
    smartsock: Option<Arc<SmartSock>>,
    incoming: Incoming,
    hyparview: HyParView,
    direct_tx: Option<DirectMessageSender>,
) -> Result<()> {
    // Extract relay from smartsock
    let udprelay = smartsock.as_ref().and_then(|ss| ss.relay());
    let udprelay_addr = smartsock.as_ref().map(|ss| ss.local_address());

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
                debug!(remote = %remote, "connection closed by application");
                hyparview.handle_peer_disconnected(verified_identity).await;
                // Clean up relay tunnels for this peer
                if let Some(ss) = &smartsock {
                    let removed = ss.cleanup_peer_relay_tunnels(&verified_identity).await;
                    if !removed.is_empty() {
                        debug!(
                            peer = hex::encode(verified_identity),
                            tunnels_removed = removed.len(),
                            "cleaned up relay tunnels on connection close"
                        );
                    }
                }
                break Ok(());
            }
            Err(quinn::ConnectionError::TimedOut) => {
                // Idle timeout is normal - connection had no activity
                debug!(remote = %remote, "connection idle timeout");
                hyparview.handle_peer_disconnected(verified_identity).await;
                // Clean up relay tunnels for this peer
                if let Some(ss) = &smartsock {
                    let removed = ss.cleanup_peer_relay_tunnels(&verified_identity).await;
                    if !removed.is_empty() {
                        debug!(
                            peer = hex::encode(verified_identity),
                            tunnels_removed = removed.len(),
                            "cleaned up relay tunnels on idle timeout"
                        );
                    }
                }
                break Ok(());
            }
            Err(e) => {
                hyparview.handle_peer_disconnected(verified_identity).await;
                // Clean up relay tunnels for this peer
                if let Some(ss) = &smartsock {
                    ss.cleanup_peer_relay_tunnels(&verified_identity).await;
                }
                break Err(e.into());
            }
        };

        let node = node.clone();
        let plumtree_h = plumtree_handler.clone();
        let udprelay = udprelay.clone();
        let remote_addr = remote;
        let verified_id = verified_identity;
        let hv = hyparview.clone();
        let direct_sender = direct_tx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_stream(node, plumtree_h, udprelay, udprelay_addr, stream, remote_addr, verified_id, hv, direct_sender).await
            {
                debug!(error = ?e, "stream error");
            }
        });
    };

    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream<N: DhtNodeRpc + PlumTreeRpc + Send + Sync + 'static>(
    node: DhtNode<N>,
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
    udprelay: Option<Relay>,
    udprelay_addr: Option<SocketAddr>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    remote_addr: SocketAddr,
    verified_identity: Identity,
    hyparview: HyParView,
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
        let error_response = DhtNodeResponse::Error {
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

    // Special handling for signaling registration - keep stream open
    if let RpcRequest::Relay(RelayRequest::Register { from_peer }) = &request {
        debug!(
            from = ?from_peer,
            remote = %remote_addr,
            "handling signaling registration"
        );
        
        let udprelay = match &udprelay {
            Some(s) => s,
            None => {
                let response = RpcResponse::Relay(RelayResponse::Rejected {
                    reason: "relay not available".to_string(),
                });
                let response_bytes = bincode::serialize(&response)?;
                let len = response_bytes.len() as u32;
                send.write_all(&len.to_be_bytes()).await?;
                send.write_all(&response_bytes).await?;
                send.finish()?;
                return Ok(());
            }
        };
        
        // Register signaling channel
        let mut notification_rx = match udprelay.register_signaling(verified_identity).await {
            Ok(rx) => rx,
            Err(e) => {
                let response = RpcResponse::Relay(RelayResponse::Rejected {
                    reason: e.to_string(),
                });
                let response_bytes = bincode::serialize(&response)?;
                let len = response_bytes.len() as u32;
                send.write_all(&len.to_be_bytes()).await?;
                send.write_all(&response_bytes).await?;
                send.finish()?;
                return Ok(());
            }
        };
        
        // Send Registered acknowledgment
        let response = RpcResponse::Relay(RelayResponse::Registered);
        let response_bytes = bincode::serialize(&response)?;
        let len = response_bytes.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&response_bytes).await?;
        // Note: NOT calling send.finish() - keep stream open
        
        debug!(
            peer = ?verified_identity,
            "signaling channel registered, listening for notifications"
        );
        
        // Buffer for detecting connection close
        let mut close_detect_buf = [0u8; 1];
        
        // Forward notifications until channel closes or connection drops
        loop {
            tokio::select! {
                notification = notification_rx.recv() => {
                    match notification {
                        Some(relay_response) => {
                            let response = RpcResponse::Relay(relay_response);
                            let response_bytes = match bincode::serialize(&response) {
                                Ok(b) => b,
                                Err(e) => {
                                    warn!(error = %e, "failed to serialize notification");
                                    continue;
                                }
                            };
                            let len = response_bytes.len() as u32;
                            
                            if let Err(e) = send.write_all(&len.to_be_bytes()).await {
                                debug!(error = %e, "signaling stream write failed");
                                break;
                            }
                            if let Err(e) = send.write_all(&response_bytes).await {
                                debug!(error = %e, "signaling stream write failed");
                                break;
                            }
                            
                            debug!(
                                peer = ?verified_identity,
                                "forwarded incoming notification"
                            );
                        }
                        None => {
                            debug!(peer = ?verified_identity, "notification channel closed");
                            break;
                        }
                    }
                }
                _ = recv.read(&mut close_detect_buf) => {
                    // Connection closed by peer
                    debug!(peer = ?verified_identity, "signaling connection closed by peer");
                    break;
                }
            }
        }
        
        // Cleanup
        udprelay.unregister_signaling(&verified_identity).await;
        let _ = send.finish();
        
        return Ok(());
    }

    let response = match tokio::time::timeout(
        REQUEST_PROCESS_TIMEOUT,
        handle_rpc_request(
            node,
            request,
            remote_addr,
            plumtree_handler,
            udprelay,
            udprelay_addr,
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
async fn handle_rpc_request<N: DhtNodeRpc + PlumTreeRpc + Send + Sync + 'static>(
    node: DhtNode<N>,
    request: RpcRequest,
    remote_addr: SocketAddr,
    plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>>,
    udprelay: Option<Relay>,
    udprelay_addr: Option<SocketAddr>,
    hyparview: HyParView,
    direct_tx: Option<DirectMessageSender>,
) -> RpcResponse {
    match request {
        RpcRequest::DhtNode(dht_request) => {
            let dht_response = handle_dht_rpc(&node, dht_request, remote_addr).await;
            RpcResponse::DhtNode(dht_response)
        }
        RpcRequest::Relay(relay_request) => {
            let relay_response = handle_relay_request(
                relay_request,
                remote_addr,
                udprelay.as_ref(),
                udprelay_addr,
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


async fn handle_dht_rpc<N: DhtNodeRpc + Send + Sync + 'static>(
    node: &DhtNode<N>,
    request: DhtNodeRequest,
    _remote_addr: SocketAddr,
) -> DhtNodeResponse {
    match request {
        DhtNodeRequest::Ping { from } => {
            trace!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                "handling PING request"
            );
            DhtNodeResponse::Ack
        }
        DhtNodeRequest::FindNode { from, target } => {
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
            DhtNodeResponse::Nodes(nodes)
        }
        DhtNodeRequest::FindValue { from, key } => {
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
            DhtNodeResponse::Value { value, closer }
        }
        DhtNodeRequest::Store { from, key, value } => {
            debug!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                key = ?hex::encode(&key[..8]),
                value_len = value.len(),
                "handling STORE request"
            );
            node.handle_store_request(&from, key, value).await;
            DhtNodeResponse::Ack
        }
        DhtNodeRequest::CheckReachability { from, probe_addr } => {
            debug!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                probe_addr = %probe_addr,
                "handling CHECK_REACHABILITY request"
            );
            
            // Create a contact for the probe address
            let probe_contact = Contact {
                identity: from.identity,
                addrs: vec![probe_addr.clone()],
            };
            
            // Attempt to ping back with a short timeout
            let reachable = tokio::time::timeout(
                Duration::from_secs(5),
                node.network().ping(&probe_contact),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            
            debug!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                probe_addr = %probe_addr,
                reachable = reachable,
                "CHECK_REACHABILITY result"
            );
            
            DhtNodeResponse::Reachable { reachable }
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

async fn handle_hyparview_rpc(
    from: Identity,
    message: HyParViewMessage,
    hyparview: HyParView,
) -> RpcResponse {
    trace!(
        from = ?hex::encode(&from.as_bytes()[..8]),
        message = ?message,
        "handling HyParView request"
    );
    
    hyparview.handle_message(from, message).await;
    
    RpcResponse::HyParViewAck
}
