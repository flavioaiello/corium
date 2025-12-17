//! # RPC Layer
//!
//! This module provides the QUIC-based RPC infrastructure for all Corium protocols.
//! It handles connection management, request/response routing, and multiplexing
//! of different protocol types over a single QUIC endpoint.
//!
//! ## Architecture
//!
//! The RPC layer uses the **Actor Pattern**:
//! - [`RpcNode`]: Public handle (cheap to clone) for making RPC calls
//! - `RpcActor`: Internal actor owning connection cache and state
//!
//! ## Protocol Traits
//!
//! Each protocol defines its own RPC trait:
//! - [`DhtNodeRpc`]: DHT operations (ping, find_node, find_value, store)
//! - [`GossipSubRpc`]: PubSub message forwarding
//! - [`RelayRpc`]: NAT traversal relay operations
//! - [`PlainRpc`]: Point-to-point messaging
//!
//! ## Connection Management
//!
//! - Connections are cached in an LRU cache (bounded by `MAX_CACHED_CONNECTIONS`)
//! - Stale connections are cleaned up periodically
//! - Failed connections trigger cache invalidation
//! - Identity→contact resolution uses DHT's routing table via `ContactResolver` trait
//!
//! ## Security
//!
//! - All connections use mutual TLS with Ed25519 certificates
//! - Peer identity is verified from the TLS certificate
//! - Request/response sizes are bounded to prevent memory exhaustion
//! - Message sender identity is authenticated via TLS, not message fields

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

use crate::messages::{self as messages, PlainRequest, DhtNodeRequest, DhtNodeResponse, GossipSubRequest, RelayRequest, RelayResponse, RpcRequest, RpcResponse};
use crate::transport::SmartSock;
use crate::crypto::{extract_verified_identity, identity_to_sni};
use crate::relay::{Relay, handle_relay_request};
use crate::dht::DhtNode;
use crate::dht::Key;
use crate::identity::{Contact, Identity};
use crate::gossipsub::GossipSub;
use crate::protocols::{DhtNodeRpc, GossipSubRpc, RelayRpc, PlainRpc};


// ============================================================================
// Security Limits
// ============================================================================

/// Maximum size of RPC response payload (1 MiB).
/// SECURITY: Prevents memory exhaustion from oversized responses.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Maximum contacts returned in a single find_node/find_value response.
/// SECURITY: Limits routing table pollution from a single response.
const MAX_CONTACTS_PER_RESPONSE: usize = 100;

/// Maximum stored value size (matches messages::MAX_VALUE_SIZE).
const MAX_VALUE_SIZE: usize = crate::messages::MAX_VALUE_SIZE;

/// Maximum number of cached QUIC connections.
/// SCALABILITY: 1,000 connections × ~200 bytes = ~200 KB (constant, not O(N)).
/// SECURITY: Bounded LruCache prevents connection table DoS.
const MAX_CACHED_CONNECTIONS: usize = 1_000;

/// Maximum concurrent in-flight connection attempts.
/// SECURITY: Prevents memory exhaustion from parallel connection floods.
const MAX_IN_FLIGHT_CONNECTIONS: usize = 100;

/// Timeout after which idle connections are considered stale.
const CONNECTION_STALE_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for individual RPC stream operations.
const RPC_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Command channel capacity for the RPC actor.
/// Back-pressure applied when full to prevent unbounded queue growth.
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
    in_flight: std::collections::HashSet<Identity>,
}

impl RpcNodeActor {
    fn new(endpoint: Endpoint, client_config: ClientConfig) -> Self {
        Self {
            endpoint,
            client_config,
            connections: LruCache::new(NonZeroUsize::new(MAX_CACHED_CONNECTIONS).unwrap()),
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
                if let Some(cached) = self.connections.get(&peer_id)
                    && !cached.is_closed()
                {
                    return Ok(cached.connection.clone());
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

        // SECURITY: Bound in-flight set to prevent memory exhaustion from connection floods
        if self.in_flight.len() >= MAX_IN_FLIGHT_CONNECTIONS {
            anyhow::bail!("too many concurrent connection attempts (max {})", MAX_IN_FLIGHT_CONNECTIONS);
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
    cmd_tx: mpsc::Sender<RpcCommand>,
    smartsock: Option<Arc<SmartSock>>,
}

impl RpcNode {
    pub fn with_identity(
        endpoint: Endpoint,
        self_contact: Contact,
        client_config: ClientConfig,
        _our_peer_id: Identity,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(RPC_COMMAND_CHANNEL_SIZE);
        
        // Spawn the actor
        let actor = RpcNodeActor::new(endpoint.clone(), client_config.clone());
        tokio::spawn(actor.run(cmd_rx));
        
        Self {
            endpoint,
            self_contact,
            client_config,
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

            let response: RpcResponse = messages::deserialize_bounded(&response_bytes)
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
            // Cleanup: tunnel was created but couldn't be activated.
            // SECURITY/ROBUSTNESS: avoid leaking stale tunnels across retries.
            smartsock.remove_relay_tunnel(&peer_id, &session_id).await;
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

            let rpc_response: RpcResponse = messages::deserialize_bounded(&response_bytes)
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
                if let Some(ref v) = value
                    && v.len() > MAX_VALUE_SIZE
                {
                    warn!(
                        peer = %to.primary_addr().unwrap_or("<no addr>"),
                        size = v.len(),
                        max = MAX_VALUE_SIZE,
                        "peer returned oversized value, rejecting"
                    );
                    anyhow::bail!("value too large: {} bytes (max {})", v.len(), MAX_VALUE_SIZE);
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
impl GossipSubRpc for RpcNode {
    async fn send_gossipsub(&self, to: &Contact, message: GossipSubRequest) -> Result<()> {
        let request = RpcRequest::GossipSub(message);
        match self.rpc_raw(to, request).await? {
            RpcResponse::GossipSubAck => Ok(()),
            RpcResponse::Error { message } => anyhow::bail!("GossipSub rejected: {}", message),
            other => anyhow::bail!("unexpected response to GossipSub: {:?}", other),
        }
    }
}


#[async_trait]
impl PlainRpc for RpcNode {
    async fn send(&self, to: &Contact, request: Vec<u8>) -> Result<Vec<u8>> {
        let rpc_request = RpcRequest::Plain(request);
        match self.rpc_raw(to, rpc_request).await? {
            RpcResponse::Plain(response) => Ok(response),
            RpcResponse::Error { message } => anyhow::bail!("Plain request rejected: {}", message),
            other => anyhow::bail!("unexpected response to Plain: {:?}", other),
        }
    }
}


#[async_trait]
impl RelayRpc for RpcNode {
    async fn complete_relay_session(
        &self,
        relay: &Contact,
        from_peer: Identity,
        session_id: [u8; 16],
    ) -> Result<()> {
        let relay_addr = relay.primary_addr()
            .context("relay contact has no address")?;
        let relay_socket: std::net::SocketAddr = relay_addr.parse()
            .context("invalid relay address")?;
        
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
        smartsock.send_relay_probe(&from_peer, session_id).await?;
        
        debug!(
            session = hex::encode(session_id),
            from_peer = ?from_peer,
            relay = %relay_addr,
            "completed relay session as receiver"
        );
        
        Ok(())
    }

    // NOTE: register_for_signaling removed - mesh-only signaling now
    // NAT peers receive signals via GossipSub mesh instead of dedicated QUIC streams

    async fn request_mesh_relay(
        &self,
        mesh_peer: &Contact,
        from_peer: Identity,
        target_peer: Identity,
        session_id: [u8; 16],
    ) -> Result<RelayResponse> {
        debug!(
            mesh_peer = ?mesh_peer.identity,
            from_peer = ?from_peer,
            target_peer = ?target_peer,
            session = hex::encode(session_id),
            "requesting mesh relay from peer"
        );

        let conn = self
            .get_or_connect(mesh_peer)
            .await
            .context("failed to connect to mesh peer for relay")?;

        let request = RelayRequest::MeshRelay {
            from_peer,
            target_peer,
            session_id,
        };

        let response = self.send_relay_rpc(&conn, request).await?;
        Ok(response)
    }
}


const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_SIZE: usize = 64 * 1024;

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<N: DhtNodeRpc + GossipSubRpc + Clone + Send + Sync + 'static>(
    node: DhtNode<N>,
    gossipsub: Option<GossipSub<N>>,
    smartsock: Option<Arc<SmartSock>>,
    incoming: Incoming,
    direct_tx: Option<PlainRequest>,
) -> Result<()> {
    // Extract relay from smartsock
    let udprelay = smartsock.as_ref().and_then(|ss| ss.relay());
    let udprelay_addr = smartsock.as_ref().map(|ss| ss.local_address());

    debug!("handle_connection: accepting incoming connection");
    let connection = incoming.await.context("failed to accept connection")?;
    let remote = connection.remote_address();

    let Some(verified_identity) = extract_verified_identity(&connection) else {
        warn!(remote = %remote, "rejecting connection: could not verify peer identity");
        return Err(anyhow::anyhow!("could not verify peer identity from certificate"));
    };

    // Register incoming peer in DHT routing table for identity resolution.
    // This enables GossipSub to send messages to peers that connected to us.
    let incoming_contact = Contact::unsigned(verified_identity, vec![remote.to_string()]);
    node.observe_contact(incoming_contact).await;
    
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

    loop {
        let stream = match connection.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!(remote = %remote, "connection closed by application");
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
                // Clean up relay tunnels for this peer
                if let Some(ss) = &smartsock {
                    ss.cleanup_peer_relay_tunnels(&verified_identity).await;
                }
                break Err(e.into());
            }
        };

        let node = node.clone();
        let gossipsub_h = gossipsub.clone();
        let udprelay = udprelay.clone();
        let remote_addr = remote;
        let verified_id = verified_identity;
        let from_contact = Contact::unsigned(verified_id, vec![remote_addr.to_string()]);
        let direct_sender = direct_tx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_stream(node, gossipsub_h, udprelay, udprelay_addr, stream, remote_addr, from_contact, direct_sender).await
            {
                debug!(error = ?e, "stream error");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream<N: DhtNodeRpc + GossipSubRpc + Send + Sync + 'static>(
    node: DhtNode<N>,
    gossipsub: Option<GossipSub<N>>,
    udprelay: Option<Relay>,
    udprelay_addr: Option<SocketAddr>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    remote_addr: SocketAddr,
    from_contact: Contact,
    direct_tx: Option<PlainRequest>,
) -> Result<()> {
    let verified_identity = from_contact.identity;
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

    if let Some(claimed_id) = request.sender_identity()
        && claimed_id != verified_identity
    {
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

    // NOTE: RelayRequest::Register handling removed - mesh-only signaling
    // NAT peers now receive signals via GossipSub mesh instead of dedicated QUIC streams

    let response = match tokio::time::timeout(
        REQUEST_PROCESS_TIMEOUT,
        handle_rpc_request(
            node,
            request,
            remote_addr,
            from_contact,
            gossipsub,
            udprelay,
            udprelay_addr,
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
async fn handle_rpc_request<N: DhtNodeRpc + GossipSubRpc + Send + Sync + 'static>(
    node: DhtNode<N>,
    request: RpcRequest,
    remote_addr: SocketAddr,
    from_contact: Contact,
    gossipsub: Option<GossipSub<N>>,
    udprelay: Option<Relay>,
    udprelay_addr: Option<SocketAddr>,
    direct_tx: Option<PlainRequest>,
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
        RpcRequest::GossipSub(message) => {
            handle_gossipsub_rpc(&from_contact, message, gossipsub).await
        }
        RpcRequest::Plain(request_data) => {
            if let Some(tx) = direct_tx {
                // Create a oneshot channel for the response
                let (response_tx, response_rx) = tokio::sync::oneshot::channel();
                
                // Send request to handler and wait for response
                if tx.send((from_contact.identity, request_data, response_tx)).await.is_ok() {
                    // Wait for the handler to provide a response (with timeout)
                    match tokio::time::timeout(REQUEST_PROCESS_TIMEOUT, response_rx).await {
                        Ok(Ok(response_data)) => RpcResponse::Plain(response_data),
                        Ok(Err(_)) => RpcResponse::Error { 
                            message: "request handler dropped without responding".to_string() 
                        },
                        Err(_) => RpcResponse::Error { 
                            message: "request handler timed out".to_string() 
                        },
                    }
                } else {
                    RpcResponse::Error { 
                        message: "request handler channel closed".to_string() 
                    }
                }
            } else {
                // No handler registered - return empty response
                RpcResponse::Plain(Vec::new())
            }
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
            const MAX_PROBE_ADDR_LOG_BYTES: usize = 128;
            let probe_addr_log = {
                use std::borrow::Cow;

                let s = probe_addr.as_str();
                if s.len() <= MAX_PROBE_ADDR_LOG_BYTES {
                    Cow::Borrowed(s)
                } else {
                    let mut end = MAX_PROBE_ADDR_LOG_BYTES;
                    while end > 0 && !s.is_char_boundary(end) {
                        end = end.saturating_sub(1);
                    }
                    Cow::Owned(format!("{}…", &s[..end]))
                }
            };

            debug!(
                from = ?hex::encode(&from.identity.as_bytes()[..8]),
                probe_addr = %probe_addr_log.as_ref(),
                probe_addr_len = probe_addr.len(),
                "handling CHECK_REACHABILITY request"
            );
            
            // SECURITY: Validate probe_addr is a valid socket address to prevent
            // this node being used as an amplification vector against arbitrary targets.
            let probe_socket: SocketAddr = match probe_addr.parse() {
                Ok(addr) => addr,
                Err(_) => {
                    warn!(
                        from = ?hex::encode(&from.identity.as_bytes()[..8]),
                        probe_addr = %probe_addr_log.as_ref(),
                        probe_addr_len = probe_addr.len(),
                        "CHECK_REACHABILITY rejected: invalid socket address"
                    );
                    return DhtNodeResponse::Reachable { reachable: false };
                }
            };
            
            // SECURITY: Only allow probing addresses that share the same IP as the
            // connection's remote address. This prevents attackers from using us
            // to probe arbitrary third-party addresses (amplification attack vector).
            if probe_socket.ip() != _remote_addr.ip() {
                warn!(
                    from = ?hex::encode(&from.identity.as_bytes()[..8]),
                    probe_addr = %probe_addr_log.as_ref(),
                    probe_addr_len = probe_addr.len(),
                    remote_addr = %_remote_addr,
                    "CHECK_REACHABILITY rejected: probe IP does not match connection IP"
                );
                return DhtNodeResponse::Reachable { reachable: false };
            }
            
            // Create a contact for the probe address
            let probe_contact = Contact::single(from.identity, probe_addr.clone());
            
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
                probe_addr = %probe_addr_log.as_ref(),
                probe_addr_len = probe_addr.len(),
                reachable = reachable,
                "CHECK_REACHABILITY result"
            );
            
            DhtNodeResponse::Reachable { reachable }
        }
    }
}

async fn handle_gossipsub_rpc<N: GossipSubRpc + Send + Sync + 'static>(
    from: &Contact,
    message: GossipSubRequest,
    gossipsub: Option<GossipSub<N>>,
) -> RpcResponse {
    if let Some(gs) = gossipsub {
        trace!(
            from = ?hex::encode(&from.identity.as_bytes()[..8]),
            message = ?message,
            "dispatching GOSSIPSUB request to handler"
        );
        if let Err(e) = gs.handle_message(from, message).await {
            warn!(from = ?hex::encode(&from.identity.as_bytes()[..8]), error = %e, "GossipSub handler returned error");
            RpcResponse::Error {
                message: format!("GossipSub error: {}", e),
            }
        } else {
            RpcResponse::GossipSubAck
        }
    } else {
        warn!(
            from = ?hex::encode(&from.identity.as_bytes()[..8]),
            message = ?message,
            "received GOSSIPSUB request but no handler registered"
        );
        RpcResponse::Error {
            message: "GossipSub not enabled on this node".to_string(),
        }
    }
}
