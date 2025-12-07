//! High-level peer connectivity with automatic NAT traversal.
//!
//! This module provides [`PeerNetwork`] and its [`smart_connect`][PeerNetwork::smart_connect]
//! method, which is the **primary API for connecting to peers**. Consumers should use
//! `smart_connect` exclusively—it abstracts away all transport complexity including:
//!
//! - Direct QUIC connections when network conditions allow
//! - Automatic relay fallback when behind Symmetric NAT (CGNAT)
//! - NAT type detection and connection strategy selection
//!
//! # Why Use `smart_connect` Instead of Raw QUIC?
//!
//! **You don't need to manage quinn/QUIC connections directly.** The `smart_connect` method
//! returns a [`SmartConnection`] that works regardless of network topology:
//!
//! ```ignore
//! // This is all you need—no quinn APIs required in your code!
//! let conn = network.smart_connect(&endpoint_record).await?;
//! 
//! // Use the connection for DHT operations
//! network.rpc(&conn.connection().remote_address().to_string(), request).await?;
//! ```
//!
//! The returned [`SmartConnection`] transparently handles:
//! - **Public IP / Full Cone NAT**: Direct QUIC connection
//! - **Restricted Cone NAT**: Direct connection (no coordination needed)
//! - **Symmetric NAT (CGNAT)**: Automatic relay with E2E encryption
//!
//! # Cryptographic Addressing
//!
//! Peers are identified by their Ed25519 public key ([`Identity`]). To connect:
//!
//! 1. **Resolve**: Look up `BLAKE3(Identity)` in the DHT to get [`EndpointRecord`]
//! 2. **Smart Connect**: Call `smart_connect(&record)` — handles all connectivity
//! 3. **Verify**: TLS certificate verification happens automatically
//!
//! # NAT Traversal Strategy
//!
//! The network uses a relay-based NAT traversal strategy:
//!
//! 1. **Direct first**: Try direct UDP connection with 5s timeout
//! 2. **Relay fallback**: If blocked by NAT, connect via relay node
//! 3. **E2E encryption**: Relay forwards encrypted packets it cannot decrypt
//!
//! For CGNAT ↔ CGNAT scenarios, relay is used automatically since direct
//! connections are unreliable with Symmetric NAT.
//!
//! # Protocol
//!
//! The network uses the ALPN identifier `corium` for connection negotiation.
//! All RPC calls are serialized using bincode over QUIC streams.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;

use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::{ClientConfig, Connection, Endpoint};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use super::smartsock::SmartSock;

use super::connection::{
    CachedConnection,
    ConnectionHealthStats,
    ConnectionHealthStatus,
    ConnectionHealthSummary,
    SmartConnection,
    MAX_CACHED_CONNECTIONS,
    CONNECTION_HEALTH_CHECK_INTERVAL,
};
use super::tls::identity_to_sni;

use crate::dht::{Contact, DhtNetwork, Key};
use crate::identity::{EndpointRecord, Identity};
use crate::messages::{DhtRequest, DhtResponse};
use crate::net::relay::{NatType, detect_nat_type, generate_session_id, DIRECT_CONNECT_TIMEOUT};

// Re-export TLS utilities - pub when tests feature, pub(crate) otherwise
#[cfg(feature = "tests")]
pub use super::tls::{
    ALPN,
    generate_ed25519_cert,
    create_server_config,
    create_client_config,
    extract_public_key_from_cert,
    verify_peer_identity,
};

#[cfg(not(feature = "tests"))]
pub(crate) use super::tls::{
    ALPN,
    generate_ed25519_cert,
    create_server_config,
    create_client_config,
    extract_public_key_from_cert,
    verify_peer_identity,
};

/// Maximum size of an RPC response in bytes (1 MB).
/// Larger than request to accommodate FIND_VALUE responses with data.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Maximum number of contacts allowed in a single response.
///
/// # Security
///
/// Limits the number of Contact entries a peer can return in FIND_NODE
/// or FIND_VALUE responses. This prevents:
/// - Memory exhaustion from processing huge contact lists
/// - CPU exhaustion from sorting/processing thousands of entries
/// - Routing table pollution attacks
///
/// Set to 100, which is 5x the typical k=20 value. Legitimate nodes
/// should never return more than k contacts.
const MAX_CONTACTS_PER_RESPONSE: usize = 100;

/// Maximum size of a value in FIND_VALUE responses.
///
/// # Security
///
/// Limits the size of data returned in DHT lookups. This is separate from
/// MAX_RESPONSE_SIZE because we want to specifically limit user data.
/// Set to 1MB to allow reasonably large values while preventing abuse.
const MAX_VALUE_SIZE: usize = crate::messages::MAX_VALUE_SIZE;

/// High-level network layer with automatic NAT traversal.
///
/// `PeerNetwork` provides the [`smart_connect`][Self::smart_connect] method, which is the
/// **recommended way to connect to peers**. It handles all transport complexity internally:
///
/// - Direct QUIC connections when possible
/// - Automatic relay fallback for Symmetric NAT (CGNAT)
/// - NAT type detection via [`detect_nat`][Self::detect_nat]
/// - Connection caching and reuse (LRU, 1,000 connections max)
/// - Passive health monitoring via Quinn path statistics
///
/// # Connection Cache
///
/// QUIC connections are cached with the following behavior:
/// - **LRU eviction**: Bounded to [`MAX_CACHED_CONNECTIONS`] (1,000)
/// - **Stale detection**: Connections idle >60s get passive health check
/// - **Passive health**: Uses Quinn's RTT estimates, no invasive probing
/// - **Auto-invalidation**: Failed RPCs remove connection from cache
///
/// # RPC Limits
///
/// - **Max response size**: 1 MB ([`MAX_RESPONSE_SIZE`])
/// - **Max contacts per response**: 100 (5x typical k=20)
/// - **Max value size**: 1 MB (same as DHT storage limit)
///
/// # Recommended Usage
///
/// ```ignore
/// // Create network (quinn setup happens once at startup)
/// let network = PeerNetwork::with_identity(endpoint, contact, config, identity);
///
/// // Detect NAT type during bootstrap
/// network.detect_nat(&bootstrap_contacts).await;
///
/// // Connect to any peer—NAT traversal is automatic!
/// let conn = network.smart_connect(&peer_record).await?;
/// ```
#[derive(Clone)]
pub struct PeerNetwork {
    /// The quinn endpoint used for QUIC connections.
    pub endpoint: Endpoint,
    /// Contact info for the local node (included in all RPC requests).
    pub self_contact: Contact,
    /// Client configuration for outgoing connections.
    client_config: ClientConfig,
    /// Our own peer ID for relay negotiations.
    our_peer_id: Option<Identity>,
    /// Detected NAT type (for connection strategy decisions).
    nat_type: Arc<RwLock<NatType>>,
    /// Our public address as seen by STUN servers.
    public_addr: Arc<RwLock<Option<SocketAddr>>>,
    /// Cached connections to peers for connection reuse.
    /// QUIC connections are long-lived and multiplexed, so we reuse them
    /// rather than creating a new connection for each RPC.
    /// Uses LruCache to prevent unbounded memory growth.
    /// Uses CachedConnection to track liveness.
    connections: Arc<RwLock<LruCache<Identity, CachedConnection>>>,
    /// SmartSock for seamless path switching.
    /// When set, peers are automatically registered for transparent relay/direct switching.
    smartsock: Option<Arc<SmartSock>>,
}

impl PeerNetwork {
    /// Create a new PeerNetwork with the given endpoint and self contact.
    pub fn new(endpoint: Endpoint, self_contact: Contact, client_config: ClientConfig) -> Self {
        Self {
            endpoint,
            self_contact,
            client_config,
            our_peer_id: None,
            nat_type: Arc::new(RwLock::new(NatType::Unknown)),
            public_addr: Arc::new(RwLock::new(None)),
            connections: Arc::new(RwLock::new(LruCache::<Identity, CachedConnection>::new(
                NonZeroUsize::new(MAX_CACHED_CONNECTIONS).unwrap()
            ))),
            smartsock: None,
        }
    }

    /// Create a PeerNetwork with our Identity for relay negotiations.
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

    /// Attach a SmartSock for seamless path switching.
    ///
    /// When set, peers connected via `smart_connect` are automatically registered
    /// with the SmartSock for transparent relay↔direct path switching.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (endpoint, smartsock) = SmartSock::bind_endpoint(addr, server_config).await?;
    /// let network = PeerNetwork::with_identity(endpoint, contact, client_config, identity)
    ///     .with_smartsock(smartsock);
    /// ```
    pub fn with_smartsock(mut self, smartsock: Arc<SmartSock>) -> Self {
        self.smartsock = Some(smartsock);
        self
    }

    /// Get the SmartSock, if configured.
    pub fn smartsock(&self) -> Option<&Arc<SmartSock>> {
        self.smartsock.as_ref()
    }

    /// Get our detected NAT type.
    pub async fn nat_type(&self) -> NatType {
        *self.nat_type.read().await
    }

    /// Get our public address (if detected).
    pub async fn public_addr(&self) -> Option<SocketAddr> {
        *self.public_addr.read().await
    }

    /// Detect our NAT type by querying multiple STUN-like servers.
    ///
    /// Queries at least 2 peers for our public address and compares results:
    /// - **Addresses match**: Cone NAT (hole punch may work)
    /// - **Addresses differ**: Symmetric NAT (relay required for CGNAT↔CGNAT)
    ///
    /// # Algorithm
    ///
    /// 1. Query first two contacts via `WhatIsMyAddr` RPC
    /// 2. Compare returned mapped addresses
    /// 3. Store result in `nat_type` and `public_addr` for `smart_connect` decisions
    ///
    /// # Arguments
    ///
    /// * `stun_contacts` - At least 2 contacts to query (returns Unknown if <2)
    ///
    /// # Returns
    ///
    /// The detected NAT type. Also stored internally for `smart_connect` decisions.
    pub async fn detect_nat(&self, stun_contacts: &[Contact]) -> NatType {
        if stun_contacts.len() < 2 {
            debug!("not enough STUN contacts for NAT detection, need at least 2");
            return NatType::Unknown;
        }

        // Query first two contacts for our public address
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

        // Parse our local address for comparison
        let local_addr: SocketAddr = self.self_contact.addr.parse().unwrap_or_else(|_| {
            "0.0.0.0:0".parse().unwrap()
        });

        // Detect NAT type
        let report = detect_nat_type(
            mapped_addrs.first().copied(),
            mapped_addrs.get(1).copied(),
            local_addr,
        );

        // Store results
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

    /// Check if we're behind Symmetric NAT (CGNAT).
    ///
    /// When true, hole punching won't work and relay is required for mesh connectivity.
    pub async fn is_symmetric_nat(&self) -> bool {
        matches!(*self.nat_type.read().await, NatType::Symmetric)
    }

    /// Parse a contact's address from the stored socket address string.
    fn parse_addr(&self, contact: &Contact) -> Result<SocketAddr> {
        contact
            .addr
            .parse()
            .with_context(|| format!("invalid socket address: {}", contact.addr))
    }

    /// Connect to a remote contact and return the connection.
    /// This creates a NEW connection, bypassing the cache. 
    /// For cached connections, use `get_or_connect` instead.
    /// 
    /// # Security
    /// 
    /// Uses SNI-based identity pinning. The peer's identity is encoded in the SNI,
    /// and the TLS handshake verifies that the certificate's public key matches the identity.
    async fn connect(&self, contact: &Contact) -> Result<Connection> {
        let addr = self.parse_addr(contact)?;
        let sni = identity_to_sni(&contact.identity);
        
        // Use the peer's identity (public key) as the SNI.
        // The custom Ed25519CertVerifier will verify that the peer's certificate
        // public key matches this identity during the handshake.
        let conn = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, &sni)
            .with_context(|| format!("failed to initiate connection to {}", addr))?
            .await
            .with_context(|| format!("failed to establish connection to {}", addr))?;
        
        Ok(conn)
    }

    /// Get an existing connection or create a new one.
    ///
    /// QUIC connections are long-lived and multiplexed, so we reuse them
    /// rather than paying the 1-RTT (or 3-RTT for full handshake) overhead
    /// for each RPC.
    ///
    /// # Cache Lookup Strategy
    ///
    /// 1. **Closed check**: If connection is explicitly closed, remove and reconnect
    /// 2. **Fresh check**: If used within 60s, reuse immediately (no probe)
    /// 3. **Stale check**: If idle >60s, run passive health check via Quinn stats:
    ///    - Check `close_reason()` for explicit closure
    ///    - Check RTT estimate is non-zero and <4s
    ///    - On failure, remove and reconnect
    ///
    /// # Bounds
    ///
    /// - **LRU eviction**: At 1,000 connections, oldest are evicted
    /// - **No blocking I/O**: Passive check uses Quinn's internal RTT estimate
    async fn get_or_connect(&self, contact: &Contact) -> Result<Connection> {
        let peer_id = contact.identity;
        
        // Fast path: check if we have a cached connection
        // Note: LruCache.get() requires &mut self, so we need write lock
        {
            let mut cache = self.connections.write().await;
            if let Some(cached) = cache.get_mut(&peer_id) {
                // Check 1: Connection explicitly closed
                if cached.is_closed() {
                    trace!(
                        peer = hex::encode(&peer_id.as_bytes()[..8]),
                        "cached connection is closed, removing"
                    );
                    cache.pop(&peer_id);
                    // Fall through to create new connection
                }
                // Check 2: Connection is fresh (used recently) - reuse without probe
                else if !cached.is_stale() {
                    return Ok(cached.connection.clone());
                }
                // Check 3: Connection is stale - use passive health check via Quinn stats
                else {
                    // Use passive health check - no need to drop lock since it's synchronous
                    if let Some(rtt) = cached.check_health_passive() {
                        // Connection appears healthy based on Quinn's path statistics
                        cached.record_health_check_success(rtt);
                        cached.mark_success();
                        return Ok(cached.connection.clone());
                    } else {
                        // Connection is closed or degraded, record failure and remove it
                        debug!(
                            peer = hex::encode(&peer_id.as_bytes()[..8]),
                            "stale connection failed passive health check, removing"
                        );
                        cached.record_failure();
                        cache.pop(&peer_id);
                        // Fall through to create new connection
                    }
                }
            }
        }
        
        // Slow path: create a new connection and cache it
        let conn = self.connect(contact).await?;
        
        // Cache the new connection with current timestamp
        // LruCache automatically evicts least-recently-used entries when full
        {
            let mut cache = self.connections.write().await;
            cache.put(peer_id, CachedConnection::new(conn.clone()));
        }
        
        Ok(conn)
    }

    /// Invalidate a cached connection (e.g., after RPC failure).
    ///
    /// # Security
    ///
    /// Call this when an RPC fails to ensure we don't keep retrying with
    /// a broken connection. This prevents timeout cascades where multiple
    /// callers wait on the same dead connection.
    async fn invalidate_connection(&self, peer_id: &Identity) {
        let mut cache = self.connections.write().await;
        if cache.pop(peer_id).is_some() {
            debug!(
                peer = hex::encode(&peer_id.as_bytes()[..8]),
                "invalidated cached connection after failure"
            );
        }
    }

    /// Mark a connection as successfully used.
    ///
    /// Updates the last_success timestamp to prevent premature staleness checks.
    async fn mark_connection_success(&self, peer_id: &Identity) {
        let mut cache = self.connections.write().await;
        if let Some(cached) = cache.get_mut(peer_id) {
            cached.mark_success();
        }
    }

    /// Run a single health check cycle on all cached connections.
    ///
    /// Checks connections that need health checks (not checked in last 15s)
    /// and removes unhealthy ones.
    ///
    /// # Passive Health Check
    ///
    /// Uses Quinn's internal path statistics rather than invasive stream probing:
    /// - `close_reason()`: Connection explicitly closed?
    /// - `rtt()`: Non-zero and reasonable (<4s)?
    ///
    /// # State Transitions
    ///
    /// - **Pass**: Record RTT sample, mark healthy
    /// - **Fail**: Increment failure counter, mark degraded
    /// - **3 failures**: Mark unhealthy and remove from cache
    ///
    /// # Returns
    ///
    /// `(checked, removed)` - Number of connections checked and removed.
    pub async fn check_connection_health(&self) -> (usize, usize) {
        // Perform health checks while holding the write lock
        // This is now fast since we use passive stats instead of I/O probes
        let mut cache = self.connections.write().await;
        
        let mut checked = 0;
        let mut removed = 0;
        let mut to_remove = Vec::new();

        for (peer_id, cached) in cache.iter_mut() {
            if !cached.needs_health_check() || cached.is_closed() {
                continue;
            }
            
            checked += 1;
            
            match cached.check_health_passive() {
                Some(rtt) => {
                    // Connection appears healthy based on Quinn's path statistics
                    cached.record_health_check_success(rtt);
                    trace!(
                        peer = hex::encode(&peer_id.as_bytes()[..8]),
                        rtt_ms = rtt.as_millis(),
                        "connection health check passed"
                    );
                }
                None => {
                    // Connection is closed or degraded
                    cached.record_failure();
                    
                    // Mark for removal if unhealthy
                    if cached.health_status == ConnectionHealthStatus::Unhealthy {
                        to_remove.push(*peer_id);
                        removed += 1;
                        debug!(
                            peer = hex::encode(&peer_id.as_bytes()[..8]),
                            "removed unhealthy connection"
                        );
                    }
                }
            }
        }

        // Remove unhealthy connections
        for peer_id in to_remove {
            cache.pop(&peer_id);
        }

        if checked > 0 {
            trace!(
                checked,
                removed,
                "connection health check cycle complete"
            );
        }

        (checked, removed)
    }

    /// Get health statistics for all cached connections.
    ///
    /// Returns a snapshot of health metrics for observability and debugging.
    pub async fn connection_health_stats(&self) -> Vec<ConnectionHealthStats> {
        let cache = self.connections.read().await;
        cache.iter()
            .map(|(_, c)| c.health_stats())
            .collect()
    }

    /// Get overall connection cache health summary.
    ///
    /// Returns counts by health status for high-level monitoring.
    pub async fn connection_health_summary(&self) -> ConnectionHealthSummary {
        let cache = self.connections.read().await;
        let mut summary = ConnectionHealthSummary::default();
        
        for (_, c) in cache.iter() {
            summary.total += 1;
            match c.health_status {
                ConnectionHealthStatus::Healthy => summary.healthy += 1,
                ConnectionHealthStatus::Degraded => summary.degraded += 1,
                ConnectionHealthStatus::Unhealthy => summary.unhealthy += 1,
                ConnectionHealthStatus::Unknown => summary.unknown += 1,
            }
            
            if let Some(rtt) = c.average_rtt_ms() {
                summary.rtt_samples.push(rtt);
            }
        }
        
        // Calculate average RTT across all connections
        if !summary.rtt_samples.is_empty() {
            summary.average_rtt_ms = Some(
                summary.rtt_samples.iter().sum::<f32>() / summary.rtt_samples.len() as f32
            );
        }
        
        summary
    }

    /// Run the health monitor loop as a background task.
    ///
    /// This runs periodic health checks on all cached connections and
    /// removes unhealthy ones proactively. Should be spawned as a background
    /// task during node initialization.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let network = PeerNetwork::new(...);
    /// tokio::spawn(async move {
    ///     network.run_health_monitor().await;
    /// });
    /// ```
    pub async fn run_health_monitor(&self) {
        let mut interval = tokio::time::interval(CONNECTION_HEALTH_CHECK_INTERVAL);
        
        loop {
            interval.tick().await;
            let (checked, removed) = self.check_connection_health().await;
            
            if removed > 0 {
                debug!(
                    checked,
                    removed,
                    "health monitor removed unhealthy connections"
                );
            }
        }
    }

    /// Send an RPC request and receive the response.
    ///
    /// # Security
    ///
    /// On failure, the cached connection is invalidated to prevent timeout
    /// cascades where multiple callers retry with a broken connection.
    /// On success, the connection's last_success timestamp is updated.
    pub(crate) async fn rpc(&self, contact: &Contact, request: DhtRequest) -> Result<DhtResponse> {
        let peer_id = contact.identity;
        let conn = self.get_or_connect(contact).await?;
        
        // Attempt the RPC, invalidating the connection cache on failure
        let result = self.rpc_inner(&conn, contact, request).await;
        
        match &result {
            Ok(_) => {
                // Success - update last_success timestamp
                self.mark_connection_success(&peer_id).await;
            }
            Err(e) => {
                // Failure - check if it's a connection-level error that should invalidate
                // the cache. We check for common QUIC connection errors.
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

    /// Internal RPC implementation (separated to allow cache management in rpc()).
    async fn rpc_inner(&self, conn: &Connection, contact: &Contact, request: DhtRequest) -> Result<DhtResponse> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open bidirectional stream")?;

        // Serialize and send request
        let request_bytes = bincode::serialize(&request).context("failed to serialize request")?;
        let len = request_bytes.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&request_bytes).await?;
        send.finish()?;

        // Receive response
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Validate response size to prevent memory exhaustion
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

        let response: DhtResponse =
            crate::messages::deserialize_response(&response_bytes).context("failed to deserialize response")?;
        Ok(response)
    }

    /// Query a remote node for our public address (STUN-like).
    ///
    /// This sends a `WhatIsMyAddr` request to the specified contact and returns
    /// our observed public IP:port as seen by that node. Useful for:
    /// - NAT type detection (compare responses from multiple servers)
    /// - Discovering our public address for hole punching
    /// - Detecting address changes (network migration)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let relay_contact = Contact { id: relay_id, addr: "1.2.3.4:5678".into() };
    /// let my_public_addr = network.what_is_my_addr(&relay_contact).await?;
    /// println!("My public address: {}", my_public_addr);
    /// ```
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

    /// Discover our public address by querying multiple nodes.
    ///
    /// Queries up to `count` nodes and returns addresses where at least 2 nodes
    /// agree, helping detect consistent NAT behavior vs symmetric NAT.
    ///
    /// Returns `(consistent_addr, all_observed)` where:
    /// - `consistent_addr` is Some if multiple nodes see the same address
    /// - `all_observed` contains all unique addresses seen
    pub async fn discover_public_addr(
        &self,
        contacts: &[Contact],
        count: usize,
    ) -> (Option<SocketAddr>, Vec<SocketAddr>) {
        use std::collections::HashMap;
        
        let mut addr_counts: HashMap<SocketAddr, usize> = HashMap::new();
        let mut all_addrs = Vec::new();
        
        for contact in contacts.iter().take(count) {
            if let Ok(addr) = self.what_is_my_addr(contact).await {
                *addr_counts.entry(addr).or_insert(0) += 1;
                if !all_addrs.contains(&addr) {
                    all_addrs.push(addr);
                }
            }
        }
        
        // Find address seen by at least 2 nodes
        let consistent = addr_counts
            .into_iter()
            .find(|(_, count)| *count >= 2)
            .map(|(addr, _)| addr);
        
        (consistent, all_addrs)
    }

    /// Connect to a peer by their cryptographic identity.
    ///
    /// This method:
    /// 1. Resolves the Identity to a network address via the provided resolver
    /// 2. Establishes a QUIC connection
    /// 3. Verifies the peer's TLS certificate matches their Identity
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The Ed25519 public key of the peer to connect to
    /// * `addrs` - Known addresses for this peer (from DHT lookup or cache)
    ///
    /// # Returns
    ///
    /// A verified QUIC connection to the peer.
    pub async fn connect_to_peer(
        &self,
        peer_id: &Identity,
        addrs: &[String],
    ) -> Result<Connection> {
        // Try each address until one works
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

    /// Connect to an address and verify the peer's identity.
    async fn connect_and_verify(
        &self,
        addr: SocketAddr,
        expected_peer_id: &Identity,
    ) -> Result<Connection> {
        // Use the peer's identity (public key) as the SNI.
        // The custom Ed25519CertVerifier will verify that the peer's certificate
        // public key matches this identity during the handshake.
        let sni = identity_to_sni(expected_peer_id);
        let conn = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, &sni)
            .with_context(|| format!("failed to initiate connection to {}", addr))?
            .await
            .with_context(|| format!("failed to establish connection to {}", addr))?;
        
        // Identity verification is now handled during the TLS handshake via SNI pinning.
        
        Ok(conn)
    }

    /// Create a Contact from a PeerId and address.
    ///
    /// This is a convenience method for creating contacts when you know
    /// both the peer's identity and their current address.
    pub fn contact_from_peer(peer_id: &Identity, addr: String) -> Contact {
        Contact {
            identity: *peer_id,
            addr,
        }
    }

    /// Smart connect: tries direct first, falls back to relay on failure.
    ///
    /// This implements the NAT traversal strategy:
    /// 1. Check NAT type - if Symmetric (CGNAT), skip direct and use relay
    /// 2. Try direct UDP connection with timeout
    /// 3. If blocked by NAT, negotiate relay via sDHT
    /// 4. Both connect outbound to relay (always traverses NAT)
    /// 5. Relay forwards E2E-encrypted packets it cannot read
    ///
    /// For CGNAT ↔ CGNAT scenarios, this automatically uses relay since
    /// hole punching is unreliable with Symmetric NAT.
    ///
    /// # This Is the Primary Connection API
    ///
    /// **Use this method instead of managing QUIC connections directly.**
    /// It abstracts all transport complexity, so your code works regardless
    /// of NAT topology. The returned [`SmartConnection`] provides a unified
    /// interface whether the connection is direct or relayed.
    ///
    /// # Arguments
    ///
    /// * `record` - The peer's endpoint record from DHT (resolve via DHT lookup)
    ///
    /// # Returns
    ///
    /// A [`SmartConnection`] that works transparently across all NAT types.
    /// Use [`SmartConnection::connection()`] to access the underlying transport.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Resolve peer's endpoint record from DHT
    /// let record = dht.resolve_identity(&peer_identity).await?;
    ///
    /// // Connect—NAT traversal handled automatically
    /// let conn = network.smart_connect(&record).await?;
    ///
    /// // Connection works regardless of network topology
    /// println!("Connected: direct={}", conn.is_direct());
    /// ```
    pub async fn smart_connect(&self, record: &EndpointRecord) -> Result<SmartConnection> {
        let peer_id = &record.identity;
        
        // Check if we're behind Symmetric NAT (CGNAT)
        // In this case, skip direct connection attempts as hole punching won't work
        let our_nat_type = *self.nat_type.read().await;
        let skip_direct = our_nat_type == NatType::Symmetric;
        
        if skip_direct {
            debug!(
                peer = ?peer_id,
                nat_type = ?our_nat_type,
                "Symmetric NAT detected, skipping direct connection (CGNAT mode)"
            );
        }

        // Try direct connection if:
        // - We have addresses AND
        // - We're NOT behind Symmetric NAT (or Unknown - try anyway)
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
                    
                    // Register peer with SmartSock for seamless path management
                    if let Some(smartsock) = &self.smartsock {
                        let addrs: Vec<std::net::SocketAddr> = record.addrs.iter()
                            .filter_map(|a| a.parse().ok())
                            .collect();
                        smartsock.register_peer(*peer_id, addrs).await;
                        debug!(peer = ?peer_id, "registered peer with SmartSock (direct)");
                    }
                    
                    return Ok(SmartConnection::Direct(conn));
                }
                Ok(Err(e)) => {
                    debug!(peer = ?peer_id, error = %e, "direct connection failed");
                }
                Err(_) => {
                    debug!(peer = ?peer_id, "direct connection timed out");
                }
            }
        }

        // Direct failed or no direct addresses - try relay
        if record.has_relays() {
            debug!(peer = ?peer_id, relays = record.relays.len(), "trying relay connection");
            
            let our_peer_id = self.our_peer_id.as_ref()
                .context("cannot use relay without our_peer_id set")?;
            
            // Pick the first available relay from peer's list
            // Simple strategy: peer advertised these relays, so they should work
            let relay = record.relays.first()
                .context("no relays available")?;
            
            let relay_peer_id = relay.relay_identity;
            let session_id = generate_session_id()
                .context("failed to generate session ID")?;
            
            // Connect to the relay
            let relay_conn = self.connect_to_peer(&relay_peer_id, &relay.relay_addrs).await
                .context("failed to connect to relay")?;
            
            // Request relay session
            let request = DhtRequest::RelayConnect {
                from_peer: *our_peer_id,
                target_peer: *peer_id,
                session_id,
            };
            
            let response = self.send_rpc(&relay_conn, request).await?;
            
            // Keep direct addrs for potential upgrade later
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
                    
                    // Parse relay data address for SmartSock (where to send CRLY frames)
                    let data_addr: Option<std::net::SocketAddr> = relay_data_addr.parse().ok();
                    
                    // Register peer and relay tunnel with SmartSock
                    if let (Some(smartsock), Some(relay_data)) = (&self.smartsock, data_addr) {
                        let addrs: Vec<std::net::SocketAddr> = direct_addrs.iter()
                            .filter_map(|a| a.parse().ok())
                            .collect();
                        smartsock.register_peer(*peer_id, addrs).await;
                        smartsock.add_relay_tunnel(peer_id, session_id, relay_data).await;
                        smartsock.use_relay_path(peer_id, session_id).await;
                        debug!(peer = ?peer_id, "registered peer with SmartSock (relay pending)");
                    }
                    
                    Ok(SmartConnection::RelayPending {
                        relay_connection: relay_conn,
                        session_id,
                        relay_peer: relay_peer_id,
                        direct_addrs,
                    })
                }
                DhtResponse::RelayConnected { session_id, relay_data_addr } => {
                    debug!(
                        peer = ?peer_id,
                        relay = ?relay_peer_id,
                        session = hex::encode(session_id),
                        relay_data = %relay_data_addr,
                        "relay session established"
                    );
                    
                    // Parse relay data address for SmartSock (where to send CRLY frames)
                    let data_addr: Option<std::net::SocketAddr> = relay_data_addr.parse().ok();
                    
                    // Register peer and relay tunnel with SmartSock
                    if let (Some(smartsock), Some(relay_data)) = (&self.smartsock, data_addr) {
                        let addrs: Vec<std::net::SocketAddr> = direct_addrs.iter()
                            .filter_map(|a| a.parse().ok())
                            .collect();
                        smartsock.register_peer(*peer_id, addrs).await;
                        smartsock.add_relay_tunnel(peer_id, session_id, relay_data).await;
                        smartsock.use_relay_path(peer_id, session_id).await;
                        debug!(peer = ?peer_id, "registered peer with SmartSock (relay connected)");
                    }
                    
                    Ok(SmartConnection::Relayed {
                        relay_connection: relay_conn,
                        session_id,
                        relay_peer: relay_peer_id,
                        direct_addrs,
                    })
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

    /// Send an RPC request on an existing connection.
    async fn send_rpc(&self, conn: &Connection, request: DhtRequest) -> Result<DhtResponse> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open bidirectional stream")?;

        // Serialize and send request
        let request_bytes = bincode::serialize(&request).context("failed to serialize request")?;
        let len = request_bytes.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&request_bytes).await?;
        send.finish()?;

        // Receive response
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Validate response size to prevent memory exhaustion
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

        let response: DhtResponse =
            crate::messages::deserialize_response(&response_bytes).context("failed to deserialize response")?;
        Ok(response)
    }

    /// Attempt to upgrade a relayed connection to direct.
    ///
    /// This should be called periodically for relayed connections to check
    /// if direct connectivity has become available (e.g., NAT mapping changed,
    /// peer moved networks, firewall rules updated).
    ///
    /// # How it works
    ///
    /// 1. Tries direct connection to peer's known addresses with short timeout
    /// 2. If successful, verifies peer identity via TLS certificate
    /// 3. Returns the **new** direct connection (caller should close relay session)
    ///
    /// # Important: This is NOT QUIC migration
    ///
    /// QUIC connection migration allows changing source IP (e.g., WiFi→cellular)
    /// but cannot switch to a different remote endpoint. Relay→direct requires
    /// a **new connection** because the relay server and peer are different hosts.
    ///
    /// After upgrade, the caller must:
    /// 1. Replace the old `SmartConnection` with the new direct connection
    /// 2. Call [`close_relay_session`][Self::close_relay_session] to clean up
    ///
    /// # Benefits of upgrading
    ///
    /// - **Lower latency**: Direct path vs relay hop
    /// - **Reduced relay load**: Frees relay capacity for other peers
    /// - **Better throughput**: No relay bottleneck
    ///
    /// # When to call
    ///
    /// - Periodically (e.g., every 30-60 seconds) for long-lived connections
    /// - After network change events (WiFi reconnect, etc.)
    /// - When relay latency degrades
    pub async fn try_upgrade_to_direct(
        &self,
        peer_id: &Identity,
        current: &SmartConnection,
    ) -> Result<Option<Connection>> {
        // Only attempt for relayed connections with direct addresses
        let direct_addrs = match current {
            SmartConnection::Direct(_) => return Ok(None), // Already direct
            SmartConnection::RelayPending { direct_addrs, .. } => direct_addrs,
            SmartConnection::Relayed { direct_addrs, .. } => direct_addrs,
        };

        if direct_addrs.is_empty() {
            return Ok(None); // No addresses to try
        }

        debug!(
            peer = ?peer_id,
            addrs = ?direct_addrs,
            "attempting relay-to-direct upgrade"
        );

        // Try direct connection with short timeout
        let upgrade_timeout = std::time::Duration::from_secs(3);
        
        let result = tokio::time::timeout(
            upgrade_timeout,
            self.connect_to_peer(peer_id, direct_addrs),
        )
        .await;

        match result {
            Ok(Ok(conn)) => {
                debug!(peer = ?peer_id, "relay-to-direct upgrade successful!");
                Ok(Some(conn))
            }
            Ok(Err(e)) => {
                debug!(peer = ?peer_id, error = %e, "direct upgrade failed");
                Ok(None)
            }
            Err(_) => {
                debug!(peer = ?peer_id, "direct upgrade timed out");
                Ok(None)
            }
        }
    }

    /// Close a relay session after upgrading to direct.
    ///
    /// Call this after successfully upgrading via `try_upgrade_to_direct`.
    /// Note: With the UDP forwarder, sessions are cleaned up automatically on timeout.
    pub async fn close_relay_session(&self, session_id: [u8; 16]) -> Result<()> {
        // UDP forwarder will timeout the session automatically
        debug!(session = hex::encode(session_id), "relay session closed (will timeout on forwarder)");
        Ok(())
    }
}

#[async_trait]
impl DhtNetwork for PeerNetwork {
    /// Send a FIND_NODE RPC to find contacts near a target identity.
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>> {
        let request = DhtRequest::FindNode {
            from: self.self_contact.clone(),
            target,
        };
        match self.rpc(to, request).await? {
            DhtResponse::Nodes(nodes) => {
                // Limit contacts to prevent memory/CPU exhaustion
                if nodes.len() > MAX_CONTACTS_PER_RESPONSE {
                    warn!(
                        peer = %to.addr,
                        count = nodes.len(),
                        max = MAX_CONTACTS_PER_RESPONSE,
                        "peer returned too many contacts, truncating"
                    );
                    // Truncate rather than reject to be tolerant of edge cases
                    Ok(nodes.into_iter().take(MAX_CONTACTS_PER_RESPONSE).collect())
                } else {
                    Ok(nodes)
                }
            }
            other => anyhow::bail!("unexpected response to FindNode: {:?}", other),
        }
    }

    /// Send a FIND_VALUE RPC to retrieve a value or get closer contacts.
    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)> {
        let request = DhtRequest::FindValue {
            from: self.self_contact.clone(),
            key,
        };
        match self.rpc(to, request).await? {
            DhtResponse::Value { value, closer } => {
                // Validate value size
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
                
                // Limit contacts to prevent memory/CPU exhaustion
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

    /// Send a STORE RPC to store a key-value pair on a node.
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

    /// Send a PING RPC to check if a node is responsive.
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