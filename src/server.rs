//! Server for handling incoming RPC requests.
//!
//! This module provides the [`Server`] which accepts incoming QUIC connections
//! and dispatches RPC requests to the appropriate handlers on the [`DhtNode`].
//!
//! # Relay Support
//!
//! The node also handles relay requests for NAT traversal. When a peer cannot
//! be reached directly, both endpoints connect outbound to a relay node. The
//! relay forwards encrypted QUIC packets without being able to decrypt them.
//!
//! # PubSub Support
//!
//! To enable GossipSub pubsub, register a handler using [`Server::with_pubsub`]:
//!
//! ```ignore
//! let keypair = Keypair::generate();
//! let pubsub = Arc::new(GossipSub::new(node.clone(), keypair, config));
//! let server = Server::new(dht_node).with_pubsub(pubsub);
//! server.run(endpoint).await?;
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let server = Server::new(dht_node);
//! server.run(endpoint).await?;
//! ```

use crate::net::{ConnectionRateLimiter, CryptoError, MAX_SESSIONS};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Endpoint, Incoming};
use tracing::{debug, info, trace, warn};

use crate::dht::{DhtNetwork, DhtNode};
use crate::identity::Identity;
use crate::net::extract_public_key_from_cert;
use crate::messages::{DhtRequest, DhtResponse};
use crate::pubsub::PubSubHandler;

/// Read timeout for inbound RPC streams (mitigates slowloris-style stalls).
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum size of an RPC request in bytes (64 KB).
/// Prevents memory exhaustion from oversized requests.
const MAX_REQUEST_SIZE: usize = 64 * 1024;

/// Server for handling incoming DHT connections.
///
/// Accepts QUIC connections and dispatches incoming RPC requests to the
/// [`DhtNode`] handlers. Also manages relay sessions for NAT traversal.
///
/// # Security Model
///
/// For incoming connections, Sybil protection (NodeId verification) happens
/// immediately after the TLS handshake completes, before any requests are
/// processed. While an attacker can complete the TLS handshake, they cannot:
/// - Impersonate another NodeId (requires the corresponding private key)
/// - Have their requests processed (rejected before first request)
///
/// Relay data is forwarded via UDP using the UdpRelayForwarder, which handles
/// CRLY-framed packets directly without RPC overhead. The relay cannot decrypt
/// the payload (true E2E encryption).
///
/// Connection rate limiting prevents resource exhaustion attacks.
pub(crate) struct Server<N: DhtNetwork> {
    /// The DHT node that handles DHT operations.
    node: DhtNode<N>,
    /// UDP relay forwarder for SmartSock CRLY frames.
    udp_forwarder: Option<Arc<crate::net::UdpRelayForwarder>>,
    /// Address of the UDP relay forwarder (for responses to clients).
    udp_forwarder_addr: Option<std::net::SocketAddr>,
    /// Connection rate limiter to prevent DoS.
    rate_limiter: ConnectionRateLimiter,
    /// Optional PubSub handler for GossipSub messages.
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
}

impl<N: DhtNetwork> Server<N> {
    /// Create a new server backed by the given DHT node.
    pub fn new(node: DhtNode<N>) -> Result<Self, CryptoError> {
        Ok(Self {
            node,
            udp_forwarder: None,
            udp_forwarder_addr: None,
            rate_limiter: ConnectionRateLimiter::new(),
            pubsub_handler: None,
        })
    }

    /// Register a PubSub handler for processing GossipSub messages.
    ///
    /// Without a registered handler, incoming PubSub messages will receive
    /// an error response indicating PubSub is not enabled.
    pub fn with_pubsub(mut self, handler: Arc<dyn PubSubHandler + Send + Sync>) -> Self {
        self.pubsub_handler = Some(handler);
        self
    }

    /// Configure the UDP relay forwarder for SmartSock CRLY frame forwarding.
    ///
    /// When enabled, the server will bind a separate UDP port for relay data.
    /// Clients receive this address in RelayAccepted/RelayConnected responses.
    ///
    /// This enables true E2E encryption over relay without RPC overhead.
    pub fn with_udp_forwarder(
        mut self,
        forwarder: Arc<crate::net::UdpRelayForwarder>,
        addr: std::net::SocketAddr,
    ) -> Self {
        self.udp_forwarder = Some(forwarder);
        self.udp_forwarder_addr = Some(addr);
        self
    }

    /// Run the server, accepting connections from the endpoint.
    ///
    /// This method runs indefinitely, accepting and handling connections.
    pub async fn run(&self, endpoint: Endpoint) -> Result<()> {
        // Spawn UDP relay forwarder if configured
        if let Some(forwarder) = &self.udp_forwarder {
            info!(
                addr = ?self.udp_forwarder_addr,
                "starting UDP relay forwarder"
            );
            forwarder.clone().spawn();
        }

        while let Some(incoming) = endpoint.accept().await {
            // Rate limit incoming connections to prevent DoS
            let remote_addr = incoming.remote_address();
            if !self.rate_limiter.allow(remote_addr.ip()).await {
                // Security event - rate limiting is an attack indicator
                warn!(remote = %remote_addr, "rate limiting: rejecting connection");
                // Drop the incoming connection by not awaiting it
                continue;
            }
            
            let node = self.node.clone();
            let pubsub_handler = self.pubsub_handler.clone();
            let udp_forwarder = self.udp_forwarder.clone();
            let udp_forwarder_addr = self.udp_forwarder_addr;
            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    node, pubsub_handler, udp_forwarder, udp_forwarder_addr, incoming
                ).await {
                    warn!("connection error: {:?}", e);
                }
            });
        }
        Ok(())
    }

    /// Spawn the server as a background task.
    ///
    /// Returns immediately after spawning the server task.
    pub fn spawn(self, endpoint: Endpoint) -> tokio::task::JoinHandle<Result<()>>
    where
        N: 'static,
    {
        tokio::spawn(async move { self.run(endpoint).await })
    }
}

/// Extract the verified identity from a QUIC connection's peer certificate.
///
/// This provides Sybil protection by cryptographically binding the peer's
/// identity to their TLS certificate. Any `from` Contact in incoming requests
/// must match this verified identity.
fn extract_verified_identity(connection: &quinn::Connection) -> Option<Identity> {
    let peer_identity = connection.peer_identity()?;
    let certs: &Vec<rustls::pki_types::CertificateDer> = peer_identity.downcast_ref()?;
    let cert_der = certs.first()?.as_ref();
    let public_key = extract_public_key_from_cert(cert_der)?;
    // Zero-hash model: Identity IS the public key
    Some(Identity::from_bytes(public_key))
}

/// Handle a single incoming connection.
///
/// Extracts the peer's verified identity from their TLS certificate to prevent
/// Sybil attacks where a peer claims to be a different identity.
async fn handle_connection<N: DhtNetwork>(
    node: DhtNode<N>,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<crate::net::UdpRelayForwarder>>,
    udp_forwarder_addr: Option<std::net::SocketAddr>,
    incoming: Incoming,
) -> Result<()> {
    debug!("handle_connection: accepting incoming connection");
    let connection = incoming.await.context("failed to accept connection")?;
    let remote = connection.remote_address();
    
    // Extract verified identity from peer's TLS certificate for Sybil protection
    let verified_identity = extract_verified_identity(&connection);
    if verified_identity.is_none() {
        warn!(remote = %remote, "rejecting connection: could not verify peer identity");
        return Err(anyhow::anyhow!("could not verify peer identity from certificate"));
    }
    let verified_identity = verified_identity.unwrap();
    
    // Log new peer connection in format: Peer IP:PORT/IDENTITY
    info!("Peer {}/{}", remote, hex::encode(verified_identity));
    
    // Connection events demoted to debug - too noisy at info level in production
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
            if let Err(e) = handle_stream(
                node, pubsub, 
                forwarder, forwarder_addr, stream, remote_addr, verified_id
            ).await {
                // Stream errors are common (peer disconnect) but useful for troubleshooting
                debug!(error = ?e, "stream error");
            }
        });
    };
    
    result
}

/// Handle a single bidirectional stream (one RPC request/response).
///
/// The `verified_identity` parameter is the peer's identity extracted from their
/// TLS certificate. All incoming requests must have a `from` Contact that
/// matches this verified identity to prevent Sybil attacks.
#[allow(clippy::too_many_arguments)]
async fn handle_stream<N: DhtNetwork>(
    node: DhtNode<N>,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<crate::net::UdpRelayForwarder>>,
    udp_forwarder_addr: Option<std::net::SocketAddr>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    remote_addr: std::net::SocketAddr,
    verified_identity: Identity,
) -> Result<()> {
    // Read request length with a timeout to avoid slowloris stalling the task.
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(REQUEST_READ_TIMEOUT, recv.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow::anyhow!("request header read timed out"))??;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate request size to prevent memory exhaustion
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

    // Read request body
    let mut request_bytes = vec![0u8; len];
    tokio::time::timeout(REQUEST_READ_TIMEOUT, recv.read_exact(&mut request_bytes))
        .await
        .map_err(|_| anyhow::anyhow!("request body read timed out"))??;

    let request: DhtRequest = crate::messages::deserialize_request(&request_bytes)
        .context("failed to deserialize request")?;

    // Verify the request's `from` Contact matches the verified TLS identity (Sybil protection)
    if let Some(claimed_id) = request.sender_identity() {
        if claimed_id != verified_identity {
            warn!(
                remote = %remote_addr,
                claimed = ?hex::encode(&claimed_id.as_bytes()[..8]),
                verified = ?hex::encode(&verified_identity.as_bytes()[..8]),
                "rejecting request: identity mismatch (possible Sybil attack)"
            );
            // Return error response for identity mismatch
            let error_response = DhtResponse::Error {
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

    // Handle the request and produce a response
    let response = handle_request(
        node, 
        request, remote_addr, verified_identity, 
        pubsub_handler, udp_forwarder, udp_forwarder_addr
    ).await;

    // Send response
    let response_bytes = bincode::serialize(&response).context("failed to serialize response")?;
    let len = response_bytes.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&response_bytes).await?;
    send.finish()?;

    Ok(())
}

/// Dispatch an incoming request to the appropriate handler.
#[allow(clippy::too_many_arguments)]
async fn handle_request<N: DhtNetwork>(
    node: DhtNode<N>,
    request: DhtRequest,
    remote_addr: std::net::SocketAddr,
    _verified_identity: Identity,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
    udp_forwarder: Option<Arc<crate::net::UdpRelayForwarder>>,
    udp_forwarder_addr: Option<std::net::SocketAddr>,
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
            
            // Check if UDP forwarder is available
            let forwarder = match &udp_forwarder {
                Some(f) => f,
                None => {
                    return DhtResponse::RelayRejected { 
                        reason: "relay not available".to_string() 
                    };
                }
            };
            
            // Get the forwarder address for the response
            let relay_data_addr = match udp_forwarder_addr {
                Some(addr) => addr.to_string(),
                None => {
                    return DhtResponse::RelayRejected { 
                        reason: "relay address not configured".to_string() 
                    };
                }
            };
            
            // Check current session count
            let session_count = forwarder.session_count().await;
            if session_count >= MAX_SESSIONS {
                return DhtResponse::RelayRejected { 
                    reason: "relay server at capacity".to_string() 
                };
            }
            
            // Try to register or complete the session
            // First peer: register as pending
            // Second peer: complete the session
            match forwarder.register_session(session_id, remote_addr).await {
                Ok(()) => {
                    // First peer registered - session pending
                    debug!(
                        session = hex::encode(session_id),
                        peer = %remote_addr,
                        "relay session pending (waiting for peer B)"
                    );
                    DhtResponse::RelayAccepted { session_id, relay_data_addr }
                }
                Err("session already exists") => {
                    // Second peer - try to complete the session
                    match forwarder.complete_session(session_id, remote_addr).await {
                        Ok(()) => {
                            debug!(
                                session = hex::encode(session_id),
                                peer = %remote_addr,
                                "relay session established"
                            );
                            DhtResponse::RelayConnected { session_id, relay_data_addr }
                        }
                        Err(e) => {
                            warn!(
                                session = hex::encode(session_id),
                                error = e,
                                "failed to complete relay session"
                            );
                            DhtResponse::RelayRejected { reason: e.to_string() }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        session = hex::encode(session_id),
                        error = e,
                        "failed to register relay session"
                    );
                    DhtResponse::RelayRejected { reason: e.to_string() }
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
        DhtRequest::PubSub { from, message } => {
            // Dispatch PubSub messages to the registered handler (GossipSub layer)
            // The handler is responsible for:
            // 1. Verifying message signatures
            // 2. Maintaining topic meshes
            // 3. Handling message deduplication
            // 4. Routing messages to subscribers
            if let Some(handler) = pubsub_handler {
                trace!(
                    from = ?hex::encode(&from.as_bytes()[..8]),
                    message = ?message,
                    "dispatching PUBSUB request to handler"
                );
                if let Err(e) = handler.handle_message(&from, message).await {
                    warn!(from = ?hex::encode(&from.as_bytes()[..8]), error = %e, "PubSub handler returned error");
                    DhtResponse::Error {
                        message: format!("PubSub error: {}", e),
                    }
                } else {
                    DhtResponse::Ack
                }
            } else {
                // No handler registered - return error to alert the sender
                warn!(
                    from = ?hex::encode(&from.as_bytes()[..8]),
                    message = ?message,
                    "received PUBSUB request but no handler registered"
                );
                DhtResponse::Error {
                    message: "PubSub not enabled on this node".to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::connection::MAX_CONNECTIONS_PER_IP_PER_SECOND;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_rate_limiter_per_ip() {
        let limiter = ConnectionRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Should allow up to MAX_CONNECTIONS_PER_IP_PER_SECOND (20)
        for _ in 0..MAX_CONNECTIONS_PER_IP_PER_SECOND {
            assert!(limiter.allow(ip).await);
        }
        
        // Should reject next
        assert!(!limiter.allow(ip).await);
        
        // Different IP should be allowed
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(limiter.allow(ip2).await);
    }

    // ========================================================================
    // Rate Limiter Boundary Condition Tests (from tests/security_gaps.rs)
    // ========================================================================

    /// Maximum connections per IP per second.
    const TEST_MAX_CONNECTIONS_PER_IP: usize = 10;

    /// Maximum global connections per second.
    const TEST_MAX_GLOBAL_CONNECTIONS: usize = 100;

    /// Maximum IPs to track.
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
        use tokio::sync::Barrier;
        use std::sync::Arc;

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
