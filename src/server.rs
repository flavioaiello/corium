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

use crate::net::holepunch::HolePunchRegistry;
use crate::net::connection::ConnectionRateLimiter;
use crate::relay::RelayConnectionRegistry;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Endpoint, Incoming};
use tracing::{debug, info, trace, warn};

use crate::dht::{DhtNetwork, DhtNode};
use crate::identity::Identity;
use crate::net::extract_public_key_from_cert;
use crate::messages::{DhtRequest, DhtResponse};
use crate::pubsub::{PubSubHandler, PubSubMessage};
use crate::relay::{CryptoError, RelayClient, RelayPacket, RelayServer, MAX_RELAY_PACKET_SIZE};

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
/// For relayed data (`RelayData` messages), the node verifies that:
/// 1. The session ID corresponds to an active relay session we initiated
/// 2. The message arrives from the relay server we established the session with
///
/// This prevents rogue relays from injecting data into sessions they don't own.
///
/// Connection rate limiting prevents resource exhaustion attacks.
pub(crate) struct Server<N: DhtNetwork> {
    /// The DHT node that handles DHT operations.
    node: DhtNode<N>,
    /// Relay server for NAT traversal (when acting as a relay).
    relay: Arc<RelayServer>,
    /// Relay client for tracking our outbound relay sessions.
    relay_client: Arc<RelayClient>,
    /// Hole punch rendezvous registry.
    hole_punch: Arc<HolePunchRegistry>,
    /// Registry of peer connections for relay forwarding.
    relay_connections: Arc<RelayConnectionRegistry>,
    /// Connection rate limiter to prevent DoS.
    rate_limiter: ConnectionRateLimiter,
    /// Optional PubSub handler for GossipSub messages.
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
}

impl<N: DhtNetwork> Server<N> {
    /// Create a new server backed by the given DHT node.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if the relay server cannot be initialized due
    /// to CSPRNG unavailability.
    pub fn new(node: DhtNode<N>) -> Result<Self, CryptoError> {
        Ok(Self {
            node,
            relay: Arc::new(RelayServer::new()?),
            relay_client: Arc::new(RelayClient::new()),
            hole_punch: Arc::new(HolePunchRegistry::new()),
            relay_connections: Arc::new(RelayConnectionRegistry::new()),
            rate_limiter: ConnectionRateLimiter::new(),
            pubsub_handler: None,
        })
    }

    /// Create a server with a custom relay server configuration.
    #[allow(dead_code)]
    pub fn with_relay(node: DhtNode<N>, relay: RelayServer) -> Self {
        Self {
            node,
            relay: Arc::new(relay),
            relay_client: Arc::new(RelayClient::new()),
            hole_punch: Arc::new(HolePunchRegistry::new()),
            relay_connections: Arc::new(RelayConnectionRegistry::new()),
            rate_limiter: ConnectionRateLimiter::new(),
            pubsub_handler: None,
        }
    }

    /// Register a PubSub handler for processing GossipSub messages.
    ///
    /// Without a registered handler, incoming PubSub messages will receive
    /// an error response indicating PubSub is not enabled.
    pub fn with_pubsub(mut self, handler: Arc<dyn PubSubHandler + Send + Sync>) -> Self {
        self.pubsub_handler = Some(handler);
        self
    }

    /// Run the server, accepting connections from the endpoint.
    ///
    /// This method runs indefinitely, accepting and handling connections.
    pub async fn run(&self, endpoint: Endpoint) -> Result<()> {
        // Spawn periodic cleanup task for relays
        let relay_cleanup = self.relay.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                relay_cleanup.cleanup_expired().await;
            }
        });

        // Spawn periodic cleanup task for hole punch registry
        let punch_cleanup = self.hole_punch.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                punch_cleanup.cleanup_expired().await;
            }
        });

        // Spawn periodic cleanup task for relay connections
        let relay_conn_cleanup = self.relay_connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                relay_conn_cleanup.cleanup().await;
            }
        });

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
            let relay = self.relay.clone();
            let relay_client = self.relay_client.clone();
            let hole_punch = self.hole_punch.clone();
            let relay_connections = self.relay_connections.clone();
            let pubsub_handler = self.pubsub_handler.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(node, relay, relay_client, hole_punch, relay_connections, pubsub_handler, incoming).await {
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
    relay: Arc<RelayServer>,
    relay_client: Arc<RelayClient>,
    hole_punch: Arc<HolePunchRegistry>,
    relay_connections: Arc<RelayConnectionRegistry>,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
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
    
    // Derive peer Identity from verified public key for relay connection tracking
    let peer_identity: Option<Identity> = {
        let peer_identity_opt = connection.peer_identity();
        if let Some(identity) = peer_identity_opt {
            if let Some(certs) = identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer>>() {
                if let Some(cert) = certs.first() {
                    extract_public_key_from_cert(cert.as_ref())
                        .map(Identity::from_bytes)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };
    
    // Register this connection for relay forwarding if we got the identity
    if let Some(ref identity) = peer_identity {
        relay_connections.register(*identity, connection.clone()).await;
    }
    
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
        let relay = relay.clone();
        let relay_client = relay_client.clone();
        let hole_punch = hole_punch.clone();
        let relay_conns = relay_connections.clone();
        let pubsub = pubsub_handler.clone();
        let remote_addr = remote;
        let verified_id = verified_identity;
        let conn_peer_identity = peer_identity;
        tokio::spawn(async move {
            if let Err(e) = handle_stream(node, relay, relay_client, hole_punch, relay_conns, pubsub, stream, remote_addr, verified_id, conn_peer_identity).await {
                // Stream errors are common (peer disconnect) but useful for troubleshooting
                debug!(error = ?e, "stream error");
            }
        });
    };
    
    // Unregister connection on disconnect
    if let Some(identity) = peer_identity {
        relay_connections.unregister(&identity).await;
    }
    
    result
}

/// Handle a single bidirectional stream (one RPC request/response).
///
/// The `verified_identity` parameter is the peer's identity extracted from their
/// TLS certificate. All incoming requests must have a `from` Contact that
/// matches this verified identity to prevent Sybil attacks.
///
/// The `connection_peer_identity` is the Identity of the peer on this connection,
/// used to verify RelayData messages come from the expected relay server.
#[allow(clippy::too_many_arguments)]
async fn handle_stream<N: DhtNetwork>(
    node: DhtNode<N>,
    relay: Arc<RelayServer>,
    relay_client: Arc<RelayClient>,
    hole_punch: Arc<HolePunchRegistry>,
    relay_connections: Arc<RelayConnectionRegistry>,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    remote_addr: std::net::SocketAddr,
    verified_identity: Identity,
    connection_peer_identity: Option<Identity>,
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
    let response = handle_request(node, relay, relay_client, hole_punch, relay_connections, request, remote_addr, verified_identity, connection_peer_identity, pubsub_handler).await;

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
    relay: Arc<RelayServer>,
    relay_client: Arc<RelayClient>,
    hole_punch: Arc<HolePunchRegistry>,
    relay_connections: Arc<RelayConnectionRegistry>,
    request: DhtRequest,
    remote_addr: std::net::SocketAddr,
    verified_identity: Identity,
    connection_peer_identity: Option<Identity>,
    pubsub_handler: Option<Arc<dyn PubSubHandler + Send + Sync>>,
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
            
            // Create a channel for this peer to receive forwarded packets
            let (tx, mut rx) = tokio::sync::mpsc::channel::<RelayPacket>(32);
            
            let relay_request = crate::relay::RelayRequest {
                from_peer,
                target_peer,
                session_id,
            };
            
            let response = relay.handle_request(relay_request, tx).await;
            
            // If session was accepted/connected, spawn a task to forward packets to this peer
            let should_spawn_forwarder = matches!(
                response, 
                crate::relay::RelayResponse::Accepted { .. } | 
                crate::relay::RelayResponse::Connected { .. }
            );
            
            if should_spawn_forwarder {
                // Check if we can accept a new forwarder task before spawning
                if !relay.forwarder_registry().can_accept().await {
                    let active_count = relay.forwarder_registry().active_count().await;
                    warn!(
                        session = hex::encode(session_id),
                        active_count = active_count,
                        "rejecting relay: forwarder task limit reached"
                    );
                    return DhtResponse::RelayRejected { 
                        reason: "relay server at capacity".to_string() 
                    };
                }
                
                let relay_conns = relay_connections.clone();
                let peer = from_peer;
                let sid = session_id;
                
                // Spawn a task to read from the channel and forward packets to this peer
                // Uses timeout to prevent task leak if peer disconnects without closing channel
                let handle = tokio::spawn(async move {
                    use crate::relay::RELAY_SESSION_TIMEOUT;
                    
                    loop {
                        // Use select with timeout to prevent indefinite blocking
                        // if the channel never receives another packet
                        tokio::select! {
                            packet_opt = rx.recv() => {
                                match packet_opt {
                                    Some(packet) => {
                                        if let Err(e) = relay_conns.forward_to_peer(&peer, packet).await {
                                            debug!(
                                                session = hex::encode(sid),
                                                error = ?e,
                                                "failed to forward packet to peer, closing relay forwarder"
                                            );
                                            break;
                                        }
                                    }
                                    None => {
                                        // Channel closed
                                        break;
                                    }
                                }
                            }
                            _ = tokio::time::sleep(RELAY_SESSION_TIMEOUT) => {
                                debug!(
                                    session = hex::encode(sid),
                                    "relay forwarder timed out waiting for packets"
                                );
                                break;
                            }
                        }
                    }
                    trace!(
                        session = hex::encode(sid),
                        "relay forwarder task completed"
                    );
                });
                
                // Register the task handle for tracking and potential cleanup
                // If registration fails (at capacity race), the task is aborted by the registry
                if !relay.forwarder_registry().register(session_id, handle).await {
                    warn!(
                        session = hex::encode(session_id),
                        "failed to register forwarder task (capacity reached)"
                    );
                    // The registry aborts the handle if registration fails
                    return DhtResponse::RelayRejected { 
                        reason: "relay server at capacity".to_string() 
                    };
                }
            }
            
            match response {
                crate::relay::RelayResponse::Accepted { session_id } => {
                    DhtResponse::RelayAccepted { session_id }
                }
                crate::relay::RelayResponse::Connected { session_id } => {
                    DhtResponse::RelayConnected { session_id }
                }
                crate::relay::RelayResponse::Rejected { reason } => {
                    DhtResponse::RelayRejected { reason }
                }
            }
        }
        DhtRequest::RelayForward { from, session_id, payload } => {
            trace!(
                session = hex::encode(session_id),
                payload_len = payload.len(),
                "handling RELAY_FORWARD request"
            );
            
            // Validate payload size to prevent memory exhaustion
            if payload.len() > MAX_RELAY_PACKET_SIZE {
                warn!(
                    session = hex::encode(session_id),
                    size = payload.len(),
                    max = MAX_RELAY_PACKET_SIZE,
                    "rejecting oversized relay payload"
                );
                return DhtResponse::Error {
                    message: format!("relay payload too large: {} bytes (max {})", payload.len(), MAX_RELAY_PACKET_SIZE),
                };
            }

            // Verify sender matches connection identity
            if from != verified_identity {
                warn!(
                    remote = %remote_addr,
                    claimed = ?hex::encode(&from.as_bytes()[..8]),
                    verified = ?hex::encode(&verified_identity.as_bytes()[..8]),
                    "rejecting RELAY_FORWARD: identity mismatch"
                );
                return DhtResponse::Error {
                    message: "Identity mismatch".to_string(),
                };
            }
            
            let packet = crate::relay::RelayPacket {
                from,
                session_id,
                payload,
            };

            match relay.forward_packet(&from, packet).await {
                Ok(_) => DhtResponse::RelayForwarded,
                Err(e) => DhtResponse::Error { message: e },
            }
        }
        DhtRequest::RelayClose { from_peer, session_id } => {
            debug!(
                from = ?hex::encode(&from_peer.as_bytes()[..8]),
                session = hex::encode(session_id),
                "handling RELAY_CLOSE request"
            );
            
            // Verify sender matches connection identity (Sybil protection)
            if from_peer != verified_identity {
                warn!(
                    remote = %remote_addr,
                    claimed = ?hex::encode(&from_peer.as_bytes()[..8]),
                    verified = ?hex::encode(&verified_identity.as_bytes()[..8]),
                    "rejecting RELAY_CLOSE: identity mismatch"
                );
                return DhtResponse::Error {
                    message: "Identity mismatch".to_string(),
                };
            }
            
            // Note: The relay server's close_session will verify that from_peer
            // is actually a participant in the session before closing it.
            // This prevents authenticated users from closing sessions they're not part of.
            relay.close_session(&session_id, &from_peer, "peer requested close").await;
            DhtResponse::RelayClosed
        }
        DhtRequest::RelayData { from, session_id, payload } => {
            // This is received by peers when the relay pushes forwarded data to them.
            // The peer should process this as incoming relay data from the other peer.
            //
            // Security Model:
            // 1. Verify we have an active relay session with this session_id
            // 2. Verify the message arrived from the relay server we established the session with
            // 3. The payload is E2E encrypted QUIC data, so the relay cannot modify its contents
            //
            // This prevents:
            // - Rogue relays from injecting data into sessions they don't own
            // - Session hijacking where an attacker guesses/steals a session ID
            // - Man-in-the-middle attacks where a malicious node claims to be a relay
            
            // Verify the relay server's identity matches our expected relay for this session
            let relay_identity = match &connection_peer_identity {
                Some(id) => id,
                None => {
                    warn!(
                        session = hex::encode(session_id),
                        remote = %remote_addr,
                        "rejecting RELAY_DATA: could not determine connection peer identity"
                    );
                    return DhtResponse::Error {
                        message: "relay verification failed".to_string(),
                    };
                }
            };
            
            // Verify the connection is from a registered/known relay
            // This provides defense-in-depth against rogue nodes claiming to be relays
            if !relay_client.is_known_relay(relay_identity).await {
                warn!(
                    session = hex::encode(session_id),
                    claimed_relay = ?hex::encode(&relay_identity.as_bytes()[..8]),
                    remote = %remote_addr,
                    "rejecting RELAY_DATA: sender is not a registered relay"
                );
                return DhtResponse::Error {
                    message: "relay verification failed".to_string(),
                };
            }
            
            // Check if we have an active session with this ID through this relay
            if !relay_client.verify_session(&session_id, relay_identity).await {
                warn!(
                    session = hex::encode(session_id),
                    relay = ?hex::encode(&relay_identity.as_bytes()[..8]),
                    remote = %remote_addr,
                    "rejecting RELAY_DATA: session not found or relay mismatch (possible injection attack)"
                );
                // Use opaque error to prevent session enumeration
                return DhtResponse::Error {
                    message: "relay verification failed".to_string(),
                };
            }
            
            // Validate payload size
            if payload.len() > MAX_RELAY_PACKET_SIZE {
                warn!(
                    session = hex::encode(session_id),
                    size = payload.len(),
                    max = MAX_RELAY_PACKET_SIZE,
                    "rejecting oversized RELAY_DATA payload"
                );
                return DhtResponse::Error {
                    message: format!("relay data too large: {} bytes (max {})", payload.len(), MAX_RELAY_PACKET_SIZE),
                };
            }
            
            trace!(
                session = hex::encode(session_id),
                from = ?hex::encode(&from.as_bytes()[..8]),
                payload_len = payload.len(),
                "received RELAY_DATA from relay"
            );
            
            // Queue the relay data for processing by the application layer.
            // The RelayClient maintains a bounded channel where incoming relay
            // data is queued. The application (or a dedicated task) consumes
            // this data and processes the E2E encrypted QUIC packets.
            //
            // Note: The payload contains encrypted QUIC packet data that needs
            // to be injected into the QUIC layer for the relayed connection.
            // The current architecture queues the data; full QUIC integration
            // would require deeper integration with Quinn's internals.
            match relay_client.queue_incoming_data(session_id, from, payload).await {
                Ok(()) => {
                    debug!(
                        session = hex::encode(session_id),
                        "relay data queued for processing"
                    );
                    DhtResponse::Ack
                }
                Err(reason) => {
                    warn!(
                        session = hex::encode(session_id),
                        reason = reason,
                        "failed to queue relay data"
                    );
                    // Return error so the relay knows delivery failed.
                    // This allows the sender to retry or fall back.
                    DhtResponse::Error {
                        message: "relay data delivery failed: receiver busy".to_string(),
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
        DhtRequest::HolePunchRegister {
            from_peer,
            target_peer,
            our_public_addr,
            punch_id,
        } => {
            debug!(
                from = ?hex::encode(&from_peer.as_bytes()[..8]),
                target = ?hex::encode(&target_peer.as_bytes()[..8]),
                punch_id = ?hex::encode(&punch_id[..8]),
                public_addr = %our_public_addr,
                "handling HOLE_PUNCH_REGISTER request"
            );
            
            // Use the registry to register or match with existing peer
            match hole_punch.register(punch_id, from_peer, target_peer, our_public_addr).await {
                Ok(Some((peer_addr, start_time_ms))) => {
                    // Both peers registered - return ready response
                    DhtResponse::HolePunchReady {
                        punch_id,
                        peer_addr,
                        start_time_ms,
                    }
                }
                Ok(None) => {
                    // First peer - waiting for the other
                    DhtResponse::HolePunchWaiting { punch_id }
                }
                Err(reason) => {
                    // Rate limited
                    DhtResponse::HolePunchFailed {
                        reason: reason.to_string(),
                    }
                }
            }
        }
        DhtRequest::HolePunchStart { punch_id } => {
            debug!(
                punch_id = ?hex::encode(&punch_id[..8]),
                "handling HOLE_PUNCH_START request"
            );
            
            // Check if punch is ready
            match hole_punch.check_ready(&punch_id).await {
                Some((peer_addr, start_time_ms)) => {
                    DhtResponse::HolePunchReady {
                        punch_id,
                        peer_addr,
                        start_time_ms,
                    }
                }
                None => {
                    DhtResponse::HolePunchFailed {
                        reason: "Punch not ready or expired".to_string(),
                    }
                }
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
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_rate_limiter_per_ip() {
        let limiter = ConnectionRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Should allow up to MAX_CONNECTIONS_PER_IP_PER_SECOND (20)
        for _ in 0..crate::net::connection::MAX_CONNECTIONS_PER_IP_PER_SECOND {
            assert!(limiter.allow(ip).await);
        }
        
        // Should reject next
        assert!(!limiter.allow(ip).await);
        
        // Different IP should be allowed
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(limiter.allow(ip2).await);
    }
}
