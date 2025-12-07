//! # Corium
//!
//! A mesh networking library with automatic NAT traversal.
//!
//! ## Quick Start
//!
//! The [`Node`] type is the primary API. It provides a simple, high-level
//! interface for mesh networking:
//!
//! ```ignore
//! use corium::{Node, Keypair};
//!
//! // Generate or load identity
//! let keypair = Keypair::generate();
//!
//! // Start the node
//! let node = Node::bind("0.0.0.0:0", keypair).await?;
//!
//! // Store and retrieve data
//! let key = node.put(b"hello world".to_vec()).await?;
//! let value = node.get(&key).await?;
//!
//! // Connect to peers with automatic NAT traversal
//! let record = node.resolve_peer(&peer_identity).await?;
//! let conn = node.connect(&record).await?;
//! ```
//!
//! ## Ed25519 Identity
//!
//! Each node has a cryptographic identity based on an Ed25519 keypair. The Identity
//! is the Ed25519 public key (32 bytes). This provides:
//!
//! - **Stable identity**: The Identity is tied to a cryptographic key, not an address
//! - **Verifiable peers**: Peers can verify that a node owns its claimed Identity
//! - **Secure transport**: TLS certificates use the same Ed25519 key
//! - **Zero-hash model**: Identity IS the public key, eliminating hash computation
//!
//! ## NAT Traversal (Handled Automatically)
//!
//! Corium uses a multi-layered approach to NAT traversal, all handled internally
//! by [`Node::connect`]:
//!
//! 1. **Direct First**: Always attempt direct UDP connection
//! 2. **Relay Fallback**: When blocked by Symmetric NAT/CGNAT, connect via relay
//! 3. **Parallel Probing**: Continuously probe all paths to find the best route
//! 4. **QUIC Migration**: Seamlessly switch paths without reconnecting
//!
//! ## PubSub Messaging
//!
//! Enable GossipSub for pub/sub messaging:
//!
//! ```ignore
//! use corium::{Node, Keypair};
//!
//! let keypair = Keypair::generate();
//! let node = Node::bind_with_pubsub("0.0.0.0:0", keypair).await?;
//!
//! // Subscribe and receive messages
//! node.subscribe("my-topic").await?;
//! let mut rx = node.take_message_receiver().await?;
//! tokio::spawn(async move {
//!     while let Some(msg) = rx.recv().await {
//!         println!("Received: {:?}", msg.data);
//!     }
//! });
//!
//! // Publish messages
//! node.publish("my-topic", b"hello!".to_vec()).await?;
//! ```
//!
//! ## Advanced Usage
//!
//! For power users who need lower-level access, the library also exports:
//!
//! - [`DhtNode`]: Direct DHT operations
//! - [`QuinnNetwork`]: QUIC transport layer
//! - [`GossipSub`]: PubSub implementation
//!
//! Most users should use [`Node`] which wires these together automatically.

/// Returns the current time in milliseconds since UNIX_EPOCH.
///
/// Uses `unwrap_or_default()` instead of `unwrap()` to gracefully handle
/// the edge case where the system clock is set before the UNIX epoch
/// (returns 0 in that case rather than panicking).
#[inline]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) mod core;
pub mod identity;
pub mod net;
pub mod protocol;
pub mod pubsub;
pub mod relay;
pub(crate) mod server;
pub mod node;

pub use core::{
    hash_content, is_valid_identity, verify_key_value_pair, xor_distance, Contact, DhtNetwork,
    DhtNode, Key, RoutingTable,
};
pub use identity::{
    verify_identity, Keypair, Identity, EndpointRecord, RelayEndpoint,
};
pub use net::{
    create_client_config, create_server_config, extract_public_key_from_cert,
    generate_ed25519_cert, verify_peer_identity,
    ConnectionManager, ConnectionStats, PathCandidate, PathProber, PathState, PathStats,
    // Path discovery protocol
    PathProbe, PathReply, PathMessage, ReachMe,
    QuinnNetwork, SmartConnection, ALPN, PATH_PROBE_INTERVAL, PATH_STALE_TIMEOUT,
    PROBE_TIMEOUT, UPGRADE_PROBE_INTERVAL,
};
pub use relay::{
    // ICE types
    CandidatePair, CandidateType, CheckState, IceAgent, IceCandidate, IceRole, IceState,
    TransportProtocol, TurnAllocation,
    // NAT detection
    detect_nat_type, gather_host_candidates, ice_connection_strategy, NatReport, NatType,
    // Connection strategy
    choose_connection_strategy, ConnectionStrategy,
    // Relay client/server
    ForwarderRegistry, RelayCapabilities, RelayClient, RelayInfo, RelayServer,
    // Relay protocol
    RelayRequest,
    // Error types
    CryptoError,
    // Constants
    DIRECT_CONNECT_TIMEOUT, ICE_CHECK_INTERVAL, ICE_KEEPALIVE_INTERVAL, MAX_RELAY_SESSIONS,
    RELAY_SESSION_TIMEOUT, STUN_TIMEOUT, TURN_ALLOCATION_LIFETIME,
};
// Primary API - unified Node facade
pub use node::{Node, PubSubHandler};
pub use pubsub::{
    GossipConfig, GossipSub, MessageId, PubSubMessage, ReceivedMessage, SignatureError,
    sign_pubsub_message, verify_pubsub_signature,
    DEFAULT_GOSSIP_INTERVAL, DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_MESH_DEGREE,
};
// Re-export TelemetrySnapshot for telemetry access
pub use core::TelemetrySnapshot;
