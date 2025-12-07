//! # Corium
//!
//! A mesh networking library with automatic NAT traversal. **Consumers connect
//! to peers via [`QuinnNetwork::smart_connect`][net::QuinnNetwork::smart_connect]—you don't
//! need to use quinn/QUIC APIs directly.**
//!
//! The library provides a Kademlia-inspired DHT for peer discovery, with adaptive
//! tiering and backpressure controls for embedding in services that need a
//! self-healing mesh key/value store.
//!
//! ## Smart Connections (Primary API)
//!
//! The [`smart_connect`][net::QuinnNetwork::smart_connect] method abstracts all transport
//! complexity. It returns a [`SmartConnection`] that works regardless
//! of NAT topology:
//!
//! ```ignore
//! // Resolve peer's endpoint record from DHT
//! let record = dht.resolve_identity(&peer_identity).await?;
//!
//! // Connect—NAT traversal is automatic!
//! let conn = network.smart_connect(&record).await?;
//!
//! // Works whether direct, hole-punched, or relayed
//! println!("Connected: direct={}", conn.is_direct());
//! ```
//!
//! **Why use `smart_connect` instead of raw QUIC?**
//! - Works behind any NAT (including CGNAT/Symmetric NAT)
//! - Automatic relay fallback when direct fails
//! - Transparent upgrade probing (relay → direct)
//! - No quinn dependency in your application code
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
//! by `smart_connect`:
//!
//! 1. **NAT Detection**: Queries multiple endpoints to classify NAT type
//! 2. **Direct First**: Always attempt direct UDP connection
//! 3. **Relay Fallback**: When blocked by Symmetric NAT/CGNAT, connect via relay
//! 4. **Parallel Probing**: Continuously probe all paths to find the best route
//! 5. **QUIC Migration**: Seamlessly switch paths without reconnecting (saves 1-2 RTTs)
//!
//! ## Modules
//!
//! - `core`: transport-agnostic Kademlia logic (routing table, storage, state machine)
//! - [`identity`]: Ed25519 keypair, cryptographic identity, and endpoint records
//! - [`net`]: **primary API** via [`QuinnNetwork::smart_connect`][net::QuinnNetwork::smart_connect]
//! - [`node`]: mesh node for accepting incoming connections
//! - [`protocol`]: RPC request/response definitions
//! - [`relay`]: NAT detection, relay nodes, and ICE candidates
//!
//! ## Getting Started
//!
//! ### Step 1: Create a Node (One-Time Setup)
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use anyhow::Result;
//! use quinn::Endpoint;
//! use corium::{
//!     create_client_config, create_server_config, generate_ed25519_cert,
//!     Contact, MeshNode, DhtNode, Keypair, QuinnNetwork,
//! };
//!
//! # async fn setup() -> Result<()> {
//! // Generate identity
//! let keypair = Keypair::generate();
//! let identity = keypair.identity();
//!
//! // Setup QUIC endpoint
//! let (certs, key) = generate_ed25519_cert(&keypair)?;
//! let server_config = create_server_config(certs, key)?;
//! let endpoint = Endpoint::server(server_config, "0.0.0.0:0".parse()?)?;
//!
//! // Create network with smart_connect capability
//! let (client_certs, client_key) = generate_ed25519_cert(&keypair)?;
//! let client_config = create_client_config(client_certs, client_key)?;
//! let contact = Contact { identity: keypair.identity(), addr: endpoint.local_addr()?.to_string() };
//! let network = QuinnNetwork::with_identity(
//!     endpoint.clone(), contact.clone(), client_config, identity
//! );
//!
//! // Create DHT and start mesh node
//! let dht = DhtNode::new(keypair.identity(), contact, network.clone(), 20, 3);
//! let mesh = MeshNode::new(dht.clone())?;
//! let _handle = mesh.spawn(endpoint);
//! # Ok(())
//! # }
//! ```
//!
//! ### Step 2: Connect to Peers
//!
//! ```ignore
//! // Get peer's endpoint record (from DHT, config file, etc.)
//! let peer_record: EndpointRecord = /* ... */;
//!
//! // Connect—NAT traversal is automatic!
//! let conn = network.smart_connect(&peer_record).await?;
//!
//! // Use the connection
//! let (mut send, mut recv) = conn.connection().open_bi().await?;
//! send.write_all(b"hello").await?;
//! ```
//!
//! See the [README](https://github.com/flavioaiello/corium) for more examples.

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
pub use node::{MeshNode, PubSubHandler};
pub use pubsub::{
    GossipConfig, GossipSub, MessageId, PubSubMessage, ReceivedMessage, SignatureError,
    sign_pubsub_message, verify_pubsub_signature,
    DEFAULT_GOSSIP_INTERVAL, DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_MESH_DEGREE,
};
