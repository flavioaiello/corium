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

// Internal modules - not part of public API
pub(crate) mod dht;
pub(crate) mod identity;
pub(crate) mod messages;
pub(crate) mod net;
pub(crate) mod pubsub;
pub(crate) mod server;

// Public facade
pub mod node;

// ============================================================================
// Public API - only types needed by Node facade users
// ============================================================================

// Primary API - the Node facade
pub use node::{Node, PubSubHandler};

// Identity types - needed for Node::bind(), identity management
pub use identity::{Identity, Keypair, EndpointRecord, RelayEndpoint};

// DHT types - used in Node method signatures
pub use dht::{Contact, Key, TelemetrySnapshot, hash_content, verify_key_value_pair};

// Connection types - returned from Node::connect()
pub use net::SmartConnection;

// PubSub types - used with Node pubsub methods
pub use pubsub::{MessageId, ReceivedMessage};

// ============================================================================
// Advanced API - for power users who need lower-level access
// ============================================================================

/// Advanced module for power users who need direct access to internal components.
///
/// Most users should use the [`Node`] facade instead. This module is for:
/// - Building custom networking protocols on top of QUIC
/// - Direct DHT operations without the Node wrapper
/// - Custom pubsub handlers
/// - Advanced NAT traversal scenarios
///
/// # Example
///
/// ```ignore
/// use corium::advanced::{generate_ed25519_cert, create_client_config, PeerNetwork};
///
/// // Build custom QUIC client
/// let (certs, key) = generate_ed25519_cert(&keypair)?;
/// let config = create_client_config(certs, key)?;
/// ```
pub mod advanced {
    // TLS/certificate utilities
    pub use crate::net::{
        create_client_config, create_server_config, generate_ed25519_cert,
        extract_public_key_from_cert, verify_peer_identity, ALPN,
    };
    
    // Network layer
    pub use crate::net::PeerNetwork;
    
    // DHT
    pub use crate::dht::{DhtNode, DhtNetwork, RoutingTable, hash_content};
    
    // PubSub
    pub use crate::pubsub::{
        GossipSub, GossipConfig, PubSubMessage, SignatureError,
        sign_pubsub_message, verify_pubsub_signature,
    };
    
    // Relay/NAT (from src/net/relay.rs)
    pub use crate::net::{
        UdpRelayForwarder, RelayInfo, NatType, NatReport, CryptoError,
        detect_nat_type, generate_session_id, DIRECT_CONNECT_TIMEOUT,
    };
    
    // Identity (for low-level operations)
    pub use crate::identity::{Keypair, verify_identity, Identity};
    
    // Wire protocol (for custom protocol implementations)
    pub use crate::messages::{
        deserialize_request, deserialize_response, serialize,
        DhtRequest, DhtResponse, MAX_DESERIALIZE_SIZE,
    };
}
