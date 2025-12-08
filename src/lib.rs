//! # Corium
//!
//! A mesh networking library with automatic NAT traversal and pubsub.
//!
//! ## Quick Start
//!
//! ```ignore
//! use corium::Node;
//!
//! // Create a node (auto-generates identity, pubsub enabled by default)
//! let node = Node::bind("0.0.0.0:0").await?;
//! println!("My identity: {}", node.identity());
//!
//! // Bootstrap from a known peer (identity = hex-encoded 64-char Ed25519 public key)
//! node.bootstrap("a1b2c3d4e5f6...", "seed.example.com:9000").await?;
//!
//! // Subscribe to a topic
//! node.subscribe("chat").await?;
//!
//! // Receive messages
//! let mut rx = node.messages().await?;
//! tokio::spawn(async move {
//!     while let Some(msg) = rx.recv().await {
//!         println!("[{}] from {}: {:?}", msg.topic, msg.from, msg.data);
//!     }
//! });
//!
//! // Publish messages  
//! node.publish("chat", b"Hello!".to_vec()).await?;
//!
//! // Connect to a peer by identity and address
//! let conn = node.connect("abc123...", "192.168.1.50:9000").await?;
//! ```
//!
//! ## Public API
//!
//! The public API consists of just 3 types:
//!
//! - [`Node`] - The mesh network node
//! - [`Message`] - A received pubsub message  
//! - [`Connection`] - A QUIC connection to a peer
//!
//! For persistent identity, use [`Node::bind_with_keypair`] with a keypair
//! from the `tests` feature module.

// ============================================================================
// Internal Modules - all crate-private by default
// ============================================================================

pub(crate) mod dht;
pub(crate) mod identity;
pub(crate) mod messages;
pub(crate) mod net;
pub(crate) mod pubsub;
pub(crate) mod node;
pub(crate) mod server;

/// Returns the current time in milliseconds since UNIX_EPOCH (crate-internal).
#[inline]
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// Public API - minimal surface for Node users
// ============================================================================

/// The mesh network node - primary API.
pub use node::Node;

/// A received pubsub message.
pub use node::Message;

/// QUIC connection to a peer.
pub use quinn::Connection;

// ============================================================================
// Test Support - exposed only with feature flag
// ============================================================================

/// Internal access for testing.
///
/// **Warning**: This module is not covered by semver guarantees.
/// Enable with `features = ["tests"]` in Cargo.toml.
#[cfg(feature = "tests")]
pub mod tests {
    // Identity (already pub items from pub(crate) identity module)
    pub use crate::identity::{Keypair, Identity, EndpointRecord, RelayEndpoint, verify_identity};
    
    // DHT (access via pub(crate) submodules)
    pub use crate::dht::node::DhtNode;
    pub use crate::dht::network::DhtNetwork;
    pub use crate::dht::routing::{RoutingTable, Contact};
    pub use crate::dht::hash::{Key, hash_content, verify_key_value_pair};
    pub use crate::dht::params::TelemetrySnapshot;
    
    // Network (access via pub(crate) submodules)
    pub use crate::net::transport::PeerNetwork;
    pub use crate::net::tls::{
        ALPN, generate_ed25519_cert,
        create_server_config, create_client_config,
        extract_public_key_from_cert, verify_peer_identity,
    };
    pub use crate::net::connection::SmartConnection;
    pub use crate::net::relay::{
        UdpRelayForwarder, RelayInfo, NatType, NatReport, CryptoError,
        detect_nat_type, generate_session_id, DIRECT_CONNECT_TIMEOUT,
    };
    
    // PubSub (access via pub(crate) submodules)
    pub use crate::pubsub::gossipsub::{GossipSub, PubSubHandler};
    pub use crate::pubsub::config::GossipConfig;
    pub use crate::pubsub::message::{MessageId, PubSubMessage};
    pub use crate::pubsub::types::ReceivedMessage;
    pub use crate::pubsub::signature::{
        SignatureError, sign_pubsub_message, verify_pubsub_signature,
    };
    
    // Wire protocol (access via pub items in pub(crate) messages module)
    pub use crate::messages::{
        DhtRequest, DhtResponse,
        deserialize_request, deserialize_response, serialize,
        MAX_DESERIALIZE_SIZE,
    };
    
    /// Time utility.
    #[inline]
    pub fn now_ms() -> u64 {
        crate::now_ms()
    }
}
