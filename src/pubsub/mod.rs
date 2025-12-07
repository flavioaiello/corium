//! GossipSub-style publish/subscribe for Corium.
//!
//! This module implements a gossip-based pubsub system inspired by libp2p's GossipSub.
//! Messages propagate through the network via epidemic broadcast, achieving O(log n)
//! hop delivery with high reliability.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Application                             │
//! │              subscribe(), publish(), on_message()           │
//! ├─────────────────────────────────────────────────────────────┤
//! │                      GossipSub                              │
//! │         Topic meshes, message routing, deduplication        │
//! ├─────────────────────────────────────────────────────────────┤
//! │                       DhtNode                               │
//! │              Peer discovery, DHT, connections               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Concepts
//!
//! - **Topic**: A named channel for messages (e.g., "chat/lobby", "sensors/temperature")
//! - **Mesh**: For each topic, maintain connections to `mesh_degree` peers (default: 6)
//! - **Fanout**: When publishing to a topic we're not subscribed to, use cached peers
//! - **Gossip**: Periodically exchange "I have" metadata to repair mesh gaps
//!
//! # Security
//!
//! All published messages are cryptographically signed by the source's private key.
//! This prevents:
//! - **Identity spoofing**: Cannot claim to be someone else
//! - **Message forgery**: Cannot create messages on behalf of others  
//! - **Dedup cache poisoning**: Cannot inject fake seqnos for other identities
//!
//! Every node verifies signatures before accepting or forwarding messages.
//!
//! # Example
//!
//! ```ignore
//! use corium::pubsub::{GossipSub, GossipConfig};
//! use corium::identity::Keypair;
//!
//! // Create pubsub layer on top of discovery node
//! let keypair = Keypair::generate();
//! let config = GossipConfig::default();
//! let mut pubsub = GossipSub::new(node.clone(), keypair, config);
//!
//! // Subscribe to a topic
//! pubsub.subscribe("chat/lobby").await?;
//!
//! // Publish a message (automatically signed)
//! pubsub.publish("chat/lobby", b"Hello, world!").await?;
//!
//! // Handle incoming messages (signatures already verified)
//! while let Some(msg) = pubsub.next_message().await {
//!     println!("[{}] {}: {:?}", msg.topic, msg.source, msg.data);
//! }
//! ```

mod config;
mod gossipsub;
mod message;
mod signature;
mod subscription;
mod types;

// Re-export public types
pub use config::GossipConfig;
pub use gossipsub::{GossipSub, PubSubHandler};
pub use message::{MessageId, PubSubMessage};
pub use signature::{SignatureError, sign_pubsub_message, verify_pubsub_signature};
pub use types::ReceivedMessage;
