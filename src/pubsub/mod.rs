//! GossipSub-style publish/subscribe for Corium.
//!
//! This module is internal to the crate. Types are exposed externally only via
//! the `tests` feature module in `lib.rs`.
//!
//! Implements a gossip-based pubsub system inspired by libp2p's GossipSub.
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
//! # Security Architecture
//!
//! The pubsub module implements defense-in-depth against common P2P messaging attacks:
//!
//! ## Message Authentication
//!
//! All published messages are cryptographically signed by the source's private key:
//!
//! | Component | Protection |
//! |-----------|------------|
//! | Signature scheme | Ed25519 (64 bytes) |
//! | Signed data | `len(topic) || topic || seqno || len(data) || data` |
//! | Verification | Every node verifies before accepting or forwarding |
//!
//! This prevents:
//! - **Identity spoofing**: Cannot claim to be someone else without their private key
//! - **Message forgery**: Cannot create messages on behalf of others
//! - **Dedup cache poisoning**: Cannot inject fake seqnos for other identities
//!
//! ## Rate Limiting (Three-Tier)
//!
//! | Limit | Value | Description |
//! |-------|-------|-------------|
//! | Publish rate | 100/s | Local publishes (`DEFAULT_PUBLISH_RATE_LIMIT`) |
//! | Forward rate | 1000/s | Forwarded messages (`DEFAULT_FORWARD_RATE_LIMIT`) |
//! | Per-peer rate | 50/s | Any single peer (`DEFAULT_PER_PEER_RATE_LIMIT`) |
//! | IWant rate | 5/s | Per-peer IWant requests (`DEFAULT_IWANT_RATE_LIMIT`) |
//!
//! ## Amplification Attack Prevention
//!
//! | Protection | Limit | Description |
//! |------------|-------|-------------|
//! | IWant message count | 10 | `DEFAULT_MAX_IWANT_MESSAGES` per request |
//! | IWant response bytes | 256 KB | `MAX_IWANT_RESPONSE_BYTES` cap |
//! | Separate IWant rate | 5/s | Prevents rapid-fire IWant floods |
//!
//! ## Bounded Resources
//!
//! | Resource | Limit | Constant |
//! |----------|-------|----------|
//! | Topics | 10,000 | `MAX_TOPICS` |
//! | Peers per topic | 1,000 | `MAX_PEERS_PER_TOPIC` |
//! | Subscriptions per peer | 100 | `MAX_SUBSCRIPTIONS_PER_PEER` |
//! | Outbound per peer | 100 | `MAX_OUTBOUND_PER_PEER` |
//! | Total outbound | 50,000 | `MAX_TOTAL_OUTBOUND_MESSAGES` |
//! | Rate limit entries | 10,000 | `MAX_RATE_LIMIT_ENTRIES` |
//! | Message cache | 10,000 | `DEFAULT_MESSAGE_CACHE_SIZE` |
//! | Message size | 64 KB | `MAX_MESSAGE_SIZE` |
//! | Topic name | 256 chars | `MAX_TOPIC_LENGTH` |
//!
//! ## Topic Validation
//!
//! Topic names are validated via `is_valid_topic()`:
//! - Non-empty
//! - Max 256 characters
//! - Printable ASCII only (prevents injection attacks)
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

pub(crate) mod config;
pub(crate) mod gossipsub;
pub(crate) mod message;
pub(crate) mod signature;
pub(crate) mod subscription;
pub(crate) mod types;

// Re-export types for internal use
pub(crate) use config::GossipConfig;
pub(crate) use gossipsub::{GossipSub, PubSubHandler};
pub(crate) use message::PubSubMessage;
pub(crate) use types::ReceivedMessage;

