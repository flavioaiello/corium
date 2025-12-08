//! Core DHT logic: transport-agnostic Kademlia implementation with adaptive tiering.
//!
//! This module is internal to the crate. Types are exposed externally only via
//! the `tests` feature module in `lib.rs`.
//!
//! # Contents
//!
//! - **Identity & Hashing**: [`hash_content`], [`verify_key_value_pair`] for content-addressed storage
//! - **Distance Metrics**: XOR distance for Kademlia-style routing
//! - **Routing**: [`RoutingTable`], [`Contact`] for peer management with 256 k-buckets
//! - **Storage**: Local content-addressable store with LRU eviction, per-peer quotas, and pressure-based backpressure
//! - **Tiering**: Latency-based peer classification using dynamic k-means clustering (1-7 tiers)
//! - **Adaptive Parameters**: Dynamic `k` (10-30) and `α` (2-5) adjustment based on network churn
//! - **Node State Machine**: [`DhtNode`] orchestrating iterative lookups, replication, and address publishing
//!
//! # Security Architecture
//!
//! The DHT implements defense-in-depth against common P2P attacks:
//!
//! ## Sybil Attack Protection
//! - **Identity = Ed25519 public key**: Creating identities requires generating valid keypairs
//! - **Per-peer rate limiting**: Each peer can only insert 50 contacts/minute into routing table
//! - **Per-peer storage quotas**: Each peer can only store 1 MB / 100 entries
//!
//! ## Eclipse Attack Protection  
//! - **Routing table insertion limits**: Prevents flooding with malicious contacts
//! - **Ping-before-evict**: Long-lived nodes are preferred over new contacts
//! - **Bucket refresh**: Stale buckets are refreshed to discover legitimate peers
//!
//! ## Storage Exhaustion Protection
//! - **Maximum value size**: 1 MB per value
//! - **Pressure monitoring**: Automatic eviction when memory/disk pressure exceeds threshold
//! - **Popularity-based eviction**: Frequently accessed data survives longer
//! - **Bounded collections**: All HashMaps have maximum size limits
//!
//! ## Replay Attack Protection
//! - **Timestamp freshness**: EndpointRecords expire after 24 hours
//! - **Signature verification**: All mutable records require valid Ed25519 signatures
//! - **Content verification**: Immutable data verified via BLAKE3 hash

pub(crate) mod hash;
pub(crate) mod tiering;
pub(crate) mod storage;
pub(crate) mod params;
pub(crate) mod routing;
pub(crate) mod network;
pub(crate) mod node;

// Re-export types used by other internal modules
pub(crate) use hash::{hash_content, Key};
pub(crate) use params::TelemetrySnapshot;
pub(crate) use routing::Contact;
pub(crate) use network::DhtNetwork;
pub(crate) use node::DhtNode;
