//! Core DHT logic: transport-agnostic Kademlia implementation with adaptive tiering.
//!
//! This module contains the fundamental building blocks of the DHT:
//!
//! - **Identity & Hashing**: [`hash_content`], [`verify_key_value_pair`] for content-addressed storage
//! - **Distance Metrics**: XOR distance for Kademlia-style routing
//! - **Routing**: [`RoutingTable`], [`Contact`] for peer management with 256 k-buckets
//! - **Storage**: Local content-addressable store with LRU eviction, per-peer quotas, and pressure-based backpressure
//! - **Tiering**: Latency-based peer classification using dynamic k-means clustering (1-7 tiers)
//! - **Adaptive Parameters**: Dynamic `k` (10-30) and `α` (2-5) adjustment based on network churn
//! - **Node State Machine**: [`DhtNode`] orchestrating iterative lookups, replication, and address publishing

mod hash;
mod tiering;
mod storage;
mod params;
mod routing;
mod network;
mod node;

// Re-export types used by other internal modules and lib.rs
pub use hash::{hash_content, verify_key_value_pair, Key};
pub use params::TelemetrySnapshot;
pub use routing::{RoutingTable, Contact};
pub use network::DhtNetwork;
pub use node::DhtNode;
