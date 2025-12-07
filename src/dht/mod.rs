//! Core DHT logic: transport-agnostic Kademlia implementation with adaptive tiering.
//!
//! This module contains the fundamental building blocks of the sloppy DHT:
//!
//! - **Identity & Hashing**: [`hash_content`], [`verify_key_value_pair`]
//! - **Distance Metrics**: [`xor_distance`] for Kademlia-style routing
//! - **Routing**: [`RoutingTable`], [`Contact`] for peer management
//! - **Storage**: Local content-addressable store with LRU eviction and backpressure
//! - **Tiering**: Latency-based peer classification using k-means clustering
//! - **Adaptive Parameters**: Dynamic `k` adjustment based on network churn
//! - **Node State Machine**: [`DhtNode`] for DHT operations

pub mod hash;
pub mod tiering;
pub mod storage;
pub mod params;
pub mod routing;
pub mod network;
pub mod node;

// Re-export public types (only items used externally via lib.rs re-exports)
pub use hash::{hash_content, verify_key_value_pair, xor_distance, is_valid_identity, Key};
pub use params::TelemetrySnapshot;
pub use routing::{RoutingTable, Contact};
pub use network::DhtNetwork;
pub use node::DhtNode;
