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

mod hash;
mod tiering;
mod storage;
mod params;
mod routing;
mod network;
mod node;

// Re-export types used by other internal modules and lib.rs
// When "tests" feature is enabled, export as `pub` for lib.rs::tests module
#[cfg(feature = "tests")]
pub use hash::{hash_content, verify_key_value_pair, Key};
#[cfg(feature = "tests")]
pub use params::TelemetrySnapshot;
#[cfg(feature = "tests")]
pub use routing::{RoutingTable, Contact};
#[cfg(feature = "tests")]
pub use network::DhtNetwork;
#[cfg(feature = "tests")]
pub use node::DhtNode;

// When "tests" feature is disabled, export as `pub(crate)` for internal use only
#[cfg(not(feature = "tests"))]
pub(crate) use hash::{hash_content, verify_key_value_pair, Key};
#[cfg(not(feature = "tests"))]
pub(crate) use params::TelemetrySnapshot;
#[cfg(not(feature = "tests"))]
pub(crate) use routing::{RoutingTable, Contact};
#[cfg(not(feature = "tests"))]
pub(crate) use network::DhtNetwork;
#[cfg(not(feature = "tests"))]
pub(crate) use node::DhtNode;
