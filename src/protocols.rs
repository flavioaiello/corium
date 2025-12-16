//! Protocol trait definitions for Corium's networking layer.
//!
//! This module defines the core protocol traits that abstract over the
//! underlying RPC transport. Each protocol (DHT, PubSub, Membership, Relay)
//! has its own trait that defines the operations it supports.
//!
//! ## Protocol Traits
//!
//! | Protocol | Trait | Purpose |
//! |----------|-------|---------|
//! | DHT | [`DhtNodeRpc`] | Distributed hash table operations |
//! | PubSub | [`PlumTreeRpc`] | Epidemic broadcast message forwarding |
//! | Membership | [`HyParViewRpc`] | Peer sampling and view management |
//! | Relay | [`RelayRpc`] | NAT traversal via relay servers |
//! | Direct | [`DirectRpc`] | Point-to-point messaging |
//!
//! ## Design
//!
//! Traits are defined here separately from implementations to:
//! - Allow protocols (HyParView, PlumTree) to depend only on traits, not implementations
//! - Enable DHT to be passed to protocols for contact resolution
//! - Avoid circular dependencies between modules

use anyhow::Result;
use async_trait::async_trait;
use quinn::Connection;

use crate::identity::{Contact, Identity};
use crate::messages::{HyParViewRequest, PlumTreeRequest, RelayResponse};
use crate::storage::Key;


/// DHT node operations for distributed routing and storage.
#[async_trait]
pub trait DhtNodeRpc: Send + Sync + 'static {
    /// Find the k closest nodes to a target identity.
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>>;

    /// Find a value by key, returning the value and/or closer nodes.
    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)>;

    /// Store a key-value pair on a remote node.
    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()>;

    /// Ping a node to check liveness.
    async fn ping(&self, to: &Contact) -> Result<()>;
    
    /// Ask a peer to check if we are reachable by connecting back to the given address.
    /// Returns true if the peer successfully connected back.
    async fn check_reachability(&self, to: &Contact, probe_addr: &str) -> Result<bool>;
}


/// PlumTree epidemic broadcast protocol operations.
#[async_trait]
pub trait PlumTreeRpc: Send + Sync {
    /// Send a PlumTree protocol message to a peer.
    async fn send_plumtree(&self, to: &Contact, message: PlumTreeRequest) -> Result<()>;
}


/// HyParView peer sampling protocol operations.
#[async_trait]
pub trait HyParViewRpc: Send + Sync {
    /// Send a HyParView protocol message to a peer.
    async fn send_hyparview(&self, to: &Contact, message: HyParViewRequest) -> Result<()>;
}


/// Relay operations for NAT traversal.
#[async_trait]
pub trait RelayRpc: Send + Sync {
    /// Request a relay session to connect to a NAT-bound peer.
    async fn request_relay_session(
        &self,
        relay: &Contact,
        from_peer: Identity,
        target_peer: Identity,
        session_id: [u8; 16],
    ) -> Result<(Connection, RelayResponse)>;

    /// Register with a relay for incoming connection notifications.
    async fn register_for_signaling(
        &self,
        relay: &Contact,
        our_identity: Identity,
    ) -> Result<tokio::sync::mpsc::Receiver<RelayResponse>>;

    /// Complete a relay session as the receiving peer.
    async fn complete_relay_session(
        &self,
        relay: &Contact,
        from_peer: Identity,
        session_id: [u8; 16],
    ) -> Result<()>;
}


/// Direct point-to-point messaging.
#[async_trait]
pub trait DirectRpc: Send + Sync {
    /// Send raw bytes directly to a peer.
    async fn send_direct(&self, to: &Contact, data: Vec<u8>) -> Result<()>;
}
