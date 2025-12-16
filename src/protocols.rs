//! Protocol trait definitions for Corium's networking layer.
//!
//! This module defines the core protocol traits that abstract over the
//! underlying RPC transport. Each protocol (DHT, PubSub, Relay)
//! has its own trait that defines the operations it supports.
//!
//! ## Protocol Traits
//!
//! | Protocol | Trait | Purpose |
//! |----------|-------|---------|
//! | DHT | [`DhtNodeRpc`] | Distributed hash table operations |
//! | PubSub | [`GossipSubRpc`] | Epidemic broadcast message forwarding |
//! | Relay | [`RelayRpc`] | NAT traversal via relay servers |
//! | Plain | [`PlainRpc`] | Point-to-point messaging |
//!
//! ## Design
//!
//! Traits are defined here separately from implementations to:
//! - Allow protocols (GossipSub) to depend only on traits, not implementations
//! - Enable DHT to be passed to protocols for contact resolution
//! - Avoid circular dependencies between modules

use anyhow::Result;
use async_trait::async_trait;

use crate::identity::{Contact, Identity};
use crate::messages::{GossipSubRequest, RelayResponse};
use crate::dht::Key;


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


/// GossipSub epidemic broadcast protocol operations.
#[async_trait]
pub trait GossipSubRpc: Send + Sync {
    /// Send a GossipSub protocol message to a peer.
    async fn send_gossipsub(&self, to: &Contact, message: GossipSubRequest) -> Result<()>;
}


/// Relay operations for NAT traversal.
#[async_trait]
pub trait RelayRpc: Send + Sync {
    /// Complete a relay session as the receiving peer.
    async fn complete_relay_session(
        &self,
        relay: &Contact,
        from_peer: Identity,
        session_id: [u8; 16],
    ) -> Result<()>;

    /// Request a mesh peer to act as a relay (Phase 4: opportunistic mesh relay).
    /// 
    /// Unlike dedicated relay servers, mesh peers provide lightweight relay
    /// for NAT-bound peers they're already connected to.
    async fn request_mesh_relay(
        &self,
        mesh_peer: &Contact,
        from_peer: Identity,
        target_peer: Identity,
        session_id: [u8; 16],
    ) -> Result<RelayResponse>;
}


/// Plain point-to-point request-response messaging.
#[async_trait]
pub trait PlainRpc: Send + Sync {
    /// Send a request directly to a peer and receive a response.
    /// 
    /// The caller sends a request and blocks until a response is received.
    async fn send(&self, to: &Contact, request: Vec<u8>) -> Result<Vec<u8>>;
}
