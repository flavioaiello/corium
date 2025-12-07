//! Network abstraction for DHT RPC operations.
//!
//! This module defines the [`DhtNetwork`] trait that abstracts the transport layer,
//! allowing the core DHT logic to work with different network implementations
//! (e.g., [`PeerNetwork`][crate::net::PeerNetwork] for QUIC, mock for testing).
//!
//! # Design
//!
//! The trait defines four core Kademlia RPCs:
//! - `find_node`: Locate k-closest peers to a target identity
//! - `find_value`: Retrieve a value or get closer contacts if not found
//! - `store`: Replicate a key-value pair to a peer
//! - `ping`: Check liveness for bucket eviction decisions

use anyhow::Result;
use async_trait::async_trait;

use super::hash::Key;
use super::routing::Contact;
use crate::identity::Identity;

/// Network abstraction for DHT RPC operations.
///
/// This trait abstracts the transport layer, allowing the core DHT logic to work
/// with different network implementations (e.g., quinn QUIC, mock for testing).
#[async_trait]
pub trait DhtNetwork: Send + Sync + 'static {
    /// Send a FIND_NODE RPC to find contacts near a target identity.
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>>;

    /// Send a FIND_VALUE RPC to retrieve a value or get closer contacts.
    ///
    /// Returns (value, closer_nodes) where value is Some if the key was found.
    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)>;

    /// Send a STORE RPC to store a key-value pair on a node.
    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()>;

    /// Ping a contact to check if it's still responsive.
    ///
    /// Used for the Kademlia "ping-before-evict" rule: when a bucket is full,
    /// the oldest contact is pinged to verify it's still alive before deciding
    /// whether to keep it or replace it with the new contact.
    async fn ping(&self, to: &Contact) -> Result<()>;
}
