//! Wire protocol for all RPC communication.
//!
//! This module defines the unified request and response types for DHT, Relay,
//! PubSub, and hole-punching communication. All messages are serializable using
//! bincode for efficient network transport.
//!
//! # Security
//!
//! Use the bounded deserialization functions (`deserialize_request`, `deserialize_response`)
//! instead of raw `bincode::deserialize` to prevent memory exhaustion attacks from
//! malicious payloads advertising large collection sizes.

use bincode::Options;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::dht::{Contact, Key};
use crate::identity::Identity;
use crate::pubsub::PubSubMessage;

/// Maximum size of a value in the DHT (1 MB).
pub const MAX_VALUE_SIZE: usize = 1024 * 1024;

/// Maximum deserialization size for RPC requests (1 MB + overhead).
/// This bounds the memory that can be allocated during deserialization.
pub const MAX_DESERIALIZE_SIZE: u64 = (MAX_VALUE_SIZE as u64) + 4096;

/// Create bincode options with bounded size.
///
/// This prevents attacks where a malicious sender advertises a huge Vec/String
/// length to cause out-of-memory conditions.
fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_DESERIALIZE_SIZE)
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

/// Deserialize a DHT request with size bounds.
///
/// Returns an error if the payload would exceed the size limit.
pub fn deserialize_request(bytes: &[u8]) -> Result<DhtRequest, bincode::Error> {
    bincode_options().deserialize(bytes)
}

/// Deserialize a DHT response with size bounds.
///
/// Returns an error if the payload would exceed the size limit.
pub fn deserialize_response(bytes: &[u8]) -> Result<DhtResponse, bincode::Error> {
    // Allow larger responses for FIND_VALUE which may contain data
    bincode::DefaultOptions::new()
        .with_limit(1024 * 1024) // 1 MB limit for responses
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(bytes)
}

/// Deserialize any type with the standard size bounds.
pub fn deserialize_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::Error> {
    bincode_options().deserialize(bytes)
}

/// Serialize with standard bincode options.
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    bincode_options().serialize(value)
}

/// DHT RPC request types.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtRequest {
    /// Ping request to check if a node is responsive.
    Ping {
        /// The sender's contact information.
        from: Contact,
    },
    /// Find nodes closest to a target identity.
    FindNode {
        /// The sender's contact information.
        from: Contact,
        /// The target identity to find neighbors for.
        target: Identity,
    },
    /// Find a value by key, or get closer nodes if not found.
    FindValue {
        /// The sender's contact information.
        from: Contact,
        /// The key to look up.
        key: Key,
    },
    /// Store a key-value pair on a node.
    Store {
        /// The sender's contact information.
        from: Contact,
        /// The key to store.
        key: Key,
        /// The value to store.
        value: Vec<u8>,
    },
    /// Request to establish a relay session.
    ///
    /// Used when direct connection fails due to NAT. Both peers connect
    /// outbound to the relay, which forwards encrypted packets via UDP.
    RelayConnect {
        /// The sender's peer ID.
        from_peer: Identity,
        /// The target peer we want to reach.
        target_peer: Identity,
        /// Session ID to correlate the two halves of the relay.
        session_id: [u8; 16],
    },
    /// STUN-like request: ask the server what our public address looks like.
    ///
    /// The relay/server responds with the observed source address of this request.
    /// This enables NAT type detection and public address discovery.
    WhatIsMyAddr,
    /// Hole punch coordination request.
    ///
    /// Sent to a rendezvous server to coordinate simultaneous connection.
    /// Both peers register, then receive a signal to start connecting.
    HolePunchRegister {
        /// Our peer ID.
        from_peer: Identity,
        /// Peer we want to connect to.
        target_peer: Identity,
        /// Our public address (from STUN).
        our_public_addr: String,
        /// Unique punch session ID.
        punch_id: [u8; 16],
    },
    /// Signal that peer should start hole punch attempt.
    HolePunchStart {
        /// The punch session ID.
        punch_id: [u8; 16],
    },
    /// PubSub message (Graft, Prune, Publish, IHave, IWant, etc.).
    ///
    /// Used by the GossipSub layer for topic-based publish/subscribe.
    PubSub {
        /// The sender's identity.
        from: Identity,
        /// The pubsub protocol message.
        message: PubSubMessage,
    },
}

impl DhtRequest {
    /// Extract the sender's identity from the request, if present.
    ///
    /// This is used for Sybil protection: the returned identity must match
    /// the verified identity from the TLS connection.
    pub fn sender_identity(&self) -> Option<Identity> {
        match self {
            DhtRequest::Ping { from } => Some(from.identity),
            DhtRequest::FindNode { from, .. } => Some(from.identity),
            DhtRequest::FindValue { from, .. } => Some(from.identity),
            DhtRequest::Store { from, .. } => Some(from.identity),
            DhtRequest::RelayConnect { from_peer, .. } => Some(*from_peer),
            DhtRequest::WhatIsMyAddr => None,
            DhtRequest::HolePunchRegister { from_peer, .. } => Some(*from_peer),
            DhtRequest::HolePunchStart { .. } => None,
            DhtRequest::PubSub { from, .. } => Some(*from),
        }
    }
}

/// DHT RPC response types.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtResponse {
    /// Acknowledgment response (for Ping and Store).
    Ack,
    /// Response containing a list of nodes (for FindNode).
    Nodes(Vec<Contact>),
    /// Response for FindValue containing optional value and closer nodes.
    Value {
        /// The value if found locally.
        value: Option<Vec<u8>>,
        /// Closer nodes to continue the lookup if value not found.
        closer: Vec<Contact>,
    },
    /// Relay session accepted, waiting for peer.
    RelayAccepted {
        /// Confirmed session ID.
        session_id: [u8; 16],
        /// UDP address for sending CRLY-framed relay data.
        /// Clients should send raw UDP packets (not RPC) with CRLY framing to this address.
        relay_data_addr: String,
    },
    /// Relay session established (both peers connected).
    RelayConnected {
        /// Session ID.
        session_id: [u8; 16],
        /// UDP address for sending CRLY-framed relay data.
        /// Clients should send raw UDP packets (not RPC) with CRLY framing to this address.
        relay_data_addr: String,
    },
    /// Relay request rejected.
    RelayRejected {
        /// Reason for rejection.
        reason: String,
    },
    /// Response to WhatIsMyAddr with the observed public address.
    ///
    /// This is the STUN-like response containing the client's public IP:port
    /// as seen by the server. Useful for NAT detection and hole punching.
    YourAddr {
        /// The observed address in "ip:port" format.
        addr: String,
    },
    /// Hole punch registration accepted, waiting for peer.
    HolePunchWaiting {
        /// The punch session ID.
        punch_id: [u8; 16],
    },
    /// Both peers registered, start punching now!
    HolePunchReady {
        /// The punch session ID.
        punch_id: [u8; 16],
        /// Peer's public address to punch towards.
        peer_addr: String,
        /// Synchronized start time (Unix millis).
        start_time_ms: u64,
    },
    /// Hole punch failed or timed out.
    HolePunchFailed {
        /// Reason for failure.
        reason: String,
    },
    /// Acknowledgement for PubSub messages.
    ///
    /// Simple ack indicating the pubsub message was received and processed.
    PubSubAck,
    /// Error response for protocol violations.
    ///
    /// Used when a request is rejected due to identity mismatch (Sybil protection)
    /// or other protocol errors.
    Error {
        /// Human-readable error message.
        message: String,
    },
}
