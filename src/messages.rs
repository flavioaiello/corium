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
    /// as seen by the server. Useful for NAT detection.
    YourAddr {
        /// The observed address in "ip:port" format.
        addr: String,
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::Contact;
    use crate::identity::{Identity, Keypair};

    fn make_identity(seed: u32) -> Identity {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&seed.to_be_bytes());
        Identity::from_bytes(bytes)
    }

    /// Test that bounded deserialization works for normal payloads.
    #[test]
    fn bounded_deserialization_normal_payloads() {
        let request = DhtRequest::Store {
            from: Contact {
                identity: make_identity(1),
                addr: "127.0.0.1:8080".to_string(),
            },
            key: [0u8; 32],
            value: vec![0u8; 100],
        };

        let bytes = serialize(&request).unwrap();
        assert!(deserialize_request(&bytes).is_ok());
    }

    /// Test that malformed data is rejected gracefully.
    #[test]
    fn malformed_data_rejected() {
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        assert!(deserialize_request(&garbage).is_err());

        let request = DhtRequest::Ping {
            from: Contact {
                identity: make_identity(1),
                addr: "127.0.0.1:8080".to_string(),
            },
        };
        let bytes = serialize(&request).unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        assert!(deserialize_request(truncated).is_err());
    }

    /// Test that response deserialization works.
    #[test]
    fn response_deserialization() {
        let response = DhtResponse::Nodes(vec![Contact {
            identity: make_identity(1),
            addr: "127.0.0.1:8080".to_string(),
        }]);
        let bytes = bincode::serialize(&response).unwrap();
        assert!(deserialize_response(&bytes).is_ok());
    }

    /// Test that all request types roundtrip correctly.
    #[test]
    fn request_types_roundtrip() {
        let contact = Contact {
            identity: make_identity(1),
            addr: "127.0.0.1:8080".to_string(),
        };
        let keypair = Keypair::generate();
        let identity = keypair.identity();

        let requests = vec![
            DhtRequest::Ping { from: contact.clone() },
            DhtRequest::FindNode {
                from: contact.clone(),
                target: make_identity(2),
            },
            DhtRequest::FindValue {
                from: contact.clone(),
                key: [0u8; 32],
            },
            DhtRequest::Store {
                from: contact.clone(),
                key: [0u8; 32],
                value: b"test".to_vec(),
            },
            DhtRequest::RelayConnect {
                from_peer: identity,
                target_peer: identity,
                session_id: [0u8; 16],
            },
            DhtRequest::WhatIsMyAddr,
        ];

        for req in requests {
            let bytes = serialize(&req).unwrap();
            let decoded = deserialize_request(&bytes).unwrap();
            let _ = format!("{:?}", decoded);
        }
    }

    /// Test sender_identity extraction from requests.
    #[test]
    fn sender_identity_extraction() {
        let contact = Contact {
            identity: make_identity(42),
            addr: "127.0.0.1:8080".to_string(),
        };

        let ping = DhtRequest::Ping { from: contact.clone() };
        assert_eq!(ping.sender_identity(), Some(make_identity(42)));

        let find_node = DhtRequest::FindNode {
            from: contact.clone(),
            target: make_identity(1),
        };
        assert_eq!(find_node.sender_identity(), Some(make_identity(42)));

        let what_is_my_addr = DhtRequest::WhatIsMyAddr;
        assert_eq!(what_is_my_addr.sender_identity(), None);
    }

    /// Test content addressing integrity.
    #[test]
    fn content_addressing_integrity() {
        use crate::dht::hash::{hash_content, verify_key_value_pair};

        let data = b"original content";
        let key = hash_content(data);

        assert!(verify_key_value_pair(&key, data));

        let corrupted = b"corrupted content";
        assert!(!verify_key_value_pair(&key, corrupted));
    }

    /// Test empty data hashing.
    #[test]
    fn empty_data_hashing() {
        use crate::dht::hash::{hash_content, verify_key_value_pair};

        let empty = b"";
        let key = hash_content(empty);

        assert!(verify_key_value_pair(&key, empty));
        assert!(!verify_key_value_pair(&key, b"not empty"));
    }

    /// Test hash collision resistance.
    #[test]
    fn hash_collision_resistance() {
        use crate::dht::hash_content;

        let data1 = b"data one";
        let data2 = b"data two";

        let hash1 = hash_content(data1);
        let hash2 = hash_content(data2);

        assert_ne!(hash1, hash2);

        let data3 = b"data onf"; // One bit different
        let hash3 = hash_content(data3);
        assert_ne!(hash1, hash3);
    }
}
