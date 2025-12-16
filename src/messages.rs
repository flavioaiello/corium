//! # Wire Protocol Messages
//!
//! This module defines all serializable message types used in Corium's wire protocols.
//! Messages are serialized using bincode with size limits to prevent memory exhaustion.
//!
//! ## Protocol Types
//!
//! | Protocol | Request Type | Response Type |
//! |----------|--------------|---------------|
//! | DHT | `DhtNodeRequest` | `DhtNodeResponse` |
//! | PubSub | `GossipSubRequest` | `GossipSubAck` |
//! | Relay | `RelayRequest` | `RelayResponse` |
//! | Plain | `Vec<u8>` | (application-defined) |
//!
//! ## Security Limits
//!
//! - `MAX_VALUE_SIZE`: Maximum size of stored values (1 MiB)
//! - `MAX_DESERIALIZE_SIZE`: Maximum deserialization buffer (prevents OOM)
//! - All deserialization uses `deserialize_bounded()` with size limits
//!
//! ## Message IDs
//!
//! PubSub messages are identified by a 32-byte `MessageId` computed as:
//! `blake3(topic || source_identity || seqno || data)`
//!
//! This provides content-addressing and deduplication.

use bincode::Options;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::dht::Key;
use crate::identity::{Contact, Identity};

/// Channel sender for plain requests that expect a response.
/// Sends (sender_identity, request_data, response_channel).
pub type PlainRequest = tokio::sync::mpsc::Sender<(
    Identity,
    Vec<u8>,
    tokio::sync::oneshot::Sender<Vec<u8>>,
)>;

/// Maximum size of a stored value in the DHT (1 MiB).
/// Larger values should be chunked or stored externally.
pub const MAX_VALUE_SIZE: usize = 1024 * 1024;

/// Maximum buffer size for deserialization.
/// Set slightly larger than MAX_VALUE_SIZE to allow for message framing overhead.
pub const MAX_DESERIALIZE_SIZE: u64 = (MAX_VALUE_SIZE as u64) + 4096;

/// Returns bincode options with size limits enforced.
/// SECURITY: Always use this for deserialization to prevent OOM attacks.
fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_DESERIALIZE_SIZE)
    .with_fixint_encoding()
}

/// Deserialize with size bounds enforced.
/// SECURITY: Use this instead of raw bincode::deserialize.
pub fn deserialize_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::Error> {
    bincode_options().deserialize(bytes)
}

pub fn serialize_request(request: &RpcRequest) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(request)
}

pub fn deserialize_request(data: &[u8]) -> Result<RpcRequest, bincode::Error> {
    bincode_options().deserialize(data)
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtNodeRequest {
    Ping {
        from: Contact,
    },
    FindNode {
        from: Contact,
        target: Identity,
    },
    FindValue {
        from: Contact,
        key: Key,
    },
    Store {
        from: Contact,
        key: Key,
        value: Vec<u8>,
    },
    /// Request peer to check if we are reachable by connecting back to us.
    /// Used for NAT detection (self-probe).
    CheckReachability {
        from: Contact,
        /// Address we want the peer to try connecting to
        probe_addr: String,
    },
}

impl DhtNodeRequest {
    pub fn sender_identity(&self) -> Option<Identity> {
        match self {
            DhtNodeRequest::Ping { from } => Some(from.identity),
            DhtNodeRequest::FindNode { from, .. } => Some(from.identity),
            DhtNodeRequest::FindValue { from, .. } => Some(from.identity),
            DhtNodeRequest::Store { from, .. } => Some(from.identity),
            DhtNodeRequest::CheckReachability { from, .. } => Some(from.identity),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtNodeResponse {
    Ack,
    Nodes(Vec<Contact>),
    Value {
        value: Option<Vec<u8>>,
        closer: Vec<Contact>,
    },
    /// Response to CheckReachability
    Reachable {
        /// True if we successfully connected back to the requesting peer
        reachable: bool,
    },
    Error {
        message: String,
    },
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelayRequest {
    /// Request to initiate or complete a relay session between two peers.
    Connect {
        from_peer: Identity,
        target_peer: Identity,
        session_id: [u8; 16],
    },
    /// Request a mesh peer to act as relay for connecting to a target peer.
    /// Phase 4: Opportunistic mesh relay - any relay-capable mesh peer can help.
    MeshRelay {
        from_peer: Identity,
        target_peer: Identity,
        session_id: [u8; 16],
    },
}

impl RelayRequest {
    pub fn sender_identity(&self) -> Identity {
        match self {
            RelayRequest::Connect { from_peer, .. } => *from_peer,
            RelayRequest::MeshRelay { from_peer, .. } => *from_peer,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelayResponse {
    /// Session initiated, waiting for peer B to connect.
    Accepted {
        session_id: [u8; 16],
        relay_data_addr: String,
    },
    /// Session established, both peers connected.
    Connected {
        session_id: [u8; 16],
        relay_data_addr: String,
    },
    /// Request rejected with reason.
    Rejected {
        reason: String,
    },
    /// Push notification: another peer wants to connect via relay.
    /// NAT-bound node should initiate Connect with the provided session_id.
    Incoming {
        from_peer: Identity,
        session_id: [u8; 16],
        relay_data_addr: String,
    },
    /// Mesh relay offer: peer is willing to relay.
    /// Phase 4: Response to MeshRelay request when peer can help.
    MeshRelayOffer {
        session_id: [u8; 16],
        relay_data_addr: String,
    },
}


pub type MessageId = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipSubRequest {
    /// Subscribe to a topic - informs peer we want messages for this topic.
    Subscribe {
        topic: String,
    },
    /// Unsubscribe from a topic - informs peer we no longer want messages.
    Unsubscribe {
        topic: String,
    },
    /// GRAFT - request to join the mesh for a topic.
    Graft {
        topic: String,
    },
    /// PRUNE - request to leave the mesh for a topic.
    /// Per GossipSub v1.1: includes backoff duration and optional peer exchange.
    Prune {
        topic: String,
        /// Peer exchange: suggested peers the pruned peer can connect to.
        peers: Vec<Identity>,
        /// Backoff duration in seconds before the peer should attempt to re-graft.
        /// If None, use default backoff (60 seconds per spec).
        backoff_secs: Option<u64>,
    },
    /// Publish a message to a topic with full content.
    Publish {
        topic: String,
        msg_id: MessageId,
        source: Identity,
        seqno: u64,
        data: Vec<u8>,
        signature: Vec<u8>,
    },
    /// IHAVE - gossip announcing message IDs we have for a topic.
    IHave {
        topic: String,
        msg_ids: Vec<MessageId>,
    },
    /// IWANT - request messages by their IDs.
    IWant {
        msg_ids: Vec<MessageId>,
    },
    /// IDONTWANT - preemptively tell peers not to send us certain messages.
    /// Per GossipSub v1.2: optimization to reduce bandwidth by indicating
    /// messages we've already received via another path.
    IDontWant {
        msg_ids: Vec<MessageId>,
    },
    /// RelaySignal - relay signaling message forwarded through mesh.
    /// 
    /// Used for mesh-mediated signaling: instead of maintaining dedicated
    /// connections to relays, signaling messages are forwarded through
    /// GossipSub mesh connections. This reduces connection overhead.
    /// 
    /// The relay sends this to notify a NAT-bound peer about an incoming
    /// connection request. The target peer processes it and completes
    /// the relay handshake.
    RelaySignal {
        /// The target peer identity (recipient of the signal).
        target: Identity,
        /// The peer requesting connection (initiator).
        from_peer: Identity,
        /// Session ID to use for the relay connection.
        session_id: [u8; 16],
        /// Address to send relay data packets to.
        relay_data_addr: String,
    },
}

impl GossipSubRequest {
    pub fn topic(&self) -> Option<&str> {
        match self {
            GossipSubRequest::Subscribe { topic } => Some(topic),
            GossipSubRequest::Unsubscribe { topic } => Some(topic),
            GossipSubRequest::Graft { topic } => Some(topic),
            GossipSubRequest::Prune { topic, .. } => Some(topic),
            GossipSubRequest::Publish { topic, .. } => Some(topic),
            GossipSubRequest::IHave { topic, .. } => Some(topic),
            GossipSubRequest::IWant { .. } => None,
            GossipSubRequest::IDontWant { .. } => None,
            GossipSubRequest::RelaySignal { .. } => None, // Not topic-based
        }
    }
}



#[derive(Clone, Debug)]
pub struct Message {
    pub topic: String,
    pub from: String,
    pub data: Vec<u8>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcRequest {
    DhtNode(DhtNodeRequest),
    Relay(RelayRequest),
    GossipSub(GossipSubRequest),
    Plain(Vec<u8>),
}

impl RpcRequest {
    /// Returns the claimed sender identity for request types that include one.
    /// GossipSub and Plain requests rely on TLS-verified identity.
    pub fn sender_identity(&self) -> Option<Identity> {
        match self {
            RpcRequest::DhtNode(dht_msg) => dht_msg.sender_identity(),
            RpcRequest::Relay(relay_req) => Some(relay_req.sender_identity()),
            // These request types rely on TLS-verified identity
            RpcRequest::GossipSub(_) => None,
            RpcRequest::Plain(_) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResponse {
    DhtNode(DhtNodeResponse),

    Relay(RelayResponse),

    GossipSubAck,

    /// Response to a plain request.
    Plain(Vec<u8>),

    Error { message: String },
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Contact, Identity, Keypair};
    use bincode::Options;

    const MAX_MESSAGE_SIZE: u64 = 64 * 1024;

    fn test_bincode_options() -> impl Options {
        bincode::DefaultOptions::new()
            .with_limit(MAX_MESSAGE_SIZE)
            .with_fixint_encoding()
            .allow_trailing_bytes()
    }

    fn serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
        test_bincode_options().serialize(value)
    }

    fn test_deserialize_request(bytes: &[u8]) -> Result<DhtNodeRequest, bincode::Error> {
        test_bincode_options().deserialize(bytes)
    }

    fn test_deserialize_response(bytes: &[u8]) -> Result<DhtNodeResponse, bincode::Error> {
        test_bincode_options().deserialize(bytes)
    }

    fn make_identity(seed: u32) -> Identity {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&seed.to_be_bytes());
        Identity::from_bytes(bytes)
    }

    fn test_identity() -> Identity {
        Identity::from([1u8; 32])
    }

    fn test_contact() -> Contact {
        Contact::single(test_identity(), "127.0.0.1:4433")
    }


    #[test]
    fn bounded_deserialization_normal_payloads() {
        let request = DhtNodeRequest::Store {
            from: Contact::single(make_identity(1), "127.0.0.1:8080"),
            key: [0u8; 32],
            value: vec![0u8; 100],
        };

        let bytes = serialize(&request).unwrap();
        assert!(test_deserialize_request(&bytes).is_ok());
    }

    #[test]
    fn malformed_data_rejected() {
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        assert!(test_deserialize_request(&garbage).is_err());

        let request = DhtNodeRequest::Ping {
            from: Contact::single(make_identity(1), "127.0.0.1:8080"),
        };
        let bytes = serialize(&request).unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        assert!(test_deserialize_request(truncated).is_err());
    }

    #[test]
    fn response_deserialization() {
        let response = DhtNodeResponse::Nodes(vec![Contact::single(make_identity(1), "127.0.0.1:8080")]);
        let bytes = bincode::serialize(&response).unwrap();
        assert!(test_deserialize_response(&bytes).is_ok());
    }

    #[test]
    fn request_types_roundtrip() {
        let contact = Contact::single(make_identity(1), "127.0.0.1:8080");
        let keypair = Keypair::generate();
        let identity = keypair.identity();

        let requests = vec![
            DhtNodeRequest::Ping { from: contact.clone() },
            DhtNodeRequest::FindNode {
                from: contact.clone(),
                target: make_identity(2),
            },
            DhtNodeRequest::FindValue {
                from: contact.clone(),
                key: [0u8; 32],
            },
            DhtNodeRequest::Store {
                from: contact.clone(),
                key: [0u8; 32],
                value: b"test".to_vec(),
            },
        ];

        for req in requests {
            let bytes = serialize(&req).unwrap();
            let decoded = test_deserialize_request(&bytes).unwrap();
            let _ = format!("{:?}", decoded);
        }
        
        let relay_request = RelayRequest::Connect {
            from_peer: identity,
            target_peer: identity,
            session_id: [0u8; 16],
        };
        let bytes = serialize(&relay_request).unwrap();
        let decoded: RelayRequest = test_bincode_options().deserialize(&bytes).unwrap();
        let _ = format!("{:?}", decoded);
    }

    #[test]
    fn sender_identity_extraction() {
        let contact = Contact::single(make_identity(42), "127.0.0.1:8080");

        let ping = DhtNodeRequest::Ping { from: contact.clone() };
        assert_eq!(ping.sender_identity(), Some(make_identity(42)));

        let find_node = DhtNodeRequest::FindNode {
            from: contact.clone(),
            target: make_identity(1),
        };
        assert_eq!(find_node.sender_identity(), Some(make_identity(42)));
    }

    #[test]
    fn content_addressing_integrity() {
        use crate::dht::{hash_content, verify_key_value_pair};

        let data = b"original content";
        let key = hash_content(data);

        assert!(verify_key_value_pair(&key, data));

        let corrupted = b"corrupted content";
        assert!(!verify_key_value_pair(&key, corrupted));
    }

    #[test]
    fn empty_data_hashing() {
        use crate::dht::{hash_content, verify_key_value_pair};

        let empty = b"";
        let key = hash_content(empty);

        assert!(verify_key_value_pair(&key, empty));
        assert!(!verify_key_value_pair(&key, b"not empty"));
    }

    #[test]
    fn hash_collision_resistance() {
        use crate::dht::hash_content;

        let data1 = b"data one";
        let data2 = b"data two";

        let hash1 = hash_content(data1);
        let hash2 = hash_content(data2);

        assert_ne!(hash1, hash2);

        let data3 = b"data onf";        let hash3 = hash_content(data3);
        assert_ne!(hash1, hash3);
    }


    #[test]
    fn gossipsub_message_variants() {
        let sub = GossipSubRequest::Subscribe {
            topic: "test".to_string(),
        };
        assert_eq!(sub.topic(), Some("test"));

        let unsub = GossipSubRequest::Unsubscribe {
            topic: "test".to_string(),
        };
        assert_eq!(unsub.topic(), Some("test"));

        let graft = GossipSubRequest::Graft {
            topic: "test".to_string(),
        };
        assert_eq!(graft.topic(), Some("test"));

        let prune = GossipSubRequest::Prune {
            topic: "test".to_string(),
            peers: vec![],
            backoff_secs: None,
        };
        assert_eq!(prune.topic(), Some("test"));

        let ihave = GossipSubRequest::IHave {
            topic: "test".to_string(),
            msg_ids: vec![],
        };
        assert_eq!(ihave.topic(), Some("test"));

        let iwant = GossipSubRequest::IWant { msg_ids: vec![] };
        assert_eq!(iwant.topic(), None);
    }

    #[test]
    fn gossipsub_message_serialization() {
        let identity = Identity::from_bytes([1u8; 32]);
        let msg = GossipSubRequest::Publish {
            topic: "test".to_string(),
            msg_id: [0u8; 32],
            source: identity,
            seqno: 1,
            data: b"hello".to_vec(),
            signature: vec![0u8; 64],
        };

        let encoded = bincode::serialize(&msg).expect("serialize failed");
        let decoded: GossipSubRequest = bincode::deserialize(&encoded).expect("deserialize failed");

        match decoded {
            GossipSubRequest::Publish {
                topic, seqno, data, ..
            } => {
                assert_eq!(topic, "test");
                assert_eq!(seqno, 1);
                assert_eq!(data, b"hello");
            }
            _ => panic!("wrong variant"),
        }
    }


    #[test]
    fn round_trip_dht_ping() {
        let request = RpcRequest::DhtNode(DhtNodeRequest::Ping {
            from: test_contact(),
        });

        let bytes = serialize_request(&request).expect("serialize should succeed");
        let decoded = deserialize_request(&bytes).expect("deserialize should succeed");

        match decoded {
            RpcRequest::DhtNode(DhtNodeRequest::Ping { from }) => {
                assert_eq!(from.identity, test_identity());
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn round_trip_dht_response() {
        let response = RpcResponse::DhtNode(DhtNodeResponse::Ack);
        let bytes = bincode::serialize(&response).expect("serialize should succeed");
        let decoded: RpcResponse =
            bincode::deserialize(&bytes).expect("deserialize should succeed");

        match decoded {
            RpcResponse::DhtNode(DhtNodeResponse::Ack) => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn round_trip_gossipsub_request() {
        let request = RpcRequest::GossipSub(GossipSubRequest::Publish {
            topic: "test".to_string(),
            msg_id: [0u8; 32],
            source: test_identity(),
            seqno: 1,
            data: b"hello".to_vec(),
            signature: vec![],
        });

        let bytes = serialize_request(&request).expect("serialize should succeed");
        let decoded = deserialize_request(&bytes).expect("deserialize should succeed");

        match decoded {
            RpcRequest::GossipSub(GossipSubRequest::Publish { topic, .. }) => {
                assert_eq!(topic, "test");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn round_trip_gossipsub_ack() {
        let response = RpcResponse::GossipSubAck;
        let bytes = bincode::serialize(&response).expect("serialize should succeed");
        let decoded: RpcResponse =
            bincode::deserialize(&bytes).expect("deserialize should succeed");

        match decoded {
            RpcResponse::GossipSubAck => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn round_trip_error_response() {
        let response = RpcResponse::Error {
            message: "test error".to_string(),
        };
        let bytes = bincode::serialize(&response).expect("serialize should succeed");
        let decoded: RpcResponse =
            bincode::deserialize(&bytes).expect("deserialize should succeed");

        match decoded {
            RpcResponse::Error { message } => {
                assert_eq!(message, "test error");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn gossipsub_message_topic_accessor() {
        let subscribe = GossipSubRequest::Subscribe { topic: "test".into() };
        assert_eq!(subscribe.topic(), Some("test"));
        
        let unsubscribe = GossipSubRequest::Unsubscribe { topic: "foo".into() };
        assert_eq!(unsubscribe.topic(), Some("foo"));
        
        let graft = GossipSubRequest::Graft { topic: "bar".into() };
        assert_eq!(graft.topic(), Some("bar"));
        
        let prune = GossipSubRequest::Prune { topic: "baz".into(), peers: vec![], backoff_secs: None };
        assert_eq!(prune.topic(), Some("baz"));
        
        let publish = GossipSubRequest::Publish {
            topic: "pub".into(),
            msg_id: [0u8; 32],
            source: test_identity(),
            seqno: 1,
            data: vec![],
            signature: vec![],
        };
        assert_eq!(publish.topic(), Some("pub"));
        
        let ihave = GossipSubRequest::IHave { topic: "ih".into(), msg_ids: vec![] };
        assert_eq!(ihave.topic(), Some("ih"));
        
        let iwant = GossipSubRequest::IWant { msg_ids: vec![] };
        assert_eq!(iwant.topic(), None);
    }
}
