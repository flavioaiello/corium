use bincode::Options;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::dht::{Contact, Key};
use crate::identity::Identity;

pub const MAX_VALUE_SIZE: usize = 1024 * 1024;

pub const MAX_DESERIALIZE_SIZE: u64 = (MAX_VALUE_SIZE as u64) + 4096;

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_DESERIALIZE_SIZE)
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

pub fn deserialize_request(bytes: &[u8]) -> Result<DhtRequest, bincode::Error> {
    bincode_options().deserialize(bytes)
}

pub fn deserialize_response(bytes: &[u8]) -> Result<DhtResponse, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_limit(1024 * 1024) // 1 MB limit for responses
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(bytes)
}

pub fn deserialize_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::Error> {
    bincode_options().deserialize(bytes)
}

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    bincode_options().serialize(value)
}

/// DHT protocol request messages.
/// 
/// These are pure DHT operations - routing, storage, and NAT/relay coordination.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtRequest {
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
    RelayConnect {
        from_peer: Identity,
        target_peer: Identity,
        session_id: [u8; 16],
    },
    WhatIsMyAddr,
}

impl DhtRequest {
    pub fn sender_identity(&self) -> Option<Identity> {
        match self {
            DhtRequest::Ping { from } => Some(from.identity),
            DhtRequest::FindNode { from, .. } => Some(from.identity),
            DhtRequest::FindValue { from, .. } => Some(from.identity),
            DhtRequest::Store { from, .. } => Some(from.identity),
            DhtRequest::RelayConnect { from_peer, .. } => Some(*from_peer),
            DhtRequest::WhatIsMyAddr => None,
        }
    }
}

/// DHT protocol response messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtResponse {
    Ack,
    Nodes(Vec<Contact>),
    Value {
        value: Option<Vec<u8>>,
        closer: Vec<Contact>,
    },
    RelayAccepted {
        session_id: [u8; 16],
        relay_data_addr: String,
    },
    RelayConnected {
        session_id: [u8; 16],
        relay_data_addr: String,
    },
    RelayRejected {
        reason: String,
    },
    YourAddr {
        addr: String,
    },
    Error {
        message: String,
    },
}

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

    #[test]
    fn response_deserialization() {
        let response = DhtResponse::Nodes(vec![Contact {
            identity: make_identity(1),
            addr: "127.0.0.1:8080".to_string(),
        }]);
        let bytes = bincode::serialize(&response).unwrap();
        assert!(deserialize_response(&bytes).is_ok());
    }

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

    #[test]
    fn content_addressing_integrity() {
        use crate::dht::hash::{hash_content, verify_key_value_pair};

        let data = b"original content";
        let key = hash_content(data);

        assert!(verify_key_value_pair(&key, data));

        let corrupted = b"corrupted content";
        assert!(!verify_key_value_pair(&key, corrupted));
    }

    #[test]
    fn empty_data_hashing() {
        use crate::dht::hash::{hash_content, verify_key_value_pair};

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

        let data3 = b"data onf"; // One bit different
        let hash3 = hash_content(data3);
        assert_ne!(hash1, hash3);
    }
}
