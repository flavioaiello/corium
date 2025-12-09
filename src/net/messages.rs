//! RPC message envelope for network transport.
//! 
//! This module defines the unified RPC envelope that carries protocol-specific
//! messages over the network. The envelope handles framing and routing while
//! keeping DHT and PubSub protocols cleanly separated.

use bincode::Options;
use serde::{Deserialize, Serialize};

use crate::dht::messages::{DhtRequest, DhtResponse};
use crate::identity::Identity;
use crate::pubsub::PubSubMessage;

/// Maximum RPC message size (1 MB).
pub const MAX_RPC_SIZE: usize = 1024 * 1024;

const MAX_DESERIALIZE_SIZE: u64 = (MAX_RPC_SIZE as u64) + 4096;

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_DESERIALIZE_SIZE)
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

/// Deserialize an RPC request from bytes.
pub fn deserialize_request(bytes: &[u8]) -> Result<RpcRequest, bincode::Error> {
    bincode_options().deserialize(bytes)
}

/// Deserialize an RPC response from bytes.
pub fn deserialize_response(bytes: &[u8]) -> Result<RpcResponse, bincode::Error> {
    bincode_options().deserialize(bytes)
}

/// Serialize an RPC message to bytes.
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    bincode_options().serialize(value)
}

/// Unified RPC request envelope.
/// 
/// Carries either DHT protocol messages or PubSub protocol messages.
/// This separation allows each protocol to evolve independently while
/// sharing the same transport layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcRequest {
    /// DHT protocol request (find_node, find_value, store, ping, etc.)
    Dht(DhtRequest),
    
    /// PubSub protocol request (gossip messages)
    PubSub {
        from: Identity,
        message: PubSubMessage,
    },
}

impl RpcRequest {
    /// Extract the sender identity from the request, if available.
    pub fn sender_identity(&self) -> Option<Identity> {
        match self {
            RpcRequest::Dht(req) => req.sender_identity(),
            RpcRequest::PubSub { from, .. } => Some(*from),
        }
    }
}

/// Unified RPC response envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcResponse {
    /// DHT protocol response
    Dht(DhtResponse),
    
    /// PubSub acknowledgment
    PubSubAck,
    
    /// Generic error
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::Contact;

    fn make_identity(seed: u32) -> Identity {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&seed.to_be_bytes());
        Identity::from_bytes(bytes)
    }

    #[test]
    fn rpc_request_dht_roundtrip() {
        let contact = Contact {
            identity: make_identity(1),
            addr: "127.0.0.1:8080".to_string(),
        };
        let req = RpcRequest::Dht(DhtRequest::Ping { from: contact });
        
        let bytes = serialize(&req).unwrap();
        let decoded: RpcRequest = deserialize_request(&bytes).unwrap();
        
        match decoded {
            RpcRequest::Dht(DhtRequest::Ping { from }) => {
                assert_eq!(from.identity, make_identity(1));
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn rpc_request_pubsub_roundtrip() {
        let req = RpcRequest::PubSub {
            from: make_identity(2),
            message: PubSubMessage::Subscribe { topic: "test".to_string() },
        };
        
        let bytes = serialize(&req).unwrap();
        let decoded: RpcRequest = deserialize_request(&bytes).unwrap();
        
        match decoded {
            RpcRequest::PubSub { from, message } => {
                assert_eq!(from, make_identity(2));
                assert!(matches!(message, PubSubMessage::Subscribe { .. }));
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn rpc_response_roundtrip() {
        let resp = RpcResponse::Dht(DhtResponse::Ack);
        let bytes = serialize(&resp).unwrap();
        let decoded: RpcResponse = deserialize_response(&bytes).unwrap();
        assert!(matches!(decoded, RpcResponse::Dht(DhtResponse::Ack)));
        
        let resp = RpcResponse::PubSubAck;
        let bytes = serialize(&resp).unwrap();
        let decoded: RpcResponse = deserialize_response(&bytes).unwrap();
        assert!(matches!(decoded, RpcResponse::PubSubAck));
    }

    #[test]
    fn sender_identity_extraction() {
        let contact = Contact {
            identity: make_identity(3),
            addr: "127.0.0.1:8080".to_string(),
        };
        
        let dht_req = RpcRequest::Dht(DhtRequest::Ping { from: contact });
        assert_eq!(dht_req.sender_identity(), Some(make_identity(3)));
        
        let pubsub_req = RpcRequest::PubSub {
            from: make_identity(4),
            message: PubSubMessage::Subscribe { topic: "t".to_string() },
        };
        assert_eq!(pubsub_req.sender_identity(), Some(make_identity(4)));
    }
}
