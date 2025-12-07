//! PubSub protocol messages.
//!
//! Defines the wire protocol messages used by GossipSub for mesh management
//! and message propagation.

use serde::{Deserialize, Serialize};

use crate::identity::Identity;

/// Unique identifier for a pubsub message.
pub type MessageId = [u8; 32];

/// A pubsub protocol message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PubSubMessage {
    /// Subscribe to a topic (join mesh).
    Subscribe {
        /// The topic to subscribe to.
        topic: String,
    },
    /// Unsubscribe from a topic (leave mesh).
    Unsubscribe {
        /// The topic to unsubscribe from.
        topic: String,
    },
    /// Request to join a peer's mesh for a topic.
    Graft {
        /// The topic to graft into.
        topic: String,
    },
    /// Notification that we're leaving a peer's mesh.
    Prune {
        /// The topic to prune from.
        topic: String,
        /// Optional: suggest other peers for the topic.
        peers: Vec<Identity>,
    },
    /// Publish a message to a topic.
    Publish {
        /// The topic to publish to.
        topic: String,
        /// Unique message identifier (hash of data).
        msg_id: MessageId,
        /// The message originator.
        source: Identity,
        /// Sequence number from source.
        seqno: u64,
        /// The message payload.
        data: Vec<u8>,
        /// Ed25519 signature over (topic || seqno || data) by source's private key.
        /// This proves the message was created by the claimed source identity.
        signature: Vec<u8>,
    },
    /// Gossip: "I have these messages" (lazy push).
    IHave {
        /// The topic these messages belong to.
        topic: String,
        /// Message IDs we have.
        msg_ids: Vec<MessageId>,
    },
    /// Request: "Send me these messages".
    IWant {
        /// Message IDs we want.
        msg_ids: Vec<MessageId>,
    },
}

impl PubSubMessage {
    /// Get the topic this message relates to, if any.
    pub fn topic(&self) -> Option<&str> {
        match self {
            PubSubMessage::Subscribe { topic } => Some(topic),
            PubSubMessage::Unsubscribe { topic } => Some(topic),
            PubSubMessage::Graft { topic } => Some(topic),
            PubSubMessage::Prune { topic, .. } => Some(topic),
            PubSubMessage::Publish { topic, .. } => Some(topic),
            PubSubMessage::IHave { topic, .. } => Some(topic),
            PubSubMessage::IWant { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubsub_message_variants() {
        // Test Subscribe
        let sub = PubSubMessage::Subscribe { topic: "test".to_string() };
        assert_eq!(sub.topic(), Some("test"));
        
        // Test Unsubscribe
        let unsub = PubSubMessage::Unsubscribe { topic: "test".to_string() };
        assert_eq!(unsub.topic(), Some("test"));
        
        // Test Graft
        let graft = PubSubMessage::Graft { topic: "test".to_string() };
        assert_eq!(graft.topic(), Some("test"));
        
        // Test Prune
        let prune = PubSubMessage::Prune { 
            topic: "test".to_string(), 
            peers: vec![] 
        };
        assert_eq!(prune.topic(), Some("test"));
        
        // Test IHave
        let ihave = PubSubMessage::IHave { 
            topic: "test".to_string(), 
            msg_ids: vec![] 
        };
        assert_eq!(ihave.topic(), Some("test"));
        
        // Test IWant (no topic)
        let iwant = PubSubMessage::IWant { msg_ids: vec![] };
        assert_eq!(iwant.topic(), None);
    }

    #[test]
    fn pubsub_message_serialization() {
        let identity = Identity::from_bytes([1u8; 32]);
        let msg = PubSubMessage::Publish {
            topic: "test".to_string(),
            msg_id: [0u8; 32],
            source: identity,
            seqno: 1,
            data: b"hello".to_vec(),
            signature: vec![0u8; 64],
        };
        
        // Serialize and deserialize
        let encoded = bincode::serialize(&msg).expect("serialize failed");
        let decoded: PubSubMessage = bincode::deserialize(&encoded).expect("deserialize failed");
        
        match decoded {
            PubSubMessage::Publish { topic, seqno, data, .. } => {
                assert_eq!(topic, "test");
                assert_eq!(seqno, 1);
                assert_eq!(data, b"hello");
            }
            _ => panic!("wrong variant"),
        }
    }
}
