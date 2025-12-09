use serde::{Deserialize, Serialize};

use crate::identity::Identity;

pub type MessageId = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PubSubMessage {
    Subscribe {
        topic: String,
    },
    Unsubscribe {
        topic: String,
    },
    Graft {
        topic: String,
    },
    Prune {
        topic: String,
        peers: Vec<Identity>,
    },
    Publish {
        topic: String,
        msg_id: MessageId,
        source: Identity,
        seqno: u64,
        data: Vec<u8>,
        signature: Vec<u8>,
    },
    IHave {
        topic: String,
        msg_ids: Vec<MessageId>,
    },
    IWant {
        msg_ids: Vec<MessageId>,
    },
}

impl PubSubMessage {
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
        let sub = PubSubMessage::Subscribe { topic: "test".to_string() };
        assert_eq!(sub.topic(), Some("test"));
        
        let unsub = PubSubMessage::Unsubscribe { topic: "test".to_string() };
        assert_eq!(unsub.topic(), Some("test"));
        
        let graft = PubSubMessage::Graft { topic: "test".to_string() };
        assert_eq!(graft.topic(), Some("test"));
        
        let prune = PubSubMessage::Prune { 
            topic: "test".to_string(), 
            peers: vec![] 
        };
        assert_eq!(prune.topic(), Some("test"));
        
        let ihave = PubSubMessage::IHave { 
            topic: "test".to_string(), 
            msg_ids: vec![] 
        };
        assert_eq!(ihave.topic(), Some("test"));
        
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
