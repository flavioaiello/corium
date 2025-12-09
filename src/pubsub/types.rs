use std::collections::{HashSet, VecDeque};
use std::time::Instant;

use crate::identity::Identity;
use super::config::{MAX_PEERS_PER_TOPIC, RATE_LIMIT_WINDOW, RATE_LIMIT_ENTRY_MAX_AGE};
use super::message::MessageId;

#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    pub topic: String,
    pub source: Identity,
    pub seqno: u64,
    pub data: Vec<u8>,
    pub msg_id: MessageId,
    pub received_at: Instant,
}

#[derive(Clone)]
pub(crate) struct CachedMessage {
    pub topic: String,
    pub source: Identity,
    pub seqno: u64,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Default)]
pub(crate) struct TopicState {
    pub mesh: HashSet<Identity>,
    pub peers: HashSet<Identity>,
    pub recent_messages: VecDeque<MessageId>,
}

impl TopicState {
    pub fn total_peers(&self) -> usize {
        self.mesh.len() + self.peers.len()
    }

    pub fn try_insert_peer(&mut self, peer: Identity) -> bool {
        if self.mesh.contains(&peer) || self.peers.contains(&peer) {
            return true;
        }

        if self.total_peers() >= MAX_PEERS_PER_TOPIC {
            return false;
        }

        self.peers.insert(peer);
        true
    }
}

#[derive(Debug)]
pub(crate) struct PeerRateLimit {
    pub publish_times: VecDeque<Instant>,
    pub iwant_times: VecDeque<Instant>,
    pub last_active: Instant,
}

impl Default for PeerRateLimit {
    fn default() -> Self {
        Self {
            publish_times: VecDeque::new(),
            iwant_times: VecDeque::new(),
            last_active: Instant::now(),
        }
    }
}

impl PeerRateLimit {
    pub fn check_and_record(&mut self, max_rate: usize) -> bool {
        self.check_and_record_generic(&mut self.publish_times.clone(), max_rate)
    }
    
    pub fn check_and_record_iwant(&mut self, max_rate: usize) -> bool {
        let now = Instant::now();
        self.last_active = now;
        
        while let Some(front) = self.iwant_times.front() {
            if now.duration_since(*front) > RATE_LIMIT_WINDOW {
                self.iwant_times.pop_front();
            } else {
                break;
            }
        }
        
        if self.iwant_times.len() >= max_rate {
            return true; // Rate limited
        }
        
        self.iwant_times.push_back(now);
        false
    }
    
    fn check_and_record_generic(&mut self, _times: &mut VecDeque<Instant>, max_rate: usize) -> bool {
        let now = Instant::now();
        self.last_active = now;
        
        while let Some(front) = self.publish_times.front() {
            if now.duration_since(*front) > RATE_LIMIT_WINDOW {
                self.publish_times.pop_front();
            } else {
                break;
            }
        }
        
        if self.publish_times.len() >= max_rate {
            return true; // Rate limited
        }
        
        self.publish_times.push_back(now);
        false
    }
    
    pub fn is_stale(&self, now: Instant) -> bool {
        now.duration_since(self.last_active) > RATE_LIMIT_ENTRY_MAX_AGE
    }
}

#[allow(dead_code)]  // Ready for future rejection handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRejection {
    MessageTooLarge,
    TopicTooLong,
    RateLimited,
    Duplicate,
    InvalidMessageId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubsub::message::PubSubMessage;
    use std::time::Duration;

    #[test]
    fn topic_state_default() {
        let state = TopicState::default();
        assert!(state.mesh.is_empty());
        assert!(state.peers.is_empty());
        assert!(state.recent_messages.is_empty());
    }

    #[test]
    fn cached_message_fields() {
        let msg = CachedMessage {
            topic: "test".to_string(),
            source: Identity::from_bytes([1u8; 32]),
            seqno: 42,
            data: vec![1, 2, 3],
            signature: vec![0u8; 64],
        };
        
        assert_eq!(msg.topic, "test");
        assert_eq!(msg.seqno, 42);
        assert_eq!(msg.data, vec![1, 2, 3]);
    }

    #[test]
    fn received_message_fields() {
        let msg = ReceivedMessage {
            topic: "test".to_string(),
            source: Identity::from_bytes([1u8; 32]),
            seqno: 1,
            data: vec![1, 2, 3],
            msg_id: [0u8; 32],
            received_at: Instant::now(),
        };
        
        assert_eq!(msg.topic, "test");
        assert_eq!(msg.seqno, 1);
        assert!(!msg.data.is_empty());
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut limiter = PeerRateLimit::default();
        
        for _ in 0..5 {
            assert!(!limiter.check_and_record(10));
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let mut limiter = PeerRateLimit::default();
        
        for _ in 0..10 {
            let _ = limiter.check_and_record(10);
        }
        
        assert!(limiter.check_and_record(10));
    }

    #[test]
    fn rate_limiter_window_expiration() {
        let mut limiter = PeerRateLimit::default();
        
        limiter.publish_times.push_back(Instant::now() - Duration::from_secs(2));
        
        assert!(!limiter.check_and_record(10));
        
        assert_eq!(limiter.publish_times.len(), 1);
    }

    #[test]
    fn message_rejection_types_exist() {
        let _ = MessageRejection::MessageTooLarge;
        let _ = MessageRejection::TopicTooLong;
        let _ = MessageRejection::RateLimited;
        let _ = MessageRejection::Duplicate;
        let _ = MessageRejection::InvalidMessageId;
    }

    #[test]
    fn subscribe_message_structure() {
        let msg = PubSubMessage::Subscribe {
            topic: "test/topic".to_string(),
        };

        assert_eq!(msg.topic(), Some("test/topic"));

        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.topic(), Some("test/topic"));
    }

    #[test]
    fn publish_message_structure() {
        use crate::identity::Keypair;

        let keypair = Keypair::generate();
        let source = keypair.identity();
        let data = b"test message".to_vec();
        let msg_id: MessageId = [0u8; 32];

        let msg = PubSubMessage::Publish {
            topic: "test/topic".to_string(),
            msg_id,
            source,
            seqno: 1,
            data: data.clone(),
            signature: vec![0u8; 64],
        };

        assert_eq!(msg.topic(), Some("test/topic"));

        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();

        if let PubSubMessage::Publish {
            topic,
            seqno,
            data: decoded_data,
            ..
        } = decoded
        {
            assert_eq!(topic, "test/topic");
            assert_eq!(seqno, 1);
            assert_eq!(decoded_data, data);
        } else {
            panic!("Expected Publish message");
        }
    }

    #[test]
    fn ihave_message_structure() {
        let msg_ids: Vec<MessageId> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let msg = PubSubMessage::IHave {
            topic: "test/topic".to_string(),
            msg_ids: msg_ids.clone(),
        };

        assert_eq!(msg.topic(), Some("test/topic"));

        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();

        if let PubSubMessage::IHave {
            msg_ids: decoded_ids,
            ..
        } = decoded
        {
            assert_eq!(decoded_ids, msg_ids);
        } else {
            panic!("Expected IHave message");
        }
    }

    #[test]
    fn iwant_message_no_topic() {
        let msg_ids: Vec<MessageId> = vec![[1u8; 32], [2u8; 32]];

        let msg = PubSubMessage::IWant { msg_ids };

        assert_eq!(msg.topic(), None);
    }

    #[test]
    fn prune_message_with_peers() {
        use crate::identity::Keypair;

        let peer1 = Keypair::generate().identity();
        let peer2 = Keypair::generate().identity();

        let msg = PubSubMessage::Prune {
            topic: "test/topic".to_string(),
            peers: vec![peer1, peer2],
        };

        assert_eq!(msg.topic(), Some("test/topic"));

        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();

        if let PubSubMessage::Prune { peers, .. } = decoded {
            assert_eq!(peers.len(), 2);
        } else {
            panic!("Expected Prune message");
        }
    }

    #[test]
    fn graft_message_structure() {
        let msg = PubSubMessage::Graft {
            topic: "test/topic".to_string(),
        };

        assert_eq!(msg.topic(), Some("test/topic"));

        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.topic(), Some("test/topic"));
    }

    #[test]
    fn unsubscribe_message_structure() {
        let msg = PubSubMessage::Unsubscribe {
            topic: "test/topic".to_string(),
        };

        assert_eq!(msg.topic(), Some("test/topic"));
    }

    #[test]
    fn all_message_types_roundtrip() {
        use crate::identity::Keypair;

        let keypair = Keypair::generate();
        let identity = keypair.identity();

        let messages = vec![
            PubSubMessage::Subscribe {
                topic: "test".to_string(),
            },
            PubSubMessage::Unsubscribe {
                topic: "test".to_string(),
            },
            PubSubMessage::Graft {
                topic: "test".to_string(),
            },
            PubSubMessage::Prune {
                topic: "test".to_string(),
                peers: vec![identity],
            },
            PubSubMessage::Publish {
                topic: "test".to_string(),
                msg_id: [0u8; 32],
                source: identity,
                seqno: 1,
                data: b"test".to_vec(),
                signature: vec![0u8; 64],
            },
            PubSubMessage::IHave {
                topic: "test".to_string(),
                msg_ids: vec![[1u8; 32]],
            },
            PubSubMessage::IWant {
                msg_ids: vec![[1u8; 32]],
            },
        ];

        for msg in messages {
            let bytes = bincode::serialize(&msg).expect("serialization should work");
            let decoded: PubSubMessage =
                bincode::deserialize(&bytes).expect("deserialization should work");

            assert_eq!(msg.topic(), decoded.topic());
        }
    }

    #[test]
    fn message_id_deterministic() {
        use crate::dht::hash_content;

        let data = b"test message data";

        let id1 = hash_content(data);
        let id2 = hash_content(data);

        assert_eq!(id1, id2);
    }

    #[test]
    fn different_data_different_ids() {
        use crate::dht::hash_content;

        let data1 = b"message one";
        let data2 = b"message two";

        let id1 = hash_content(data1);
        let id2 = hash_content(data2);

        assert_ne!(id1, id2);
    }

    #[test]
    fn message_id_collision_resistance() {
        use crate::dht::hash_content;
        use std::collections::HashSet;

        let mut ids = HashSet::new();

        for i in 0..10000 {
            let data = format!("message number {}", i);
            let id = hash_content(data.as_bytes());
            assert!(ids.insert(id), "Collision at message {}", i);
        }
    }
}
