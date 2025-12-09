use serde::{Deserialize, Serialize};

use crate::identity::Identity;

const MAX_TOPIC_SUBSCRIBERS: usize = 50;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriberEntry {
    pub identity: Identity,
    pub timestamp: u64,
}

impl SubscriberEntry {
    pub fn new(identity: Identity) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self { identity, timestamp }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TopicSubscribers {
    pub subscribers: Vec<SubscriberEntry>,
}

impl<'de> Deserialize<'de> for TopicSubscribers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawTopicSubscribers {
            subscribers: Vec<SubscriberEntry>,
        }
        
        let raw = RawTopicSubscribers::deserialize(deserializer)?;
        
        let subscribers = if raw.subscribers.len() > MAX_TOPIC_SUBSCRIBERS {
            raw.subscribers.into_iter().take(MAX_TOPIC_SUBSCRIBERS).collect()
        } else {
            raw.subscribers
        };
        
        Ok(TopicSubscribers { subscribers })
    }
}

impl TopicSubscribers {
    pub fn new() -> Self {
        Self { subscribers: Vec::new() }
    }

    #[allow(dead_code)]  // Tested and ready for future use
    pub fn add_subscriber(&mut self, identity: Identity) {
        self.subscribers.retain(|e| e.identity != identity);
        
        self.subscribers.push(SubscriberEntry::new(identity));
        
        while self.subscribers.len() > MAX_TOPIC_SUBSCRIBERS {
            if let Some(oldest_idx) = self.subscribers
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(i, _)| i)
            {
                self.subscribers.remove(oldest_idx);
            }
        }
    }

    pub fn remove_subscriber(&mut self, identity: &Identity) {
        self.subscribers.retain(|e| &e.identity != identity);
    }

    pub fn merge(&mut self, other: TopicSubscribers) {
        for entry in other.subscribers {
            if let Some(existing) = self.subscribers.iter_mut().find(|e| e.identity == entry.identity) {
                if entry.timestamp > existing.timestamp {
                    existing.timestamp = entry.timestamp;
                }
            } else {
                self.subscribers.push(entry);
            }
        }
        
        while self.subscribers.len() > MAX_TOPIC_SUBSCRIBERS {
            if let Some(oldest_idx) = self.subscribers
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(i, _)| i)
            {
                self.subscribers.remove(oldest_idx);
            }
        }
    }

    pub fn get_subscribers(&self) -> Vec<Identity> {
        self.subscribers
            .iter()
            .map(|e| e.identity)
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopicSubscription {
    pub subscriber: Identity,
    pub topics: Vec<String>,
    pub timestamp: u64,
}

impl TopicSubscription {
    #[allow(dead_code)]  // Tested and kept for backward compatibility
    pub fn new(subscriber: Identity, topics: Vec<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            subscriber,
            topics,
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriber_entry_creation() {
        let identity = Identity::from_bytes([42u8; 32]);
        let entry = SubscriberEntry::new(identity);
        
        assert_eq!(entry.identity, identity);
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn topic_subscribers_add_and_get() {
        let mut subscribers = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        let id2 = Identity::from_bytes([2u8; 32]);
        let id3 = Identity::from_bytes([3u8; 32]);
        
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id2);
        subscribers.add_subscriber(id3);
        
        let result = subscribers.get_subscribers();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&id1));
        assert!(result.contains(&id2));
        assert!(result.contains(&id3));
    }

    #[test]
    fn topic_subscribers_remove() {
        let mut subscribers = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        let id2 = Identity::from_bytes([2u8; 32]);
        
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id2);
        
        subscribers.remove_subscriber(&id1);
        
        let result = subscribers.get_subscribers();
        assert_eq!(result.len(), 1);
        assert!(!result.contains(&id1));
        assert!(result.contains(&id2));
    }

    #[test]
    fn topic_subscribers_update_existing() {
        let mut subscribers = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id1);
        
        assert_eq!(subscribers.subscribers.len(), 1);
    }

    #[test]
    fn topic_subscribers_merge() {
        let mut subscribers1 = TopicSubscribers::new();
        let mut subscribers2 = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        let id2 = Identity::from_bytes([2u8; 32]);
        let id3 = Identity::from_bytes([3u8; 32]);
        
        subscribers1.add_subscriber(id1);
        subscribers1.add_subscriber(id2);
        
        subscribers2.add_subscriber(id2);
        subscribers2.add_subscriber(id3);
        
        subscribers1.merge(subscribers2);
        
        let result = subscribers1.get_subscribers();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&id1));
        assert!(result.contains(&id2));
        assert!(result.contains(&id3));
    }

    #[test]
    fn topic_subscribers_serialization() {
        let mut subscribers = TopicSubscribers::new();
        
        let id1 = Identity::from_bytes([1u8; 32]);
        let id2 = Identity::from_bytes([2u8; 32]);
        
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id2);
        
        let data = bincode::serialize(&subscribers).expect("serialize failed");
        
        let restored: TopicSubscribers = bincode::deserialize(&data).expect("deserialize failed");
        
        let result = restored.get_subscribers();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&id1));
        assert!(result.contains(&id2));
    }

    #[test]
    fn topic_subscribers_limits_size() {
        let mut subscribers = TopicSubscribers::new();
        
        for i in 0..60 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            subscribers.add_subscriber(Identity::from_bytes(bytes));
        }
        
        assert!(subscribers.subscribers.len() <= MAX_TOPIC_SUBSCRIBERS);
    }

    #[test]
    fn topic_subscription_serialization() {
        let identity = Identity::from_bytes([42u8; 32]);
        let topics = vec!["topic1".to_string(), "topic2".to_string()];
        let record = TopicSubscription::new(identity, topics.clone());
        
        let data = bincode::serialize(&record).expect("serialization failed");
        
        let restored: TopicSubscription = bincode::deserialize(&data).expect("deserialization failed");
        
        assert_eq!(restored.subscriber, identity);
        assert_eq!(restored.topics, topics);
    }
}
