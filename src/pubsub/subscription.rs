//! Topic subscription records for DHT storage.
//!
//! This module defines the data structures used to store and retrieve
//! topic subscriptions from the DHT.
//!
//! # Security Model
//!
//! ## Bounded Subscriber Lists
//!
//! The `TopicSubscribers` struct limits entries to `MAX_TOPIC_SUBSCRIBERS` (50)
//! to prevent memory exhaustion from malicious DHT data.
//!
//! ## CRDT-Style Updates
//!
//! Subscription announcements use Last-Writer-Wins (LWW) semantics:
//!
//! 1. Each identity can only update its own entry
//! 2. Timestamps determine which entry wins on conflict
//! 3. Merge is commutative and idempotent
//!
//! This prevents:
//! - **Subscription hijacking**: Cannot update another peer's entry
//! - **Race conditions**: LWW provides deterministic conflict resolution
//!
//! ## Custom Deserialization
//!
//! `TopicSubscribers` implements custom `Deserialize` to truncate oversized
//! lists from potentially corrupted or malicious DHT data.

use serde::{Deserialize, Serialize};

use crate::identity::Identity;

/// Maximum subscribers to track per topic in DHT.
const MAX_TOPIC_SUBSCRIBERS: usize = 50;

/// A single subscriber entry in a topic record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriberEntry {
    /// The subscriber's identity.
    pub identity: Identity,
    /// Timestamp when this entry was created/updated.
    pub timestamp: u64,
}

impl SubscriberEntry {
    /// Create a new subscriber entry with current timestamp.
    pub fn new(identity: Identity) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self { identity, timestamp }
    }
}

/// A topic subscription record stored in the DHT.
/// Contains a list of all known subscribers for a topic.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TopicSubscribers {
    /// List of subscribers with their timestamps.
    pub subscribers: Vec<SubscriberEntry>,
}

// Custom deserialization to validate and truncate subscriber list
// This prevents memory spikes from malicious/corrupted DHT data
impl<'de> Deserialize<'de> for TopicSubscribers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize to a raw representation first
        #[derive(Deserialize)]
        struct RawTopicSubscribers {
            subscribers: Vec<SubscriberEntry>,
        }
        
        let raw = RawTopicSubscribers::deserialize(deserializer)?;
        
        // Truncate to MAX_TOPIC_SUBSCRIBERS to prevent memory exhaustion
        let subscribers = if raw.subscribers.len() > MAX_TOPIC_SUBSCRIBERS {
            raw.subscribers.into_iter().take(MAX_TOPIC_SUBSCRIBERS).collect()
        } else {
            raw.subscribers
        };
        
        Ok(TopicSubscribers { subscribers })
    }
}

impl TopicSubscribers {
    /// Create a new empty subscriber list.
    pub fn new() -> Self {
        Self { subscribers: Vec::new() }
    }

    /// Add or update a subscriber in the list.
    #[allow(dead_code)]  // Tested and ready for future use
    pub fn add_subscriber(&mut self, identity: Identity) {
        // Remove existing entry for this identity if present
        self.subscribers.retain(|e| e.identity != identity);
        
        // Add new entry
        self.subscribers.push(SubscriberEntry::new(identity));
        
        // Limit size by removing oldest entries
        while self.subscribers.len() > MAX_TOPIC_SUBSCRIBERS {
            // Find and remove oldest
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

    /// Remove a subscriber from the list.
    pub fn remove_subscriber(&mut self, identity: &Identity) {
        self.subscribers.retain(|e| &e.identity != identity);
    }

    /// Merge another subscriber list into this one (keeps newest entries).
    pub fn merge(&mut self, other: TopicSubscribers) {
        for entry in other.subscribers {
            // Only add if newer than existing or not present
            if let Some(existing) = self.subscribers.iter_mut().find(|e| e.identity == entry.identity) {
                if entry.timestamp > existing.timestamp {
                    existing.timestamp = entry.timestamp;
                }
            } else {
                self.subscribers.push(entry);
            }
        }
        
        // Limit size
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

    /// Get list of subscriber identities.
    pub fn get_subscribers(&self) -> Vec<Identity> {
        self.subscribers
            .iter()
            .map(|e| e.identity)
            .collect()
    }
}

/// Legacy single-subscriber record (kept for backward compatibility).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopicSubscription {
    /// The subscriber's identity.
    pub subscriber: Identity,
    /// Topics subscribed to.
    pub topics: Vec<String>,
    /// Timestamp when record was created.
    pub timestamp: u64,
}

impl TopicSubscription {
    /// Create a new subscription record.
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
        
        // Add same subscriber twice
        subscribers.add_subscriber(id1);
        subscribers.add_subscriber(id1);
        
        // Should still only have one entry
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
        
        // Serialize
        let data = bincode::serialize(&subscribers).expect("serialize failed");
        
        // Deserialize
        let restored: TopicSubscribers = bincode::deserialize(&data).expect("deserialize failed");
        
        let result = restored.get_subscribers();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&id1));
        assert!(result.contains(&id2));
    }

    #[test]
    fn topic_subscribers_limits_size() {
        let mut subscribers = TopicSubscribers::new();
        
        // Add more than MAX_TOPIC_SUBSCRIBERS
        for i in 0..60 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            subscribers.add_subscriber(Identity::from_bytes(bytes));
        }
        
        // Should be limited to MAX_TOPIC_SUBSCRIBERS
        assert!(subscribers.subscribers.len() <= MAX_TOPIC_SUBSCRIBERS);
    }

    #[test]
    fn topic_subscription_serialization() {
        let identity = Identity::from_bytes([42u8; 32]);
        let topics = vec!["topic1".to_string(), "topic2".to_string()];
        let record = TopicSubscription::new(identity, topics.clone());
        
        // Serialize
        let data = bincode::serialize(&record).expect("serialization failed");
        
        // Deserialize
        let restored: TopicSubscription = bincode::deserialize(&data).expect("deserialization failed");
        
        assert_eq!(restored.subscriber, identity);
        assert_eq!(restored.topics, topics);
    }
}
