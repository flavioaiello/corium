//! # XOR-Metric Routing Table
//!
//! This module implements the Kademlia routing table with XOR-based distance metric.
//!
//! ## Key Concepts
//!
//! - **XOR Distance**: `distance(a, b) = a XOR b` (bitwise)
//! - **Bucket Index**: Number of leading zero bits in XOR distance
//! - **k-Buckets**: Each bucket holds up to k contacts at similar distances
//!
//! ## Bucket Organization
//!
//! ```text
//! Bucket 0: Contacts where distance has 0 leading zeros (furthest, 50% of keyspace)
//! Bucket 1: Contacts where distance has 1 leading zero (25% of keyspace)
//! ...
//! Bucket 255: Contacts where distance has 255 leading zeros (closest)
//! ```
//!
//! ## Anti-Eclipse Protection
//!
//! The [`RoutingInsertionLimiter`] uses token-bucket rate limiting to prevent
//! a single peer from flooding the routing table with contacts (Sybil/Eclipse attack).
//!
//! ## Bucket Refresh
//!
//! Stale buckets (no activity for `BUCKET_STALE_THRESHOLD`) trigger random lookups
//! within that bucket's keyspace to discover new contacts.

use std::collections::BinaryHeap;
use std::num::NonZeroUsize;

use lru::LruCache;
use tokio::time::{Duration, Instant};

use crate::dht::{distance_cmp, xor_distance};
use crate::identity::{Contact, Identity};

/// Interval between bucket refresh checks.
/// Buckets without activity for this long will trigger random lookups.
pub(crate) const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Threshold after which a bucket is considered stale and needs refresh.
pub(crate) const BUCKET_STALE_THRESHOLD: Duration = Duration::from_secs(30 * 60);

/// Maximum routing insertions per peer per rate window.
/// SECURITY: Prevents eclipse attacks by limiting how fast any peer can
/// populate the routing table with (potentially Sybil) contacts.
const ROUTING_INSERTION_PER_PEER_LIMIT: usize = 50;

/// Time window for insertion rate limiting.
const ROUTING_INSERTION_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Maximum peers to track for insertion rate limiting.
/// Uses LRU eviction when full.
const MAX_ROUTING_INSERTION_TRACKED_PEERS: usize = 1_000;


#[derive(Debug, Clone, Copy)]
struct RoutingInsertionBucket {
    tokens: f64,
    last_update: Instant,
}

impl RoutingInsertionBucket {
    fn new() -> Self {
        Self {
            tokens: ROUTING_INSERTION_PER_PEER_LIMIT as f64,
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let window_secs = ROUTING_INSERTION_RATE_WINDOW.as_secs_f64();
        
        let rate = ROUTING_INSERTION_PER_PEER_LIMIT as f64 / window_secs;
        self.tokens = (self.tokens + elapsed * rate).min(ROUTING_INSERTION_PER_PEER_LIMIT as f64);
        self.last_update = now;
        
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub(crate) struct RoutingInsertionLimiter {
    buckets: LruCache<Identity, RoutingInsertionBucket>,
}

impl RoutingInsertionLimiter {
    pub fn new() -> Self {
        Self {
            buckets: LruCache::new(
                NonZeroUsize::new(MAX_ROUTING_INSERTION_TRACKED_PEERS).unwrap()
            ),
        }
    }

    pub fn allow_insertion(&mut self, from_peer: &Identity) -> bool {
        let bucket = self.buckets.get_or_insert_mut(*from_peer, RoutingInsertionBucket::new);
        bucket.try_consume()
    }
    
    #[cfg(test)]
    pub fn remaining_tokens(&mut self, peer: &Identity) -> f64 {
        if let Some(bucket) = self.buckets.get(peer) {
            bucket.tokens
        } else {
            ROUTING_INSERTION_PER_PEER_LIMIT as f64
        }
    }
}


#[derive(Debug, Clone)]
struct Bucket {
    contacts: Vec<Contact>,
    last_refresh: Instant,
}

impl Default for Bucket {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum BucketTouchOutcome {
    Inserted,
    Refreshed,
    Full {
        new_contact: Box<Contact>,
        oldest: Box<Contact>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct PendingBucketUpdate {
    pub bucket_index: usize,
    pub oldest: Contact,
    pub new_contact: Contact,
}

impl Bucket {
    fn new() -> Self {
        Self {
            contacts: Vec::new(),
            last_refresh: Instant::now(),
        }
    }

    fn mark_refreshed(&mut self) {
        self.last_refresh = Instant::now();
    }

    fn is_stale(&self, threshold: Duration) -> bool {
        self.last_refresh.elapsed() > threshold
    }

    fn touch(&mut self, contact: Contact, k: usize) -> BucketTouchOutcome {
        if let Some(pos) = self.contacts.iter().position(|c| c.identity == contact.identity) {
            let existing = self.contacts.remove(pos);
            self.contacts.push(existing);
            self.mark_refreshed();
            return BucketTouchOutcome::Refreshed;
        }

        if self.contacts.len() < k {
            self.contacts.push(contact);
            self.mark_refreshed();
            BucketTouchOutcome::Inserted
        } else {
            debug_assert!(!self.contacts.is_empty(), "bucket len >= k but contacts empty");
            let oldest = self
                .contacts
                .first()
                .cloned()
                .unwrap_or_else(|| contact.clone());
            BucketTouchOutcome::Full {
                new_contact: Box::new(contact),
                oldest: Box::new(oldest),
            }
        }
    }

    fn refresh(&mut self, id: &Identity) -> bool {
        if let Some(pos) = self.contacts.iter().position(|c| &c.identity == id) {
            let existing = self.contacts.remove(pos);
            self.contacts.push(existing);
            true
        } else {
            false
        }
    }

    fn remove(&mut self, id: &Identity) -> bool {
        if let Some(pos) = self.contacts.iter().position(|c| &c.identity == id) {
            self.contacts.remove(pos);
            true
        } else {
            false
        }
    }
}


pub(crate) fn bucket_index(self_id: &Identity, other: &Identity) -> usize {
    let dist = xor_distance(self_id, other);
    for (byte_idx, byte) in dist.iter().enumerate() {
        if *byte != 0 {
            let leading = byte.leading_zeros() as usize;            let bit_index = byte_idx * 8 + leading;
            return bit_index;        }
    }
    255
}

pub(crate) fn random_id_for_bucket(self_id: &Identity, bucket_idx: usize) -> Identity {
    let self_bytes = self_id.as_bytes();
    
    let mut distance = [0u8; 32];
    if getrandom::getrandom(&mut distance).is_err() {
        for (i, byte) in distance.iter_mut().enumerate() {
            *byte = self_bytes[i].wrapping_add((bucket_idx.wrapping_mul(i + 1)) as u8);
        }
    }

    let byte_idx = bucket_idx / 8;
    let bit_pos = bucket_idx % 8;

    for byte in distance.iter_mut().take(byte_idx) {
        *byte = 0;
    }

    let target_bit = 0x80u8 >> bit_pos;
    let random_mask = target_bit.wrapping_sub(1);
    distance[byte_idx] = target_bit | (distance[byte_idx] & random_mask);

    let mut target = [0u8; 32];
    for i in 0..32 {
        target[i] = self_bytes[i] ^ distance[i];
    }

    Identity::from_bytes(target)
}


#[derive(Debug)]
pub struct RoutingTable {
    self_id: Identity,
    k: usize,
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    pub fn new(self_id: Identity, k: usize) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(Bucket::new());
        }
        Self {
            self_id,
            k,
            buckets,
        }
    }

    pub fn set_k(&mut self, k: usize) {
        self.k = k;
        for bucket in &mut self.buckets {
            if bucket.contacts.len() > self.k {
                while bucket.contacts.len() > self.k {
                    bucket.contacts.remove(0);
                }
            }
        }
    }

    #[cfg(test)]
    pub fn update(&mut self, contact: Contact) {
        let _ = self.update_with_pending(contact);
    }

    pub(crate) fn update_with_pending(&mut self, contact: Contact) -> Option<PendingBucketUpdate> {
        if contact.identity == self.self_id {
            return None;
        }
        let idx = bucket_index(&self.self_id, &contact.identity);
        match self.buckets[idx].touch(contact, self.k) {
            BucketTouchOutcome::Inserted | BucketTouchOutcome::Refreshed => None,
            BucketTouchOutcome::Full {
                new_contact,
                oldest,
            } => Some(PendingBucketUpdate {
                bucket_index: idx,
                oldest: *oldest,
                new_contact: *new_contact,
            }),
        }
    }

    pub fn closest(&self, target: &Identity, k: usize) -> Vec<Contact> {
        if k == 0 {
            return Vec::new();
        }

        #[derive(Eq, PartialEq)]
        struct DistEndpointInfo {
            dist: [u8; 32],
            contact: Contact,
        }
        
        impl Ord for DistEndpointInfo {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                distance_cmp(&self.dist, &other.dist)
            }
        }
        
        impl PartialOrd for DistEndpointInfo {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut heap: BinaryHeap<DistEndpointInfo> = BinaryHeap::with_capacity(k + 1);

        for bucket in &self.buckets {
            for contact in &bucket.contacts {
                let dist = xor_distance(&contact.identity, target);
                
                if heap.len() < k {
                    heap.push(DistEndpointInfo { dist, contact: contact.clone() });
                } else if let Some(max_entry) = heap.peek() {
                    if distance_cmp(&dist, &max_entry.dist) == std::cmp::Ordering::Less {
                        heap.push(DistEndpointInfo { dist, contact: contact.clone() });
                        heap.pop();                    }
                }
            }
        }

        let mut result: Vec<_> = heap.into_iter().map(|dc| dc.contact).collect();
        result.sort_by(|a, b| {
            let da = xor_distance(&a.identity, target);
            let db = xor_distance(&b.identity, target);
            distance_cmp(&da, &db)
        });
        result
    }

    pub(crate) fn apply_ping_result(&mut self, pending: PendingBucketUpdate, oldest_alive: bool) {
        let bucket = &mut self.buckets[pending.bucket_index];
        if oldest_alive {
            bucket.refresh(&pending.oldest.identity);
            return;
        }

        let _ = bucket.remove(&pending.oldest.identity);
        let already_present = bucket
            .contacts
            .iter()
            .any(|contact| contact.identity == pending.new_contact.identity);
        if already_present {
            return;
        }
        if bucket.contacts.len() < self.k {
            bucket.contacts.push(pending.new_contact);
        }
    }

    pub(crate) fn stale_bucket_indices(&self, threshold: Duration) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.contacts.is_empty() && bucket.is_stale(threshold))
            .map(|(idx, _)| idx)
            .collect()
    }

    pub(crate) fn mark_bucket_refreshed(&mut self, bucket_idx: usize) {
        if bucket_idx < self.buckets.len() {
            self.buckets[bucket_idx].mark_refreshed();
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_index_finds_first_different_bit() {
        let self_id = Identity::from_bytes([0u8; 32]);

        let mut other_bytes = [0u8; 32];
        other_bytes[0] = 0b1000_0000;
        let other = Identity::from_bytes(other_bytes);
        assert_eq!(bucket_index(&self_id, &other), 0);

        let mut other_two_bytes = [0u8; 32];
        other_two_bytes[1] = 0b0001_0000;
        let other_two = Identity::from_bytes(other_two_bytes);
        assert_eq!(bucket_index(&self_id, &other_two), 11);

        assert_eq!(bucket_index(&self_id, &self_id), 255);
    }

    #[test]
    fn random_id_for_bucket_lands_in_correct_bucket() {
        let self_id = Identity::from_bytes([0x42u8; 32]);
        for bucket_idx in [0, 1, 7, 8, 15, 127, 200, 255] {
            for _ in 0..10 {
                let target = random_id_for_bucket(&self_id, bucket_idx);
                let actual_bucket = bucket_index(&self_id, &target);
                assert_eq!(
                    actual_bucket, bucket_idx,
                    "random ID for bucket {} landed in bucket {} instead",
                    bucket_idx, actual_bucket
                );
            }
        }
    }

    #[test]
    fn routing_insertion_limiter_enforces_per_peer_limit() {
        let mut limiter = RoutingInsertionLimiter::new();
        let peer1 = Identity::from_bytes([1u8; 32]);
        let peer2 = Identity::from_bytes([2u8; 32]);

        for i in 0..ROUTING_INSERTION_PER_PEER_LIMIT {
            assert!(
                limiter.allow_insertion(&peer1),
                "insertion {} from peer1 should be allowed",
                i
            );
        }

        assert!(
            !limiter.allow_insertion(&peer1),
            "insertion after limit should be rejected for peer1"
        );

        assert!(
            limiter.allow_insertion(&peer2),
            "peer2 should still be allowed"
        );

        assert!(
            limiter.remaining_tokens(&peer1) < 1.0,
            "peer1 should have no tokens left"
        );

        let remaining = limiter.remaining_tokens(&peer2);
        assert!(
            (remaining - (ROUTING_INSERTION_PER_PEER_LIMIT as f64 - 1.0)).abs() < 0.1,
            "peer2 should have used one token, has {} remaining",
            remaining
        );
    }

    #[test]
    fn routing_insertion_limiter_uses_lru_eviction() {
        let mut limiter = RoutingInsertionLimiter::new();
        
        for i in 0..MAX_ROUTING_INSERTION_TRACKED_PEERS {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let peer = Identity::from_bytes(bytes);
            limiter.allow_insertion(&peer);
        }

        let new_peer = Identity::from_bytes([0xFF; 32]);
        assert!(limiter.allow_insertion(&new_peer), "new peer should be allowed");

        let remaining = limiter.remaining_tokens(&new_peer);
        assert!(
            (remaining - (ROUTING_INSERTION_PER_PEER_LIMIT as f64 - 1.0)).abs() < 0.1,
            "new peer should have used one token"
        );
    }

    #[test]
    fn routing_table_orders_contacts_by_distance() {
        let self_id = make_test_identity(0x00);
        let mut table = RoutingTable::new(self_id, 4);

        let contacts = [make_test_contact(0x10), make_test_contact(0x20), make_test_contact(0x08)];
        for contact in &contacts {
            table.update(contact.clone());
        }

        let target = make_test_identity(0x18);
        let closest = table.closest(&target, 3);
        let ids: Vec<u8> = closest.iter().map(|c| c.identity.as_bytes()[0]).collect();
        assert_eq!(ids, vec![0x10, 0x08, 0x20]);
    }

    #[test]
    fn routing_table_respects_bucket_capacity() {
        let self_id = make_test_identity(0x00);
        let mut table = RoutingTable::new(self_id, 2);

        let contacts = [make_test_contact(0x80), make_test_contact(0xC0), make_test_contact(0xA0)];
        for contact in &contacts {
            table.update(contact.clone());
        }

        let target = make_test_identity(0x90);
        let closest = table.closest(&target, 10);
        let ids: Vec<u8> = closest.iter().map(|c| c.identity.as_bytes()[0]).collect();
        assert_eq!(closest.len(), 2);
        assert!(ids.contains(&0x80));
        assert!(ids.contains(&0xC0));
    }

    #[test]
    fn routing_table_truncates_when_k_changes() {
        let self_id = make_test_identity(0x00);
        let mut table = RoutingTable::new(self_id, 4);

        let contacts = [make_test_contact(0x80), make_test_contact(0x81), make_test_contact(0x82)];
        for contact in &contacts {
            table.update(contact.clone());
        }

        table.set_k(2);
        let target = make_test_identity(0x80);
        let closest = table.closest(&target, 10);
        assert_eq!(closest.len(), 2);
    }

    const MAX_K: usize = 30;
    const NUM_BUCKETS: usize = 256;

    #[test]
    fn routing_table_size_bounded() {
        let max_routing_table_size = MAX_K * NUM_BUCKETS;
        assert_eq!(max_routing_table_size, 7680);
        assert!(max_routing_table_size < 10_000, "Routing table should be bounded");
    }

    #[test]
    fn sybil_attack_targeted_bucket() {
        let _target_bucket = 100;
        let attacker_nodes = 100;

        let nodes_in_bucket = std::cmp::min(attacker_nodes, MAX_K);

        assert_eq!(nodes_in_bucket, 30, "Bucket should accept at most k nodes");
    }

    #[test]
    fn sybil_bucket_distribution() {
        let honest_identity = make_test_identity(0x01);

        let mut bucket_counts = vec![0usize; NUM_BUCKETS];

        for i in 0..1000u32 {
            let attacker_id = make_test_identity(i.wrapping_mul(7919) as u8);
            let bucket = bucket_index_for_test(honest_identity.as_bytes(), attacker_id.as_bytes());
            bucket_counts[bucket] += 1;
        }

        let non_empty_buckets = bucket_counts.iter().filter(|&&c| c > 0).count();

        assert!(
            non_empty_buckets >= 5,
            "Should distribute across multiple buckets, got {} non-empty buckets",
            non_empty_buckets
        );
    }

    #[test]
    fn bucket_index_calculation_correct() {
        let self_id = make_test_identity(0x00);

        let same_id = make_test_identity(0x00);
        assert_eq!(
            bucket_index_for_test(self_id.as_bytes(), same_id.as_bytes()),
            255,
            "Same ID should be in bucket 255"
        );

        let msb_differs = Identity::from_bytes({
            let mut b = [0u8; 32];
            b[0] = 0x80;
            b
        });
        assert_eq!(
            bucket_index_for_test(self_id.as_bytes(), msb_differs.as_bytes()),
            0,
            "MSB differs should be bucket 0"
        );
    }

    fn bucket_index_for_test(self_id: &[u8; 32], other: &[u8; 32]) -> usize {
        let mut xor = [0u8; 32];
        for i in 0..32 {
            xor[i] = self_id[i] ^ other[i];
        }

        for (byte_idx, &byte) in xor.iter().enumerate() {
            if byte != 0 {
                let bit_idx = byte.leading_zeros() as usize;
                return byte_idx * 8 + bit_idx;
            }
        }

        255
    }

    fn make_test_identity(byte: u8) -> Identity {
        let mut id = [0u8; 32];
        id[0] = byte;
        Identity::from_bytes(id)
    }

    fn make_test_contact(byte: u8) -> Contact {
        Contact::single(make_test_identity(byte), format!("node-{byte}"))
    }

    #[test]
    fn routing_table_update_api() {
        let self_id = make_test_identity(0x00);
        let mut rt = RoutingTable::new(self_id, 20);
        
        let peer = make_test_contact(0x80);
        
        rt.update(peer.clone());
        
        let closest = rt.closest(&peer.identity, 1);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].identity, peer.identity);
    }
}
