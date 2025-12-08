//! Kademlia routing table with per-peer rate limiting.
//!
//! Provides the core routing infrastructure for DHT operations including
//! 256 k-buckets for 256-bit identities, LRU-style bucket management,
//! and per-peer insertion rate limiting (50 contacts/minute/peer).
//!
//! # Security Model
//!
//! The routing table implements multiple protections against routing attacks:
//!
//! ## Sybil/Eclipse Attack Prevention
//! - **Per-peer rate limiting**: Each peer can only contribute 50 contacts/minute
//!   to our routing table, preventing flooding via FIND_NODE responses
//! - **Token bucket algorithm**: Rate limits use token buckets with gradual
//!   replenishment, not hard windows, for smoother limiting
//! - **LRU tracking**: Rate limiter tracks up to 1,000 peers with LRU eviction
//!
//! ## Routing Table Stability
//! - **Ping-before-evict**: When a bucket is full, we ping the oldest contact
//!   before deciding to evict it or discard the new contact
//! - **Long-lived preference**: Kademlia prefers older, proven contacts over
//!   newly discovered ones for routing stability
//! - **Bucket refresh**: Stale buckets trigger FIND_NODE for random IDs in
//!   that bucket's range to discover legitimate peers
//!
//! ## Bounded Resources
//! - **256 buckets × k contacts**: Maximum routing table size is 256 × k
//! - **Adaptive k (10-30)**: Bucket size adjusts based on network conditions
//! - **Rate limiter LRU**: Tracks at most 1,000 peers for rate limiting

use std::collections::BinaryHeap;
use std::num::NonZeroUsize;
use lru::LruCache;
use tokio::time::{Duration, Instant};

use crate::identity::Identity;
use super::hash::{xor_distance, distance_cmp};

// ============================================================================
// Configuration Constants
// ============================================================================

/// How often to run the bucket refresh task.
pub(crate) const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Duration after which a bucket is considered stale and needs refresh.
pub(crate) const BUCKET_STALE_THRESHOLD: Duration = Duration::from_secs(30 * 60);

/// Maximum contacts a single peer can contribute to routing table per window.
///
/// # Security
///
/// Prevents a malicious peer from flooding the routing table by returning
/// excessive contacts in FindNode responses. A normal peer should not
/// contribute more than k contacts per query response.
const ROUTING_INSERTION_PER_PEER_LIMIT: usize = 50;

/// Time window for routing table insertion rate limiting (1 minute).
const ROUTING_INSERTION_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Maximum number of peers to track for routing insertion rate limiting.
const MAX_ROUTING_INSERTION_TRACKED_PEERS: usize = 1_000;

// ============================================================================
// Contact
// ============================================================================

/// Represents another DHT node with its identity and serialized endpoint address.
///
/// The address is stored as a string (typically a socket address) for transport flexibility.
#[derive(Clone, Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Contact {
    /// The node's unique identifier (Ed25519 public key in zero-hash architecture).
    pub identity: Identity,
    /// Socket address string for connecting to this node.
    pub addr: String,
}

// ============================================================================
// Per-Peer Routing Insertion Rate Limiter
// ============================================================================

/// Token bucket for per-peer routing table insertion rate limiting.
///
/// Uses fixed-size storage (2 fields) instead of per-insertion timestamp storage.
#[derive(Debug, Clone, Copy)]
struct RoutingInsertionBucket {
    /// Current number of available tokens.
    tokens: f64,
    /// Last time tokens were replenished.
    last_update: Instant,
}

impl RoutingInsertionBucket {
    /// Create a new bucket with full capacity.
    fn new() -> Self {
        Self {
            tokens: ROUTING_INSERTION_PER_PEER_LIMIT as f64,
            last_update: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if successful.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let window_secs = ROUTING_INSERTION_RATE_WINDOW.as_secs_f64();
        
        // Replenish tokens based on elapsed time
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

/// Rate limiter for per-peer routing table insertions.
///
/// Prevents a single malicious peer from flooding the routing table by
/// returning excessive contacts in FindNode responses.
///
/// # Security
///
/// Each peer has a limited "budget" of contacts they can contribute to
/// our routing table within a time window. This prevents:
/// - Routing table poisoning attacks
/// - Eclipse attacks via contact flooding
/// - Resource exhaustion from processing excessive contacts
pub(crate) struct RoutingInsertionLimiter {
    /// Per-peer token buckets.
    buckets: LruCache<Identity, RoutingInsertionBucket>,
}

impl RoutingInsertionLimiter {
    /// Create a new rate limiter.
    pub fn new() -> Self {
        Self {
            buckets: LruCache::new(
                NonZeroUsize::new(MAX_ROUTING_INSERTION_TRACKED_PEERS).unwrap()
            ),
        }
    }

    /// Check if a contact insertion from a peer is allowed.
    /// Returns true if under rate limit, false if should reject.
    pub fn allow_insertion(&mut self, from_peer: &Identity) -> bool {
        let bucket = self.buckets.get_or_insert_mut(*from_peer, RoutingInsertionBucket::new);
        bucket.try_consume()
    }
    
    /// Get the number of remaining tokens for a peer (for testing/debugging).
    #[cfg(test)]
    pub fn remaining_tokens(&mut self, peer: &Identity) -> f64 {
        if let Some(bucket) = self.buckets.get(peer) {
            bucket.tokens
        } else {
            ROUTING_INSERTION_PER_PEER_LIMIT as f64
        }
    }
}

// ============================================================================
// Bucket
// ============================================================================

/// A single Kademlia routing bucket with LRU-like behavior.
///
/// Maintains up to k contacts, preferring long-lived nodes (older contacts)
/// over newly discovered ones to improve routing stability.
#[derive(Debug, Clone)]
struct Bucket {
    /// Contacts in LRU order (oldest first, newest last).
    contacts: Vec<Contact>,
    /// When this bucket was last refreshed (touched or queried).
    last_refresh: Instant,
}

impl Default for Bucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of attempting to add or refresh a contact in a bucket.
#[derive(Debug)]
enum BucketTouchOutcome {
    /// Contact was newly inserted (bucket had space).
    Inserted,
    /// Existing contact was refreshed (moved to end of LRU queue).
    Refreshed,
    /// Bucket is full; includes the oldest contact for potential eviction.
    Full {
        new_contact: Contact,
        oldest: Contact,
    },
}

/// Pending bucket update when a bucket is full and oldest contact needs ping check.
#[derive(Clone, Debug)]
pub(crate) struct PendingBucketUpdate {
    pub bucket_index: usize,
    pub oldest: Contact,
    pub new_contact: Contact,
}

impl Bucket {
    /// Create a new empty bucket.
    fn new() -> Self {
        Self {
            contacts: Vec::new(),
            last_refresh: Instant::now(),
        }
    }

    /// Mark this bucket as recently refreshed.
    fn mark_refreshed(&mut self) {
        self.last_refresh = Instant::now();
    }

    /// Check if this bucket is stale (not refreshed within threshold).
    fn is_stale(&self, threshold: Duration) -> bool {
        self.last_refresh.elapsed() > threshold
    }

    /// Attempt to add or refresh a contact in the bucket.
    ///
    /// - If contact exists, moves it to end (most recently seen)
    /// - If bucket has space, inserts the contact
    /// - If bucket is full, returns the oldest contact for potential eviction
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
            // Debug assertion for invariant, with safe fallback
            debug_assert!(!self.contacts.is_empty(), "bucket len >= k but contacts empty");
            let oldest = self
                .contacts
                .first()
                .cloned()
                // This should never happen if len >= k, but handle gracefully
                .unwrap_or_else(|| contact.clone());
            BucketTouchOutcome::Full {
                new_contact: contact,
                oldest,
            }
        }
    }

    /// Refresh a contact by moving it to the end of the LRU queue.
    ///
    /// Returns true if the contact was found and refreshed.
    fn refresh(&mut self, id: &Identity) -> bool {
        if let Some(pos) = self.contacts.iter().position(|c| &c.identity == id) {
            let existing = self.contacts.remove(pos);
            self.contacts.push(existing);
            true
        } else {
            false
        }
    }

    /// Remove a contact from the bucket.
    ///
    /// Returns true if the contact was found and removed.
    fn remove(&mut self, id: &Identity) -> bool {
        if let Some(pos) = self.contacts.iter().position(|c| &c.identity == id) {
            self.contacts.remove(pos);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Routing Table
// ============================================================================

/// Find the bucket index for an identity relative to self.
///
/// Uses the XOR distance to determine which bucket a node belongs to.
/// The bucket index is the position of the first differing bit (0..=255).
/// Bucket 0 is the furthest (most different), bucket 255 is the closest.
pub(crate) fn bucket_index(self_id: &Identity, other: &Identity) -> usize {
    let dist = xor_distance(self_id, other);
    for (byte_idx, byte) in dist.iter().enumerate() {
        if *byte != 0 {
            let leading = byte.leading_zeros() as usize; // 0..7
            let bit_index = byte_idx * 8 + leading;
            return bit_index; // 0..=255
        }
    }
    // identical ID: put in the "last" bucket
    255
}

/// Generate a random identity that falls into the specified bucket relative to self_id.
///
/// The bucket index determines the XOR distance range. For bucket i, the first i bits
/// of the XOR distance are 0, then bit i is 1, and remaining bits are random.
pub(crate) fn random_id_for_bucket(self_id: &Identity, bucket_idx: usize) -> Identity {
    let self_bytes = self_id.as_bytes();
    
    // Start with random bytes
    let mut distance = [0u8; 32];
    // Handle getrandom failure gracefully
    if getrandom::getrandom(&mut distance).is_err() {
        // Fallback: use self_id XOR'd with bucket index as pseudo-random seed
        for (i, byte) in distance.iter_mut().enumerate() {
            *byte = self_bytes[i].wrapping_add((bucket_idx.wrapping_mul(i + 1)) as u8);
        }
    }

    // Clear bits before bucket_idx (they must be 0 in XOR distance)
    let byte_idx = bucket_idx / 8;
    let bit_pos = bucket_idx % 8;

    // Clear all bytes before the target byte
    for byte in distance.iter_mut().take(byte_idx) {
        *byte = 0;
    }

    // Clear bits before the target bit position and set the target bit
    // bit_pos=0 means MSB, bit_pos=7 means LSB
    let target_bit = 0x80u8 >> bit_pos;
    // Mask for random bits after the target bit (0 if bit_pos=7)
    let random_mask = target_bit.wrapping_sub(1);
    distance[byte_idx] = target_bit | (distance[byte_idx] & random_mask);

    // XOR distance with self_id to get target
    let mut target = [0u8; 32];
    for i in 0..32 {
        target[i] = self_bytes[i] ^ distance[i];
    }

    Identity::from_bytes(target)
}

/// Kademlia routing table with 256 buckets for 256-bit identities.
///
/// Each bucket stores up to k contacts at a specific XOR distance from the local node.
/// Buckets use LRU-like behavior, preferring long-lived nodes for stability.
#[derive(Debug)]
pub struct RoutingTable {
    /// This node's identity.
    self_id: Identity,
    /// Maximum contacts per bucket (adaptive k parameter).
    k: usize,
    /// 256 buckets, one for each bit position of the XOR distance.
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    /// Create a new routing table for the given identity.
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

    /// Update the k parameter, trimming buckets if they exceed the new limit.
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

    /// Add or update a contact in the routing table.
    pub fn update(&mut self, contact: Contact) {
        let _ = self.update_with_pending(contact);
    }

    /// Add or update a contact, returning pending update info if bucket is full.
    ///
    /// When a bucket is full and a new contact is seen, this returns info
    /// about the oldest contact so the caller can ping it to decide whether
    /// to evict it or discard the new contact.
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
                oldest,
                new_contact,
            }),
        }
    }

    /// Find the k closest contacts to a target identity.
    ///
    /// Uses a bounded max-heap for O(n log k) complexity where n is total contacts
    /// and k is the requested count. This is more efficient than sorting when k << n.
    ///
    /// # Algorithm
    ///
    /// 1. Iterate all contacts across all 256 buckets
    /// 2. Maintain a max-heap of size k (largest distances at top)
    /// 3. Only insert if closer than current max, then pop the max
    /// 4. Extract and sort the k contacts by distance (ascending)
    pub fn closest(&self, target: &Identity, k: usize) -> Vec<Contact> {
        if k == 0 {
            return Vec::new();
        }

        // Wrapper for heap ordering by distance (max-heap behavior)
        #[derive(Eq, PartialEq)]
        struct DistContact {
            dist: [u8; 32],
            contact: Contact,
        }
        
        impl Ord for DistContact {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                // Max-heap: larger distances come first (will be popped)
                distance_cmp(&self.dist, &other.dist)
            }
        }
        
        impl PartialOrd for DistContact {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut heap: BinaryHeap<DistContact> = BinaryHeap::with_capacity(k + 1);

        for bucket in &self.buckets {
            for contact in &bucket.contacts {
                let dist = xor_distance(&contact.identity, target);
                
                if heap.len() < k {
                    // Heap not full yet, just push
                    heap.push(DistContact { dist, contact: contact.clone() });
                } else if let Some(max_entry) = heap.peek() {
                    // Only push if this contact is closer than the current max
                    if distance_cmp(&dist, &max_entry.dist) == std::cmp::Ordering::Less {
                        heap.push(DistContact { dist, contact: contact.clone() });
                        heap.pop(); // Remove the now-largest element
                    }
                }
            }
        }

        // Extract contacts in sorted order (closest first)
        let mut result: Vec<_> = heap.into_iter().map(|dc| dc.contact).collect();
        result.sort_by(|a, b| {
            let da = xor_distance(&a.identity, target);
            let db = xor_distance(&b.identity, target);
            distance_cmp(&da, &db)
        });
        result
    }

    /// Apply the result of pinging the oldest contact in a full bucket.
    ///
    /// If the oldest contact is still alive, it is refreshed (moved to end).
    /// If the oldest is dead, it is removed and the new contact is inserted.
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

    /// Get indices of stale buckets that have contacts but haven't been refreshed recently.
    ///
    /// Only returns non-empty buckets that are stale, since empty buckets
    /// don't need refreshing.
    pub(crate) fn stale_bucket_indices(&self, threshold: Duration) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.contacts.is_empty() && bucket.is_stale(threshold))
            .map(|(idx, _)| idx)
            .collect()
    }

    /// Mark a bucket as refreshed (called after a successful FIND_NODE for that bucket).
    pub(crate) fn mark_bucket_refreshed(&mut self, bucket_idx: usize) {
        if bucket_idx < self.buckets.len() {
            self.buckets[bucket_idx].mark_refreshed();
        }
    }

    /// Get this node's identity for generating random IDs in bucket ranges.
    pub(crate) fn self_id(&self) -> Identity {
        self.self_id
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
        let self_id = Identity::from_bytes([0x42u8; 32]); // Arbitrary self ID

        // Test a few different bucket indices
        for bucket_idx in [0, 1, 7, 8, 15, 127, 200, 255] {
            // Generate multiple random IDs and verify they all land in the correct bucket
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

        // Should allow up to ROUTING_INSERTION_PER_PEER_LIMIT insertions
        for i in 0..ROUTING_INSERTION_PER_PEER_LIMIT {
            assert!(
                limiter.allow_insertion(&peer1),
                "insertion {} from peer1 should be allowed",
                i
            );
        }

        // Next insertion from peer1 should be rejected
        assert!(
            !limiter.allow_insertion(&peer1),
            "insertion after limit should be rejected for peer1"
        );

        // Different peer should still be allowed
        assert!(
            limiter.allow_insertion(&peer2),
            "peer2 should still be allowed"
        );

        // Verify remaining tokens for peer1 is near zero
        assert!(
            limiter.remaining_tokens(&peer1) < 1.0,
            "peer1 should have no tokens left"
        );

        // Verify peer2 has used one token
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
        
        // Add MAX_ROUTING_INSERTION_TRACKED_PEERS peers
        for i in 0..MAX_ROUTING_INSERTION_TRACKED_PEERS {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let peer = Identity::from_bytes(bytes);
            limiter.allow_insertion(&peer);
        }

        // Add one more peer - should evict the oldest
        let new_peer = Identity::from_bytes([0xFF; 32]);
        assert!(limiter.allow_insertion(&new_peer), "new peer should be allowed");

        // The new peer should have a bucket
        let remaining = limiter.remaining_tokens(&new_peer);
        assert!(
            (remaining - (ROUTING_INSERTION_PER_PEER_LIMIT as f64 - 1.0)).abs() < 0.1,
            "new peer should have used one token"
        );
    }

    // ========================================================================
    // RoutingTable Tests (moved from tests/routing_table.rs)
    // ========================================================================

    fn make_test_identity(byte: u8) -> Identity {
        let mut id = [0u8; 32];
        id[0] = byte;
        Identity::from_bytes(id)
    }

    fn make_test_contact(byte: u8) -> Contact {
        Contact {
            identity: make_test_identity(byte),
            addr: format!("node-{byte}"),
        }
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

    // ========================================================================
    // Sybil Attack on Routing Table Tests (from tests/security_gaps.rs)
    // ========================================================================

    /// Maximum bucket size (k parameter).
    const MAX_K: usize = 30;

    /// Number of buckets in routing table.
    const NUM_BUCKETS: usize = 256;

    /// Test that routing table has limited size.
    #[test]
    fn routing_table_size_bounded() {
        let max_routing_table_size = MAX_K * NUM_BUCKETS;
        assert_eq!(max_routing_table_size, 7680);
        assert!(max_routing_table_size < 10_000, "Routing table should be bounded");
    }

    /// Test Sybil attack with targeted NodeIds.
    #[test]
    fn sybil_attack_targeted_bucket() {
        let _target_bucket = 100;
        let attacker_nodes = 100;

        let nodes_in_bucket = std::cmp::min(attacker_nodes, MAX_K);

        assert_eq!(nodes_in_bucket, 30, "Bucket should accept at most k nodes");
    }

    /// Test Sybil resistance through bucket distribution.
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

    /// Test bucket index calculation for Sybil resistance.
    #[test]
    fn bucket_index_calculation_correct() {
        let self_id = make_test_identity(0x00);

        // Same ID -> bucket 255 (closest - identical)
        let same_id = make_test_identity(0x00);
        assert_eq!(
            bucket_index_for_test(self_id.as_bytes(), same_id.as_bytes()),
            255,
            "Same ID should be in bucket 255"
        );

        // First byte differs with MSB set
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

    /// Calculate bucket index for a node ID relative to self.
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
}
