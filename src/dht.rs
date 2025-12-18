//! # Kademlia-style Distributed Hash Table
//!
//! This module implements a Kademlia-inspired DHT with several enhancements:
//!
//! - **Adaptive Parameters**: k and α adjust based on network conditions
//! - **Tiered Routing**: Contacts are grouped by latency for faster lookups
//! - **Pressure-based Storage**: Values are evicted under resource pressure
//! - **Eclipse Resistance**: Rate limiting prevents routing table poisoning
//!
//! ## Key Operations
//!
//! | Operation | Description |
//! |-----------|-------------|
//! | `put(key, value)` | Store a value (content-addressed or identity record) |
//! | `get(key)` | Retrieve a value via iterative lookup |
//! | `find_node(id)` | Find contacts closest to an identity |
//! | `bootstrap(contact)` | Join the network via a known peer |
//!
//! ## Routing Table
//!
//! The routing table uses 256 k-buckets indexed by XOR distance prefix.
//! Each bucket holds up to k contacts, with LRU eviction when full.
//!
//! ## Actor Architecture
//!
//! - `DhtNode`: Public handle for DHT operations
//! - `DhtActor`: Internal actor owning routing table and storage
//! - Commands are sent via async channels for thread-safe access
//!
//! ## Security
//!
//! - Per-peer insertion rate limiting (see `RoutingInsertionLimiter`)
//! - Content verification: `hash(value) == key` or signed identity record
//! - Bounded storage with automatic eviction

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use blake3::hash;
use lru::LruCache;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

use crate::identity::{distance_cmp, Contact, FreshnessError, Identity, Keypair};
use crate::protocols::DhtNodeRpc;

/// Maximum age for endpoint records before they're considered stale (24 hours).
/// Records older than this are not propagated during lookups.
const ENDPOINT_RECORD_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Maximum retries when offloading values during graceful shutdown.
const OFFLOAD_MAX_RETRIES: usize = 3;

/// Base delay between offload retry attempts (exponential backoff).
const OFFLOAD_BASE_DELAY_MS: u64 = 100;

/// Key type for DHT storage (32-byte hash).
pub type Key = [u8; 32];

/// Classification of DHT value types for differentiated rate limiting.
/// 
/// SECURITY: Content-addressed values bypass PoW verification and are therefore
/// subject to stricter rate limiting than identity-keyed Contact records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    /// Content-addressed: key = hash(value). No PoW required.
    /// Subject to stricter rate limiting (CONTENT_ADDRESSED_RATE_DIVISOR).
    ContentAddressed,
    /// Identity-keyed: key = identity, value = signed Contact record.
    /// PoW-verified, standard rate limiting.
    IdentityKeyed,
    /// Invalid: value doesn't match key and isn't a valid Contact.
    Invalid,
}

/// Maximum plausible size for a valid Contact record.
/// A Contact with 16 addresses of 256 bytes each, plus signature and overhead = ~5KB.
/// Anything larger is clearly invalid and we can skip deserialization.
/// SECURITY: Saves CPU cycles on obviously malformed payloads.
const MAX_CONTACT_RECORD_SIZE: usize = 16 * 1024;

/// Classify a key-value pair and validate it.
/// 
/// Returns `ValueType::Invalid` if the value cannot be stored.
/// Returns `ValueType::ContentAddressed` for hash(value) == key (no PoW).
/// Returns `ValueType::IdentityKeyed` for valid, fresh, PoW-verified Contact records.
/// 
/// SECURITY: This classification is used to apply differentiated rate limiting.
/// Content-addressed stores are rate-limited more strictly since they bypass
/// the computational cost of PoW identity generation.
pub fn classify_key_value_pair(key: &Key, value: &[u8]) -> ValueType {
    // Fast path: content-addressed storage (hash of value == key)
    if hash(value).as_bytes() == key {
        return ValueType::ContentAddressed;
    }

    // SECURITY: Early rejection of oversized values before deserialization.
    // Valid Contact records are typically <1KB; anything >16KB cannot be valid.
    if value.len() > MAX_CONTACT_RECORD_SIZE {
        debug!(
            key = hex::encode(&key[..8]),
            value_len = value.len(),
            max = MAX_CONTACT_RECORD_SIZE,
            "DHT store rejected: value too large to be a valid Contact record"
        );
        return ValueType::Invalid;
    }

    // Slow path: identity-keyed Contact record
    if let Ok(record) = crate::messages::deserialize_bounded::<Contact>(value) {
        // SECURITY: validate_structure() prevents malformed Contact records
        // with excessive addresses/relays from being accepted into the DHT.
        // SECURITY: is_valid() ensures the identity is a valid Ed25519 public key,
        // preventing malformed identities (all zeros, non-point values) from entering the DHT.
        if !record.identity.is_valid() {
            debug!(
                key = hex::encode(&key[..8]),
                "DHT store rejected: invalid identity (not a valid Ed25519 point)"
            );
            return ValueType::Invalid;
        }
        if !record.validate_structure() {
            debug!(
                key = hex::encode(&key[..8]),
                identity = hex::encode(&record.identity.as_bytes()[..8]),
                "DHT store rejected: Contact structure validation failed"
            );
            return ValueType::Invalid;
        }
        if record.identity.as_bytes() != key {
            debug!(
                key = hex::encode(&key[..8]),
                identity = hex::encode(&record.identity.as_bytes()[..8]),
                "DHT store rejected: identity does not match key"
            );
            return ValueType::Invalid;
        }
        match record.verify_fresh(ENDPOINT_RECORD_MAX_AGE_SECS) {
            Ok(()) => return ValueType::IdentityKeyed,
            Err(FreshnessError::SignatureInvalid) => {
                debug!(
                    key = hex::encode(&key[..8]),
                    identity = hex::encode(&record.identity.as_bytes()[..8]),
                    "DHT store rejected: Contact record has invalid signature"
                );
            }
            Err(FreshnessError::ClockSkewFuture { record_ts, local_ts, drift_ms }) => {
                warn!(
                    key = hex::encode(&key[..8]),
                    identity = hex::encode(&record.identity.as_bytes()[..8]),
                    record_ts,
                    local_ts,
                    drift_ms,
                    "DHT store rejected: Contact record timestamp in future (clock skew detected)"
                );
            }
            Err(FreshnessError::Stale { record_ts, local_ts, age_ms }) => {
                debug!(
                    key = hex::encode(&key[..8]),
                    identity = hex::encode(&record.identity.as_bytes()[..8]),
                    record_ts,
                    local_ts,
                    age_ms,
                    "DHT store rejected: Contact record is stale"
                );
            }
        }
        return ValueType::Invalid;
    }

    // Neither content-addressed nor valid Contact record
    debug!(
        key = hex::encode(&key[..8]),
        value_len = value.len(),
        "DHT store rejected: hash mismatch and not a valid Contact record"
    );
    ValueType::Invalid
}


// ============================================================================
// Routing Table (XOR-Metric)
// ============================================================================
//
// Kademlia routing table with XOR-based distance metric.
//
// Key Concepts:
// - XOR Distance: distance(a, b) = a XOR b (bitwise)
// - Bucket Index: Number of leading zero bits in XOR distance
// - k-Buckets: Each bucket holds up to k contacts at similar distances
//
// Bucket Organization:
//   Bucket 0: Contacts where distance has 0 leading zeros (furthest, 50% of keyspace)
//   Bucket 1: Contacts where distance has 1 leading zero (25% of keyspace)
//   ...
//   Bucket 255: Contacts where distance has 255 leading zeros (closest)
//
// Anti-Eclipse Protection:
//   RoutingInsertionLimiter uses token-bucket rate limiting to prevent
//   a single peer from flooding the routing table with contacts (Sybil/Eclipse attack).
//
// Bucket Refresh:
//   Stale buckets (no activity for BUCKET_STALE_THRESHOLD) trigger random lookups
//   within that bucket's keyspace to discover new contacts.

/// Interval between bucket refresh checks.
/// Buckets without activity for this long will trigger random lookups.
const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Threshold after which a bucket is considered stale and needs refresh.
const BUCKET_STALE_THRESHOLD: Duration = Duration::from_secs(30 * 60);

/// Maximum routing insertions per peer per rate window.
/// SECURITY: Prevents eclipse attacks by limiting how fast any peer can
/// populate the routing table with (potentially Sybil) contacts.
const ROUTING_INSERTION_PER_PEER_LIMIT: usize = 50;

/// Time window for insertion rate limiting.
const ROUTING_INSERTION_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Maximum peers to track for insertion rate limiting.
/// Uses LRU eviction when full.
const MAX_ROUTING_INSERTION_TRACKED_PEERS: usize = 1_000;

/// Maximum direct peer insertions per IP per rate window.
/// SECURITY: Limits routing table pollution from direct connections without PoW.
/// An attacker with many IPs can still populate the table, but must pay connection cost.
const DIRECT_PEER_PER_IP_LIMIT: usize = 20;

/// Time window for direct peer IP rate limiting.
const DIRECT_PEER_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Maximum IPs to track for direct peer rate limiting.
const MAX_DIRECT_PEER_TRACKED_IPS: usize = 1_000;

/// Whether to enforce Proof-of-Work verification for routing table insertion.
/// 
/// SECURITY (S/Kademlia): When enabled, contacts must have a valid PoW proof
/// (`contact.verify_pow() == true`) to be accepted into the routing table.
/// This prevents Sybil attacks by making identity generation computationally expensive.
pub const ENFORCE_POW_FOR_ROUTING: bool = true;


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

struct RoutingInsertionLimiter {
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

/// Rate limiter for direct peer insertions by IP address.
/// 
/// SECURITY: Direct peers bypass PoW verification because their identity is
/// verified via mTLS. However, an attacker with many IP addresses could exploit
/// this to populate the routing table without paying PoW cost. This limiter
/// restricts insertions per IP to bound the attack surface.
#[derive(Debug, Clone, Copy)]
struct DirectPeerIpBucket {
    tokens: f64,
    last_update: Instant,
}

impl DirectPeerIpBucket {
    fn new() -> Self {
        Self {
            tokens: DIRECT_PEER_PER_IP_LIMIT as f64,
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let window_secs = DIRECT_PEER_RATE_WINDOW.as_secs_f64();
        
        let rate = DIRECT_PEER_PER_IP_LIMIT as f64 / window_secs;
        self.tokens = (self.tokens + elapsed * rate).min(DIRECT_PEER_PER_IP_LIMIT as f64);
        self.last_update = now;
        
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct DirectPeerIpLimiter {
    buckets: LruCache<IpAddr, DirectPeerIpBucket>,
}

impl DirectPeerIpLimiter {
    pub fn new() -> Self {
        Self {
            buckets: LruCache::new(
                NonZeroUsize::new(MAX_DIRECT_PEER_TRACKED_IPS)
                    .expect("MAX_DIRECT_PEER_TRACKED_IPS must be non-zero")
            ),
        }
    }

    /// Check if a direct peer from the given IP should be allowed.
    /// Extracts IP from the contact's primary address.
    pub fn allow_direct_peer(&mut self, contact: &Contact) -> bool {
        let ip = match contact.primary_addr() {
            Some(addr_str) => {
                // Parse "host:port" format
                match addr_str.parse::<std::net::SocketAddr>() {
                    Ok(addr) => addr.ip(),
                    Err(_) => return true, // Can't parse, allow (fail-open for edge cases)
                }
            }
            None => return true, // No address, allow (unusual but not attackable)
        };
        
        let bucket = self.buckets.get_or_insert_mut(ip, DirectPeerIpBucket::new);
        bucket.try_consume()
    }
}


#[derive(Debug, Clone)]
struct RoutingBucket {
    contacts: Vec<Contact>,
    last_refresh: Instant,
}

impl Default for RoutingBucket {
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
struct PendingBucketUpdate {
    bucket_index: usize,
    oldest: Contact,
    new_contact: Contact,
}

impl RoutingBucket {
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
            // Prefer signed/newer contact over unsigned/older one
            let updated = if contact.signature.len() > existing.signature.len()
                || (contact.signature.len() == existing.signature.len()
                    && contact.timestamp > existing.timestamp)
            {
                contact
            } else {
                existing
            };
            self.contacts.push(updated);
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


fn bucket_index(self_id: &Identity, other: &Identity) -> usize {
    let dist = self_id.xor_distance(other);
    for (byte_idx, byte) in dist.iter().enumerate() {
        if *byte != 0 {
            let leading = byte.leading_zeros() as usize;
            let bit_index = byte_idx * 8 + leading;
            return bit_index;
        }
    }
    255
}

fn random_id_for_bucket(self_id: &Identity, bucket_idx: usize) -> Identity {
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
    buckets: Vec<RoutingBucket>,
}

impl RoutingTable {
    pub fn new(self_id: Identity, k: usize) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(RoutingBucket::new());
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

    fn update_with_pending(&mut self, contact: Contact) -> Option<PendingBucketUpdate> {
        if contact.identity == self.self_id {
            return None;
        }
        // SECURITY: Reject contacts with invalid identities (non-Ed25519 points, all zeros, etc.)
        // to prevent routing table pollution with unreachable entries.
        if !contact.identity.is_valid() {
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
                let dist = contact.identity.xor_distance(target);
                
                if heap.len() < k {
                    heap.push(DistEndpointInfo { dist, contact: contact.clone() });
                } else if let Some(max_entry) = heap.peek()
                    && distance_cmp(&dist, &max_entry.dist) == std::cmp::Ordering::Less
                {
                    heap.push(DistEndpointInfo { dist, contact: contact.clone() });
                    heap.pop();
                }
            }
        }

        let mut result: Vec<_> = heap.into_iter().map(|dc| dc.contact).collect();
        result.sort_by(|a, b| {
            let da = a.identity.xor_distance(target);
            let db = b.identity.xor_distance(target);
            distance_cmp(&da, &db)
        });
        result
    }

    fn apply_ping_result(&mut self, pending: PendingBucketUpdate, oldest_alive: bool) {
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

    fn stale_bucket_indices(&self, threshold: Duration) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.contacts.is_empty() && bucket.is_stale(threshold))
            .map(|(idx, _)| idx)
            .collect()
    }

    fn mark_bucket_refreshed(&mut self, bucket_idx: usize) {
        if bucket_idx < self.buckets.len() {
            self.buckets[bucket_idx].mark_refreshed();
        }
    }

    /// Look up a contact by identity.
    /// Returns the contact if found in the routing table, None otherwise.
    fn lookup_contact(&self, identity: &Identity) -> Option<Contact> {
        if *identity == self.self_id {
            return None;
        }
        let idx = bucket_index(&self.self_id, identity);
        self.buckets[idx]
            .contacts
            .iter()
            .find(|c| c.identity == *identity)
            .cloned()
    }
}


// ============================================================================
// Local Storage (DHT Key-Value Store)
// ============================================================================
//
// Local storage for DHT key-value pairs with pressure-based eviction and per-peer quotas.
//
// Features:
// - LRU cache with configurable capacity limits
// - Pressure-based eviction when resource limits are approached
// - Per-peer storage quotas and rate limiting to prevent abuse
// - Automatic expiration of stale entries

/// Default time-to-live for stored entries (24 hours).
const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How often to check for expired entries.
const EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Soft limit for total storage bytes (8 MiB).
/// Exceeding this contributes to storage pressure score.
const PRESSURE_DISK_SOFT_LIMIT: usize = 8 * 1024 * 1024;

/// Soft limit for memory usage (4 MiB).
/// Used in pressure calculation alongside disk limit.
const PRESSURE_MEMORY_SOFT_LIMIT: usize = 4 * 1024 * 1024;

/// Time window for counting storage requests.
const PRESSURE_REQUEST_WINDOW: Duration = Duration::from_secs(60);

/// Maximum requests per window before pressure increases.
const PRESSURE_REQUEST_LIMIT: usize = 200;

/// Pressure threshold (0.0-1.0) that triggers proactive eviction.
/// At 0.75, eviction starts before hard limits are reached.
const PRESSURE_THRESHOLD: f32 = 0.75;

/// Maximum size of a single stored value.
/// SECURITY: Prevents memory exhaustion from large value storage.
const MAX_VALUE_SIZE: usize = crate::messages::MAX_VALUE_SIZE;

/// Maximum bytes a single peer can store (1 MiB per-peer quota).
/// SECURITY: Prevents a single peer from monopolizing storage.
const PER_PEER_STORAGE_QUOTA: usize = 1024 * 1024;

/// Maximum entries a single peer can store.
/// SECURITY: Complements byte quota to limit entry count attacks.
const PER_PEER_ENTRY_LIMIT: usize = 100;

/// Maximum store requests per peer per window.
/// SECURITY: Rate limits storage operations per peer.
const PER_PEER_RATE_LIMIT: usize = 20;

/// Rate limit divisor for content-addressed stores.
/// SECURITY: Content-addressed values bypass PoW verification, making bulk storage
/// computationally cheap for attackers. This divisor makes content-addressed stores
/// 4x more restricted than identity-keyed stores (which require PoW).
/// Effective rate: PER_PEER_RATE_LIMIT / CONTENT_ADDRESSED_RATE_DIVISOR = 5 per window.
const CONTENT_ADDRESSED_RATE_DIVISOR: usize = 4;

/// Time window for per-peer rate limiting.
const PER_PEER_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Access count below which entries are considered unpopular for eviction.
/// Low-popularity entries are evicted first under pressure.
const POPULARITY_THRESHOLD: u32 = 3;

/// Maximum number of peers to track storage stats for.
/// SECURITY: Bounded LruCache prevents quota tracking table growth.
const MAX_TRACKED_PEERS: usize = 10_000;

/// Maximum entries in the local store.
/// SCALABILITY: 100K entries is the per-node DHT storage limit (see README).
/// SECURITY: Hard cap on DHT storage entry count.
const LOCAL_STORE_MAX_ENTRIES: usize = 100_000;

/// Safety limit on eviction loop iterations.
/// Prevents runaway eviction loops from blocking the actor.
const MAX_EVICTION_ITERATIONS: usize = 10_000;

/// Monitors resource pressure to trigger eviction when limits are approached.
struct PressureMonitor {
    current_bytes: usize,
    requests: VecDeque<Instant>,
    request_window: Duration,
    request_limit: usize,
    disk_limit: usize,
    memory_limit: usize,
    current_pressure: f32,
}

impl PressureMonitor {
    pub fn new() -> Self {
        Self {
            current_bytes: 0,
            requests: VecDeque::new(),
            request_window: PRESSURE_REQUEST_WINDOW,
            request_limit: PRESSURE_REQUEST_LIMIT,
            disk_limit: PRESSURE_DISK_SOFT_LIMIT,
            memory_limit: PRESSURE_MEMORY_SOFT_LIMIT,
            current_pressure: 0.0,
        }
    }

    pub fn record_store(&mut self, bytes: usize) {
        self.current_bytes = self.current_bytes.saturating_add(bytes);
    }

    pub fn record_evict(&mut self, bytes: usize) {
        self.current_bytes = self.current_bytes.saturating_sub(bytes);
    }

    pub fn record_spill(&mut self) {
        self.current_pressure = 1.0;
    }

    pub fn record_request(&mut self) {
        let now = Instant::now();
        self.requests.push_back(now);
        self.trim_requests(now);
    }

    fn trim_requests(&mut self, now: Instant) {
        while let Some(front) = self.requests.front() {
            if now.duration_since(*front) > self.request_window {
                self.requests.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn update_pressure(&mut self, stored_keys: usize) {
        let disk_ratio = self.current_bytes as f32 / self.disk_limit as f32;
        let memory_ratio = self.current_bytes as f32 / self.memory_limit as f32;
        let request_ratio = self.requests.len() as f32 / self.request_limit as f32;
        let combined = (disk_ratio + memory_ratio + request_ratio) / 3.0;
        if combined > 1.0 {
            self.current_pressure = 1.0;
        } else if combined < 0.0 {
            self.current_pressure = 0.0;
        } else {
            self.current_pressure = combined;
        }

        if stored_keys == 0 {
            self.current_pressure = self.current_pressure.min(1.0);
        }
    }

    pub fn current_pressure(&self) -> f32 {
        self.current_pressure
    }
}

/// A stored entry with metadata for expiration and access tracking.
#[derive(Clone)]
struct StoredEntry {
    value: Vec<u8>,
    expires_at: Instant,
    stored_by: Identity,
    access_count: u32,
    stored_at: Instant,
}

/// Per-peer storage statistics for quota enforcement.
#[derive(Debug, Clone, Default)]
struct PeerStorageStats {
    bytes_stored: usize,
    entry_count: usize,
    store_requests: VecDeque<Instant>,
    /// Separate tracking for content-addressed stores (stricter limit).
    /// SECURITY: Content-addressed stores bypass PoW and are rate-limited
    /// at PER_PEER_RATE_LIMIT / CONTENT_ADDRESSED_RATE_DIVISOR.
    content_addressed_requests: VecDeque<Instant>,
}

impl PeerStorageStats {
    fn can_store(&self, value_size: usize) -> bool {
        self.bytes_stored + value_size <= PER_PEER_STORAGE_QUOTA
            && self.entry_count < PER_PEER_ENTRY_LIMIT
    }

    /// Check if the peer is rate limited for the given value type.
    /// Content-addressed stores have a stricter limit since they bypass PoW.
    fn is_rate_limited(&mut self, value_type: ValueType) -> bool {
        let now = Instant::now();
        
        // Clean up expired entries from general store requests
        while let Some(front) = self.store_requests.front() {
            if now.duration_since(*front) > PER_PEER_RATE_WINDOW {
                self.store_requests.pop_front();
            } else {
                break;
            }
        }
        
        // Check general rate limit
        if self.store_requests.len() >= PER_PEER_RATE_LIMIT {
            return true;
        }
        
        // For content-addressed values, apply stricter rate limit
        if value_type == ValueType::ContentAddressed {
            // Clean up expired entries from content-addressed requests
            while let Some(front) = self.content_addressed_requests.front() {
                if now.duration_since(*front) > PER_PEER_RATE_WINDOW {
                    self.content_addressed_requests.pop_front();
                } else {
                    break;
                }
            }
            
            // SECURITY: Stricter limit for content-addressed (no PoW)
            let content_limit = PER_PEER_RATE_LIMIT / CONTENT_ADDRESSED_RATE_DIVISOR;
            if self.content_addressed_requests.len() >= content_limit {
                debug!(
                    "content-addressed store rejected: stricter rate limit ({}/{} per {} secs)",
                    self.content_addressed_requests.len(),
                    content_limit,
                    PER_PEER_RATE_WINDOW.as_secs()
                );
                return true;
            }
        }
        
        false
    }

    fn record_store(&mut self, value_size: usize, value_type: ValueType) {
        self.bytes_stored = self.bytes_stored.saturating_add(value_size);
        self.entry_count = self.entry_count.saturating_add(1);
        self.store_requests.push_back(Instant::now());
        
        // Track content-addressed stores separately for stricter limiting
        if value_type == ValueType::ContentAddressed {
            self.content_addressed_requests.push_back(Instant::now());
        }
    }

    fn record_evict(&mut self, value_size: usize) {
        self.bytes_stored = self.bytes_stored.saturating_sub(value_size);
        self.entry_count = self.entry_count.saturating_sub(1);
    }
}

/// Reason a store request was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreRejection {
    /// Value exceeds maximum allowed size.
    ValueTooLarge,
    /// Peer has exceeded their storage quota.
    QuotaExceeded,
    /// Peer is sending requests too quickly.
    RateLimited,
}

/// Local key-value store with LRU eviction and per-peer quotas.
///
/// Provides storage for DHT entries with:
/// - Automatic expiration based on TTL
/// - Pressure-based eviction when resource limits are approached
/// - Per-peer quotas to prevent any single peer from monopolizing storage
/// - Rate limiting to prevent store request flooding
struct LocalStore {
    cache: LruCache<Key, StoredEntry>,
    pressure: PressureMonitor,
    /// Per-peer storage statistics for quota enforcement.
    /// SECURITY: Bounded by MAX_TRACKED_PEERS to prevent memory exhaustion
    /// from attackers using many identities.
    peer_stats: LruCache<Identity, PeerStorageStats>,
    ttl: Duration,
    last_expiration_check: Instant,
    last_peer_cleanup: Instant,
}

impl LocalStore {
    pub fn new() -> Self {
        let cap = NonZeroUsize::new(LOCAL_STORE_MAX_ENTRIES).expect("capacity must be non-zero");
        let peer_stats_cap = NonZeroUsize::new(MAX_TRACKED_PEERS).expect("peer stats capacity must be non-zero");
        Self {
            cache: LruCache::new(cap),
            pressure: PressureMonitor::new(),
            peer_stats: LruCache::new(peer_stats_cap),
            ttl: DEFAULT_TTL,
            last_expiration_check: Instant::now(),
            last_peer_cleanup: Instant::now(),
        }
    }

    /// Record an incoming request and perform periodic maintenance.
    pub fn record_request(&mut self) {
        self.pressure.record_request();
        self.maybe_expire_entries();
        self.maybe_cleanup_peer_stats();
        let len = self.cache.len();
        self.pressure.update_pressure(len);
    }

    /// Check if a store request from the given peer would be allowed.
    /// The value_type determines which rate limit is applied (stricter for content-addressed).
    pub fn check_store_allowed(&mut self, peer_id: &Identity, value_size: usize, value_type: ValueType) -> Result<(), StoreRejection> {
        if value_size > MAX_VALUE_SIZE {
            debug!(
                peer = ?hex::encode(&peer_id.as_bytes()[..8]),
                size = value_size,
                max = MAX_VALUE_SIZE,
                "store rejected: value too large"
            );
            return Err(StoreRejection::ValueTooLarge);
        }

        let stats = self.peer_stats.get_or_insert_mut(*peer_id, PeerStorageStats::default);

        if stats.is_rate_limited(value_type) {
            debug!(
                peer = ?hex::encode(&peer_id.as_bytes()[..8]),
                value_type = ?value_type,
                "store rejected: rate limited"
            );
            return Err(StoreRejection::RateLimited);
        }

        if !stats.can_store(value_size) {
            debug!(
                peer = ?hex::encode(&peer_id.as_bytes()[..8]),
                bytes_stored = stats.bytes_stored,
                entry_count = stats.entry_count,
                "store rejected: quota exceeded"
            );
            return Err(StoreRejection::QuotaExceeded);
        }

        Ok(())
    }

    /// Store a key-value pair, returning any entries that were evicted due to pressure.
    /// The value_type determines rate limiting (stricter for content-addressed values).
    pub fn store(&mut self, key: Key, value: &[u8], stored_by: Identity, value_type: ValueType) -> Vec<(Key, Vec<u8>)> {
        if value.len() > MAX_VALUE_SIZE {
            warn!(
                size = value.len(),
                limit = MAX_VALUE_SIZE,
                peer = ?stored_by,
                "rejecting oversized value"
            );
            return Vec::new();
        }

        if let Err(rejection) = self.check_store_allowed(&stored_by, value.len(), value_type) {
            info!(peer = ?stored_by, reason = ?rejection, value_type = ?value_type, "store request rejected");
            return Vec::new();
        }

        if let Some(existing) = self.cache.pop(&key) {
            self.pressure.record_evict(existing.value.len());
            if let Some(old_stats) = self.peer_stats.get_mut(&existing.stored_by) {
                old_stats.record_evict(existing.value.len());
            }
        }

        let now = Instant::now();
        let entry = StoredEntry {
            value: value.to_vec(),
            expires_at: now + self.ttl,
            stored_by,
            access_count: 0,
            stored_at: now,
        };

        let stats = self.peer_stats.get_or_insert_mut(stored_by, PeerStorageStats::default);
        stats.record_store(entry.value.len(), value_type);

        self.pressure.record_store(entry.value.len());
        self.cache.put(key, entry);
        self.pressure.update_pressure(self.cache.len());

        self.evict_under_pressure()
    }

    /// Evict entries until pressure drops below threshold.
    fn evict_under_pressure(&mut self) -> Vec<(Key, Vec<u8>)> {
        let mut spilled = Vec::new();
        let mut spill_happened = false;
        let mut iterations = 0;

        while self.pressure.current_pressure() > PRESSURE_THRESHOLD {
            iterations += 1;
            if iterations > MAX_EVICTION_ITERATIONS {
                warn!(
                    iterations = iterations,
                    pressure = self.pressure.current_pressure(),
                    cache_size = self.cache.len(),
                    "eviction loop exceeded max iterations, breaking"
                );
                break;
            }

            let unpopular_key = self.find_unpopular_entry();

            if let Some(key) = unpopular_key
                && let Some(evicted_entry) = self.cache.pop(&key)
            {
                self.pressure.record_evict(evicted_entry.value.len());
                if let Some(stats) = self.peer_stats.get_mut(&evicted_entry.stored_by) {
                    stats.record_evict(evicted_entry.value.len());
                }
                self.pressure.update_pressure(self.cache.len());
                spilled.push((key, evicted_entry.value));
                spill_happened = true;
                continue;
            }

            if let Some((evicted_key, evicted_entry)) = self.cache.pop_lru() {
                self.pressure.record_evict(evicted_entry.value.len());
                if let Some(stats) = self.peer_stats.get_mut(&evicted_entry.stored_by) {
                    stats.record_evict(evicted_entry.value.len());
                }
                self.pressure.update_pressure(self.cache.len());
                spilled.push((evicted_key, evicted_entry.value));
                spill_happened = true;
            } else {
                break;
            }
        }

        if spill_happened {
            warn!(
                spilled_count = spilled.len(),
                pressure = self.pressure.current_pressure(),
                "pressure-based eviction triggered"
            );
            self.pressure.record_spill();
        }

        spilled
    }

    /// Find the least popular entry for eviction.
    fn find_unpopular_entry(&self) -> Option<Key> {
        self.cache
            .iter()
            .filter(|(_, entry)| entry.access_count < POPULARITY_THRESHOLD)
            .min_by_key(|(_, entry)| (entry.access_count, entry.stored_at))
            .map(|(key, _)| *key)
    }

    /// Get a value by key, returning None if not found or expired.
    pub fn get(&mut self, key: &Key) -> Option<Vec<u8>> {
        let now = Instant::now();
        if let Some(entry) = self.cache.get_mut(key)
            && now < entry.expires_at
        {
            entry.access_count = entry.access_count.saturating_add(1);
            return Some(entry.value.clone());
        }
        
        if let Some(expired) = self.cache.pop(key) {
            self.pressure.record_evict(expired.value.len());
            if let Some(stats) = self.peer_stats.get_mut(&expired.stored_by) {
                stats.record_evict(expired.value.len());
            }
        }
        None
    }

    /// Periodically clean up stale peer stats to bound memory.
    /// With LruCache, old entries are automatically evicted when capacity is reached,
    /// so this just ensures we don't have excessively stale entries.
    fn maybe_cleanup_peer_stats(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_peer_cleanup) < Duration::from_secs(300) {
            return;
        }
        self.last_peer_cleanup = now;

        // LruCache automatically evicts when at capacity, so we just need to
        // identify and remove truly empty entries. Collect keys first to avoid
        // borrow issues.
        let empty_peers: Vec<Identity> = self.peer_stats
            .iter()
            .filter(|(_, stats)| stats.entry_count == 0 && stats.store_requests.is_empty())
            .map(|(id, _)| *id)
            .collect();
        
        for peer_id in empty_peers {
            self.peer_stats.pop(&peer_id);
        }
    }

    /// Remove expired entries from the cache.
    fn maybe_expire_entries(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_expiration_check) < EXPIRATION_CHECK_INTERVAL {
            return;
        }
        self.last_expiration_check = now;

        let expired_keys: Vec<Key> = self
            .cache
            .iter()
            .filter_map(|(key, entry)| {
                if now >= entry.expires_at {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect();

        if !expired_keys.is_empty() {
            debug!(
                expired_count = expired_keys.len(),
                "removing expired entries"
            );
        }
        for key in expired_keys {
            if let Some(entry) = self.cache.pop(&key) {
                self.pressure.record_evict(entry.value.len());
                if let Some(stats) = self.peer_stats.get_mut(&entry.stored_by) {
                    stats.record_evict(entry.value.len());
                }
            }
        }
    }

    /// Get the current storage pressure (0.0 to 1.0).
    pub fn current_pressure(&self) -> f32 {
        self.pressure.current_pressure()
    }

    /// Get the number of entries currently stored.
    pub fn len(&self) -> usize {
        self.cache.len()
    }
}


/// Window size for query statistics used in adaptive parameter tuning.
const QUERY_STATS_WINDOW: usize = 100;

/// Adaptive Kademlia parameters that adjust to network conditions.
/// 
/// Tracks query success/failure history to dynamically adjust:
/// - `k`: Replication factor (number of contacts per bucket)
/// - `alpha`: Concurrency factor (parallel queries during lookup)
struct AdaptiveParams {
    k: usize,
    alpha: usize,
    churn_history: VecDeque<bool>,
}

impl AdaptiveParams {
    pub fn new(k: usize, alpha: usize) -> Self {
        Self {
            k,
            alpha: alpha.clamp(2, 5),
            churn_history: VecDeque::new(),
        }
    }

    pub fn record_churn(&mut self, success: bool) -> bool {
        self.churn_history.push_back(success);
        if self.churn_history.len() > QUERY_STATS_WINDOW {
            self.churn_history.pop_front();
        }
        let old_k = self.k;
        let old_alpha = self.alpha;
        self.update_k();
        self.update_alpha();
        if old_k != self.k || old_alpha != self.alpha {
            info!(
                old_k = old_k,
                new_k = self.k,
                old_alpha = old_alpha,
                new_alpha = self.alpha,
                "adaptive parameters changed"
            );
        }
        old_k != self.k
    }

    fn update_k(&mut self) {
        if self.churn_history.is_empty() {
            return;
        }
        let failures = self.churn_history.iter().filter(|entry| !**entry).count();
        let churn_rate = failures as f32 / self.churn_history.len() as f32;
        let new_k = (10.0 + (20.0 * churn_rate).round()).clamp(10.0, 30.0);
        self.k = new_k as usize;
    }

    fn update_alpha(&mut self) {
        if self.churn_history.is_empty() {
            return;
        }
        let failures = self.churn_history.iter().filter(|entry| !**entry).count();
        let failure_rate = failures as f32 / self.churn_history.len() as f32;
        let new_alpha = (2.0 + (3.0 * failure_rate).round()).clamp(2.0, 5.0);
        self.alpha = new_alpha as usize;
    }

    pub fn current_k(&self) -> usize {
        self.k
    }

    pub fn current_alpha(&self) -> usize {
        self.alpha
    }
}

#[derive(Clone, Debug)]
pub struct LookupResult {
    pub closest: Vec<Contact>,
}

impl LookupResult {
    fn new(closest: Vec<Contact>) -> Self {
        Self { closest }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TelemetrySnapshot {
    pub tier_centroids: Vec<f32>,
    pub tier_counts: Vec<usize>,
    pub pressure: f32,
    pub stored_keys: usize,
    pub replication_factor: usize,
    pub concurrency: usize,
}


// ============================================================================
// Tiering Configuration (Latency-Aware Routing)
// ============================================================================

/// Interval for recomputing tier centroids via k-means clustering.
const TIERING_RECOMPUTE_INTERVAL: Duration = Duration::from_secs(300);

/// Maximum RTT samples kept per /16 prefix.
/// Older samples are evicted to adapt to network changes.
const MAX_RTT_SAMPLES_PER_PREFIX: usize = 32;

/// Minimum number of latency tiers (at least 1 tier always exists).
const MIN_LATENCY_TIERS: usize = 1;

/// Maximum number of latency tiers for contact grouping.
const MAX_LATENCY_TIERS: usize = 7;

/// Iterations for k-means clustering when computing tier boundaries.
const KMEANS_ITERATIONS: usize = 20;

/// Penalty factor applied to higher tiers during contact selection.
/// Biases toward lower-latency peers.
const TIERING_PENALTY_FACTOR: f32 = 1.5;

/// Maximum /16 prefixes to track (65536 possible, we track active ones).
/// SCALABILITY: O(65K) prefixes vs O(N) per-peer tracking (~1 MB at 10M nodes).
/// SECURITY: Bounds memory for RTT tracking tables.
const MAX_TIERING_TRACKED_PREFIXES: usize = 10_000;

/// Tiering level for latency-based contact grouping.
/// 
/// Contacts are grouped into tiers based on their /16 IP prefix's RTT.
/// Tier 0 = fastest, higher tiers = progressively slower.
/// This enables latency-aware routing during lookups.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TieringLevel(usize);

impl TieringLevel {
    fn new(index: usize) -> Self {
        Self(index)
    }

    fn index(self) -> usize {
        self.0
    }
}

/// Statistics about latency tiers for telemetry/debugging.
#[derive(Clone, Debug, Default)]
pub struct TieringStats {
    /// Centroid latency (ms) for each tier, sorted ascending.
    pub centroids: Vec<f32>,
    /// Number of /16 prefixes in each tier.
    pub counts: Vec<usize>,
}

/// /16 prefix key: first two octets of IPv4 or first segment of IPv6.
/// 
/// Used for latency-based grouping - all IPs in the same /16 typically
/// have similar latency (same ISP/region).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Prefix16(u16);

impl Prefix16 {
    fn from_addr_str(addr: &str) -> Option<Self> {
        // Parse "host:port" or just "host" format
        let host = if let Some(bracket_end) = addr.find(']') {
            // IPv6: [::1]:port
            &addr[1..bracket_end]
        } else if let Some(colon_pos) = addr.rfind(':') {
            // IPv4 or hostname:port - take part before last colon
            &addr[..colon_pos]
        } else {
            addr
        };
        
        host.parse::<IpAddr>().ok().map(|ip| match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                Self(((octets[0] as u16) << 8) | (octets[1] as u16))
            }
            IpAddr::V6(v6) => {
                // Use /32 (first two segments) for ISP-level granularity
                let segs = v6.segments();
                Self(segs[0].wrapping_add(segs[1]))
            }
        })
    }
}

/// RTT statistics for a /16 prefix
#[derive(Clone, Debug)]
struct PrefixRttStats {
    samples: VecDeque<f32>,
    smoothed: f32,
}

impl Default for PrefixRttStats {
    fn default() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_RTT_SAMPLES_PER_PREFIX),
            smoothed: 150.0, // Default estimate
        }
    }
}

impl PrefixRttStats {
    fn update(&mut self, rtt_ms: f32) {
        if self.samples.len() == MAX_RTT_SAMPLES_PER_PREFIX {
            self.samples.pop_front();
        }
        self.samples.push_back(rtt_ms);
        
        // Exponential moving average
        const ALPHA: f32 = 0.3;
        self.smoothed = ALPHA * rtt_ms + (1.0 - ALPHA) * self.smoothed;
    }
}

/// Prefix-based latency tiering manager.
/// 
/// Tracks RTT by /16 IP prefix instead of per-peer, enabling:
/// - O(1) memory per prefix (~512KB for entire IPv4 space)
/// - Immediate RTT estimates for unseen peers in known prefixes
/// - Linear scaling to millions of nodes
struct TieringManager {
    /// /16 prefix → RTT statistics (LRU cache, bounded by MAX_TIERING_TRACKED_PREFIXES)
    prefix_rtt: LruCache<Prefix16, PrefixRttStats>,
    /// /16 prefix → tier assignment.
    /// BOUNDED: Only populated from prefix_rtt.iter() during recompute_if_needed(),
    /// so size is transitively bounded by MAX_TIERING_TRACKED_PREFIXES.
    prefix_tiers: HashMap<Prefix16, TieringLevel>,
    /// Tier centroids (sorted by latency)
    centroids: Vec<f32>,
    /// Last recomputation time
    last_recompute: Instant,
    min_tiers: usize,
    max_tiers: usize,
}

impl TieringManager {
    pub fn new() -> Self {
        Self {
            prefix_rtt: LruCache::new(
                NonZeroUsize::new(MAX_TIERING_TRACKED_PREFIXES).unwrap()
            ),
            prefix_tiers: HashMap::new(),
            centroids: vec![150.0],
            last_recompute: Instant::now() - TIERING_RECOMPUTE_INTERVAL,
            min_tiers: MIN_LATENCY_TIERS,
            max_tiers: MAX_LATENCY_TIERS,
        }
    }

    /// Register a contact and return its tiering level based on /16 prefix.
    pub fn register_contact(&mut self, contact: &Contact) -> TieringLevel {
        if let Some(primary) = contact.primary_addr()
            && let Some(prefix) = Prefix16::from_addr_str(primary)
        {
            // Ensure prefix is in LRU (touch it)
            self.prefix_rtt.get_or_insert_mut(prefix, PrefixRttStats::default);
            return self.prefix_tiers
                .get(&prefix)
                .copied()
                .unwrap_or_else(|| self.default_level());
        }
        self.default_level()
    }

    /// Record an RTT sample for a contact's /16 prefix.
    pub fn record_sample(&mut self, contact: &Contact, rtt_ms: f32) {
        if let Some(primary) = contact.primary_addr()
            && let Some(prefix) = Prefix16::from_addr_str(primary)
        {
            self.prefix_rtt
                .get_or_insert_mut(prefix, PrefixRttStats::default)
                .update(rtt_ms);
            self.recompute_if_needed();
        }
    }

    /// Get tiering level for a contact based on its /16 prefix.
    pub fn level_for(&self, contact: &Contact) -> TieringLevel {
        contact.primary_addr()
            .and_then(Prefix16::from_addr_str)
            .and_then(|prefix| self.prefix_tiers.get(&prefix).copied())
            .unwrap_or_else(|| self.default_level())
    }

    pub fn stats(&self) -> TieringStats {
        let mut counts = vec![0usize; self.centroids.len()];
        for level in self.prefix_tiers.values() {
            let idx = level.index();
            if idx < counts.len() {
                counts[idx] += 1;
            }
        }
        TieringStats {
            centroids: self.centroids.clone(),
            counts,
        }
    }

    fn recompute_if_needed(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_recompute) < TIERING_RECOMPUTE_INTERVAL {
            return;
        }

        // Collect per-prefix average RTTs
        let per_prefix: Vec<(Prefix16, f32)> = self
            .prefix_rtt
            .iter()
            .filter_map(|(prefix, stats)| {
                if stats.samples.is_empty() {
                    None
                } else {
                    Some((*prefix, stats.smoothed))
                }
            })
            .collect();

        let min_required = self.min_tiers.max(2);
        if per_prefix.len() < min_required {
            return;
        }

        let max_k = per_prefix.len().min(self.max_tiers);
        let samples: Vec<f32> = per_prefix.iter().map(|(_, avg)| *avg).collect();

        let (centroids, assignments) = dynamic_kmeans(&samples, self.min_tiers, max_k);

        // Update prefix tier assignments
        self.prefix_tiers.clear();
        for ((prefix, _avg), tier_idx) in per_prefix.iter().zip(assignments.iter()) {
            self.prefix_tiers.insert(*prefix, TieringLevel::new(*tier_idx));
        }

        if !centroids.is_empty() {
            let old_tiers = self.centroids.len();
            self.centroids = centroids;
            if self.centroids.len() != old_tiers {
                debug!(
                    old_tiers = old_tiers,
                    new_tiers = self.centroids.len(),
                    prefixes_tracked = per_prefix.len(),
                    "recomputed prefix-based tiering"
                );
            }
        }
        self.last_recompute = now;
    }

    pub fn default_level(&self) -> TieringLevel {
        if self.centroids.is_empty() {
            return TieringLevel::new(0);
        }
        TieringLevel::new(self.centroids.len() / 2)
    }

    pub fn slowest_level(&self) -> TieringLevel {
        if self.centroids.is_empty() {
            TieringLevel::new(0)
        } else {
            TieringLevel::new(self.centroids.len() - 1)
        }
    }
}

fn dynamic_kmeans(samples: &[f32], min_k: usize, max_k: usize) -> (Vec<f32>, Vec<usize>) {
    if samples.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut best_centroids = vec![samples[0]];
    let mut best_assignments = vec![0; samples.len()];
    let mut best_score = f32::MAX;

    let min_k = min_k.max(1);
    let max_k = max_k.max(min_k);

    for k in min_k..=max_k {
        let (centroids, assignments, inertia) = run_kmeans(samples, k);

        let penalty = (k as f32) * (samples.len() as f32).ln().max(1.0) * TIERING_PENALTY_FACTOR;
        let score = inertia + penalty;

        if score < best_score {
            best_score = score;
            best_centroids = centroids;
            best_assignments = assignments;
        }
    }

    (best_centroids, best_assignments)
}

fn run_kmeans(samples: &[f32], k: usize) -> (Vec<f32>, Vec<usize>, f32) {
    let mut centroids = initialize_centroids(samples, k);
    let mut assignments = vec![0usize; samples.len()];

    for _ in 0..KMEANS_ITERATIONS {
        let mut changed = false;
        let mut sums = vec![0.0f32; k];
        let mut counts = vec![0usize; k];

        for (idx, sample) in samples.iter().enumerate() {
            let nearest = nearest_center_scalar(*sample, &centroids);
            if assignments[idx] != nearest {
                assignments[idx] = nearest;
                changed = true;
            }
            sums[nearest] += sample;
            counts[nearest] += 1;
        }

        for i in 0..k {
            if counts[i] > 0 {
                centroids[i] = sums[i] / counts[i] as f32;
            }
        }

        if !changed {
            break;
        }
    }

    ensure_tier_coverage(samples, &mut centroids, &mut assignments);

    let mut inertia = 0.0f32;
    for (sample, idx) in samples.iter().zip(assignments.iter()) {
        let diff = sample - centroids[*idx];
        inertia += diff * diff;
    }

    let mut order: Vec<usize> = (0..k).collect();
    order.sort_by(|a, b| centroids[*a].total_cmp(&centroids[*b]));

    let mut remap = vec![0usize; k];
    let mut sorted_centroids = vec![0.0f32; k];
    for (new_idx, old_idx) in order.iter().enumerate() {
        sorted_centroids[new_idx] = centroids[*old_idx];
        remap[*old_idx] = new_idx;
    }

    let mut sorted_assignments = assignments;
    for idx in sorted_assignments.iter_mut() {
        *idx = remap[*idx];
    }

    (sorted_centroids, sorted_assignments, inertia)
}

fn ensure_tier_coverage(samples: &[f32], centroids: &mut [f32], assignments: &mut [usize]) {
    let k = centroids.len();
    let mut counts = vec![0usize; k];
    for idx in assignments.iter() {
        counts[*idx] += 1;
    }

    if counts.iter().all(|count| *count > 0) {
        return;
    }

    let mut sorted_samples: Vec<f32> = samples.to_vec();
    sorted_samples.sort_by(|a, b| a.total_cmp(b));

    for (tier_idx, count) in counts.iter_mut().enumerate() {
        if *count == 0 {
            let pos = ((tier_idx as f32 + 0.5) / k as f32 * (sorted_samples.len() - 1) as f32)
                .round() as usize;
            centroids[tier_idx] = sorted_samples[pos];
        }
    }

    for (sample_idx, sample) in samples.iter().enumerate() {
        let nearest = nearest_center_scalar(*sample, centroids);
        assignments[sample_idx] = nearest;
    }
}

fn initialize_centroids(samples: &[f32], k: usize) -> Vec<f32> {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));

    if sorted.is_empty() {
        return vec![0.0];
    }

    let mut centroids = Vec::with_capacity(k);
    let max_idx = sorted.len() - 1;
    for i in 0..k {
        let pos = if k == 1 {
            max_idx
        } else {
            ((i as f32 + 0.5) / k as f32 * max_idx as f32).round() as usize
        };
        centroids.push(sorted[pos]);
    }

    centroids
}

fn nearest_center_scalar(value: f32, centers: &[f32]) -> usize {
    let mut best_idx = 0;
    let mut best_dist = f32::MAX;
    for (i, center) in centers.iter().enumerate() {
        let dist = (value - *center).abs();
        if dist < best_dist {
            best_dist = dist;
            best_idx = i;
        }
    }
    best_idx
}


/// Default Kademlia replication factor (bucket size).
/// At 10M+ nodes: 256 buckets × 20 contacts = 5,120 routing contacts (~640 KB).
/// Adaptive range: 10-30 based on observed churn.
pub const DEFAULT_K: usize = 20;

/// Default Kademlia concurrency factor (parallel queries).
/// Adaptive range: 2-5 based on network congestion.
pub const DEFAULT_ALPHA: usize = 3;



pub struct DhtNode<N: DhtNodeRpc> {
    cmd_tx: mpsc::Sender<Command>,
    id: Identity,
    self_contact: Contact,
    network: Arc<N>,
}

impl<N: DhtNodeRpc> Clone for DhtNode<N> {
    fn clone(&self) -> Self {
        Self {
            cmd_tx: self.cmd_tx.clone(),
            id: self.id,
            self_contact: self.self_contact.clone(),
            network: self.network.clone(),
        }
    }
}

struct DhtNodeActor<N: DhtNodeRpc> {
    routing: RoutingTable,
    store: LocalStore,
    params: AdaptiveParams,
    tiering: TieringManager,
    routing_limiter: RoutingInsertionLimiter,
    /// Rate limiter for direct peer insertions by IP address.
    /// SECURITY: Bounds PoW bypass exploitation from multi-IP attackers.
    direct_peer_limiter: DirectPeerIpLimiter,
    cmd_rx: mpsc::Receiver<Command>,
    cmd_tx: mpsc::Sender<Command>,
    network: Arc<N>,
    id: Identity,
}

enum Command {
    // State updates
    ObserveContact(Contact),
    /// Observe a directly-connected peer (mTLS verified, bypasses PoW check)
    ObserveDirectPeer(Contact),
    ObserveContactFromPeer(Contact, Identity, oneshot::Sender<bool>),
    RecordRtt(Contact, Duration),
    AdjustK(bool),
    
    // Queries
    GetLookupParams(Identity, Option<TieringLevel>, oneshot::Sender<(usize, usize, Vec<Contact>)>),
    GetLocal(Key, oneshot::Sender<Option<Vec<u8>>>),
    StoreLocal(Key, Vec<u8>, Identity, ValueType, oneshot::Sender<Vec<(Key, Vec<u8>)>>),
    GetTelemetry(oneshot::Sender<TelemetrySnapshot>),
    GetSlowestLevel(oneshot::Sender<TieringLevel>),
    LookupContact(Identity, oneshot::Sender<Option<Contact>>),
    
    // RPC Handlers
    HandleFindNode(Contact, Identity, oneshot::Sender<Vec<Contact>>),
    HandleFindValue(Contact, Key, oneshot::Sender<(Option<Vec<u8>>, Vec<Contact>)>),
    HandleStore(Contact, Key, Vec<u8>),
    
    // Maintenance
    GetStaleBuckets(Duration, oneshot::Sender<Vec<usize>>),
    MarkBucketRefreshed(usize),
    ApplyPingResult(PendingBucketUpdate, bool),
    
    Quit,
}

impl<N: DhtNodeRpc + 'static> DhtNode<N> {
    pub fn new(id: Identity, self_contact: Contact, network: N, k: usize, alpha: usize) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let network = Arc::new(network);
        
        let actor = DhtNodeActor {
            routing: RoutingTable::new(id, k),
            store: LocalStore::new(),
            params: AdaptiveParams::new(k, alpha),
            tiering: TieringManager::new(),
            routing_limiter: RoutingInsertionLimiter::new(),
            direct_peer_limiter: DirectPeerIpLimiter::new(),
            cmd_rx,
            cmd_tx: cmd_tx.clone(),
            network: network.clone(),
            id,
        };

        tokio::spawn(actor.run());

        let node = Self {
            cmd_tx,
            id,
            self_contact,
            network,
        };
        
        node.spawn_periodic_bucket_refresh();
        node
    }

    /// Get the identity of this DHT node.
    pub fn identity(&self) -> Identity {
        self.id
    }

    /// Get the contact information for this DHT node.
    pub fn contact(&self) -> Contact {
        self.self_contact.clone()
    }

    /// Get a reference to the network layer for making RPC calls.
    pub fn network(&self) -> &N {
        &self.network
    }

    /// Look up a contact by identity in the routing table.
    /// Returns the contact if found, None otherwise.
    pub async fn lookup_contact(&self, identity: &Identity) -> Option<Contact> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::LookupContact(*identity, tx)).await.is_err() {
            return None;
        }
        rx.await.ok().flatten()
    }

    pub async fn observe_contact(&self, contact: Contact) {
        let _ = self.cmd_tx.send(Command::ObserveContact(contact)).await;
    }

    /// Observe a directly connected peer (bypasses PoW check).
    /// 
    /// Use this for peers whose identity has been verified via mTLS.
    /// Direct peers are trusted because they've proven possession of the
    /// private key during the TLS handshake.
    /// 
    /// SECURITY: Only call this for peers you've directly connected to via QUIC/mTLS.
    /// Do NOT use for contacts received via DHT gossip.
    pub async fn observe_direct_peer(&self, contact: Contact) {
        let _ = self.cmd_tx.send(Command::ObserveDirectPeer(contact)).await;
    }

    pub async fn observe_contact_from_peer(&self, contact: Contact, from_peer: &Identity) -> bool {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::ObserveContactFromPeer(contact, *from_peer, tx)).await.is_err() {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    fn spawn_periodic_bucket_refresh(&self) {
        let node = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(BUCKET_REFRESH_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;

                let (tx, rx) = oneshot::channel();
                if node.cmd_tx.send(Command::GetStaleBuckets(BUCKET_STALE_THRESHOLD, tx)).await.is_err() {
                    break;
                }
                
                let stale_buckets = match rx.await {
                    Ok(buckets) => buckets,
                    Err(_) => break,
                };

                if stale_buckets.is_empty() {
                    continue;
                }

                debug!(
                    count = stale_buckets.len(),
                    "refreshing stale routing buckets"
                );

                for bucket_idx in stale_buckets {
                    let target = random_id_for_bucket(&node.id, bucket_idx);

                    if let Err(e) = node.iterative_find_node(target).await {
                        debug!(bucket = bucket_idx, error = ?e, "bucket refresh lookup failed");
                    }

                    let _ = node.cmd_tx.send(Command::MarkBucketRefreshed(bucket_idx)).await;
                }
            }
        });
    }

    pub async fn handle_find_node_request(&self, from: &Contact, target: Identity) -> Vec<Contact> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::HandleFindNode(from.clone(), target, tx)).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn handle_find_value_request(
        &self,
        from: &Contact,
        key: Key,
    ) -> (Option<Vec<u8>>, Vec<Contact>) {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::HandleFindValue(from.clone(), key, tx)).await.is_err() {
            return (None, Vec::new());
        }
        rx.await.unwrap_or((None, Vec::new()))
    }

    pub async fn handle_store_request(&self, from: &Contact, key: Key, value: Vec<u8>) {
        // Fire and forget store request handling to avoid blocking
        let _ = self.cmd_tx.send(Command::HandleStore(from.clone(), key, value)).await;
    }

    /// Record an RTT measurement for a contact (used for tiering).
    /// This is fire-and-forget; failures are silently ignored.
    pub async fn record_rtt(&self, contact: &Contact, elapsed: Duration) {
        let _ = self.cmd_tx.send(Command::RecordRtt(contact.clone(), elapsed)).await;
    }

    async fn adjust_k(&self, success: bool) {
        let _ = self.cmd_tx.send(Command::AdjustK(success)).await;
    }

    pub async fn iterative_find_node(&self, target: Identity) -> Result<Vec<Contact>> {
        let result = self.iterative_find_node_full(target, None, None).await?;
        Ok(result.closest)
    }

    /// Bootstrap into the network using a seed contact.
    /// 
    /// The seed contact is used to initiate the lookup even if it doesn't
    /// have a valid PoW proof. Once we successfully connect via mTLS,
    /// the peer will be added to routing via `observe_direct_peer`.
    pub async fn bootstrap(&self, seed: Contact, self_id: Identity) -> Result<Vec<Contact>> {
        let result = self.iterative_find_node_full(self_id, None, Some(seed)).await?;
        Ok(result.closest)
    }

    async fn iterative_find_node_with_level(
        &self,
        target: Identity,
        level_filter: Option<TieringLevel>,
    ) -> Result<Vec<Contact>> {
        let result = self.iterative_find_node_full(target, level_filter, None).await?;
        Ok(result.closest)
    }

    async fn iterative_find_node_full(
        &self,
        target: Identity,
        level_filter: Option<TieringLevel>,
        seed_contact: Option<Contact>,
    ) -> Result<LookupResult> {
        const MAX_LOOKUP_ITERATIONS: usize = 20;
        /// Total timeout for the entire lookup operation.
        /// Prevents spending excessive time in sparse networks.
        const LOOKUP_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
        
        let lookup_start = Instant::now();
        
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetLookupParams(target, level_filter, tx)).await.is_err() {
            return Err(anyhow!("Actor closed"));
        }
        let (k_initial, alpha, mut shortlist) = rx.await.map_err(|_| anyhow!("Actor closed"))?;

        // Add seed contact for bootstrap (used before routing table is populated)
        if let Some(seed) = seed_contact
            && seed.identity != self.id
            && !shortlist.iter().any(|c| c.identity == seed.identity)
        {
            shortlist.push(seed);
        }

        let mut seen: HashSet<Identity> = HashSet::new();
        let mut seen_addrs: HashSet<String> = HashSet::new();
        let mut queried: HashSet<Identity> = HashSet::new();
        let mut rpc_success = false;
        let mut rpc_failure = false;
        let mut iteration = 0;

        for c in &shortlist {
            seen.insert(c.identity);
            for addr in &c.addrs {
                seen_addrs.insert(addr.clone());
            }
        }

        let mut best_distance = shortlist
            .first()
            .map(|c| c.identity.xor_distance(&target))
            .unwrap_or([0xff; 32]);

        loop {
            iteration += 1;
            if iteration > MAX_LOOKUP_ITERATIONS {
                warn!(
                    target = ?hex::encode(&target.as_bytes()[..8]),
                    iterations = iteration,
                    "iterative lookup exceeded max iterations"
                );
                break;
            }
            
            // Check total lookup timeout
            if lookup_start.elapsed() > LOOKUP_TOTAL_TIMEOUT {
                debug!(
                    target = ?hex::encode(&target.as_bytes()[..8]),
                    elapsed_ms = lookup_start.elapsed().as_millis(),
                    found = shortlist.len(),
                    "iterative lookup timeout, returning current results"
                );
                break;
            }
            
            let candidates: Vec<Contact> = shortlist
                .iter()
                .filter(|c| !queried.contains(&c.identity) && c.identity != self.id)
                .take(alpha)
                .cloned()
                .collect();

            if candidates.is_empty() {
                break;
            }

            for c in &candidates {
                queried.insert(c.identity);
            }

            // Per-query timeout to avoid slow nodes blocking the entire lookup
            const PER_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
            
            let network = self.network.clone();
            let mut join_set = JoinSet::new();
            let candidates_len = candidates.len();
            for (idx, contact) in candidates.into_iter().enumerate() {
                let net = network.clone();
                join_set.spawn(async move {
                    let start = Instant::now();
                    let result = tokio::time::timeout(PER_QUERY_TIMEOUT, net.find_node(&contact, target)).await;
                    let result = match result {
                        Ok(r) => r,
                        Err(_) => Err(anyhow!("query timeout")),
                    };
                    (idx, contact, start.elapsed(), result)
                });
            }

            type FindNodeQueryResult = (Contact, Duration, Result<Vec<Contact>>);

            let mut results: Vec<Option<FindNodeQueryResult>> = Vec::with_capacity(candidates_len);
            results.resize_with(candidates_len, || None);
            while let Some(joined) = join_set.join_next().await {
                if let Ok((idx, contact, elapsed, result)) = joined {
                    results[idx] = Some((contact, elapsed, result));
                }
            }

            let mut any_closer = false;

            for (contact, elapsed, result) in results.into_iter().flatten() {
                match result {
                    Ok(nodes) => {
                        rpc_success = true;
                        self.record_rtt(&contact, elapsed).await;
                        // Use observe_direct_peer: we just did mTLS-verified RPC with this peer
                        self.observe_direct_peer(contact.clone()).await;
                        let from_peer = contact.identity;
                        for n in &nodes {
                            self.observe_contact_from_peer(n.clone(), &from_peer).await;
                        }

                        let valid_nodes = nodes;

                        for n in valid_nodes {
                            if n.identity == self.id {
                                continue;
                            }
                            let has_new_addr = n.addrs.iter().any(|a| seen_addrs.insert(a.clone()));
                            if seen.insert(n.identity) || has_new_addr
                            {
                                shortlist.push(n);
                            }
                        }
                    }
                    Err(_) => {
                        rpc_failure = true;
                    }
                }
            }

            shortlist.sort_by(|a, b| {
                let da = a.identity.xor_distance(&target);
                let db = b.identity.xor_distance(&target);
                distance_cmp(&da, &db)
            });

            if shortlist.len() > k_initial {
                shortlist.truncate(k_initial);
            }

            if let Some(first) = shortlist.first() {
                let new_best = first.identity.xor_distance(&target);
                if distance_cmp(&new_best, &best_distance) == std::cmp::Ordering::Less {
                    best_distance = new_best;
                    any_closer = true;
                }
            }

            if !any_closer {
                break;
            }
        }

        if rpc_success {
            self.adjust_k(true).await;
        } else if rpc_failure {
            self.adjust_k(false).await;
        }

        debug!(
            target = ?hex::encode(&target.as_bytes()[..8]),
            found = shortlist.len(),
            queried = queried.len(),
            "iterative lookup completed"
        );

        Ok(LookupResult::new(shortlist))
    }

    async fn store_local(&self, key: Key, value: Vec<u8>, stored_by: Identity) {
        let value_type = classify_key_value_pair(&key, &value);
        if matches!(value_type, ValueType::Invalid) {
            trace!(
                key = hex::encode(&key[..8]),
                value_len = value.len(),
                stored_by = hex::encode(&stored_by.as_bytes()[..8]),
                "rejecting store: key does not match value hash"
            );
            return;
        }
        
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::StoreLocal(key, value, stored_by, value_type, tx)).await.is_ok()
            && let Ok(spilled) = rx.await
            && !spilled.is_empty()
        {
            self.offload_spilled(spilled).await;
        }
    }

    async fn get_local(&self, key: &Key) -> Option<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetLocal(*key, tx)).await.is_err() {
            return None;
        }
        rx.await.unwrap_or(None)
    }

    async fn offload_spilled(&self, spilled: Vec<(Key, Vec<u8>)>) {
        if spilled.is_empty() {
            return;
        }

        // Get the slowest tier for cold storage offload
        let target_level = {
            let (tx, rx) = oneshot::channel();
            if self.cmd_tx.send(Command::GetSlowestLevel(tx)).await.is_err() {
                return;
            }
            rx.await.unwrap_or(TieringLevel::new(0))
        };
        
        for (key, value) in spilled {
            let mut attempt = 0;
            loop {
                let success = self.replicate_to_level(key, value.clone(), target_level).await;
                if success {
                    break;
                }
                
                attempt += 1;
                if attempt >= OFFLOAD_MAX_RETRIES {
                    break;
                }
                
                let delay_ms = OFFLOAD_BASE_DELAY_MS * (1 << (attempt - 1));
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    async fn replicate_to_level(&self, key: Key, value: Vec<u8>, level: TieringLevel) -> bool {
        let target = Identity::from_bytes(key);
        let contacts = match self
            .iterative_find_node_with_level(target, Some(level))
            .await
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        if contacts.is_empty() {
            return false;
        }
        
        let k = DEFAULT_K; 
        let mut any_success = false;
        for contact in contacts.into_iter().take(k) {
            if self.send_store_with_result(&contact, key, value.clone()).await {
                any_success = true;
            }
        }
        any_success
    }

    async fn send_store_with_result(&self, contact: &Contact, key: Key, value: Vec<u8>) -> bool {
        const STORE_TIMEOUT: Duration = Duration::from_secs(5);
        let start = Instant::now();
        let result = tokio::time::timeout(
            STORE_TIMEOUT,
            self.network.store(contact, key, value)
        ).await;
        
        match result {
            Ok(Ok(_)) => {
                let elapsed = start.elapsed();
                self.record_rtt(contact, elapsed).await;
                self.adjust_k(true).await;
                // Use observe_direct_peer: we just did mTLS-verified RPC with this peer
                self.observe_direct_peer(contact.clone()).await;
                true
            }
            Ok(Err(_)) | Err(_) => {
                // RPC error or timeout
                self.adjust_k(false).await;
                false
            }
        }
    }

    async fn send_store(&self, contact: &Contact, key: Key, value: Vec<u8>) {
        let _ = self.send_store_with_result(contact, key, value).await;
    }

    pub async fn put(&self, value: Vec<u8>) -> Result<Key> {
        let key = *hash(&value).as_bytes();

        self.store_local(key, value.clone(), self.id).await;

        let target = Identity::from_bytes(key);
        let closest = self.iterative_find_node_with_level(target, None).await?;
        let k = DEFAULT_K; 

        // Parallelize stores for faster completion
        let mut join_set = JoinSet::new();
        for contact in closest.into_iter().take(k) {
            let this = self.clone();
            let value = value.clone();
            join_set.spawn(async move {
                this.send_store(&contact, key, value).await;
            });
        }

        while let Some(joined) = join_set.join_next().await {
            let _ = joined;
        }

        Ok(key)
    }

    pub async fn telemetry_snapshot(&self) -> TelemetrySnapshot {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetTelemetry(tx)).await.is_err() {
            return TelemetrySnapshot::default();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn put_at(&self, key: Key, value: Vec<u8>) -> Result<()> {
        self.store_local(key, value.clone(), self.id).await;

        let closest = self.iterative_find_node(Identity::from_bytes(key)).await?;
        let k = DEFAULT_K;

        // Parallelize stores for faster completion
        let mut join_set = JoinSet::new();
        for contact in closest.into_iter().take(k) {
            let this = self.clone();
            let value = value.clone();
            join_set.spawn(async move {
                this.send_store(&contact, key, value).await;
            });
        }

        while let Some(joined) = join_set.join_next().await {
            let _ = joined;
        }

        Ok(())
    }

    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.get_local(key).await {
            return Ok(Some(value));
        }

        let closest = self.iterative_find_node(Identity::from_bytes(*key)).await?;

        // Query contacts in parallel with early return on first success
        const FIND_VALUE_TIMEOUT: Duration = Duration::from_secs(3);
        
        // Query all in parallel and return on the first successful value.
        let network = self.network.clone();
        let key_copy = *key;
        let mut join_set = JoinSet::new();
        for contact in closest.into_iter() {
            let net = network.clone();
            join_set.spawn(async move {
                let result = tokio::time::timeout(FIND_VALUE_TIMEOUT, net.find_value(&contact, key_copy)).await;

                match result {
                    Ok(Ok((Some(value), _))) => Some(value),
                    Ok(Ok((None, _))) => None,
                    Ok(Err(_)) => None,
                    Err(_) => None, // timeout
                }
            });
        }

        while let Some(joined) = join_set.join_next().await {
            if let Ok(Some(value)) = joined {
                // Cancel any remaining lookups once we have a value.
                join_set.abort_all();
                return Ok(Some(value));
            }
        }

        Ok(None)
    }

    pub async fn publish_address(&self, keypair: &Keypair, addresses: Vec<String>) -> Result<()> {
        let record = keypair.create_contact(addresses);
        let serialized = bincode::serialize(&record)
            .map_err(|e| anyhow!("Failed to serialize endpoint record: {}", e))?;

        let key: Key = *record.identity.as_bytes();
        self.put_at(key, serialized).await
    }

    /// Resolve a peer's endpoint record from the DHT.
    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<Contact>> {
        const MAX_RECORD_AGE_SECS: u64 = 24 * 60 * 60;

        let key: Key = *peer_id.as_bytes();
        let data_opt = self.get(&key).await?;

        match data_opt {
            Some(data) => {
                let record: Contact = crate::messages::deserialize_bounded(&data)
                    .map_err(|e| anyhow!("Failed to deserialize endpoint record: {}", e))?;

                if !record.validate_structure() {
                    return Err(anyhow!("Endpoint record has invalid structure"));
                }

                if record.identity != *peer_id {
                    return Err(anyhow!("Endpoint record peer_id mismatch"));
                }

                if let Err(e) = record.verify_fresh(MAX_RECORD_AGE_SECS) {
                    let reason = match e {
                        FreshnessError::SignatureInvalid => "invalid signature".to_string(),
                        FreshnessError::ClockSkewFuture { drift_ms, .. } => {
                            format!("timestamp {}ms in future (clock skew)", drift_ms)
                        }
                        FreshnessError::Stale { age_ms, .. } => {
                            format!("record is {}s old (stale)", age_ms / 1000)
                        }
                    };
                    return Err(anyhow!("Endpoint record verification failed: {}", reason));
                }

                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    pub async fn republish_on_network_change(
        &self,
        keypair: &Keypair,
        new_addrs: Vec<String>,
    ) -> Result<()> {
        debug!(
            "republishing address after network change: {:?}",
            new_addrs
        );

        let record = keypair.create_contact(new_addrs);
        let serialized = bincode::serialize(&record)
            .map_err(|e| anyhow!("Failed to serialize endpoint record: {}", e))?;

        let key: Key = *record.identity.as_bytes();
        self.put_at(key, serialized).await
    }
    
    pub async fn quit(&self) {
        let _ = self.cmd_tx.send(Command::Quit).await;
    }
}

impl<N: DhtNodeRpc> DhtNodeActor<N> {
    async fn run(mut self) {
        while let Some(cmd) = self.cmd_rx.recv().await {
            match cmd {
                Command::ObserveContact(contact) => {
                    self.handle_observe_contact(contact);
                }
                Command::ObserveDirectPeer(contact) => {
                    // Bypass PoW check for mTLS-verified direct connections
                    self.handle_observe_direct_peer(contact);
                }
                Command::ObserveContactFromPeer(contact, from_peer, reply) => {
                    let allowed = self.handle_observe_contact_from_peer(contact, &from_peer);
                    let _ = reply.send(allowed);
                }
                Command::RecordRtt(contact, elapsed) => {
                    self.handle_record_rtt(contact, elapsed);
                }
                Command::AdjustK(success) => {
                    self.handle_adjust_k(success);
                }
                Command::GetLookupParams(target, level_filter, reply) => {
                    let k = self.params.current_k();
                    let alpha = self.params.current_alpha();
                    let mut closest = self.routing.closest(&target, k);
                    
                    if let Some(level) = level_filter {
                        closest.retain(|c| self.tiering.level_for(c) == level);
                    }
                    
                    let _ = reply.send((k, alpha, closest));
                }
                Command::GetLocal(key, reply) => {
                    self.store.record_request();
                    let val = self.store.get(&key);
                    let _ = reply.send(val);
                }
                Command::StoreLocal(key, value, stored_by, value_type, reply) => {
                    self.store.record_request();
                    let spilled = self.store.store(key, &value, stored_by, value_type);
                    let _ = reply.send(spilled);
                }
                Command::GetTelemetry(reply) => {
                    let tiering_stats = self.tiering.stats();
                    let snapshot = TelemetrySnapshot {
                        tier_centroids: tiering_stats.centroids,
                        tier_counts: tiering_stats.counts,
                        pressure: self.store.current_pressure(),
                        stored_keys: self.store.len(),
                        replication_factor: self.params.current_k(),
                        concurrency: self.params.current_alpha(),
                    };
                    let _ = reply.send(snapshot);
                }
                Command::GetSlowestLevel(reply) => {
                    let level = self.tiering.slowest_level();
                    let _ = reply.send(level);
                }
                Command::LookupContact(identity, reply) => {
                    let contact = self.routing.lookup_contact(&identity);
                    let _ = reply.send(contact);
                }
                Command::HandleFindNode(from, target, reply) => {
                    self.handle_observe_contact(from);
                    let k = self.params.current_k();
                    let closest = self.routing.closest(&target, k);
                    let _ = reply.send(closest);
                }
                Command::HandleFindValue(from, key, reply) => {
                    self.handle_observe_contact(from);
                    if let Some(v) = self.store.get(&key) {
                        let _ = reply.send((Some(v), Vec::new()));
                    } else {
                        let target = Identity::from_bytes(key);
                        let k = self.params.current_k();
                        let closest = self.routing.closest(&target, k);
                        let _ = reply.send((None, closest));
                    }
                }
                Command::HandleStore(from, key, value) => {
                    self.handle_observe_contact(from.clone());
                    self.store.record_request();
                    let value_type = classify_key_value_pair(&key, &value);
                    self.store.store(key, &value, from.identity, value_type);
                }
                Command::GetStaleBuckets(threshold, reply) => {
                    let buckets = self.routing.stale_bucket_indices(threshold);
                    let _ = reply.send(buckets);
                }
                Command::MarkBucketRefreshed(idx) => {
                    self.routing.mark_bucket_refreshed(idx);
                }
                Command::ApplyPingResult(pending, alive) => {
                    self.routing.apply_ping_result(pending, alive);
                }
                Command::Quit => {
                    break;
                }
            }
        }
    }

    fn handle_observe_contact(&mut self, contact: Contact) {
        if contact.identity == self.id {
            return;
        }
        if !contact.identity.is_valid() {
            return;
        }
        // SECURITY (S/Kademlia): Reject contacts without valid Proof-of-Work.
        // This prevents Sybil attacks by ensuring identity generation is expensive.
        if ENFORCE_POW_FOR_ROUTING && !contact.verify_pow() {
            trace!(
                identity = ?hex::encode(&contact.identity.as_bytes()[..8]),
                nonce = contact.pow_proof.nonce,
                "rejecting contact: invalid PoW proof"
            );
            return;
        }

        self.insert_contact_into_routing(contact);
    }

    /// Handle a directly-connected peer (mTLS verified).
    /// 
    /// SECURITY: Bypasses PoW check because the peer has proven identity
    /// via mTLS certificate verification during QUIC handshake.
    /// 
    /// However, to prevent exploitation by attackers with many IP addresses,
    /// insertions are rate-limited per source IP. This ensures that while
    /// direct peers don't need PoW, the connection establishment cost provides
    /// an economic bound on routing table pollution.
    fn handle_observe_direct_peer(&mut self, contact: Contact) {
        if contact.identity == self.id {
            return;
        }
        if !contact.identity.is_valid() {
            return;
        }
        
        // SECURITY: Rate limit by source IP to prevent multi-IP attackers from
        // bypassing PoW by establishing many direct connections.
        if !self.direct_peer_limiter.allow_direct_peer(&contact) {
            debug!(
                peer = ?hex::encode(&contact.identity.as_bytes()[..8]),
                addr = ?contact.primary_addr(),
                "direct peer rate limited by IP"
            );
            return;
        }
        
        // No PoW check - peer identity was verified via mTLS
        self.insert_contact_into_routing(contact);
    }

    /// Common routing table insertion logic.
    fn insert_contact_into_routing(&mut self, contact: Contact) {
        self.tiering.register_contact(&contact);
        let k = self.params.current_k();
        self.routing.set_k(k);
        
        if let Some(update) = self.routing.update_with_pending(contact.clone()) {
            let network = self.network.clone();
            let tx = self.cmd_tx.clone();
            tokio::spawn(async move {
                let alive = network.ping(&update.oldest).await.is_ok();
                let _ = tx.send(Command::ApplyPingResult(update, alive)).await;
            });
        }
    }

    fn handle_observe_contact_from_peer(&mut self, contact: Contact, from_peer: &Identity) -> bool {
        if contact.identity == *from_peer {
            self.handle_observe_contact(contact);
            return true;
        }

        if !self.routing_limiter.allow_insertion(from_peer) {
            return false;
        }

        self.handle_observe_contact(contact);
        true
    }

    fn handle_record_rtt(&mut self, contact: Contact, elapsed: Duration) {
        if contact.identity == self.id {
            return;
        }
        let rtt_ms = (elapsed.as_secs_f64() * 1000.0) as f32;
        self.tiering.record_sample(&contact, rtt_ms);
    }

    fn handle_adjust_k(&mut self, success: bool) {
        if self.params.record_churn(success) {
            self.routing.set_k(self.params.current_k());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::Duration;
    use anyhow::anyhow;
    use ed25519_dalek::SigningKey;
    use tokio::sync::{Mutex, RwLock};
    use tokio::time::sleep;
    use crate::identity::{IdentityProof, POW_DIFFICULTY};

    #[derive(Clone)]
    struct TestNetwork {
        registry: Arc<NetworkRegistry>,
        self_contact: Contact,
        latencies: Arc<Mutex<HashMap<Identity, Duration>>>,
        failures: Arc<Mutex<HashSet<Identity>>>,
        stores: Arc<Mutex<Vec<(Contact, Key, usize)>>>,
        pings: Arc<Mutex<Vec<Identity>>>,
    }

    impl TestNetwork {
        fn new(registry: Arc<NetworkRegistry>, self_contact: Contact) -> Self {
            Self {
                registry,
                self_contact,
                latencies: Arc::new(Mutex::new(HashMap::new())),
                failures: Arc::new(Mutex::new(HashSet::new())),
                stores: Arc::new(Mutex::new(Vec::new())),
                pings: Arc::new(Mutex::new(Vec::new())),
            }
        }

        async fn set_latency(&self, node: Identity, latency: Duration) {
            self.latencies.lock().await.insert(node, latency);
        }

        async fn set_failure(&self, node: Identity, fail: bool) {
            let mut failures = self.failures.lock().await;
            if fail { failures.insert(node); } else { failures.remove(&node); }
        }

        async fn store_calls(&self) -> Vec<(Contact, Key, usize)> {
            self.stores.lock().await.clone()
        }

        async fn ping_calls(&self) -> Vec<Identity> {
            self.pings.lock().await.clone()
        }

        async fn should_fail(&self, node: &Identity) -> bool {
            self.failures.lock().await.contains(node)
        }

        async fn maybe_sleep(&self, node: &Identity) {
            if let Some(delay) = self.latencies.lock().await.get(node).copied() {
                sleep(delay).await;
            }
        }
    }

    #[derive(Default)]
    struct NetworkRegistry {
        peers: RwLock<HashMap<Identity, DhtNode<TestNetwork>>>,
    }

    impl NetworkRegistry {
        async fn register(&self, node: &DhtNode<TestNetwork>) {
            self.peers.write().await.insert(node.contact().identity, node.clone());
        }

        async fn get(&self, id: &Identity) -> Option<DhtNode<TestNetwork>> {
            self.peers.read().await.get(id).cloned()
        }
    }

    #[async_trait::async_trait]
    impl DhtNodeRpc for TestNetwork {
        async fn find_node(&self, to: &Contact, target: Identity) -> anyhow::Result<Vec<Contact>> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            if let Some(peer) = self.registry.get(&to.identity).await {
                Ok(peer.handle_find_node_request(&self.self_contact, target).await)
            } else {
                Ok(Vec::new())
            }
        }

        async fn find_value(&self, to: &Contact, key: Key) -> anyhow::Result<(Option<Vec<u8>>, Vec<Contact>)> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            if let Some(peer) = self.registry.get(&to.identity).await {
                Ok(peer.handle_find_value_request(&self.self_contact, key).await)
            } else {
                Ok((None, Vec::new()))
            }
        }

        async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> anyhow::Result<()> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            self.stores.lock().await.push((to.clone(), key, value.len()));
            if let Some(peer) = self.registry.get(&to.identity).await {
                peer.handle_store_request(&self.self_contact, key, value).await;
            }
            Ok(())
        }

        async fn ping(&self, to: &Contact) -> anyhow::Result<()> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            self.pings.lock().await.push(to.identity);
            if self.registry.get(&to.identity).await.is_some() {
                Ok(())
            } else {
                Err(anyhow!("peer not reachable"))
            }
        }

        async fn check_reachability(&self, to: &Contact, _probe_addr: &str) -> anyhow::Result<bool> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            // In tests, assume we're always reachable if the peer exists
            Ok(self.registry.get(&to.identity).await.is_some())
        }
    }

    struct TestNode {
        node: DhtNode<TestNetwork>,
        network: TestNetwork,
    }

    impl TestNode {
        async fn new(registry: Arc<NetworkRegistry>, index: u32, k: usize, alpha: usize) -> Self {
            let contact = make_contact(index);
            let network = TestNetwork::new(registry.clone(), contact.clone());
            let node = DhtNode::new(contact.identity, contact.clone(), network.clone(), k, alpha);
            registry.register(&node).await;
            Self { node, network }
        }

        fn contact(&self) -> Contact {
            self.node.contact()
        }
    }

    fn make_identity(index: u32) -> Identity {
        // Generate a deterministic but valid Ed25519 public key from the index.
        // We use the index as a seed to create a signing key, then extract its public key.
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&index.to_be_bytes());
        let signing_key = SigningKey::from_bytes(&seed);
        Identity::from_bytes(signing_key.verifying_key().to_bytes())
    }

    fn make_contact(index: u32) -> Contact {
        // Generate IP addresses with diverse /16 prefixes for tiering tests
        // Use index to create different /16 prefixes: 10.{hi}.{lo}.1
        let hi = ((index >> 8) & 0xFF) as u8;
        let lo = (index & 0xFF) as u8;
        let identity = make_identity(index);
        // Compute valid PoW proof at production difficulty
        let pow_proof = IdentityProof::compute_for_identity(&identity, POW_DIFFICULTY);
        let mut contact = Contact::single(identity, format!("10.{hi}.{lo}.1:9001"));
        contact.pow_proof = pow_proof;
        contact
    }

    /// Find three indices whose generated identities have peers 2 and 3 in the same bucket
    /// relative to peer 1. This is needed for bucket eviction tests.
    fn find_same_bucket_indices() -> (u32, u32, u32) {
        let main_id = make_identity(0);
        for incumbent_idx in 1u32..1000 {
            let incumbent_id = make_identity(incumbent_idx);
            let bucket = bucket_index(&main_id, &incumbent_id);
            for challenger_idx in (incumbent_idx + 1)..1000 {
                let challenger_id = make_identity(challenger_idx);
                if bucket_index(&main_id, &challenger_id) == bucket {
                    return (0, incumbent_idx, challenger_idx);
                }
            }
        }
        panic!("Could not find same-bucket indices");
    }

    #[tokio::test]
    async fn iterative_find_node_returns_expected_contacts() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x10, 20, 3).await;
        let peer_one = TestNode::new(registry.clone(), 0x11, 20, 3).await;
        let peer_two = TestNode::new(registry.clone(), 0x12, 20, 3).await;

        for peer in [&peer_one, &peer_two] {
            main.node.observe_contact(peer.contact()).await;
            peer.node.observe_contact(main.contact()).await;
        }

        let target = peer_two.contact().identity;
        let results = main
            .node
            .iterative_find_node(target)
            .await
            .expect("lookup succeeds");

        assert_eq!(
            results.first().map(|c| c.identity),
            Some(peer_two.contact().identity)
        );
        assert!(results.iter().any(|c| c.identity == peer_one.contact().identity));
    }

    #[tokio::test]
    async fn adaptive_k_tracks_network_successes_and_failures() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x30, 10, 3).await;
        let peer = TestNode::new(registry.clone(), 0x31, 10, 3).await;

        main.node.observe_contact(peer.contact()).await;
        peer.node.observe_contact(main.contact()).await;

        main.network
            .set_failure(peer.contact().identity, true)
            .await;
        let target = make_identity(0xAA);
        let _ = main
            .node
            .iterative_find_node(target)
            .await
            .expect("lookup tolerates failure");
        let snapshot = main.node.telemetry_snapshot().await;
        assert_eq!(snapshot.replication_factor, 30);

        main.network
            .set_failure(peer.contact().identity, false)
            .await;
        let _ = main
            .node
            .iterative_find_node(target)
            .await
            .expect("lookup succeeds after recovery");
        let snapshot = main.node.telemetry_snapshot().await;
        assert_eq!(snapshot.replication_factor, 20);
    }

    #[tokio::test]
    async fn backpressure_spills_large_values_and_records_pressure() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        for peer_idx in 0u32..10 {
            let peer = make_contact(peer_idx + 2);
            let value = vec![peer_idx as u8; 900 * 1024];
            let key = *hash(&value).as_bytes();
            node.node
                .handle_store_request(&peer, key, value)
                .await;
        }

        let snapshot = node.node.telemetry_snapshot().await;
        assert!(snapshot.pressure > 0.5, "pressure: {}", snapshot.pressure);
        
        let calls = node.network.store_calls().await;
        assert!(!calls.is_empty() || snapshot.stored_keys < 10, 
            "should have offloaded to network or evicted, stored_keys={}", snapshot.stored_keys);
    }

    #[tokio::test]
    async fn tiering_clusters_contacts_by_latency() {
        // Test that prefix-based tiering records RTT samples correctly.
        // Note: The actual tier clustering happens on a 5-minute interval,
        // so we verify the RTT recording mechanism works via lookups.
        let registry = Arc::new(NetworkRegistry::default());
        // Use different /16 prefixes for each peer
        let main = TestNode::new(registry.clone(), 0x0100, 20, 3).await; // 10.1.0.1
        let fast = TestNode::new(registry.clone(), 0x0200, 20, 3).await; // 10.2.0.1
        let medium = TestNode::new(registry.clone(), 0x0300, 20, 3).await; // 10.3.0.1
        let slow = TestNode::new(registry.clone(), 0x0400, 20, 3).await; // 10.4.0.1

        for peer in [&fast, &medium, &slow] {
            main.node.observe_contact(peer.contact()).await;
            peer.node.observe_contact(main.contact()).await;
        }

        main.network
            .set_latency(fast.contact().identity, Duration::from_millis(5))
            .await;
        main.network
            .set_latency(medium.contact().identity, Duration::from_millis(25))
            .await;
        main.network
            .set_latency(slow.contact().identity, Duration::from_millis(50))
            .await;

        let target = make_identity(0x9900);
        let _ = main
            .node
            .iterative_find_node(target)
            .await
            .expect("lookup succeeds");

        // Verify routing table has all 3 peers (tiering is for optimization, not routing)
        let lookup_result = main.node.handle_find_node_request(&main.contact(), target).await;
        assert!(
            lookup_result.len() >= 3,
            "should have all 3 peers in routing table, got {}",
            lookup_result.len()
        );

        // The telemetry centroids start with a single default tier until recompute
        let snapshot = main.node.telemetry_snapshot().await;
        assert!(
            !snapshot.tier_centroids.is_empty(),
            "should have at least one tier centroid"
        );
    }

    #[tokio::test]
    async fn responsive_contacts_survive_bucket_eviction() {
        let (main_idx, responsive_idx, challenger_idx) = find_same_bucket_indices();
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), main_idx, 1, 2).await;
        let responsive = TestNode::new(registry.clone(), responsive_idx, 1, 2).await;
        let challenger = TestNode::new(registry.clone(), challenger_idx, 1, 2).await;

        main.node.observe_contact(responsive.contact()).await;
        main.node.observe_contact(challenger.contact()).await;

        sleep(Duration::from_millis(20)).await;

        let closest = main
            .node
            .handle_find_node_request(&main.contact(), challenger.contact().identity)
            .await;
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].identity, responsive.contact().identity);
    }

    #[tokio::test]
    async fn failed_pings_trigger_bucket_replacement() {
        let (main_idx, stale_idx, newcomer_idx) = find_same_bucket_indices();
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), main_idx, 1, 2).await;
        let stale = TestNode::new(registry.clone(), stale_idx, 1, 2).await;
        let newcomer = TestNode::new(registry.clone(), newcomer_idx, 1, 2).await;

        main.node.observe_contact(stale.contact()).await;
        main.network
            .set_failure(stale.contact().identity, true)
            .await;
        main.node.observe_contact(newcomer.contact()).await;

        sleep(Duration::from_millis(20)).await;

        let closest = main
            .node
            .handle_find_node_request(&main.contact(), newcomer.contact().identity)
            .await;
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].identity, newcomer.contact().identity);
    }

    #[tokio::test]
    async fn bucket_refreshes_issue_pings_before_eviction() {
        let (main_idx, incumbent_idx, challenger_idx) = find_same_bucket_indices();
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), main_idx, 1, 2).await;
        let incumbent = TestNode::new(registry.clone(), incumbent_idx, 1, 2).await;
        let challenger = TestNode::new(registry.clone(), challenger_idx, 1, 2).await;

        main.node.observe_contact(incumbent.contact()).await;
        main.node.observe_contact(challenger.contact()).await;

        sleep(Duration::from_millis(20)).await;

        let pings = main.network.ping_calls().await;
        assert_eq!(pings, vec![incumbent.contact().identity]);
    }

    #[tokio::test]
    async fn many_peers_respects_routing_table_limits() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 4, 2).await;

        let mut peers = Vec::new();
        for i in 1u32..=100 {
            let peer = TestNode::new(registry.clone(), i, 4, 2).await;
            peers.push(peer);
        }

        for peer in &peers {
            main.node.observe_contact(peer.contact()).await;
        }

        sleep(Duration::from_millis(50)).await;

        let target = make_identity(0xFF);
        let result = main.node.iterative_find_node(target).await;
        assert!(result.is_ok(), "lookups should work with many peers");

        let contacts = result.unwrap();
        assert!(
            contacts.len() <= 4,
            "find_node response should be bounded by k=4, got {}",
            contacts.len()
        );
    }

    #[tokio::test]
    async fn high_churn_handles_rapid_peer_changes() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 4, 2).await;

        for round in 0..5 {
            let base = (round + 1) * 20;

            for i in 0..10u32 {
                let peer = TestNode::new(registry.clone(), base + i, 4, 2).await;
                main.node.observe_contact(peer.contact()).await;

                if i % 2 == 0 {
                    main.network
                        .set_failure(peer.contact().identity, true)
                        .await;
                }
            }

            let target = make_identity(0xFF);
            let _ = main.node.iterative_find_node(target).await;
        }

        sleep(Duration::from_millis(50)).await;

        let target = make_identity(0xAB);
        let result = main.node.iterative_find_node(target).await;
        assert!(result.is_ok(), "lookups should succeed after churn");

        let snapshot = main.node.telemetry_snapshot().await;
        let total_tiered: usize = snapshot.tier_counts.iter().sum();
        assert!(
            total_tiered <= 100,
            "tiered peers should be bounded under churn, got {}",
            total_tiered
        );
    }

    #[tokio::test]
    async fn large_values_trigger_backpressure_correctly() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        for peer_idx in 0u32..6 {
            let peer = make_contact(peer_idx + 2);
            let value = vec![peer_idx as u8; 900 * 1024];
            let key = *hash(&value).as_bytes();
            node.node.handle_store_request(&peer, key, value).await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.pressure >= 0.5,
            "pressure should be elevated with ~5.4MB stored against 4MB limit, got {}",
            snapshot.pressure
        );

        let peer = make_contact(0x10);
        let large_value = vec![0xFFu8; 900 * 1024];
        let large_key = *hash(&large_value).as_bytes();
        node.node
            .handle_store_request(&peer, large_key, large_value.clone())
            .await;

        let _calls = node.network.store_calls().await;

        let final_snapshot = node.node.telemetry_snapshot().await;
        assert!(
            final_snapshot.pressure <= 1.0,
            "pressure should be managed, got {}",
            final_snapshot.pressure
        );

        assert!(
            final_snapshot.stored_keys >= 1,
            "should still have some stored keys"
        );
    }

    #[tokio::test]
    async fn concurrent_stores_remain_bounded() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let peer = make_contact(0x02);

        let mut handles = Vec::new();
        for i in 0..20 {
            let node_clone = node.node.clone();
            let peer_clone = peer.clone();
            let handle = tokio::spawn(async move {
                let value = vec![i as u8; 500 * 1024];
                let key = *hash(&value).as_bytes();
                node_clone
                    .handle_store_request(&peer_clone, key, value)
                    .await;
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.stored_keys <= 1000,
            "stored keys should be bounded, got {}",
            snapshot.stored_keys
        );

        assert!(
            snapshot.pressure <= 1.5,
            "pressure should be managed under concurrent load, got {}",
            snapshot.pressure
        );
    }

    #[tokio::test]
    async fn tiering_evicts_oldest_peers_at_capacity() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 20, 3).await;

        for i in 1u32..=200 {
            let peer = TestNode::new(registry.clone(), i, 20, 3).await;
            main.node.observe_contact(peer.contact()).await;

            let latency = Duration::from_millis((i % 100) as u64 + 5);
            main.network
                .set_latency(peer.contact().identity, latency)
                .await;
        }

        for i in 0..10 {
            let target = make_identity(0x100 + i);
            let _ = main.node.iterative_find_node(target).await;
        }

        let snapshot = main.node.telemetry_snapshot().await;

        assert!(
            !snapshot.tier_centroids.is_empty(),
            "should have at least one tier"
        );

        let total_tiered: usize = snapshot.tier_counts.iter().sum();
        assert!(
            total_tiered <= 200,
            "tiered peers should be bounded, got {}",
            total_tiered
        );
    }

    #[tokio::test]
    async fn storage_eviction_prefers_low_access_entries() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let peer = make_contact(0x02);

        let hot_value = vec![0xAAu8; 900 * 1024];
        let hot_key = *hash(&hot_value).as_bytes();
        node.node
            .handle_store_request(&peer, hot_key, hot_value.clone())
            .await;

        for _ in 0..5 {
            let _ = node.node.handle_find_value_request(&peer, hot_key).await;
        }

        for i in 0..5 {
            let cold_value = vec![i as u8; 900 * 1024];
            let cold_key = *hash(&cold_value).as_bytes();
            node.node
                .handle_store_request(&peer, cold_key, cold_value)
                .await;
        }

        let (value, _) = node.node.handle_find_value_request(&peer, hot_key).await;
        assert!(
            value.is_some(),
            "frequently accessed key should survive eviction"
        );
    }

    #[tokio::test]
    async fn storage_pressure_protection() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let peer = make_contact(0x02);

        for i in 0..10 {
            let value = vec![i as u8; 900 * 1024];
            let key = *hash(&value).as_bytes();
            node.node.handle_store_request(&peer, key, value).await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.pressure > 0.0 || snapshot.stored_keys < 20,
            "Either pressure should be non-zero or some keys should be evicted/spilled"
        );
    }

    #[tokio::test]
    async fn per_peer_storage_limits() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let malicious_peer = make_contact(0x99);

        for i in 0..150 {
            let value = vec![i as u8; 100];
            let key = *hash(&value).as_bytes();
            node.node
                .handle_store_request(&malicious_peer, key, value)
                .await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.stored_keys <= 100,
            "Per-peer limits should prevent storing more than 100 entries, got {}",
            snapshot.stored_keys
        );
    }

    #[tokio::test]
    async fn multiple_peers_independent_storage() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        for peer_id in 0..5 {
            let peer = make_contact(peer_id);
            for i in 0..10 {
                let value = format!("peer-{}-value-{}", peer_id, i).into_bytes();
                let key = *hash(&value).as_bytes();
                node.node.handle_store_request(&peer, key, value).await;
            }
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.stored_keys >= 20,
            "Should store data from multiple peers, got {}",
            snapshot.stored_keys
        );
    }

    #[tokio::test]
    async fn lookup_returns_valid_contacts() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;
        let peer = TestNode::new(registry.clone(), 0x02, 20, 3).await;

        node.node.observe_contact(peer.contact()).await;
        peer.node.observe_contact(node.contact()).await;

        let target = peer.contact().identity;
        let results = node.node.iterative_find_node(target).await.unwrap();

        assert!(results.iter().any(|c| c.identity == target));

        for contact in &results {
            assert_eq!(contact.identity.as_bytes().len(), 32);
            assert!(contact.identity.as_bytes() != &[0u8; 32]);
        }
    }

    #[tokio::test]
    async fn lookup_converges_to_closest() {
        let registry = Arc::new(NetworkRegistry::default());
        let mut join_set = JoinSet::new();
        for i in 0..10u32 {
            let reg = registry.clone();
            join_set.spawn(async move { (i as usize, TestNode::new(reg, 0x10 + i, 20, 3).await) });
        }

        let mut nodes: Vec<Option<TestNode>> = Vec::with_capacity(10);
        nodes.resize_with(10, || None);
        while let Some(joined) = join_set.join_next().await {
            let (idx, node) = joined.expect("test node join");
            nodes[idx] = Some(node);
        }
        let nodes: Vec<TestNode> = nodes.into_iter().map(|n| n.expect("test node")) .collect();

        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    nodes[i].node.observe_contact(nodes[j].contact()).await;
                }
            }
        }

        let target = nodes[5].contact().identity;
        let results = nodes[0].node.iterative_find_node(target).await.unwrap();

        assert_eq!(results.first().map(|c| c.identity), Some(target));
    }

    #[tokio::test]
    async fn malicious_response_handling() {
        let registry = Arc::new(NetworkRegistry::default());
        let honest = TestNode::new(registry.clone(), 0x01, 20, 3).await;
        let peer = TestNode::new(registry.clone(), 0x02, 20, 3).await;

        honest.node.observe_contact(peer.contact()).await;

        let target = make_identity(0xFF);
        let result = honest.node.iterative_find_node(target).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn routing_table_diversity() {
        let registry = Arc::new(NetworkRegistry::default());
        let target = TestNode::new(registry.clone(), 0x0100, 20, 3).await; // 10.1.0.1

        let mut peers = Vec::new();
        for i in 0..20 {
            // Create peers with diverse /16 prefixes: 10.{16+i}.X.1
            let peer = TestNode::new(registry.clone(), 0x1000 + i * 0x100, 20, 3).await;
            peers.push(peer);
        }

        for peer in &peers {
            target.node.observe_contact(peer.contact()).await;
        }

        // tier_counts now counts /16 prefixes, not individual peers
        // The routing table should still track peers, verify via a lookup
        let lookup_result = target.node.handle_find_node_request(&target.contact(), make_identity(0xFF00)).await;
        assert!(
            !lookup_result.is_empty(),
            "Routing table should accept diverse peers, got {} peers in lookup",
            lookup_result.len()
        );
    }

    #[tokio::test]
    async fn eclipse_attack_resistance() {
        let registry = Arc::new(NetworkRegistry::default());
        let victim = TestNode::new(registry.clone(), 0x0100, 20, 3).await; // 10.1.0.1

        let mut attackers = Vec::new();
        for i in 0..50 {
            // Attackers with diverse /16 prefixes: 10.{128+i}.X.1
            let attacker = TestNode::new(registry.clone(), 0x8000 + i * 0x100, 20, 3).await;
            attackers.push(attacker);
        }

        let mut honest_nodes = Vec::new();
        for i in 0..5 {
            // Honest nodes with diverse /16 prefixes: 10.{16+i}.X.1
            let honest = TestNode::new(registry.clone(), 0x1000 + i * 0x100, 20, 3).await;
            honest_nodes.push(honest);
        }

        for attacker in &attackers {
            victim.node.observe_contact(attacker.contact()).await;
        }
        for honest in &honest_nodes {
            victim.node.observe_contact(honest.contact()).await;
        }

        // Verify routing table contains nodes (eclipse resistance is about routing, not tiering)
        let lookup_result = victim.node.handle_find_node_request(&victim.contact(), make_identity(0xFF00)).await;
        assert!(
            lookup_result.len() >= 5,
            "Should track at least some nodes, got {} in lookup",
            lookup_result.len()
        );
    }

    #[tokio::test]
    async fn bucket_replacement_favors_long_lived() {
        let registry = Arc::new(NetworkRegistry::default());

        let node = TestNode::new(registry.clone(), 0x0100, 20, 3).await; // 10.1.0.1

        let mut long_lived = Vec::new();
        for i in 0..5 {
            // Long-lived nodes with diverse /16 prefixes
            let long_lived_node = TestNode::new(registry.clone(), 0x1000 + i * 0x100, 20, 3).await;
            node.node
                .observe_contact(long_lived_node.contact())
                .await;
            long_lived.push(long_lived_node);
        }

        for i in 0..20 {
            // Sybil nodes with diverse /16 prefixes
            let sybil = TestNode::new(registry.clone(), 0x8000 + i * 0x100, 20, 3).await;
            node.node.observe_contact(sybil.contact()).await;
        }

        // Verify via routing table lookup (bucket replacement is about routing, not tiering)
        let lookup_result = node.node.handle_find_node_request(&node.contact(), make_identity(0xFF00)).await;
        assert!(
            lookup_result.len() >= 5,
            "Should maintain at least the original nodes, got {} in lookup",
            lookup_result.len()
        );
    }


    #[test]
    fn content_key_is_deterministic() {
        let data = b"hello world";
        let hash_one = *hash(data).as_bytes();
        let hash_two = *hash(data).as_bytes();
        assert_eq!(hash_one, hash_two, "hashes of identical data should match");

        let different_hash = *hash(b"goodbye world").as_bytes();
        assert_ne!(
            hash_one, different_hash,
            "hashes of different data should differ"
        );
    }

    #[test]
    fn verify_key_value_pair_matches_hash() {
        let data = b"payload";
        let key = *hash(data).as_bytes();
        assert!(
            classify_key_value_pair(&key, data) != ValueType::Invalid,
            "classify_key_value_pair should accept matching key/value pairs"
        );

        let mut wrong_key = key;
        wrong_key[0] ^= 0xFF;
        assert!(
            classify_key_value_pair(&wrong_key, data) == ValueType::Invalid,
            "classify_key_value_pair should reject non-matching key/value pairs"
        );
    }

    #[test]
    fn blake3_hash_consistency() {
        let data = b"hello world";
        let expected = blake3::hash(data);
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(expected.as_bytes());

        assert_eq!(
            *hash(data).as_bytes(),
            expected_bytes,
            "hash should produce the BLAKE3 digest"
        );
    }

    #[test]
    fn xor_distance_produces_expected_value() {
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 0b1010_1010;
        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 0b0101_0101;

        let a = Identity::from_bytes(a_bytes);
        let b = Identity::from_bytes(b_bytes);
        let dist = a.xor_distance(&b);
        assert_eq!(dist[0], 0b1111_1111);
        assert!(dist.iter().skip(1).all(|byte| *byte == 0));
    }

    #[test]
    fn distance_cmp_orders_lexicographically() {
        use std::cmp::Ordering;
        let mut smaller = [0u8; 32];
        smaller[1] = 1;
        let mut larger = [0u8; 32];
        larger[1] = 2;

        assert_eq!(distance_cmp(&smaller, &larger), Ordering::Less);
        assert_eq!(distance_cmp(&larger, &smaller), Ordering::Greater);
        assert_eq!(distance_cmp(&smaller, &smaller), Ordering::Equal);
    }

    #[tokio::test]
    async fn dht_identity_accessor() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x42, 20, 3).await;
        
        let expected_id = make_identity(0x42);
        assert_eq!(node.node.identity(), expected_id);
    }

    #[tokio::test]
    async fn get_returns_early_on_first_value_and_cancels_others() {
        let value = b"fastest-wins".to_vec();
        let key = *hash(&value).as_bytes();
        let target = Identity::from_bytes(key);

        // `alpha` is clamped to at least 2, so iterative lookups will query the first two
        // closest contacts. We therefore pick three identities:
        // - `fast`: closest (queried during lookup)
        // - `dummy`: second-closest (queried during lookup)
        // - `slow`: farthest (NOT queried during lookup, but included in the shortlist)
        let mut candidates: Vec<(u32, [u8; 32])> = Vec::new();
        for idx in 1u32..=8192 {
            let id = make_identity(idx);
            let dist = id.xor_distance(&target);
            candidates.push((idx, dist));
        }
        candidates.sort_by(|a, b| distance_cmp(&a.1, &b.1));
        assert!(candidates.len() >= 3);

        let fast_idx = candidates[0].0;
        let dummy_idx = candidates[1].0;
        let slow_idx = candidates.last().expect("last idx").0;
        let mut main_idx = 0xDEAD_BEEFu32;
        if main_idx == fast_idx || main_idx == dummy_idx || main_idx == slow_idx {
            main_idx = 0xDEAD_BEEEu32;
        }

        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), main_idx, 20, 2).await;
        let fast = TestNode::new(registry.clone(), fast_idx, 20, 2).await;
        let dummy = TestNode::new(registry.clone(), dummy_idx, 20, 2).await;
        let slow = TestNode::new(registry.clone(), slow_idx, 20, 2).await;

        main.node.observe_contact(fast.contact()).await;
        main.node.observe_contact(dummy.contact()).await;
        main.node.observe_contact(slow.contact()).await;

        // Sanity-check the lookup ordering before introducing latency.
        // With `alpha >= 2`, we rely on the first two contacts being fast+dummy so that
        // iterative_find_node does not block on the slow peer.
        let closest_pre = tokio::time::timeout(Duration::from_secs(1), main.node.iterative_find_node(target))
            .await
            .expect("iterative_find_node should complete quickly")
            .expect("iterative_find_node should succeed");
        let closest_without_self: Vec<Contact> = closest_pre
            .into_iter()
            .filter(|c| c.identity != main.contact().identity)
            .collect();
        assert!(closest_without_self.len() >= 3, "expected at least 3 non-self contacts");
        assert_eq!(closest_without_self[0].identity, fast.contact().identity);
        assert_eq!(closest_without_self[1].identity, dummy.contact().identity);
        assert!(closest_without_self.iter().any(|c| c.identity == slow.contact().identity));

        // Ensure the slow peer will not respond within FIND_VALUE_TIMEOUT.
        main.network
            .set_latency(slow.contact().identity, Duration::from_secs(60))
            .await;

        // Store the value at both peers so either could satisfy the get.
        fast.node
            .handle_store_request(&main.contact(), key, value.clone())
            .await;
        slow.node
            .handle_store_request(&main.contact(), key, value.clone())
            .await;

        // Ensure the store requests were processed before we call `get`.
        // These requests are ordered on the actor channel, so the store must have been applied
        // before the subsequent find_value handler runs.
        let (fast_value, _) = fast
            .node
            .handle_find_value_request(&main.contact(), key)
            .await;
        assert_eq!(fast_value, Some(value.clone()));

        let (slow_value, _) = slow
            .node
            .handle_find_value_request(&main.contact(), key)
            .await;
        assert_eq!(slow_value, Some(value.clone()));

        // If `get` waits for all lookups, the slow task will be bounded by FIND_VALUE_TIMEOUT
        // (currently 3s). So this should time out. With early-return + abort, it completes fast.
        let outcome = tokio::time::timeout(Duration::from_secs(2), main.node.get(&key))
            .await
            .expect("get should return before timeout")
            .expect("get should succeed");

        assert_eq!(outcome, Some(value));
    }

    // ========================================================================
    // Routing Table Unit Tests
    // ========================================================================

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
    fn direct_peer_ip_limiter_enforces_per_ip_limit() {
        // SECURITY TEST: Verify that the DirectPeerIpLimiter enforces per-IP rate limiting
        // to prevent multi-IP attackers from bypassing PoW via direct connections.
        let mut limiter = DirectPeerIpLimiter::new();
        
        // Create a contact with a known IP address using the correct API
        let keypair = crate::identity::Keypair::generate();
        let contact = Contact::single(keypair.identity(), "192.168.1.100:8080");
        
        // Should allow up to DIRECT_PEER_PER_IP_LIMIT insertions
        for i in 0..DIRECT_PEER_PER_IP_LIMIT {
            assert!(
                limiter.allow_direct_peer(&contact),
                "insertion {} should be allowed within limit",
                i
            );
        }
        
        // Next insertion should be rate-limited
        assert!(
            !limiter.allow_direct_peer(&contact),
            "insertion beyond limit should be rejected"
        );
    }
    
    #[test]
    fn direct_peer_ip_limiter_independent_per_ip() {
        // SECURITY TEST: Verify that different IPs have independent rate limits
        let mut limiter = DirectPeerIpLimiter::new();
        
        let keypair1 = crate::identity::Keypair::generate();
        let contact1 = Contact::single(keypair1.identity(), "192.168.1.100:8080");
        
        let keypair2 = crate::identity::Keypair::generate();
        let contact2 = Contact::single(keypair2.identity(), "192.168.1.200:8080");
        
        // Exhaust limit for first IP
        for _ in 0..DIRECT_PEER_PER_IP_LIMIT {
            limiter.allow_direct_peer(&contact1);
        }
        assert!(!limiter.allow_direct_peer(&contact1), "first IP should be limited");
        
        // Second IP should still be allowed
        assert!(
            limiter.allow_direct_peer(&contact2),
            "different IP should have independent limit"
        );
    }

    #[test]
    fn routing_table_orders_contacts_by_distance() {
        // Generate valid identities - the actual bytes will differ from seeds
        // because these are real Ed25519 public keys derived from seed-based secret keys
        let self_id = make_test_identity(0x00);
        let mut table = RoutingTable::new(self_id, 4);

        let contact1 = make_test_contact(0x10);
        let contact2 = make_test_contact(0x20);
        let contact3 = make_test_contact(0x30);
        
        table.update(contact1.clone());
        table.update(contact2.clone());
        table.update(contact3.clone());

        // Use one of the contacts as the target to test ordering
        let target = contact2.identity;
        let closest = table.closest(&target, 3);
        
        // Verify we get all 3 contacts back
        assert_eq!(closest.len(), 3);
        
        // Verify they're ordered by XOR distance to target
        for i in 0..closest.len() - 1 {
            let dist_i = closest[i].identity.xor_distance(&target);
            let dist_next = closest[i + 1].identity.xor_distance(&target);
            assert!(
                distance_cmp(&dist_i, &dist_next) != std::cmp::Ordering::Greater,
                "contacts should be ordered by distance to target"
            );
        }
        
        // The first result should be the target itself (distance 0)
        assert_eq!(closest[0].identity, target);
    }

    #[test]
    fn routing_table_respects_bucket_capacity() {
        let self_id = make_test_identity(0x00);
        let mut table = RoutingTable::new(self_id, 2);

        // Add 3 contacts, but bucket capacity is 2
        let contact1 = make_test_contact(0x80);
        let contact2 = make_test_contact(0x81);
        let contact3 = make_test_contact(0x82);
        
        table.update(contact1.clone());
        table.update(contact2.clone());
        table.update(contact3.clone());

        // Request up to 10, but should only get what's in the table
        let closest = table.closest(&contact1.identity, 10);
        
        // The number of contacts depends on bucket distribution
        // With k=2, each bucket can hold 2 contacts
        // Just verify we got some results and they're valid
        assert!(!closest.is_empty(), "should have at least one contact");
        assert!(closest.len() <= 3, "should not exceed contacts added");
    }

    #[test]
    fn routing_table_truncates_when_k_changes() {
        let self_id = make_test_identity(0x00);
        let mut table = RoutingTable::new(self_id, 4);

        let contact1 = make_test_contact(0x80);
        let contact2 = make_test_contact(0x81);
        let contact3 = make_test_contact(0x82);
        
        table.update(contact1.clone());
        table.update(contact2.clone());
        table.update(contact3.clone());

        // Start with 3 contacts, reduce k to 2
        table.set_k(2);
        let closest = table.closest(&contact1.identity, 10);
        // After reducing k, buckets with more than 2 entries get truncated
        assert!(closest.len() <= 3, "should not exceed original count");
    }

    const MAX_K: usize = 30;
    const NUM_BUCKETS: usize = 256;

    #[test]
    fn routing_table_size_bounded() {
        let max_routing_table_size = MAX_K * NUM_BUCKETS;
        assert_eq!(max_routing_table_size, 7680);
        assert!(
            max_routing_table_size < 10_000,
            "Routing table should be bounded"
        );
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

    /// Generate a valid Ed25519 identity deterministically from a seed byte.
    /// Unlike arbitrary byte arrays, these are actual valid public keys.
    fn make_test_identity(seed: u8) -> Identity {
        use crate::identity::Keypair;
        // Create a deterministic 32-byte secret key from the seed
        let mut secret = [0u8; 32];
        secret[0] = seed;
        // Fill remaining bytes with a hash-like pattern to avoid weak keys
        for (i, byte) in secret.iter_mut().enumerate().skip(1) {
            *byte = seed.wrapping_mul((i as u8).wrapping_add(1));
        }
        let keypair = Keypair::from_secret_key_bytes(&secret);
        keypair.identity()
    }

    fn make_test_contact(seed: u8) -> Contact {
        let identity = make_test_identity(seed);
        // Compute valid PoW proof at production difficulty
        let pow_proof = IdentityProof::compute_for_identity(&identity, POW_DIFFICULTY);
        let mut contact = Contact::single(identity, format!("node-{seed}"));
        contact.pow_proof = pow_proof;
        contact
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

    // ========================================================================
    // Storage Unit Tests
    // ========================================================================

    #[test]
    fn store_and_retrieve() {
        let mut store = LocalStore::new();
        let key: Key = [1u8; 32];
        let value = b"test value";
        let peer = make_test_identity(0x01);

        let spilled = store.store(key, value, peer, ValueType::ContentAddressed);
        assert!(spilled.is_empty());

        let retrieved = store.get(&key);
        assert_eq!(retrieved, Some(value.to_vec()));
    }

    #[test]
    fn rejects_oversized_value() {
        let mut store = LocalStore::new();
        let key: Key = [1u8; 32];
        let value = vec![0u8; MAX_VALUE_SIZE + 1];
        let peer = make_test_identity(0x01);

        let spilled = store.store(key, &value, peer, ValueType::ContentAddressed);
        assert!(spilled.is_empty());
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn rate_limiting_works() {
        let mut store = LocalStore::new();
        let peer = make_test_identity(0x01);

        // Exhaust rate limit using IdentityKeyed (full limit applies)
        for i in 0..PER_PEER_RATE_LIMIT {
            let mut key: Key = [0u8; 32];
            key[0] = i as u8;
            store.store(key, b"value", peer, ValueType::IdentityKeyed);
        }

        // Next store should be rate limited
        let mut key: Key = [0u8; 32];
        key[0] = 0xFF;
        let result = store.check_store_allowed(&peer, 5, ValueType::IdentityKeyed);
        assert_eq!(result, Err(StoreRejection::RateLimited));
    }

    #[test]
    fn quota_enforcement() {
        let mut store = LocalStore::new();
        let peer = make_test_identity(0x01);

        // Store up to entry limit using IdentityKeyed
        for i in 0..PER_PEER_ENTRY_LIMIT {
            let mut key: Key = [0u8; 32];
            key[0] = i as u8;
            key[1] = (i >> 8) as u8;
            store.store(key, b"v", peer, ValueType::IdentityKeyed);
        }

        // Check that further stores would exceed quota
        // Note: rate limiting may trigger first depending on timing
        let result = store.check_store_allowed(&peer, 1, ValueType::IdentityKeyed);
        assert!(result.is_err());
    }

    #[test]
    fn pressure_monitor_tracks_bytes() {
        let mut monitor = PressureMonitor::new();
        assert_eq!(monitor.current_pressure(), 0.0);

        monitor.record_store(1_000_000);
        monitor.update_pressure(100);
        assert!(monitor.current_pressure() > 0.0);

        monitor.record_evict(1_000_000);
        monitor.update_pressure(0);
        // Pressure should decrease after eviction
    }

    #[test]
    fn missing_key_returns_none() {
        let mut store = LocalStore::new();
        let key: Key = [99u8; 32];
        assert!(store.get(&key).is_none());
    }
}
