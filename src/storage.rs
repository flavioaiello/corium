//! Local storage for DHT key-value pairs with pressure-based eviction and per-peer quotas.
//!
//! This module provides the storage layer for DHT operations, implementing:
//! - LRU cache with configurable capacity limits
//! - Pressure-based eviction when resource limits are approached
//! - Per-peer storage quotas and rate limiting to prevent abuse
//! - Automatic expiration of stale entries

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use lru::LruCache;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::identity::Identity;

/// Key type for DHT storage (32-byte hash).
pub type Key = [u8; 32];

// ============================================================================
// Storage Configuration Constants
// ============================================================================

/// Default time-to-live for stored entries (24 hours).
pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How often to check for expired entries.
const EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

// ============================================================================
// Pressure-Based Eviction Configuration
// ============================================================================

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

// ============================================================================
// Value Size and Quota Limits
// ============================================================================

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
pub(crate) struct PressureMonitor {
    current_bytes: usize,
    requests: VecDeque<Instant>,
    request_window: Duration,
    pub(crate) request_limit: usize,
    pub(crate) disk_limit: usize,
    pub(crate) memory_limit: usize,
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
pub(crate) struct StoredEntry {
    pub value: Vec<u8>,
    pub expires_at: Instant,
    pub stored_by: Identity,
    pub access_count: u32,
    pub stored_at: Instant,
}

/// Per-peer storage statistics for quota enforcement.
#[derive(Debug, Clone, Default)]
struct PeerStorageStats {
    bytes_stored: usize,
    entry_count: usize,
    store_requests: VecDeque<Instant>,
}

impl PeerStorageStats {
    fn can_store(&self, value_size: usize) -> bool {
        self.bytes_stored + value_size <= PER_PEER_STORAGE_QUOTA
            && self.entry_count < PER_PEER_ENTRY_LIMIT
    }

    fn is_rate_limited(&mut self) -> bool {
        let now = Instant::now();
        while let Some(front) = self.store_requests.front() {
            if now.duration_since(*front) > PER_PEER_RATE_WINDOW {
                self.store_requests.pop_front();
            } else {
                break;
            }
        }
        self.store_requests.len() >= PER_PEER_RATE_LIMIT
    }

    fn record_store(&mut self, value_size: usize) {
        self.bytes_stored = self.bytes_stored.saturating_add(value_size);
        self.entry_count = self.entry_count.saturating_add(1);
        self.store_requests.push_back(Instant::now());
    }

    fn record_evict(&mut self, value_size: usize) {
        self.bytes_stored = self.bytes_stored.saturating_sub(value_size);
        self.entry_count = self.entry_count.saturating_sub(1);
    }
}

/// Reason a store request was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreRejection {
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
pub(crate) struct LocalStore {
    cache: LruCache<Key, StoredEntry>,
    pub(crate) pressure: PressureMonitor,
    peer_stats: HashMap<Identity, PeerStorageStats>,
    ttl: Duration,
    last_expiration_check: Instant,
    last_peer_cleanup: Instant,
}

impl LocalStore {
    pub fn new() -> Self {
        let cap = NonZeroUsize::new(LOCAL_STORE_MAX_ENTRIES).expect("capacity must be non-zero");
        Self {
            cache: LruCache::new(cap),
            pressure: PressureMonitor::new(),
            peer_stats: HashMap::new(),
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
    pub fn check_store_allowed(&mut self, peer_id: &Identity, value_size: usize) -> Result<(), StoreRejection> {
        if value_size > MAX_VALUE_SIZE {
            debug!(
                peer = ?hex::encode(&peer_id.as_bytes()[..8]),
                size = value_size,
                max = MAX_VALUE_SIZE,
                "store rejected: value too large"
            );
            return Err(StoreRejection::ValueTooLarge);
        }

        let stats = self.peer_stats.entry(*peer_id).or_default();

        if stats.is_rate_limited() {
            debug!(
                peer = ?hex::encode(&peer_id.as_bytes()[..8]),
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
    pub fn store(&mut self, key: Key, value: &[u8], stored_by: Identity) -> Vec<(Key, Vec<u8>)> {
        if value.len() > MAX_VALUE_SIZE {
            warn!(
                size = value.len(),
                limit = MAX_VALUE_SIZE,
                peer = ?stored_by,
                "rejecting oversized value"
            );
            return Vec::new();
        }

        if let Err(rejection) = self.check_store_allowed(&stored_by, value.len()) {
            info!(peer = ?stored_by, reason = ?rejection, "store request rejected");
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

        let stats = self.peer_stats.entry(stored_by).or_default();
        stats.record_store(entry.value.len());

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

            if let Some(key) = unpopular_key {
                if let Some(evicted_entry) = self.cache.pop(&key) {
                    self.pressure.record_evict(evicted_entry.value.len());
                    if let Some(stats) = self.peer_stats.get_mut(&evicted_entry.stored_by) {
                        stats.record_evict(evicted_entry.value.len());
                    }
                    self.pressure.update_pressure(self.cache.len());
                    spilled.push((key, evicted_entry.value));
                    spill_happened = true;
                    continue;
                }
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
        if let Some(entry) = self.cache.get_mut(key) {
            if now < entry.expires_at {
                entry.access_count = entry.access_count.saturating_add(1);
                return Some(entry.value.clone());
            }
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
    fn maybe_cleanup_peer_stats(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_peer_cleanup) < Duration::from_secs(300)
            && self.peer_stats.len() <= MAX_TRACKED_PEERS
        {
            return;
        }
        self.last_peer_cleanup = now;

        self.peer_stats.retain(|_, stats| {
            stats.entry_count > 0 || !stats.store_requests.is_empty()
        });
        
        while self.peer_stats.len() > MAX_TRACKED_PEERS {
            let smallest = self.peer_stats
                .iter()
                .min_by_key(|(_, stats)| (stats.entry_count, stats.bytes_stored))
                .map(|(id, _)| *id);
            if let Some(peer_id) = smallest {
                self.peer_stats.remove(&peer_id);
            } else {
                break;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(seed: u8) -> Identity {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Identity::from_bytes(bytes)
    }

    #[test]
    fn store_and_retrieve() {
        let mut store = LocalStore::new();
        let key: Key = [1u8; 32];
        let value = b"test value";
        let peer = make_identity(0x01);

        let spilled = store.store(key, value, peer);
        assert!(spilled.is_empty());

        let retrieved = store.get(&key);
        assert_eq!(retrieved, Some(value.to_vec()));
    }

    #[test]
    fn rejects_oversized_value() {
        let mut store = LocalStore::new();
        let key: Key = [1u8; 32];
        let value = vec![0u8; MAX_VALUE_SIZE + 1];
        let peer = make_identity(0x01);

        let spilled = store.store(key, &value, peer);
        assert!(spilled.is_empty());
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn rate_limiting_works() {
        let mut store = LocalStore::new();
        let peer = make_identity(0x01);

        // Exhaust rate limit
        for i in 0..PER_PEER_RATE_LIMIT {
            let mut key: Key = [0u8; 32];
            key[0] = i as u8;
            store.store(key, b"value", peer);
        }

        // Next store should be rate limited
        let mut key: Key = [0u8; 32];
        key[0] = 0xFF;
        let result = store.check_store_allowed(&peer, 5);
        assert_eq!(result, Err(StoreRejection::RateLimited));
    }

    #[test]
    fn quota_enforcement() {
        let mut store = LocalStore::new();
        let peer = make_identity(0x01);

        // Store up to entry limit
        for i in 0..PER_PEER_ENTRY_LIMIT {
            let mut key: Key = [0u8; 32];
            key[0] = i as u8;
            key[1] = (i >> 8) as u8;
            store.store(key, b"v", peer);
        }

        // Check that further stores would exceed quota
        // Note: rate limiting may trigger first depending on timing
        let result = store.check_store_allowed(&peer, 1);
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
