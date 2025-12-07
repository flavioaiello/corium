//! Local key-value storage with LRU eviction and pressure-based backpressure.
//!
//! Provides content-addressed storage with per-peer quotas, rate limiting,
//! and popularity-based eviction to prevent storage exhaustion attacks.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use lru::LruCache;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::identity::Identity;
use super::hash::Key;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default TTL for stored data (24 hours, per Kademlia spec).
pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How often to run the expiration cleanup task.
const EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Soft limit for approximate disk usage before triggering backpressure (8 MiB).
const PRESSURE_DISK_SOFT_LIMIT: usize = 8 * 1024 * 1024;

/// Soft limit for approximate memory usage before triggering backpressure (4 MiB).
const PRESSURE_MEMORY_SOFT_LIMIT: usize = 4 * 1024 * 1024;

/// Time window for counting store/get requests in pressure calculation.
const PRESSURE_REQUEST_WINDOW: Duration = Duration::from_secs(60);

/// Maximum requests within the window before contributing to pressure.
const PRESSURE_REQUEST_LIMIT: usize = 200;

/// Pressure threshold (0.0-1.0) above which LRU eviction is triggered.
const PRESSURE_THRESHOLD: f32 = 0.75;

/// Maximum size of a single stored value (1 MB).
/// Prevents memory exhaustion from large value attacks.
const MAX_VALUE_SIZE: usize = crate::messages::MAX_VALUE_SIZE;

/// Maximum bytes a single peer can store (1 MB).
/// Prevents any single peer from exhausting storage.
const PER_PEER_STORAGE_QUOTA: usize = 1024 * 1024;

/// Maximum number of entries a single peer can store.
const PER_PEER_ENTRY_LIMIT: usize = 100;

/// Maximum store requests per peer per minute.
const PER_PEER_RATE_LIMIT: usize = 20;

/// Time window for per-peer rate limiting.
const PER_PEER_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Access count threshold below which entries are evicted first.
/// Popular data (accessed more than this) survives longer.
const POPULARITY_THRESHOLD: u32 = 3;

/// Maximum number of peers to track for quota enforcement.
/// Prevents memory exhaustion from tracking too many peers.
const MAX_TRACKED_PEERS: usize = 10_000;

/// Maximum number of entries in the LRU cache.
/// This is a reasonable default; pressure-based eviction may kick in earlier.
const LOCAL_STORE_MAX_ENTRIES: usize = 100_000;

/// Maximum iterations for the eviction loop.
///
/// Prevents potential infinite loop in pathological cases where
/// pressure calculation doesn't decrease despite evictions.
/// Set to a high value that should never be reached in normal operation.
const MAX_EVICTION_ITERATIONS: usize = 10_000;

// ============================================================================
// Pressure Monitoring
// ============================================================================

/// Monitors system pressure to prevent resource exhaustion.
///
/// Tracks memory usage, disk usage, and request rates to compute a composite
/// pressure score used for adaptive rate limiting and request rejection.
pub(crate) struct PressureMonitor {
    /// Current estimated memory usage in bytes.
    current_bytes: usize,
    /// Sliding window of recent request timestamps.
    requests: VecDeque<Instant>,
    /// Duration of the request rate window.
    request_window: Duration,
    /// Maximum requests allowed per window.
    pub(crate) request_limit: usize,
    /// Maximum disk storage in bytes.
    pub(crate) disk_limit: usize,
    /// Maximum memory usage in bytes.
    pub(crate) memory_limit: usize,
    /// Current composite pressure score (0.0 = no pressure, 1.0 = critical).
    current_pressure: f32,
}

impl PressureMonitor {
    /// Create a new pressure monitor with default limits.
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

    /// Record bytes added to storage.
    pub fn record_store(&mut self, bytes: usize) {
        self.current_bytes = self.current_bytes.saturating_add(bytes);
    }

    /// Record bytes removed from storage via eviction.
    pub fn record_evict(&mut self, bytes: usize) {
        self.current_bytes = self.current_bytes.saturating_sub(bytes);
    }

    /// Record a disk spill event, indicating critical pressure.
    pub fn record_spill(&mut self) {
        self.current_pressure = 1.0;
    }

    /// Record an incoming request for rate limiting.
    pub fn record_request(&mut self) {
        let now = Instant::now();
        self.requests.push_back(now);
        self.trim_requests(now);
    }

    /// Remove expired requests outside the rate limit window.
    fn trim_requests(&mut self, now: Instant) {
        while let Some(front) = self.requests.front() {
            if now.duration_since(*front) > self.request_window {
                self.requests.pop_front();
            } else {
                break;
            }
        }
    }

    /// Recompute the composite pressure score from disk, memory, and request metrics.
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

    /// Get the current pressure score.
    pub fn current_pressure(&self) -> f32 {
        self.current_pressure
    }
}

// ============================================================================
// Per-Peer Statistics
// ============================================================================

/// A stored entry with its value and expiration timestamp.
#[derive(Clone)]
pub(crate) struct StoredEntry {
    /// The stored value.
    pub value: Vec<u8>,
    /// When this entry expires and should be deleted.
    pub expires_at: Instant,
    /// Identity of the peer that stored this entry (for per-peer quota tracking).
    pub stored_by: Identity,
    /// Number of times this entry has been accessed (for popularity-based eviction).
    pub access_count: u32,
    /// When this entry was stored.
    pub stored_at: Instant,
}

/// Per-peer storage tracking for quota enforcement.
#[derive(Debug, Clone, Default)]
struct PeerStorageStats {
    /// Total bytes stored by this peer.
    bytes_stored: usize,
    /// Number of entries stored by this peer.
    entry_count: usize,
    /// Recent store request timestamps for rate limiting.
    store_requests: VecDeque<Instant>,
}

impl PeerStorageStats {
    /// Check if peer can store more data.
    fn can_store(&self, value_size: usize) -> bool {
        self.bytes_stored + value_size <= PER_PEER_STORAGE_QUOTA
            && self.entry_count < PER_PEER_ENTRY_LIMIT
    }

    /// Check if peer is rate limited.
    fn is_rate_limited(&mut self) -> bool {
        let now = Instant::now();
        // Trim old requests
        while let Some(front) = self.store_requests.front() {
            if now.duration_since(*front) > PER_PEER_RATE_WINDOW {
                self.store_requests.pop_front();
            } else {
                break;
            }
        }
        self.store_requests.len() >= PER_PEER_RATE_LIMIT
    }

    /// Record a store request.
    fn record_store(&mut self, value_size: usize) {
        self.bytes_stored = self.bytes_stored.saturating_add(value_size);
        self.entry_count = self.entry_count.saturating_add(1);
        self.store_requests.push_back(Instant::now());
    }

    /// Record an eviction.
    fn record_evict(&mut self, value_size: usize) {
        self.bytes_stored = self.bytes_stored.saturating_sub(value_size);
        self.entry_count = self.entry_count.saturating_sub(1);
    }
}

// ============================================================================
// Store Rejection
// ============================================================================

/// Reason why a store request was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreRejection {
    /// Value exceeds maximum allowed size.
    ValueTooLarge,
    /// Peer has exceeded their storage quota.
    QuotaExceeded,
    /// Peer is sending requests too fast.
    RateLimited,
}

// ============================================================================
// Local Store
// ============================================================================

/// Local key-value store using LRU eviction with pressure-based adaptive behavior.
///
/// Uses an O(1) LRU cache for efficient storage operations and integrates with
/// pressure monitoring for adaptive eviction under resource constraints.
/// Entries automatically expire after [`DEFAULT_TTL`] (24 hours).
///
/// # Storage Exhaustion Protection
///
/// This store implements multiple layers of protection against abuse:
///
/// 1. **Maximum value size**: Rejects values larger than 64 KB
/// 2. **Per-peer quotas**: Each peer can store at most 1 MB / 100 entries
/// 3. **Per-peer rate limiting**: Max 20 store requests per minute per peer
/// 4. **Popularity-based eviction**: Frequently accessed data survives longer
/// 5. **Pressure-based eviction**: Automatic eviction when resources are constrained
pub(crate) struct LocalStore {
    /// LRU cache providing O(1) get, put, and eviction operations.
    cache: LruCache<Key, StoredEntry>,
    /// Pressure monitor for adaptive resource management.
    pub(crate) pressure: PressureMonitor,
    /// Per-peer storage statistics for quota enforcement.
    peer_stats: HashMap<Identity, PeerStorageStats>,
    /// TTL for new entries.
    ttl: Duration,
    /// Last time expiration cleanup was run.
    last_expiration_check: Instant,
    /// Last time peer stats were cleaned up.
    last_peer_cleanup: Instant,
}

impl LocalStore {
    /// Create a new local store with default capacity and TTL.
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

    /// Override default pressure limits for testing or custom configurations.
    pub fn override_limits(&mut self, disk_limit: usize, memory_limit: usize, request_limit: usize) {
        self.pressure.disk_limit = disk_limit;
        self.pressure.memory_limit = memory_limit;
        self.pressure.request_limit = request_limit;
    }

    /// Record an incoming request for rate limiting purposes.
    pub fn record_request(&mut self) {
        self.pressure.record_request();
        self.maybe_expire_entries();
        self.maybe_cleanup_peer_stats();
        let len = self.cache.len();
        self.pressure.update_pressure(len);
    }

    /// Check if a store request should be accepted.
    ///
    /// Returns `Ok(())` if the request is allowed, or `Err(reason)` if rejected.
    pub fn check_store_allowed(&mut self, peer_id: &Identity, value_size: usize) -> Result<(), StoreRejection> {
        // Check 1: Maximum value size
        if value_size > MAX_VALUE_SIZE {
            debug!(
                peer = ?hex::encode(&peer_id.as_bytes()[..8]),
                size = value_size,
                max = MAX_VALUE_SIZE,
                "store rejected: value too large"
            );
            return Err(StoreRejection::ValueTooLarge);
        }

        // Get or create peer stats
        let stats = self.peer_stats.entry(*peer_id).or_default();

        // Check 2: Rate limiting
        if stats.is_rate_limited() {
            debug!(
                peer = ?hex::encode(&peer_id.as_bytes()[..8]),
                "store rejected: rate limited"
            );
            return Err(StoreRejection::RateLimited);
        }

        // Check 3: Per-peer quota
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

    /// Store a key-value pair with per-peer quota and rate limiting.
    ///
    /// Enforces storage exhaustion protections:
    /// - Per-peer rate limiting (prevents rapid-fire STORE attacks)
    /// - Per-peer entry/byte quotas (limits total resources per peer)
    /// - Value size limits (rejects oversized values)
    ///
    /// Returns a list of key-value pairs that were evicted due to pressure.
    pub fn store(&mut self, key: Key, value: &[u8], stored_by: Identity) -> Vec<(Key, Vec<u8>)> {
        // Enforce value size limit
        if value.len() > MAX_VALUE_SIZE {
            warn!(
                size = value.len(),
                limit = MAX_VALUE_SIZE,
                peer = ?stored_by,
                "rejecting oversized value"
            );
            return Vec::new();
        }

        // Check per-peer rate limiting and quotas
        if let Err(rejection) = self.check_store_allowed(&stored_by, value.len()) {
            // Store rejection is useful for observability - promoted to info
            info!(peer = ?stored_by, reason = ?rejection, "store request rejected");
            return Vec::new();
        }

        // If key exists, remove it first to update pressure accounting
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

        // Update peer stats
        let stats = self.peer_stats.entry(stored_by).or_default();
        stats.record_store(entry.value.len());

        self.pressure.record_store(entry.value.len());
        self.cache.put(key, entry);
        self.pressure.update_pressure(self.cache.len());

        self.evict_under_pressure()
    }

    /// Evict entries until pressure is acceptable.
    ///
    /// Uses popularity-aware eviction: unpopular entries (low access_count)
    /// are evicted before popular ones.
    ///
    /// # Safety
    ///
    /// Uses a bounded iteration count to prevent potential infinite loops
    /// in pathological cases where pressure doesn't decrease as expected.
    fn evict_under_pressure(&mut self) -> Vec<(Key, Vec<u8>)> {
        let mut spilled = Vec::new();
        let mut spill_happened = false;
        let mut iterations = 0;

        while self.pressure.current_pressure() > PRESSURE_THRESHOLD {
            // Bound iterations to prevent infinite loop
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

            // First pass: try to evict unpopular entries
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

            // Fallback: evict LRU entry
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

    /// Find an unpopular entry (low access count) for eviction.
    fn find_unpopular_entry(&self) -> Option<Key> {
        self.cache
            .iter()
            .filter(|(_, entry)| entry.access_count < POPULARITY_THRESHOLD)
            .min_by_key(|(_, entry)| (entry.access_count, entry.stored_at))
            .map(|(key, _)| *key)
    }

    /// Get a value by key, promoting it to most-recently-used in O(1) time.
    ///
    /// Returns `None` if the key doesn't exist or has expired.
    /// Increments the access count for popularity tracking.
    pub fn get(&mut self, key: &Key) -> Option<Vec<u8>> {
        let now = Instant::now();
        // Check if entry exists and is not expired
        if let Some(entry) = self.cache.get_mut(key) {
            if now < entry.expires_at {
                entry.access_count = entry.access_count.saturating_add(1);
                return Some(entry.value.clone());
            }
            // Entry has expired - we'll remove it below
        }
        
        // Remove expired entry if it exists
        if let Some(expired) = self.cache.pop(key) {
            self.pressure.record_evict(expired.value.len());
            if let Some(stats) = self.peer_stats.get_mut(&expired.stored_by) {
                stats.record_evict(expired.value.len());
            }
        }
        None
    }

    /// Clean up stale peer stats (peers with no entries).
    fn maybe_cleanup_peer_stats(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_peer_cleanup) < Duration::from_secs(300) {
            // Still check if we're over limit even outside cleanup interval
            if self.peer_stats.len() <= MAX_TRACKED_PEERS {
                return;
            }
        }
        self.last_peer_cleanup = now;

        // Remove peers with no entries and no recent requests
        self.peer_stats.retain(|_, stats| {
            stats.entry_count > 0 || !stats.store_requests.is_empty()
        });
        
        // If still over limit, remove peers with smallest entry counts
        while self.peer_stats.len() > MAX_TRACKED_PEERS {
            // Find peer with smallest footprint (entry_count + bytes_stored)
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
    ///
    /// Called periodically during requests to clean up stale data.
    /// Also updates per-peer statistics when entries expire.
    fn maybe_expire_entries(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_expiration_check) < EXPIRATION_CHECK_INTERVAL {
            return;
        }
        self.last_expiration_check = now;

        // Collect expired keys (we can't modify while iterating)
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

        // Remove expired entries and update peer stats
        if !expired_keys.is_empty() {
            debug!(
                expired_count = expired_keys.len(),
                "removing expired entries"
            );
        }
        for key in expired_keys {
            if let Some(entry) = self.cache.pop(&key) {
                self.pressure.record_evict(entry.value.len());
                // Update peer stats for the node that stored this entry
                if let Some(stats) = self.peer_stats.get_mut(&entry.stored_by) {
                    stats.record_evict(entry.value.len());
                }
            }
        }
    }

    /// Get the current pressure score.
    pub fn current_pressure(&self) -> f32 {
        self.pressure.current_pressure()
    }

    /// Get the current number of stored entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }
}
