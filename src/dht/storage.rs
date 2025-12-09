use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use lru::LruCache;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::identity::Identity;
use super::hash::Key;

pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

const EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

const PRESSURE_DISK_SOFT_LIMIT: usize = 8 * 1024 * 1024;

const PRESSURE_MEMORY_SOFT_LIMIT: usize = 4 * 1024 * 1024;

const PRESSURE_REQUEST_WINDOW: Duration = Duration::from_secs(60);

const PRESSURE_REQUEST_LIMIT: usize = 200;

const PRESSURE_THRESHOLD: f32 = 0.75;

const MAX_VALUE_SIZE: usize = crate::dht::messages::MAX_VALUE_SIZE;

const PER_PEER_STORAGE_QUOTA: usize = 1024 * 1024;

const PER_PEER_ENTRY_LIMIT: usize = 100;

const PER_PEER_RATE_LIMIT: usize = 20;

const PER_PEER_RATE_WINDOW: Duration = Duration::from_secs(60);

const POPULARITY_THRESHOLD: u32 = 3;

const MAX_TRACKED_PEERS: usize = 10_000;

const LOCAL_STORE_MAX_ENTRIES: usize = 100_000;

const MAX_EVICTION_ITERATIONS: usize = 10_000;

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

#[derive(Clone)]
pub(crate) struct StoredEntry {
    pub value: Vec<u8>,
    pub expires_at: Instant,
    pub stored_by: Identity,
    pub access_count: u32,
    pub stored_at: Instant,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreRejection {
    ValueTooLarge,
    QuotaExceeded,
    RateLimited,
}

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

    pub fn override_limits(&mut self, disk_limit: usize, memory_limit: usize, request_limit: usize) {
        self.pressure.disk_limit = disk_limit;
        self.pressure.memory_limit = memory_limit;
        self.pressure.request_limit = request_limit;
    }

    pub fn record_request(&mut self) {
        self.pressure.record_request();
        self.maybe_expire_entries();
        self.maybe_cleanup_peer_stats();
        let len = self.cache.len();
        self.pressure.update_pressure(len);
    }

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

    fn find_unpopular_entry(&self) -> Option<Key> {
        self.cache
            .iter()
            .filter(|(_, entry)| entry.access_count < POPULARITY_THRESHOLD)
            .min_by_key(|(_, entry)| (entry.access_count, entry.stored_at))
            .map(|(key, _)| *key)
    }

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

    fn maybe_cleanup_peer_stats(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_peer_cleanup) < Duration::from_secs(300) {
            if self.peer_stats.len() <= MAX_TRACKED_PEERS {
                return;
            }
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

    pub fn current_pressure(&self) -> f32 {
        self.pressure.current_pressure()
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }
}
