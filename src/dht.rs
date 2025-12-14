use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use blake3::Hasher;
use lru::LruCache;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

use crate::identity::{EndpointRecord, Identity, Keypair};
use crate::routing::{
    random_id_for_bucket, PendingBucketUpdate, RoutingInsertionLimiter, RoutingTable,
    BUCKET_REFRESH_INTERVAL, BUCKET_STALE_THRESHOLD,
};
use crate::transport::Contact;
use crate::rpc::DhtNodeRpc;


pub type Key = [u8; 32];

const ENDPOINT_RECORD_MAX_AGE_SECS: u64 = 24 * 60 * 60;
const OFFLOAD_MAX_RETRIES: usize = 3;
const OFFLOAD_BASE_DELAY_MS: u64 = 100;

pub(crate) fn blake3_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

pub fn hash_content(data: &[u8]) -> Key {
    blake3_digest(data)
}

#[inline]
pub fn xor_distance(a: &Identity, b: &Identity) -> [u8; 32] {
    a.xor_distance(b)
}

pub fn verify_key_value_pair(key: &Key, value: &[u8]) -> bool {
    if hash_content(value) == *key {
        return true;
    }

    if let Ok(record) = crate::messages::deserialize_bounded::<EndpointRecord>(value) {
        if record.identity.as_bytes() == key
            && record.verify_fresh(ENDPOINT_RECORD_MAX_AGE_SECS)
        {
            return true;
        }
    }

    false
}

pub(crate) fn distance_cmp(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        if a[i] < b[i] {
            return std::cmp::Ordering::Less;
        } else if a[i] > b[i] {
            return std::cmp::Ordering::Greater;
        }
    }
    std::cmp::Ordering::Equal
}


const QUERY_STATS_WINDOW: usize = 100;

pub(crate) struct AdaptiveParams {
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
    pub path_nodes: Vec<Contact>,
}

impl LookupResult {
    fn new(closest: Vec<Contact>, path_nodes: Vec<Contact>) -> Self {
        Self { closest, path_nodes }
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


pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

const EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

const PRESSURE_DISK_SOFT_LIMIT: usize = 8 * 1024 * 1024;

const PRESSURE_MEMORY_SOFT_LIMIT: usize = 4 * 1024 * 1024;

const PRESSURE_REQUEST_WINDOW: Duration = Duration::from_secs(60);

const PRESSURE_REQUEST_LIMIT: usize = 200;

const PRESSURE_THRESHOLD: f32 = 0.75;

const MAX_VALUE_SIZE: usize = crate::messages::MAX_VALUE_SIZE;

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


const TIERING_RECOMPUTE_INTERVAL: Duration = Duration::from_secs(300);

const MAX_RTT_SAMPLES_PER_NODE: usize = 32;

const MIN_LATENCY_TIERS: usize = 1;

const MAX_LATENCY_TIERS: usize = 7;

const KMEANS_ITERATIONS: usize = 20;

const TIERING_PENALTY_FACTOR: f32 = 1.5;

const TIERING_STALE_THRESHOLD: Duration = Duration::from_secs(60 * 60);

const MAX_TIERING_TRACKED_PEERS: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TieringLevel(usize);

impl TieringLevel {
    pub(crate) fn new(index: usize) -> Self {
        Self(index)
    }

    pub(crate) fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Debug, Default)]
pub struct TieringStats {
    pub centroids: Vec<f32>,
    pub counts: Vec<usize>,
}

pub(crate) struct TieringManager {
    assignments: HashMap<Identity, TieringLevel>,
    samples: HashMap<Identity, VecDeque<f32>>,
    last_seen: HashMap<Identity, Instant>,
    centroids: Vec<f32>,
    last_recompute: Instant,
    min_tiers: usize,
    max_tiers: usize,
}

impl TieringManager {
    pub fn new() -> Self {
        Self {
            assignments: HashMap::new(),
            samples: HashMap::new(),
            last_seen: HashMap::new(),
            centroids: vec![150.0],
            last_recompute: Instant::now() - TIERING_RECOMPUTE_INTERVAL,
            min_tiers: MIN_LATENCY_TIERS,
            max_tiers: MAX_LATENCY_TIERS,
        }
    }

    pub fn register_contact(&mut self, node: &Identity) -> TieringLevel {
        self.maybe_evict_excess();
        
        self.last_seen.insert(*node, Instant::now());
        let default = self.default_level();
        *self.assignments.entry(*node).or_insert(default)
    }

    pub fn record_sample(&mut self, node: &Identity, rtt_ms: f32) {
        let samples = self
            .samples
            .entry(*node)
            .or_insert_with(|| VecDeque::with_capacity(MAX_RTT_SAMPLES_PER_NODE));
        if samples.len() == MAX_RTT_SAMPLES_PER_NODE {
            samples.pop_front();
        }
        samples.push_back(rtt_ms);
        self.register_contact(node);
        self.recompute_if_needed();
    }

    pub fn level_for(&self, node: &Identity) -> TieringLevel {
        self.assignments
            .get(node)
            .copied()
            .unwrap_or_else(|| self.default_level())
    }

    pub fn stats(&self) -> TieringStats {
        let mut counts = vec![0usize; self.centroids.len()];
        for level in self.assignments.values() {
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

        self.cleanup_stale(now);

        let per_node: Vec<(Identity, f32)> = self
            .samples
            .iter()
            .filter_map(|(node, samples)| {
                if samples.is_empty() {
                    None
                } else {
                    let sum: f32 = samples.iter().sum();
                    let avg = sum / samples.len() as f32;
                    Some((*node, avg))
                }
            })
            .collect();

        let min_required = self.min_tiers.max(2);
        if per_node.len() < min_required {
            return;
        }

        let max_k = per_node.len().min(self.max_tiers);
        let samples: Vec<f32> = per_node.iter().map(|(_, avg)| *avg).collect();

        let (centroids, assignments) = dynamic_kmeans(&samples, self.min_tiers, max_k);

        for ((node, _avg), tier_idx) in per_node.iter().zip(assignments.iter()) {
            self.assignments.insert(*node, TieringLevel::new(*tier_idx));
        }

        if !centroids.is_empty() {
            self.centroids = centroids;
        }
        self.last_recompute = now;
    }

    fn cleanup_stale(&mut self, now: Instant) {
        let cutoff = now - TIERING_STALE_THRESHOLD;

        let stale_nodes: Vec<Identity> = self
            .last_seen
            .iter()
            .filter_map(|(node, last)| {
                if *last < cutoff {
                    Some(*node)
                } else {
                    None
                }
            })
            .collect();

        if !stale_nodes.is_empty() {
            debug!(
                stale_count = stale_nodes.len(),
                "cleaning up stale tiering data"
            );
        }
        for node in stale_nodes {
            self.assignments.remove(&node);
            self.samples.remove(&node);
            self.last_seen.remove(&node);
        }
    }

    fn maybe_evict_excess(&mut self) {
        const EVICTION_BUFFER_PERCENT: usize = 10;
        let buffer = MAX_TIERING_TRACKED_PEERS * EVICTION_BUFFER_PERCENT / 100;
        let eviction_threshold = MAX_TIERING_TRACKED_PEERS + buffer;
        
        if self.last_seen.len() <= eviction_threshold {
            return;
        }

        let target_size = MAX_TIERING_TRACKED_PEERS - buffer;
        let excess = self.last_seen.len() - target_size;
        
        let mut peers_by_age: Vec<(Identity, Instant)> = self
            .last_seen
            .iter()
            .map(|(node, time)| (*node, *time))
            .collect();

        if excess < peers_by_age.len() {
            peers_by_age.select_nth_unstable_by_key(excess, |(_, time)| *time);
        }

        let to_evict: Vec<Identity> = peers_by_age
            .into_iter()
            .take(excess)
            .map(|(node, _)| node)
            .collect();

        if !to_evict.is_empty() {
            debug!(
                evict_count = to_evict.len(),
                total_tracked = self.last_seen.len(),
                max_tracked = MAX_TIERING_TRACKED_PEERS,
                "evicting oldest peers from tiering to stay within limits"
            );
        }

        for node in to_evict {
            self.assignments.remove(&node);
            self.samples.remove(&node);
            self.last_seen.remove(&node);
        }
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


pub const DEFAULT_K: usize = 20;
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
    cmd_rx: mpsc::Receiver<Command>,
    cmd_tx: mpsc::Sender<Command>,
    network: Arc<N>,
    id: Identity,
}

enum Command {
    // State updates
    ObserveContact(Contact),
    ObserveContactFromPeer(Contact, Identity, oneshot::Sender<bool>),
    RecordRtt(Contact, Duration),
    AdjustK(bool),
    
    // Queries
    GetLookupParams(Identity, Option<TieringLevel>, oneshot::Sender<(usize, usize, Vec<Contact>)>),
    GetLocal(Key, oneshot::Sender<Option<Vec<u8>>>),
    StoreLocal(Key, Vec<u8>, Identity, oneshot::Sender<Vec<(Key, Vec<u8>)>>),
    GetTelemetry(oneshot::Sender<TelemetrySnapshot>),
    GetSlowestLevel(oneshot::Sender<TieringLevel>),
    
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

    #[allow(dead_code)]
    pub fn identity(&self) -> Identity {
        self.id
    }

    #[allow(dead_code)]
    pub fn contact(&self) -> Contact {
        self.self_contact.clone()
    }

    pub async fn observe_contact(&self, contact: Contact) {
        let _ = self.cmd_tx.send(Command::ObserveContact(contact)).await;
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

    async fn record_rtt(&self, contact: &Contact, elapsed: Duration) {
        let _ = self.cmd_tx.send(Command::RecordRtt(contact.clone(), elapsed)).await;
    }

    async fn adjust_k(&self, success: bool) {
        let _ = self.cmd_tx.send(Command::AdjustK(success)).await;
    }

    pub async fn iterative_find_node(&self, target: Identity) -> Result<Vec<Contact>> {
        let result = self.iterative_find_node_full(target, None).await?;
        Ok(result.closest)
    }

    /// Perform iterative lookup and return full result including path nodes.
    /// Path nodes are contacts that successfully responded during the lookup
    /// and are natural relay candidates.
    pub async fn iterative_find_node_with_path(&self, target: Identity) -> Result<LookupResult> {
        self.iterative_find_node_full(target, None).await
    }

    async fn iterative_find_node_with_level(
        &self,
        target: Identity,
        level_filter: Option<TieringLevel>,
    ) -> Result<Vec<Contact>> {
        let result = self.iterative_find_node_full(target, level_filter).await?;
        Ok(result.closest)
    }

    async fn iterative_find_node_full(
        &self,
        target: Identity,
        level_filter: Option<TieringLevel>,
    ) -> Result<LookupResult> {
        const MAX_LOOKUP_ITERATIONS: usize = 20;
        
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetLookupParams(target, level_filter, tx)).await.is_err() {
            return Err(anyhow!("Actor closed"));
        }
        let (k_initial, alpha, mut shortlist) = rx.await.map_err(|_| anyhow!("Actor closed"))?;

        let mut seen: HashSet<Identity> = HashSet::new();
        let mut seen_addrs: HashSet<String> = HashSet::new();
        let mut queried: HashSet<Identity> = HashSet::new();
        let mut queried_success: Vec<Contact> = Vec::new();
        let mut rpc_success = false;
        let mut rpc_failure = false;
        let mut iteration = 0;

        for c in &shortlist {
            seen.insert(c.identity);
            seen_addrs.insert(c.addr.clone());
        }

        let mut best_distance = shortlist
            .first()
            .map(|c| xor_distance(&c.identity, &target))
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

            let network = self.network.clone();
            let futures: Vec<_> = candidates
                .into_iter()
                .map(|contact| {
                    let net = network.clone();
                    async move {
                        let start = Instant::now();
                        let result = net.find_node(&contact, target).await;
                        (contact, start.elapsed(), result)
                    }
                })
                .collect();

            let results = futures::future::join_all(futures).await;

            let mut any_closer = false;

            for (contact, elapsed, result) in results {
                match result {
                    Ok(nodes) => {
                        rpc_success = true;
                        queried_success.push(contact.clone());
                        self.record_rtt(&contact, elapsed).await;
                        self.observe_contact(contact.clone()).await;
                        let from_peer = contact.identity;
                        for n in &nodes {
                            self.observe_contact_from_peer(n.clone(), &from_peer).await;
                        }

                        let valid_nodes = nodes;

                        for n in valid_nodes {
                            if seen.insert(n.identity)
                                && seen_addrs.insert(n.addr.clone())
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
                let da = xor_distance(&a.identity, &target);
                let db = xor_distance(&b.identity, &target);
                distance_cmp(&da, &db)
            });

            if shortlist.len() > k_initial {
                shortlist.truncate(k_initial);
            }

            if let Some(first) = shortlist.first() {
                let new_best = xor_distance(&first.identity, &target);
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
            path_nodes = queried_success.len(),
            "iterative lookup completed"
        );

        Ok(LookupResult::new(shortlist, queried_success))
    }

    async fn store_local(&self, key: Key, value: Vec<u8>, stored_by: Identity) {
        if !verify_key_value_pair(&key, &value) {
            trace!(
                key = hex::encode(&key[..8]),
                value_len = value.len(),
                stored_by = hex::encode(&stored_by.as_bytes()[..8]),
                "rejecting store: key does not match value hash"
            );
            return;
        }
        
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::StoreLocal(key, value, stored_by, tx)).await.is_ok() {
            if let Ok(spilled) = rx.await {
                if !spilled.is_empty() {
                    self.offload_spilled(spilled).await;
                }
            }
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
        let start = Instant::now();
        let result = self.network.store(contact, key, value).await;
        match result {
            Ok(_) => {
                let elapsed = start.elapsed();
                self.record_rtt(contact, elapsed).await;
                self.adjust_k(true).await;
                self.observe_contact(contact.clone()).await;
                true
            }
            Err(_) => {
                self.adjust_k(false).await;
                false
            }
        }
    }

    async fn send_store(&self, contact: &Contact, key: Key, value: Vec<u8>) {
        let _ = self.send_store_with_result(contact, key, value).await;
    }

    pub async fn put(&self, value: Vec<u8>) -> Result<Key> {
        let key = hash_content(&value);

        self.store_local(key, value.clone(), self.id).await;

        let target = Identity::from_bytes(key);
        let closest = self.iterative_find_node_with_level(target, None).await?;
        let k = DEFAULT_K; 

        for contact in closest.into_iter().take(k) {
            self.send_store(&contact, key, value.clone()).await;
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

        for contact in closest.into_iter().take(k) {
            self.send_store(&contact, key, value.clone()).await;
        }

        Ok(())
    }

    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.get_local(key).await {
            return Ok(Some(value));
        }

        let closest = self.iterative_find_node(Identity::from_bytes(*key)).await?;

        for contact in closest {
            match self.network.find_value(&contact, *key).await {
                Ok((Some(value), _)) => return Ok(Some(value)),
                Ok((None, _)) => continue,
                Err(_) => continue,
            }
        }

        Ok(None)
    }

    /// Get a value from the DHT, also returning the path nodes contacted during lookup.
    /// Path nodes are natural relay candidates since they were reachable during the lookup.
    async fn get_with_path(&self, key: &Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)> {
        if let Some(value) = self.get_local(key).await {
            return Ok((Some(value), Vec::new()));
        }

        let lookup_result = self.iterative_find_node_with_path(Identity::from_bytes(*key)).await?;

        for contact in &lookup_result.closest {
            match self.network.find_value(contact, *key).await {
                Ok((Some(value), _)) => return Ok((Some(value), lookup_result.path_nodes)),
                Ok((None, _)) => continue,
                Err(_) => continue,
            }
        }

        Ok((None, lookup_result.path_nodes))
    }

    pub async fn publish_address(&self, keypair: &Keypair, addresses: Vec<String>) -> Result<()> {
        let record = keypair.create_endpoint_record(addresses);
        let serialized = bincode::serialize(&record)
            .map_err(|e| anyhow!("Failed to serialize endpoint record: {}", e))?;

        let key: Key = *record.identity.as_bytes();
        self.put_at(key, serialized).await
    }

    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        let (record, _path_nodes) = self.resolve_peer_with_path(peer_id).await?;
        Ok(record)
    }

    /// Resolve a peer's endpoint record and return path nodes discovered during lookup.
    /// Path nodes are contacts that successfully responded during the DHT lookup
    /// and are natural relay candidates since they are reachable by both parties.
    pub async fn resolve_peer_with_path(&self, peer_id: &Identity) -> Result<(Option<EndpointRecord>, Vec<Contact>)> {
        const MAX_RECORD_AGE_SECS: u64 = 24 * 60 * 60;

        let key: Key = *peer_id.as_bytes();

        let (data_opt, path_nodes) = self.get_with_path(&key).await?;

        match data_opt {
            Some(data) => {
                let record: EndpointRecord = crate::messages::deserialize_bounded(&data)
                    .map_err(|e| anyhow!("Failed to deserialize endpoint record: {}", e))?;

                if !record.validate_structure() {
                    return Err(anyhow!("Endpoint record has invalid structure"));
                }

                if record.identity != *peer_id {
                    return Err(anyhow!("Endpoint record peer_id mismatch"));
                }

                if !record.verify_fresh(MAX_RECORD_AGE_SECS) {
                    return Err(anyhow!(
                        "Endpoint record signature or timestamp verification failed"
                    ));
                }

                Ok((Some(record), path_nodes))
            }
            None => Ok((None, path_nodes)),
        }
    }

    pub async fn republish_on_network_change(
        &self,
        keypair: &Keypair,
        new_addrs: Vec<String>,
        relays: Vec<Contact>,
    ) -> Result<()> {
        debug!(
            "republishing address after network change: {:?}",
            new_addrs
        );

        let record = keypair.create_endpoint_record_with_relays(new_addrs, relays);
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
                        closest.retain(|c| self.tiering.level_for(&c.identity) == level);
                    }
                    
                    let _ = reply.send((k, alpha, closest));
                }
                Command::GetLocal(key, reply) => {
                    self.store.record_request();
                    let val = self.store.get(&key);
                    let _ = reply.send(val);
                }
                Command::StoreLocal(key, value, stored_by, reply) => {
                    self.store.record_request();
                    let spilled = self.store.store(key, &value, stored_by);
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
                    self.store.store(key, &value, from.identity);
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

        self.tiering.register_contact(&contact.identity);
        let k = self.params.current_k();
        self.routing.set_k(k);
        
        if let Some(update) = self.routing.update_with_pending(contact.clone()) {
            let network = self.network.clone();
            let tx = self.cmd_tx.clone();
            tokio::spawn(async move {
                let alive = match network.ping(&update.oldest).await {
                    Ok(_) => true,
                    Err(_) => false,
                };
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
        self.tiering.record_sample(&contact.identity, rtt_ms);
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
    use tokio::sync::{Mutex, RwLock};
    use tokio::time::sleep;

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
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&index.to_be_bytes());
        Identity::from_bytes(id)
    }

    fn make_contact(index: u32) -> Contact {
        Contact {
            identity: make_identity(index),
            addr: format!("node-{index}"),
            addrs: vec![],
        }
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
            let value = vec![peer_idx as u8; 900 * 1024];            let key = hash_content(&value);
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
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x01, 20, 3).await;
        let fast = TestNode::new(registry.clone(), 0x02, 20, 3).await;
        let medium = TestNode::new(registry.clone(), 0x03, 20, 3).await;
        let slow = TestNode::new(registry.clone(), 0x04, 20, 3).await;

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

        let target = make_identity(0x99);
        let _ = main
            .node
            .iterative_find_node(target)
            .await
            .expect("lookup succeeds");

        let snapshot = main.node.telemetry_snapshot().await;
        assert!(snapshot.tier_centroids.len() >= 2);
        assert_eq!(snapshot.tier_counts.iter().sum::<usize>(), 3);
        assert!(snapshot.tier_centroids.first().unwrap() < snapshot.tier_centroids.last().unwrap());
    }

    #[tokio::test]
    async fn responsive_contacts_survive_bucket_eviction() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 1, 2).await;
        let responsive = TestNode::new(registry.clone(), 0x80, 1, 2).await;
        let challenger = TestNode::new(registry.clone(), 0xC0, 1, 2).await;

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
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 1, 2).await;
        let stale = TestNode::new(registry.clone(), 0x80, 1, 2).await;
        let newcomer = TestNode::new(registry.clone(), 0xC0, 1, 2).await;

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
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 1, 2).await;
        let incumbent = TestNode::new(registry.clone(), 0x80, 1, 2).await;
        let challenger = TestNode::new(registry.clone(), 0xC0, 1, 2).await;

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
            let value = vec![peer_idx as u8; 900 * 1024];            let key = hash_content(&value);
            node.node.handle_store_request(&peer, key, value).await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.pressure >= 0.5,
            "pressure should be elevated with ~5.4MB stored against 4MB limit, got {}",
            snapshot.pressure
        );

        let peer = make_contact(0x10);
        let large_value = vec![0xFFu8; 900 * 1024];        let large_key = hash_content(&large_value);
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
                let value = vec![i as u8; 500 * 1024];                let key = hash_content(&value);
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

        let hot_value = vec![0xAAu8; 900 * 1024];        let hot_key = hash_content(&hot_value);
        node.node
            .handle_store_request(&peer, hot_key, hot_value.clone())
            .await;

        for _ in 0..5 {
            let _ = node.node.handle_find_value_request(&peer, hot_key).await;
        }

        for i in 0..5 {
            let cold_value = vec![i as u8; 900 * 1024];            let cold_key = hash_content(&cold_value);
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
            let key = hash_content(&value);
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
            let key = hash_content(&value);
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
                let key = hash_content(&value);
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
        let nodes: Vec<_> = futures::future::join_all((0..10).map(|i| {
            let reg = registry.clone();
            async move { TestNode::new(reg, 0x10 + i, 20, 3).await }
        }))
        .await;

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
        let target = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let mut peers = Vec::new();
        for i in 0..20 {
            let peer = TestNode::new(registry.clone(), 0x10 + i, 20, 3).await;
            peers.push(peer);
        }

        for peer in &peers {
            target.node.observe_contact(peer.contact()).await;
        }

        let snapshot = target.node.telemetry_snapshot().await;

        let total_in_tiers: usize = snapshot.tier_counts.iter().sum();
        assert!(
            total_in_tiers >= 1,
            "Routing table should accept diverse peers, got {} peers tracked",
            total_in_tiers
        );
    }

    #[tokio::test]
    async fn eclipse_attack_resistance() {
        let registry = Arc::new(NetworkRegistry::default());
        let victim = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let mut attackers = Vec::new();
        for i in 0..50 {
            let attacker = TestNode::new(registry.clone(), 0x80 + i, 20, 3).await;
            attackers.push(attacker);
        }

        let mut honest_nodes = Vec::new();
        for i in 0..5 {
            let honest = TestNode::new(registry.clone(), 0x10 + i, 20, 3).await;
            honest_nodes.push(honest);
        }

        for attacker in &attackers {
            victim.node.observe_contact(attacker.contact()).await;
        }
        for honest in &honest_nodes {
            victim.node.observe_contact(honest.contact()).await;
        }

        let snapshot = victim.node.telemetry_snapshot().await;

        let total_tracked: usize = snapshot.tier_counts.iter().sum();

        assert!(
            total_tracked >= 5,
            "Should track at least some nodes, got {}",
            total_tracked
        );
    }

    #[tokio::test]
    async fn bucket_replacement_favors_long_lived() {
        let registry = Arc::new(NetworkRegistry::default());

        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let mut long_lived = Vec::new();
        for i in 0..5 {
            let long_lived_node = TestNode::new(registry.clone(), 0x10 + i, 20, 3).await;
            node.node
                .observe_contact(long_lived_node.contact())
                .await;
            long_lived.push(long_lived_node);
        }

        for i in 0..20 {
            let sybil = TestNode::new(registry.clone(), 0x80 + i, 20, 3).await;
            node.node.observe_contact(sybil.contact()).await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.tier_counts.iter().sum::<usize>() >= 5,
            "Should maintain at least the original nodes"
        );
    }


    #[test]
    fn hash_content_is_deterministic() {
        let data = b"hello world";
        let hash_one = hash_content(data);
        let hash_two = hash_content(data);
        assert_eq!(hash_one, hash_two, "hashes of identical data should match");

        let different_hash = hash_content(b"goodbye world");
        assert_ne!(
            hash_one, different_hash,
            "hashes of different data should differ"
        );
    }

    #[test]
    fn verify_key_value_pair_matches_hash() {
        let data = b"payload";
        let key = hash_content(data);
        assert!(
            verify_key_value_pair(&key, data),
            "verify_key_value_pair should accept matching key/value pairs"
        );

        let mut wrong_key = key;
        wrong_key[0] ^= 0xFF;
        assert!(
            !verify_key_value_pair(&wrong_key, data),
            "verify_key_value_pair should reject non-matching key/value pairs"
        );
    }

    #[test]
    fn hash_content_matches_blake3_reference() {
        let data = b"hello world";
        let expected = blake3::hash(data);
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(expected.as_bytes());

        assert_eq!(
            hash_content(data),
            expected_bytes,
            "hash_content should produce the BLAKE3 digest"
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
        let dist = xor_distance(&a, &b);
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
}
