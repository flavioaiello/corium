//! Core DHT logic: transport-agnostic Kademlia implementation with adaptive tiering.
//!
//! This module contains the fundamental building blocks of the sloppy DHT:
//!
//! - **Identity & Hashing**: [`Identity`], [`Key`], [`hash_content`]
//! - **Distance Metrics**: [`xor_distance`] for Kademlia-style routing
//! - **Routing**: [`RoutingTable`], [`Contact`] for peer management
//! - **Storage**: Local content-addressable store with LRU eviction and backpressure
//! - **Tiering**: Latency-based peer classification using k-means clustering
//! - **Adaptive Parameters**: Dynamic `k` adjustment based on network churn
//! - **Node State Machine**: [`DhtNode`] for DHT operations

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::identity::Keypair;
use crate::identity::EndpointRecord;
use async_trait::async_trait;
use blake3::Hasher;
use lru::LruCache;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

// ============================================================================
// Type Aliases & Re-exports
// ============================================================================

// Re-export Identity from identity module for use throughout the crate
use crate::identity::Identity;

/// A 256-bit content-addressed key for stored values.
///
/// Keys are computed as the BLAKE3 hash of the content, providing
/// content-addressable storage with built-in integrity verification.
pub type Key = [u8; 32];

/// Check if an Identity is valid (not a placeholder or obviously invalid).
///
/// # Security
///
/// Used to prevent routing table pollution from placeholder IDs.
/// Returns false for:
/// - All-zeros (placeholder for unknown peers)
/// - All-ones (reserved/invalid)
#[inline]
pub fn is_valid_identity(id: &Identity) -> bool {
    let bytes = id.as_bytes();
    // Check for all-zeros (placeholder)
    if bytes.iter().all(|&b| b == 0) {
        return false;
    }
    // Check for all-ones (reserved/invalid)
    if bytes.iter().all(|&b| b == 0xFF) {
        return false;
    }
    true
}

// ============================================================================
// Configuration Constants
// ============================================================================

/// How often to recompute latency tier assignments (5 minutes).
const TIERING_RECOMPUTE_INTERVAL: Duration = Duration::from_secs(300);

/// Maximum RTT samples retained per node for latency averaging.
const MAX_RTT_SAMPLES_PER_NODE: usize = 32;

/// Minimum number of latency tiers to maintain.
const MIN_LATENCY_TIERS: usize = 1;

/// Maximum number of latency tiers (prevents over-fragmentation).
const MAX_LATENCY_TIERS: usize = 7;

/// Number of iterations for k-means clustering convergence.
const KMEANS_ITERATIONS: usize = 20;

/// Penalty factor to discourage excessive tier count in k-means.
/// Higher values favor fewer, larger tiers.
const TIERING_PENALTY_FACTOR: f32 = 1.5;

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

/// Sliding window size for tracking RPC success/failure for adaptive `k`.
const QUERY_STATS_WINDOW: usize = 100;

/// Default TTL for stored data (24 hours, per Kademlia spec).
const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How often to run the expiration cleanup task.
const EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Duration after which tiering data for a node is considered stale (24 hours).
/// Nodes not seen within this period have their tiering data removed.
const TIERING_STALE_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);

/// How often to run the bucket refresh task.
const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Duration after which a bucket is considered stale and needs refresh.
const BUCKET_STALE_THRESHOLD: Duration = Duration::from_secs(30 * 60);

// ============================================================================
// Storage Exhaustion Protection Constants
// ============================================================================

/// Maximum size of a single stored value (1 MB).
/// Prevents memory exhaustion from large value attacks.
const MAX_VALUE_SIZE: usize = crate::protocol::MAX_VALUE_SIZE;

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

/// Maximum number of peers to track for latency tiering.
///
/// # Security
///
/// Prevents memory exhaustion from tracking too many peers in the tiering
/// system. When this limit is reached, the oldest (least recently seen)
/// peers are evicted to make room for new ones.
const MAX_TIERING_TRACKED_PEERS: usize = 10_000;

/// Maximum iterations for the eviction loop.
///
/// Prevents potential infinite loop in pathological cases where
/// pressure calculation doesn't decrease despite evictions.
/// Set to a high value that should never be reached in normal operation.
const MAX_EVICTION_ITERATIONS: usize = 10_000;

// ============================================================================
// Per-Peer Routing Table Insertion Rate Limiting
// ============================================================================

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
// Hashing Functions
// ============================================================================

/// Compute a 32-byte BLAKE3 digest of the input data.
fn blake3_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// Compute a content-addressed key as the BLAKE3 hash of content bytes.
///
/// This is the standard way to derive a DHT key for storing content:
///
/// ```
/// use corium::hash_content;
///
/// let content = b"hello world";
/// let key = hash_content(content);
/// // The same content always produces the same key
/// assert_eq!(key, hash_content(content));
/// ```
pub fn hash_content(data: &[u8]) -> Key {
    blake3_digest(data)
}

/// Compute XOR distance between two Identities for DHT routing.
///
/// # Zero-Hash Property
/// In the zero-hash architecture, XOR distance is computed directly
/// on Identity bytes (which ARE the public key bytes).
#[inline]
pub fn xor_distance(a: &Identity, b: &Identity) -> [u8; 32] {
    a.xor_distance(b)
}

/// Maximum age for EndpointRecords to prevent replay attacks (24 hours).
const ENDPOINT_RECORD_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Verify that a key matches the hash of a value.
///
/// Used to validate content integrity after retrieval:
///
/// ```
/// use corium::{hash_content, verify_key_value_pair};
///
/// let content = b"my data";
/// let key = hash_content(content);
/// assert!(verify_key_value_pair(&key, content));
/// assert!(!verify_key_value_pair(&key, b"wrong data"));
/// ```
///
/// # Security
///
/// For EndpointRecords, this function verifies both the cryptographic signature
/// AND timestamp freshness to prevent replay attacks where attackers re-publish
/// old records to redirect traffic to stale addresses.
pub fn verify_key_value_pair(key: &Key, value: &[u8]) -> bool {
    // 1. Check strict content addressing (immutable data)
    if hash_content(value) == *key {
        return true;
    }

    // 2. Check for signed EndpointRecord (mutable identity data)
    // Try to deserialize as EndpointRecord
    if let Ok(record) = crate::protocol::deserialize_bounded::<EndpointRecord>(value) {
        // Check if the record belongs to the key (key == Identity bytes in zero-hash)
        if record.identity.as_bytes() == key {
            // Verify the signature AND timestamp freshness to prevent replay attacks
            // Old records with valid signatures should be rejected to prevent
            // attackers from redirecting traffic to stale/controlled addresses
            if record.verify_fresh(ENDPOINT_RECORD_MAX_AGE_SECS) {
                return true;
            }
        }
    }

    false
}

// ============================================================================
// Distance Metrics
// ============================================================================

/// Compare two XOR distances lexicographically.
///
/// Returns `Ordering::Less` if `a` represents a smaller distance,
/// `Ordering::Greater` if larger, or `Ordering::Equal` if identical.
fn distance_cmp(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        if a[i] < b[i] {
            return std::cmp::Ordering::Less;
        } else if a[i] > b[i] {
            return std::cmp::Ordering::Greater;
        }
    }
    std::cmp::Ordering::Equal
}

// ============================================================================
// Latency Tiering
// ============================================================================

/// A tier assignment for a node based on observed latency.
///
/// Lower tier indices represent faster (lower latency) peers.
/// Tier 0 is the fastest tier, and the highest index is the slowest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TieringLevel(usize);

impl TieringLevel {
    /// Create a new tiering level with the given index.
    fn new(index: usize) -> Self {
        Self(index)
    }

    /// Get the numeric index of this tier (0 = fastest).
    fn index(self) -> usize {
        self.0
    }
}

/// Statistics about the current latency tier distribution.
#[derive(Clone, Debug, Default)]
pub struct TieringStats {
    /// Centroid latencies for each tier in milliseconds (sorted fastest to slowest).
    pub centroids: Vec<f32>,
    /// Number of peers assigned to each tier.
    pub counts: Vec<usize>,
}

/// Manages latency-based tiering of DHT peers using k-means clustering.
///
/// The tiering manager:
/// 1. Collects RTT samples from RPC interactions
/// 2. Periodically recomputes tier assignments using k-means
/// 3. Assigns new contacts to a default middle tier
/// 4. Cleans up stale data for nodes not seen in 24 hours
///
/// This enables latency-aware routing where fast peers are preferred.
struct TieringManager {
    /// Current tier assignment for each known node.
    assignments: HashMap<Identity, TieringLevel>,
    /// Rolling RTT samples per node (up to MAX_RTT_SAMPLES_PER_NODE).
    samples: HashMap<Identity, VecDeque<f32>>,
    /// Last time each node was observed (for stale data cleanup).
    last_seen: HashMap<Identity, Instant>,
    /// Current tier centroids in milliseconds (sorted fastest to slowest).
    centroids: Vec<f32>,
    /// Timestamp of last tier recomputation.
    last_recompute: Instant,
    /// Minimum number of tiers to maintain.
    min_tiers: usize,
    /// Maximum number of tiers allowed.
    max_tiers: usize,
}

impl TieringManager {
    /// Create a new tiering manager with default settings.
    fn new() -> Self {
        Self {
            assignments: HashMap::new(),
            samples: HashMap::new(),
            last_seen: HashMap::new(),
            // Start with a single tier at 150ms as a reasonable default
            centroids: vec![150.0],
            last_recompute: Instant::now() - TIERING_RECOMPUTE_INTERVAL,
            min_tiers: MIN_LATENCY_TIERS,
            max_tiers: MAX_LATENCY_TIERS,
        }
    }

    /// Register a contact and assign it to the default tier if new.
    /// Updates the last_seen timestamp for the node.
    ///
    /// # Security
    ///
    /// Evicts oldest peers if we're over the tracking limit to prevent
    /// memory exhaustion from unbounded peer accumulation.
    fn register_contact(&mut self, node: &Identity) -> TieringLevel {
        // Evict excess peers before adding new ones
        self.maybe_evict_excess();
        
        self.last_seen.insert(*node, Instant::now());
        let default = self.default_level();
        *self.assignments.entry(*node).or_insert(default)
    }

    /// Record an RTT sample for a node and trigger recomputation if due.
    fn record_sample(&mut self, node: &Identity, rtt_ms: f32) {
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

    /// Get the current tier level for a node.
    fn level_for(&self, node: &Identity) -> TieringLevel {
        self.assignments
            .get(node)
            .copied()
            .unwrap_or_else(|| self.default_level())
    }

    /// Get current tiering statistics including centroids and node counts per tier.
    fn stats(&self) -> TieringStats {
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

    /// Recompute tier assignments using k-means clustering if the recompute interval has elapsed.
    ///
    /// This method:
    /// 1. Cleans up stale node data (not seen in 24 hours)
    /// 2. Computes average RTT for each node from collected samples
    /// 3. Runs dynamic k-means to find optimal tier centroids
    /// 4. Reassigns all nodes to their closest tier
    fn recompute_if_needed(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_recompute) < TIERING_RECOMPUTE_INTERVAL {
            return;
        }

        // Clean up stale tiering data before recomputation
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

    /// Remove tiering data for nodes not seen within the stale threshold.
    ///
    /// This prevents unbounded memory growth from accumulating data for
    /// nodes that have left the network or are no longer reachable.
    fn cleanup_stale(&mut self, now: Instant) {
        let cutoff = now - TIERING_STALE_THRESHOLD;

        // Collect stale node IDs
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

        // Remove stale data from all maps
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

    /// Evict oldest peers if we're over the tracking limit.
    ///
    /// # Security
    ///
    /// Prevents memory exhaustion from unbounded peer accumulation.
    /// Evicts peers that were seen least recently, preferring to keep
    /// recently active peers in the tiering system.
    ///
    /// # Performance
    ///
    /// Uses batch eviction with O(n) partial selection instead of O(n log n) sort.
    /// Eviction only triggers when 10% over capacity, amortizing the cost.
    fn maybe_evict_excess(&mut self) {
        // Use a 10% buffer to avoid evicting on every registration at capacity.
        // This amortizes the O(n) eviction cost across multiple registrations.
        const EVICTION_BUFFER_PERCENT: usize = 10;
        let buffer = MAX_TIERING_TRACKED_PEERS * EVICTION_BUFFER_PERCENT / 100;
        let eviction_threshold = MAX_TIERING_TRACKED_PEERS + buffer;
        
        // Check if we're over the threshold (not just at capacity)
        if self.last_seen.len() <= eviction_threshold {
            return;
        }

        // Evict back down to 90% of capacity to provide room for new entries
        let target_size = MAX_TIERING_TRACKED_PEERS - buffer;
        let excess = self.last_seen.len() - target_size;
        
        // Collect (node, last_seen) pairs
        let mut peers_by_age: Vec<(Identity, Instant)> = self
            .last_seen
            .iter()
            .map(|(node, time)| (*node, *time))
            .collect();

        // Use partial sort: O(n) to find the `excess` oldest elements
        // This avoids O(n log n) full sort when we only need the oldest few
        if excess < peers_by_age.len() {
            // select_nth_unstable partitions so elements before index are <= element at index
            peers_by_age.select_nth_unstable_by_key(excess, |(_, time)| *time);
        }

        // Evict the oldest peers (first `excess` elements after partial sort)
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

    /// Get the default tier level (middle tier) for new nodes without samples.
    fn default_level(&self) -> TieringLevel {
        if self.centroids.is_empty() {
            return TieringLevel::new(0);
        }
        TieringLevel::new(self.centroids.len() / 2)
    }

    /// Get the slowest (highest latency) tier level.
    fn slowest_level(&self) -> TieringLevel {
        if self.centroids.is_empty() {
            TieringLevel::new(0)
        } else {
            TieringLevel::new(self.centroids.len() - 1)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// K-means Clustering for Latency Tiering
// ─────────────────────────────────────────────────────────────────────────────

/// Run dynamic k-means clustering to find the optimal number of tiers.
///
/// Uses a BIC-like penalty to balance cluster fit against model complexity.
/// Returns (centroids sorted by latency, tier assignments for each sample).
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

        // Penalize more clusters using BIC-like criterion
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

/// Run k-means clustering with a fixed number of clusters.
///
/// Returns (centroids, assignments, inertia) where inertia is the sum of squared
/// distances from samples to their assigned centroids.
fn run_kmeans(samples: &[f32], k: usize) -> (Vec<f32>, Vec<usize>, f32) {
    let mut centroids = initialize_centroids(samples, k);
    let mut assignments = vec![0usize; samples.len()];

    for _ in 0..KMEANS_ITERATIONS {
        let mut changed = false;
        let mut sums = vec![0.0f32; k];
        let mut counts = vec![0usize; k];

        // Assign each sample to the nearest centroid
        for (idx, sample) in samples.iter().enumerate() {
            let nearest = nearest_center_scalar(*sample, &centroids);
            if assignments[idx] != nearest {
                assignments[idx] = nearest;
                changed = true;
            }
            sums[nearest] += sample;
            counts[nearest] += 1;
        }

        // Update centroids to mean of assigned samples
        for i in 0..k {
            if counts[i] > 0 {
                centroids[i] = sums[i] / counts[i] as f32;
            }
        }

        if !changed {
            break;
        }
    }

    // Reinitialize empty tiers if any
    ensure_tier_coverage(samples, &mut centroids, &mut assignments);

    // Compute inertia and sort centroids to enforce ordering from fastest to slowest.
    let mut inertia = 0.0f32;
    for (sample, idx) in samples.iter().zip(assignments.iter()) {
        let diff = sample - centroids[*idx];
        inertia += diff * diff;
    }

    // Sort centroids and remap assignments to maintain tier ordering
    // Use total_cmp for NaN-safe comparison (NaN sorts to end)
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

/// Ensure all tiers have at least one node by redistributing empty centroids.
///
/// If any tier is empty after k-means, this reinitializes its centroid to an
/// evenly-spaced position in the latency distribution and reassigns samples.
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
    // Use total_cmp for NaN-safe comparison
    sorted_samples.sort_by(|a, b| a.total_cmp(b));

    // Reinitialize empty tier centroids to evenly-spaced percentile positions
    for (tier_idx, count) in counts.iter_mut().enumerate() {
        if *count == 0 {
            let pos = ((tier_idx as f32 + 0.5) / k as f32 * (sorted_samples.len() - 1) as f32)
                .round() as usize;
            centroids[tier_idx] = sorted_samples[pos];
        }
    }

    // Reassign all samples to nearest centroid after redistribution
    for (sample_idx, sample) in samples.iter().enumerate() {
        let nearest = nearest_center_scalar(*sample, centroids);
        assignments[sample_idx] = nearest;
    }
}

/// Initialize k-means centroids using uniform percentile spacing.
///
/// Centroids are placed at evenly-spaced positions across the sorted sample
/// distribution to ensure good initial coverage.
fn initialize_centroids(samples: &[f32], k: usize) -> Vec<f32> {
    let mut sorted = samples.to_vec();
    // Use total_cmp for NaN-safe comparison
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

/// Find the index of the nearest centroid to a given value.
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

// ─────────────────────────────────────────────────────────────────────────────
// Pressure Monitoring and Rate Limiting
// ─────────────────────────────────────────────────────────────────────────────

/// Monitors system pressure to prevent resource exhaustion.
///
/// Tracks memory usage, disk usage, and request rates to compute a composite
/// pressure score used for adaptive rate limiting and request rejection.
struct PressureMonitor {
    /// Current estimated memory usage in bytes.
    current_bytes: usize,
    /// Sliding window of recent request timestamps.
    requests: VecDeque<Instant>,
    /// Duration of the request rate window.
    request_window: Duration,
    /// Maximum requests allowed per window.
    request_limit: usize,
    /// Maximum disk storage in bytes.
    disk_limit: usize,
    /// Maximum memory usage in bytes.
    memory_limit: usize,
    /// Current composite pressure score (0.0 = no pressure, 1.0 = critical).
    current_pressure: f32,
}

impl PressureMonitor {
    /// Create a new pressure monitor with default limits.
    fn new() -> Self {
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
    fn record_store(&mut self, bytes: usize) {
        self.current_bytes = self.current_bytes.saturating_add(bytes);
    }

    /// Record bytes removed from storage via eviction.
    fn record_evict(&mut self, bytes: usize) {
        self.current_bytes = self.current_bytes.saturating_sub(bytes);
    }

    /// Record a disk spill event, indicating critical pressure.
    fn record_spill(&mut self) {
        self.current_pressure = 1.0;
    }

    /// Record an incoming request for rate limiting.
    fn record_request(&mut self) {
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
    fn update_pressure(&mut self, stored_keys: usize) {
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
    fn current_pressure(&self) -> f32 {
        self.current_pressure
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Local Key-Value Storage
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of entries in the LRU cache.
/// This is a reasonable default; pressure-based eviction may kick in earlier.
const LOCAL_STORE_MAX_ENTRIES: usize = 100_000;

/// A stored entry with its value and expiration timestamp.
#[derive(Clone)]
struct StoredEntry {
    /// The stored value.
    value: Vec<u8>,
    /// When this entry expires and should be deleted.
    expires_at: Instant,
    /// Identity of the peer that stored this entry (for per-peer quota tracking).
    stored_by: Identity,
    /// Number of times this entry has been accessed (for popularity-based eviction).
    access_count: u32,
    /// When this entry was stored.
    stored_at: Instant,
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
struct LocalStore {
    /// LRU cache providing O(1) get, put, and eviction operations.
    cache: LruCache<Key, StoredEntry>,
    /// Pressure monitor for adaptive resource management.
    pressure: PressureMonitor,
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
    fn new() -> Self {
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
    fn override_limits(&mut self, disk_limit: usize, memory_limit: usize, request_limit: usize) {
        self.pressure.disk_limit = disk_limit;
        self.pressure.memory_limit = memory_limit;
        self.pressure.request_limit = request_limit;
    }

    /// Record an incoming request for rate limiting purposes.
    fn record_request(&mut self) {
        self.pressure.record_request();
        self.maybe_expire_entries();
        self.maybe_cleanup_peer_stats();
        let len = self.cache.len();
        self.pressure.update_pressure(len);
    }

    /// Check if a store request should be accepted.
    ///
    /// Returns `Ok(())` if the request is allowed, or `Err(reason)` if rejected.
    fn check_store_allowed(&mut self, peer_id: &Identity, value_size: usize) -> Result<(), StoreRejection> {
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

    /// Store a key-value pair with per-peer quota enforcement.
    /// Store a key-value pair with per-peer quota and rate limiting.
    ///
    /// Enforces storage exhaustion protections:
    /// - Per-peer rate limiting (prevents rapid-fire STORE attacks)
    /// - Per-peer entry/byte quotas (limits total resources per peer)
    /// - Value size limits (rejects oversized values)
    ///
    /// Returns a list of key-value pairs that were evicted due to pressure.
    fn store(&mut self, key: Key, value: &[u8], stored_by: Identity) -> Vec<(Key, Vec<u8>)> {
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
    fn get(&mut self, key: &Key) -> Option<Vec<u8>> {
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
    fn current_pressure(&self) -> f32 {
        self.pressure.current_pressure()
    }

    /// Get the current number of stored entries.
    fn len(&self) -> usize {
        self.cache.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptive Parameters
// ─────────────────────────────────────────────────────────────────────────────

/// Adaptive parameters for DHT operations based on network conditions.
///
/// Dynamically adjusts:
/// - **k** (bucket size): 10-30, increases with churn rate for routing resilience
/// - **α** (parallelism): 2-5, increases with failure rate to improve lookup success
struct AdaptiveParams {
    /// Current k parameter (bucket size), ranges from 10 to 30.
    k: usize,
    /// Parallelism factor for lookups, ranges from 2 to 5.
    alpha: usize,
    /// Sliding window of recent churn observations (true = success, false = failure).
    churn_history: VecDeque<bool>,
}

impl AdaptiveParams {
    /// Create new adaptive parameters with initial k and alpha values.
    fn new(k: usize, alpha: usize) -> Self {
        Self {
            k,
            alpha: alpha.clamp(2, 5),
            churn_history: VecDeque::new(),
        }
    }

    /// Record a churn observation and update k and alpha if needed.
    ///
    /// Returns true if k was changed.
    fn record_churn(&mut self, success: bool) -> bool {
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

    /// Recompute k based on observed churn rate.
    ///
    /// Higher churn rates result in larger k values to maintain routing table resilience.
    /// k ranges from 10 (low churn) to 30 (high churn).
    fn update_k(&mut self) {
        if self.churn_history.is_empty() {
            return;
        }
        let failures = self.churn_history.iter().filter(|entry| !**entry).count();
        let churn_rate = failures as f32 / self.churn_history.len() as f32;
        let new_k = (10.0 + (20.0 * churn_rate).round()).clamp(10.0, 30.0);
        self.k = new_k as usize;
    }

    /// Recompute alpha based on observed failure rate.
    ///
    /// Higher failure rates result in larger alpha values to improve lookup success
    /// by querying more nodes in parallel. Alpha ranges from 2 (healthy) to 5 (degraded).
    fn update_alpha(&mut self) {
        if self.churn_history.is_empty() {
            return;
        }
        let failures = self.churn_history.iter().filter(|entry| !**entry).count();
        let failure_rate = failures as f32 / self.churn_history.len() as f32;
        // α = 2 at 0% failures, α = 5 at 100% failures
        let new_alpha = (2.0 + (3.0 * failure_rate).round()).clamp(2.0, 5.0);
        self.alpha = new_alpha as usize;
    }

    /// Get the current k parameter.
    fn current_k(&self) -> usize {
        self.k
    }

    /// Get the current alpha (parallelism) parameter.
    fn current_alpha(&self) -> usize {
        self.alpha
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Telemetry and Diagnostics
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot of current DHT node state for telemetry and debugging.
#[derive(Clone, Debug, Default)]
pub struct TelemetrySnapshot {
    /// Current latency tier centroids in milliseconds.
    pub tier_centroids: Vec<f32>,
    /// Number of nodes in each tier.
    pub tier_counts: Vec<usize>,
    /// Current resource pressure (0.0 to 1.0).
    pub pressure: f32,
    /// Number of key-value pairs in local storage.
    pub stored_keys: usize,
    /// Current replication factor (k parameter).
    pub replication_factor: usize,
    /// Current lookup concurrency (alpha parameter).
    pub concurrency: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-Peer Routing Insertion Rate Limiter
// ─────────────────────────────────────────────────────────────────────────────

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
struct RoutingInsertionLimiter {
    /// Per-peer token buckets.
    buckets: LruCache<Identity, RoutingInsertionBucket>,
}

impl RoutingInsertionLimiter {
    /// Create a new rate limiter.
    fn new() -> Self {
        Self {
            buckets: LruCache::new(
                NonZeroUsize::new(MAX_ROUTING_INSERTION_TRACKED_PEERS).unwrap()
            ),
        }
    }

    /// Check if a contact insertion from a peer is allowed.
    /// Returns true if under rate limit, false if should reject.
    fn allow_insertion(&mut self, from_peer: &Identity) -> bool {
        let bucket = self.buckets.get_or_insert_mut(*from_peer, RoutingInsertionBucket::new);
        bucket.try_consume()
    }
    
    /// Get the number of remaining tokens for a peer (for testing/debugging).
    #[cfg(test)]
    fn remaining_tokens(&mut self, peer: &Identity) -> f64 {
        if let Some(bucket) = self.buckets.get(peer) {
            bucket.tokens
        } else {
            ROUTING_INSERTION_PER_PEER_LIMIT as f64
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Routing Table
// ─────────────────────────────────────────────────────────────────────────────

/// Find the bucket index for an identity relative to self.
///
/// Uses the XOR distance to determine which bucket a node belongs to.
/// The bucket index is the position of the first differing bit (0..=255).
/// Bucket 0 is the furthest (most different), bucket 255 is the closest.
fn bucket_index(self_id: &Identity, other: &Identity) -> usize {
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
fn random_id_for_bucket(self_id: &Identity, bucket_idx: usize) -> Identity {
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
struct PendingBucketUpdate {
    bucket_index: usize,
    oldest: Contact,
    new_contact: Contact,
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
    fn update_with_pending(&mut self, contact: Contact) -> Option<PendingBucketUpdate> {
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
    /// Uses a bounded max-heap for O(n log k) complexity instead of O(n log n).
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

    /// Get indices of stale buckets that have contacts but haven't been refreshed recently.
    ///
    /// Only returns non-empty buckets that are stale, since empty buckets
    /// don't need refreshing.
    fn stale_bucket_indices(&self, threshold: Duration) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.contacts.is_empty() && bucket.is_stale(threshold))
            .map(|(idx, _)| idx)
            .collect()
    }

    /// Mark a bucket as refreshed (called after a successful FIND_NODE for that bucket).
    fn mark_bucket_refreshed(&mut self, bucket_idx: usize) {
        if bucket_idx < self.buckets.len() {
            self.buckets[bucket_idx].mark_refreshed();
        }
    }

    /// Get this node's identity for generating random IDs in bucket ranges.
    fn self_id(&self) -> Identity {
        self.self_id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Network abstraction for DHT RPC operations.
///
/// This trait abstracts the transport layer, allowing the core DHT logic to work
/// with different network implementations (e.g., quinn QUIC, mock for testing).
#[async_trait]
pub trait DhtNetwork: Send + Sync + 'static {
    /// Send a FIND_NODE RPC to find contacts near a target identity.
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>>;

    /// Send a FIND_VALUE RPC to retrieve a value or get closer contacts.
    ///
    /// Returns (value, closer_nodes) where value is Some if the key was found.
    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)>;

    /// Send a STORE RPC to store a key-value pair on a node.
    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()>;

    /// Ping a contact to check if it's still responsive.
    ///
    /// Used for the Kademlia "ping-before-evict" rule: when a bucket is full,
    /// the oldest contact is pinged to verify it's still alive before deciding
    /// whether to keep it or replace it with the new contact.
    async fn ping(&self, to: &Contact) -> Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// DHT Node
// ─────────────────────────────────────────────────────────────────────────────

/// High-level DHT node implementing adaptive Kademlia.
///
/// A `DhtNode` owns a routing table, a content-addressable store, and the
/// [`DhtNetwork`] transport used to send RPCs to other peers. The type is
/// generic over the network layer so tests can use an in-memory mock while
/// production uses [`crate::net::QuinnNetwork`].
///
/// # Key Methods
///
/// * [`observe_contact`](Self::observe_contact) - Update routing table when peers are discovered
/// * [`iterative_find_node`](Self::iterative_find_node) - Perform iterative lookup with adaptive tuning
/// * [`put`](Self::put) - Store a key-value pair with replication
/// * [`get`](Self::get) - Retrieve a value from the DHT
/// * [`publish_address`](Self::publish_address) - Publish node addresses to the DHT
/// * [`resolve_peer`](Self::resolve_peer) - Resolve a peer's addresses from the DHT
/// * [`handle_find_node_request`](Self::handle_find_node_request) - Handle incoming FIND_NODE RPC
/// * [`handle_find_value_request`](Self::handle_find_value_request) - Handle incoming FIND_VALUE RPC
/// * [`handle_store_request`](Self::handle_store_request) - Handle incoming STORE RPC
///
/// The node is cloneable (via internal `Arc`) and can be shared between tasks.
///
/// # Example
///
/// ```ignore
/// let node = DhtNode::new(id, contact, network, K_DEFAULT, ALPHA_DEFAULT);
/// node.observe_contact(peer_contact).await;
/// let closest = node.iterative_find_node(target_id).await?;
/// ```
pub struct DhtNode<N: DhtNetwork> {
    /// This node's unique identity.
    id: Identity,
    /// Contact info for this node (identity + serialized address).
    self_contact: Contact,
    /// Kademlia routing table with 256 buckets.
    routing: Arc<Mutex<RoutingTable>>,
    /// Local key-value storage with LRU eviction.
    store: Arc<Mutex<LocalStore>>,
    /// Network transport for sending RPCs.
    network: Arc<N>,
    /// Adaptive parameters (k, alpha) tuned based on network conditions.
    params: Arc<Mutex<AdaptiveParams>>,
    /// Latency-based tiering for prioritizing fast peers.
    tiering: Arc<Mutex<TieringManager>>,
    /// Per-peer routing table insertion rate limiter.
    routing_limiter: Arc<Mutex<RoutingInsertionLimiter>>,
}

impl<N: DhtNetwork> Clone for DhtNode<N> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            self_contact: self.self_contact.clone(),
            routing: self.routing.clone(),
            store: self.store.clone(),
            network: self.network.clone(),
            params: self.params.clone(),
            tiering: self.tiering.clone(),
            routing_limiter: self.routing_limiter.clone(),
        }
    }
}

impl<N: DhtNetwork> DhtNode<N> {
    /// Create a new DHT node with the given identity, contact info, network, and initial parameters.
    ///
    /// Automatically starts a background task for periodic bucket refresh
    /// to maintain routing table health.
    pub fn new(id: Identity, self_contact: Contact, network: N, k: usize, alpha: usize) -> Self {
        let node = Self {
            id,
            self_contact,
            routing: Arc::new(Mutex::new(RoutingTable::new(id, k))),
            store: Arc::new(Mutex::new(LocalStore::new())),
            network: Arc::new(network),
            params: Arc::new(Mutex::new(AdaptiveParams::new(k, alpha))),
            tiering: Arc::new(Mutex::new(TieringManager::new())),
            routing_limiter: Arc::new(Mutex::new(RoutingInsertionLimiter::new())),
        };
        node.spawn_periodic_bucket_refresh();
        node
    }

    /// Get this node's unique identity.
    pub fn identity(&self) -> Identity {
        self.id
    }

    /// Get this node's contact information.
    pub fn contact(&self) -> Contact {
        self.self_contact.clone()
    }

    /// Observe a contact and update the routing table.
    ///
    /// If the bucket for this contact is full, spawns a background task to ping
    /// the oldest contact and decide whether to evict it.
    ///
    /// # Security
    ///
    /// Rejects contacts with placeholder or invalid identities to prevent
    /// routing table pollution from bootstrap peers with unknown IDs.
    pub async fn observe_contact(&self, contact: Contact) {
        if contact.identity == self.id {
            return;
        }

        // Reject placeholder and invalid identities
        if !is_valid_identity(&contact.identity) {
            trace!(
                addr = %contact.addr,
                identity = %hex::encode(&contact.identity.as_bytes()[..8]),
                "rejecting contact with invalid identity"
            );
            return;
        }

        {
            let mut tiering = self.tiering.lock().await;
            tiering.register_contact(&contact.identity);
        }
        let k = {
            let params = self.params.lock().await;
            params.current_k()
        };
        let pending = {
            let mut rt = self.routing.lock().await;
            rt.set_k(k);
            rt.update_with_pending(contact.clone())
        };
        
        // Log when a contact is added/updated in the routing table
        info!(
            addr = %contact.addr,
            identity = %hex::encode(&contact.identity.as_bytes()[..16]),
            "Contact observed"
        );
        
        if let Some(update) = pending {
            self.spawn_bucket_refresh(update);
        }
    }

    /// Observe a contact from a specific peer, with rate limiting.
    ///
    /// This method should be used when processing contacts returned by other
    /// peers (e.g., in FindNode responses) to prevent routing table flooding.
    ///
    /// # Security
    ///
    /// Each peer has a limited budget of contacts they can contribute to our
    /// routing table within a time window. This prevents:
    /// - Routing table poisoning attacks
    /// - Eclipse attacks via contact flooding
    /// - Resource exhaustion from processing excessive contacts
    ///
    /// Returns true if the contact was processed, false if rate-limited.
    pub async fn observe_contact_from_peer(&self, contact: Contact, from_peer: &Identity) -> bool {
        // Skip rate limiting for direct observations (the peer itself)
        if contact.identity == *from_peer {
            self.observe_contact(contact).await;
            return true;
        }

        // Check rate limit for this peer
        {
            let mut limiter = self.routing_limiter.lock().await;
            if !limiter.allow_insertion(from_peer) {
                trace!(
                    from_peer = %hex::encode(&from_peer.as_bytes()[..8]),
                    contact = %hex::encode(&contact.identity.as_bytes()[..8]),
                    "rate-limited contact insertion from peer"
                );
                return false;
            }
        }

        self.observe_contact(contact).await;
        true
    }

    /// Store a key-value pair locally with content verification and quota enforcement.
    ///
    /// Verifies that the key matches the BLAKE3 hash of the value before storing.
    /// Enforces per-peer quotas and rate limits to prevent storage exhaustion attacks.
    /// May trigger pressure-based eviction, offloading spilled entries.
    ///
    /// # Arguments
    /// * `key` - Content-addressed key (BLAKE3 hash of value)
    /// * `value` - The value to store
    /// * `stored_by` - Identity of the peer requesting storage (for quota tracking)
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
        let spilled = {
            let mut store = self.store.lock().await;
            store.record_request();
            store.store(key, &value, stored_by)
        };
        if !spilled.is_empty() {
            self.offload_spilled(spilled).await;
        }
    }

    /// Spawn a background task to ping the oldest contact in a full bucket.
    ///
    /// This implements the Kademlia "ping-before-evict" rule.
    fn spawn_bucket_refresh(&self, pending: PendingBucketUpdate) {
        let network = self.network.clone();
        let routing = self.routing.clone();
        tokio::spawn(async move {
            let alive = match network.ping(&pending.oldest).await {
                Ok(_) => true,
                Err(err) => {
                    debug!(
                        peer = ?pending.oldest.identity,
                        addr = %pending.oldest.addr,
                        "ping failed: {err:?}"
                    );
                    false
                }
            };
            let mut rt = routing.lock().await;
            rt.apply_ping_result(pending, alive);
        });
    }

    /// Spawn a background task for periodic bucket refresh.
    ///
    /// This implements lazy bucket refresh: every BUCKET_REFRESH_INTERVAL,
    /// we find buckets that haven't been touched in BUCKET_STALE_THRESHOLD
    /// and perform a FIND_NODE for a random ID in each stale bucket's range.
    ///
    /// This keeps the routing table fresh and helps discover new peers
    /// while removing dead ones (via RPC failure handling).
    fn spawn_periodic_bucket_refresh(&self) {
        let node = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(BUCKET_REFRESH_INTERVAL);
            interval.tick().await; // Skip first immediate tick

            loop {
                interval.tick().await;

                // Get list of stale bucket indices
                let stale_buckets: Vec<usize> = {
                    let rt = node.routing.lock().await;
                    rt.stale_bucket_indices(BUCKET_STALE_THRESHOLD)
                };

                if stale_buckets.is_empty() {
                    continue;
                }

                debug!(
                    count = stale_buckets.len(),
                    "refreshing stale routing buckets"
                );

                // Refresh each stale bucket
                for bucket_idx in stale_buckets {
                    // Generate random ID in this bucket's range
                    let target = {
                        let rt = node.routing.lock().await;
                        random_id_for_bucket(&rt.self_id(), bucket_idx)
                    };

                    // Perform FIND_NODE lookup - this discovers peers and 
                    // removes dead ones via RPC failure handling
                    if let Err(e) = node.iterative_find_node(target).await {
                        debug!(
                            bucket = bucket_idx,
                            error = ?e,
                            "bucket refresh lookup failed"
                        );
                    }

                    // Mark bucket as refreshed
                    {
                        let mut rt = node.routing.lock().await;
                        rt.mark_bucket_refreshed(bucket_idx);
                    }
                }
            }
        });
    }

    /// Retrieve a value from local storage.
    async fn get_local(&self, key: &Key) -> Option<Vec<u8>> {
        let mut store = self.store.lock().await;
        store.record_request();
        let result = store.get(key);
        if result.is_none() {
            trace!(
                key = hex::encode(&key[..8]),
                "local store miss"
            );
        }
        result
    }

    /// Override pressure limits for testing or custom configurations.
    pub async fn override_pressure_limits(
        &self,
        disk_limit: usize,
        memory_limit: usize,
        request_limit: usize,
    ) {
        let mut store = self.store.lock().await;
        store.override_limits(disk_limit, memory_limit, request_limit);
    }

    /// Handle an incoming FIND_NODE RPC request.
    ///
    /// Returns the k closest contacts to the target identity from our routing table.
    pub async fn handle_find_node_request(&self, from: &Contact, target: Identity) -> Vec<Contact> {
        self.observe_contact(from.clone()).await;
        let k = {
            let params = self.params.lock().await;
            params.current_k()
        };
        let rt = self.routing.lock().await;
        rt.closest(&target, k)
    }

    /// Handle an incoming FIND_VALUE RPC request.
    ///
    /// If we have the value locally, returns it. Otherwise, returns the k closest
    /// contacts to the key for the requester to continue the lookup.
    pub async fn handle_find_value_request(
        &self,
        from: &Contact,
        key: Key,
    ) -> (Option<Vec<u8>>, Vec<Contact>) {
        self.observe_contact(from.clone()).await;
        if let Some(v) = self.get_local(&key).await {
            return (Some(v), Vec::new());
        }
        let target = Identity::from_bytes(key);
        let k = {
            let params = self.params.lock().await;
            params.current_k()
        };
        let rt = self.routing.lock().await;
        let closer = rt.closest(&target, k);
        (None, closer)
    }

    /// Handle an incoming STORE RPC request.
    ///
    /// Verifies the key-value pair and stores it locally if valid.
    /// Tracks the requesting peer's identity for quota enforcement.
    pub async fn handle_store_request(&self, from: &Contact, key: Key, value: Vec<u8>) {
        self.observe_contact(from.clone()).await;
        self.store_local(key, value, from.identity).await;
    }

    /// Check if a node matches the given tier level filter.
    async fn level_matches(&self, node: &Identity, level_filter: Option<TieringLevel>) -> bool {
        if let Some(level) = level_filter {
            let tiering = self.tiering.lock().await;
            tiering.level_for(node) == level
        } else {
            true
        }
    }

    /// Filter contacts to only those in the specified tier level.
    async fn filter_contacts(
        &self,
        contacts: Vec<Contact>,
        level_filter: Option<TieringLevel>,
    ) -> Vec<Contact> {
        if level_filter.is_none() {
            return contacts;
        }
        let level = level_filter.unwrap();
        let tiering = self.tiering.lock().await;
        contacts
            .into_iter()
            .filter(|c| tiering.level_for(&c.identity) == level)
            .collect()
    }

    /// Record an RTT sample for a contact for latency tiering.
    async fn record_rtt(&self, contact: &Contact, elapsed: Duration) {
        if contact.identity == self.id {
            return;
        }
        let rtt_ms = (elapsed.as_secs_f64() * 1000.0) as f32;
        let mut tiering = self.tiering.lock().await;
        tiering.record_sample(&contact.identity, rtt_ms);
    }

    /// Record a churn observation and adjust k if needed.
    async fn adjust_k(&self, success: bool) {
        let (changed, new_k) = {
            let mut params = self.params.lock().await;
            let changed = params.record_churn(success);
            let current_k = params.current_k();
            (changed, current_k)
        };
        if changed {
            let mut rt = self.routing.lock().await;
            rt.set_k(new_k);
        }
    }

    /// Get the current k parameter.
    async fn current_k(&self) -> usize {
        let params = self.params.lock().await;
        params.current_k()
    }

    /// Get the current alpha (parallelism) parameter.
    async fn current_alpha(&self) -> usize {
        let params = self.params.lock().await;
        params.current_alpha()
    }

    /// Perform an iterative FIND_NODE lookup for the target identity.
    ///
    /// Returns the k closest contacts to the target found during the lookup.
    /// Automatically adjusts k based on observed churn.
    pub async fn iterative_find_node(&self, target: Identity) -> Result<Vec<Contact>> {
        self.iterative_find_node_with_level(target, None).await
    }

    /// Perform an iterative FIND_NODE lookup with optional tier filtering.
    ///
    /// The lookup process:
    /// 1. Start with k closest contacts from routing table
    /// 2. Query alpha contacts in parallel, collect responses
    /// 3. Add newly discovered contacts to shortlist
    /// 4. Repeat until no closer contacts are found
    /// 5. Return the k closest contacts found
    async fn iterative_find_node_with_level(
        &self,
        target: Identity,
        level_filter: Option<TieringLevel>,
    ) -> Result<Vec<Contact>> {
        let mut seen: HashSet<Identity> = HashSet::new();
        let mut queried: HashSet<Identity> = HashSet::new();
        let mut rpc_success = false;
        let mut rpc_failure = false;
        let k_initial = self.current_k().await;
        let mut shortlist = {
            let rt = self.routing.lock().await;
            rt.closest(&target, k_initial)
        };
        shortlist = self.filter_contacts(shortlist, level_filter).await;
        shortlist.sort_by(|a, b| {
            let da = xor_distance(&a.identity, &target);
            let db = xor_distance(&b.identity, &target);
            distance_cmp(&da, &db)
        });

        for c in &shortlist {
            seen.insert(c.identity);
        }

        let mut best_distance = shortlist
            .first()
            .map(|c| xor_distance(&c.identity, &target))
            .unwrap_or([0xff; 32]);

        loop {
            let alpha = self.current_alpha().await;
            // Select up to alpha unqueried candidates
            let candidates: Vec<Contact> = shortlist
                .iter()
                .filter(|c| !queried.contains(&c.identity) && c.identity != self.id)
                .take(alpha)
                .cloned()
                .collect();

            if candidates.is_empty() {
                break;
            }

            // Mark all candidates as queried before parallel execution
            for c in &candidates {
                queried.insert(c.identity);
            }

            // Query alpha contacts in parallel
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

            // Process all parallel results
            for (contact, elapsed, result) in results {
                match result {
                    Ok(nodes) => {
                        rpc_success = true;
                        self.record_rtt(&contact, elapsed).await;
                        // Direct contact observation (the peer itself)
                        self.observe_contact(contact.clone()).await;
                        // Rate-limited observation for contacts returned by this peer
                        let from_peer = contact.identity;
                        for n in &nodes {
                            self.observe_contact_from_peer(n.clone(), &from_peer).await;
                        }

                        // Add new contacts to shortlist
                        for n in nodes {
                            if seen.insert(n.identity) && self.level_matches(&n.identity, level_filter).await {
                                shortlist.push(n);
                            }
                        }
                    }
                    Err(_) => {
                        rpc_failure = true;
                    }
                }
            }

            // Re-sort shortlist by distance to target
            shortlist.sort_by(|a, b| {
                let da = xor_distance(&a.identity, &target);
                let db = xor_distance(&b.identity, &target);
                distance_cmp(&da, &db)
            });

            // Truncate to k closest
            let k = self.current_k().await;
            if shortlist.len() > k {
                shortlist.truncate(k);
            }

            // Check if we found any closer contacts
            if let Some(first) = shortlist.first() {
                let new_best = xor_distance(&first.identity, &target);
                if distance_cmp(&new_best, &best_distance) == std::cmp::Ordering::Less {
                    best_distance = new_best;
                    any_closer = true;
                }
            }

            // Stop if no progress was made
            if !any_closer {
                break;
            }
        }

        // Adjust k based on lookup success/failure
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

        Ok(shortlist)
    }

    /// Offload spilled entries to slower-tier nodes.
    ///
    /// When local storage is under pressure, evicted entries are replicated
    /// to nodes in the slowest tier to preserve data availability.
    async fn offload_spilled(&self, spilled: Vec<(Key, Vec<u8>)>) {
        if spilled.is_empty() {
            return;
        }

        let target_level = {
            let tiering = self.tiering.lock().await;
            tiering.slowest_level()
        };

        for (key, value) in spilled {
            self.replicate_to_level(key, value.clone(), target_level)
                .await;
        }
    }

    /// Replicate a key-value pair to nodes in a specific tier.
    async fn replicate_to_level(&self, key: Key, value: Vec<u8>, level: TieringLevel) {
        let target = Identity::from_bytes(key);
        if let Ok(contacts) = self
            .iterative_find_node_with_level(target, Some(level))
            .await
        {
            let k = self.current_k().await;
            for contact in contacts.into_iter().take(k) {
                self.send_store(&contact, key, value.clone()).await;
            }
        }
    }

    /// Send a STORE RPC to a contact and record metrics.
    async fn send_store(&self, contact: &Contact, key: Key, value: Vec<u8>) {
        let start = Instant::now();
        let result = self.network.store(contact, key, value).await;
        match result {
            Ok(_) => {
                let elapsed = start.elapsed();
                self.record_rtt(contact, elapsed).await;
                self.adjust_k(true).await;
                self.observe_contact(contact.clone()).await;
            }
            Err(_) => {
                self.adjust_k(false).await;
            }
        }
    }

    /// Store a value in the DHT with distance-based replication.
    ///
    /// The key is derived from the BLAKE3 hash of the value (content-addressed).
    /// The value is stored locally and replicated to the k closest nodes.
    pub async fn put(&self, value: Vec<u8>) -> Result<Key> {
        let key = hash_content(&value);

        // When storing locally via put(), use our own ID as the stored_by peer
        self.store_local(key, value.clone(), self.id).await;

        let target = Identity::from_bytes(key);
        let closest = self.iterative_find_node_with_level(target, None).await?;
        let k = self.current_k().await;

        for contact in closest.into_iter().take(k) {
            self.send_store(&contact, key, value.clone()).await;
        }

        Ok(key)
    }

    /// Get a snapshot of current node state for telemetry.
    pub async fn telemetry_snapshot(&self) -> TelemetrySnapshot {
        let tiering_stats = {
            let tiering = self.tiering.lock().await;
            tiering.stats()
        };
        let (pressure, stored_keys) = {
            let store = self.store.lock().await;
            (store.current_pressure(), store.len())
        };
        let params = self.params.lock().await;
        TelemetrySnapshot {
            tier_centroids: tiering_stats.centroids,
            tier_counts: tiering_stats.counts,
            pressure,
            stored_keys,
            replication_factor: params.current_k(),
            concurrency: params.current_alpha(),
        }
    }

    /// Store a value at a specific key in the DHT.
    ///
    /// Unlike `put()` which derives the key from the value's hash,
    /// this stores at an arbitrary key. Used for endpoint records
    /// where the key is derived from the Identity.
    pub async fn put_at(&self, key: Key, value: Vec<u8>) -> Result<()> {
        // Store locally using our own ID as stored_by
        self.store_local(key, value.clone(), self.id).await;

        // Find closest nodes and replicate
        let closest = self.iterative_find_node(Identity::from_bytes(key)).await?;
        let k = self.current_k().await;

        for contact in closest.into_iter().take(k) {
            self.send_store(&contact, key, value.clone()).await;
        }

        Ok(())
    }

    /// Look up a value from the DHT by key.
    ///
    /// Returns the value if found, either locally or from the network.
    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        // Check local storage first
        if let Some(value) = self.get_local(key).await {
            return Ok(Some(value));
        }

        // Query closest nodes
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

    /// Publish this node's current network addresses to the DHT.
    ///
    /// This creates a signed [`EndpointRecord`] containing the node's addresses
    /// and stores it in the DHT under the node's [`Identity`]. Other nodes can
    /// then resolve this peer's addresses by looking up its Identity.
    ///
    /// # Arguments
    /// * `keypair` - The node's Ed25519 keypair for signing the record
    /// * `addresses` - The current network addresses (e.g., "192.168.1.100:4433")
    pub async fn publish_address(&self, keypair: &Keypair, addresses: Vec<String>) -> Result<()> {
        let record = keypair.create_endpoint_record(addresses);
        let serialized = bincode::serialize(&record)
            .map_err(|e| anyhow!("Failed to serialize endpoint record: {}", e))?;
        
        // Store under the Identity's DHT key (Identity bytes directly in zero-hash model)
        let key: Key = *record.identity.as_bytes();
        self.put_at(key, serialized).await
    }

    /// Resolve a peer's current network addresses from the DHT.
    ///
    /// Looks up the [`EndpointRecord`] for the given [`Identity`] and verifies
    /// the signature and timestamp freshness before returning it.
    ///
    /// # Arguments
    /// * `peer_id` - The Ed25519 public key of the peer to resolve
    ///
    /// # Returns
    /// * `Ok(Some(record))` - The verified endpoint record
    /// * `Ok(None)` - No record found for this peer
    /// * `Err(_)` - Lookup or verification failed
    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        // Maximum age for endpoint records: 24 hours (matches DHT TTL)
        const MAX_RECORD_AGE_SECS: u64 = 24 * 60 * 60;
        
        let key: Key = *peer_id.as_bytes();
        
        match self.get(&key).await? {
            Some(data) => {
                let record: EndpointRecord = crate::protocol::deserialize_bounded(&data)
                    .map_err(|e| anyhow!("Failed to deserialize endpoint record: {}", e))?;
                
                // Validate structure to prevent resource exhaustion
                if !record.validate_structure() {
                    return Err(anyhow!("Endpoint record has invalid structure"));
                }
                
                // Verify the record is signed by the claimed peer
                if record.identity != *peer_id {
                    return Err(anyhow!("Endpoint record peer_id mismatch"));
                }
                
                // Verify signature AND timestamp freshness to prevent replay attacks
                if !record.verify_fresh(MAX_RECORD_AGE_SECS) {
                    return Err(anyhow!("Endpoint record signature or timestamp verification failed"));
                }
                
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Republish address when network changes.
    ///
    /// Call this when the local network address changes (e.g., WiFi → cellular).
    /// QUIC connection migration will handle existing connections seamlessly,
    /// saving 2 RTTs per reconnection (no new handshake needed).
    ///
    /// This method:
    /// 1. Creates a new signed EndpointRecord with the new address(es)
    /// 2. Publishes it to the DHT
    /// 3. QUIC connections continue working via connection migration
    ///
    /// # Arguments
    /// * `keypair` - The node's Ed25519 keypair for signing
    /// * `new_addrs` - The new network addresses after the change
    /// * `relays` - Optional relay endpoints (for NAT situations)
    pub async fn republish_on_network_change(
        &self,
        keypair: &Keypair,
        new_addrs: Vec<String>,
        relays: Vec<crate::identity::RelayEndpoint>,
    ) -> Result<()> {
        debug!(
            "republishing address after network change: {:?}",
            new_addrs
        );
        
        let record = keypair.create_endpoint_record_with_relays(new_addrs, relays);
        let serialized = bincode::serialize(&record)
            .map_err(|e| anyhow!("Failed to serialize endpoint record: {}", e))?;
        
        // Store under the Identity's DHT key (Identity bytes directly in zero-hash model)
        let key: Key = *record.identity.as_bytes();
        self.put_at(key, serialized).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

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

    // NOTE: derive_node_id test removed - zero-hash model uses Ed25519 pubkey directly as Identity

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
        let mut smaller = [0u8; 32];
        smaller[1] = 1;
        let mut larger = [0u8; 32];
        larger[1] = 2;

        assert_eq!(distance_cmp(&smaller, &larger), Ordering::Less);
        assert_eq!(distance_cmp(&larger, &smaller), Ordering::Greater);
        assert_eq!(distance_cmp(&smaller, &smaller), Ordering::Equal);
    }

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
}
