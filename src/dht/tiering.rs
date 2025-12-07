//! Latency-based peer tiering using k-means clustering.
//!
//! Peers are assigned to tiers based on observed RTT latency, enabling
//! latency-aware routing where fast peers are preferred.

use std::collections::{HashMap, VecDeque};
use tokio::time::{Duration, Instant};
use tracing::debug;

use crate::identity::Identity;

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

/// Duration after which tiering data for a node is considered stale (24 hours).
/// Nodes not seen within this period have their tiering data removed.
const TIERING_STALE_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum number of peers to track for latency tiering.
///
/// # Security
///
/// Prevents memory exhaustion from tracking too many peers in the tiering
/// system. When this limit is reached, the oldest (least recently seen)
/// peers are evicted to make room for new ones.
const MAX_TIERING_TRACKED_PEERS: usize = 10_000;

// ============================================================================
// Tiering Types
// ============================================================================

/// A tier assignment for a node based on observed latency.
///
/// Lower tier indices represent faster (lower latency) peers.
/// Tier 0 is the fastest tier, and the highest index is the slowest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TieringLevel(usize);

impl TieringLevel {
    /// Create a new tiering level with the given index.
    pub(crate) fn new(index: usize) -> Self {
        Self(index)
    }

    /// Get the numeric index of this tier (0 = fastest).
    pub(crate) fn index(self) -> usize {
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

// ============================================================================
// Tiering Manager
// ============================================================================

/// Manages latency-based tiering of DHT peers using dynamic k-means clustering.
///
/// The tiering manager:
/// 1. Collects RTT samples from RPC interactions (up to 32 samples per peer)
/// 2. Recomputes tier assignments every 5 minutes using dynamic k-means
/// 3. Dynamically selects optimal tier count (1-7) using BIC-like penalty
/// 4. Assigns new contacts to the middle tier (centroids.len() / 2)
/// 5. Cleans up stale data for nodes not seen in 24 hours
/// 6. Evicts oldest peers when tracking exceeds 10,000 limit
///
/// Lower tier indices (e.g., tier 0) represent faster, lower-latency peers.
/// This enables latency-aware routing where fast peers are preferred.
pub(crate) struct TieringManager {
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
    pub fn new() -> Self {
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
    pub fn register_contact(&mut self, node: &Identity) -> TieringLevel {
        // Evict excess peers before adding new ones
        self.maybe_evict_excess();
        
        self.last_seen.insert(*node, Instant::now());
        let default = self.default_level();
        *self.assignments.entry(*node).or_insert(default)
    }

    /// Record an RTT sample for a node and trigger recomputation if due.
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

    /// Get the current tier level for a node.
    pub fn level_for(&self, node: &Identity) -> TieringLevel {
        self.assignments
            .get(node)
            .copied()
            .unwrap_or_else(|| self.default_level())
    }

    /// Get current tiering statistics including centroids and node counts per tier.
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
    pub fn default_level(&self) -> TieringLevel {
        if self.centroids.is_empty() {
            return TieringLevel::new(0);
        }
        TieringLevel::new(self.centroids.len() / 2)
    }

    /// Get the slowest (highest latency) tier level.
    pub fn slowest_level(&self) -> TieringLevel {
        if self.centroids.is_empty() {
            TieringLevel::new(0)
        } else {
            TieringLevel::new(self.centroids.len() - 1)
        }
    }
}

// ============================================================================
// K-means Clustering
// ============================================================================

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
