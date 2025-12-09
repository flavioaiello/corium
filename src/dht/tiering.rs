use std::collections::{HashMap, VecDeque};
use tokio::time::{Duration, Instant};
use tracing::debug;

use crate::identity::Identity;

const TIERING_RECOMPUTE_INTERVAL: Duration = Duration::from_secs(300);

const MAX_RTT_SAMPLES_PER_NODE: usize = 32;

const MIN_LATENCY_TIERS: usize = 1;

const MAX_LATENCY_TIERS: usize = 7;

const KMEANS_ITERATIONS: usize = 20;

const TIERING_PENALTY_FACTOR: f32 = 1.5;

const TIERING_STALE_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);

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
