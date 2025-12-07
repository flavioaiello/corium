//! Adaptive parameters for DHT operations based on network conditions.
//!
//! Dynamically adjusts k (bucket size) and alpha (parallelism) based on
//! observed churn rate to maintain routing table resilience.

use std::collections::VecDeque;
use tracing::info;

/// Sliding window size for tracking RPC success/failure for adaptive `k`.
const QUERY_STATS_WINDOW: usize = 100;

// ============================================================================
// Adaptive Parameters
// ============================================================================

/// Adaptive parameters for DHT operations based on network conditions.
///
/// Dynamically adjusts parameters based on observed success/failure rates:
/// - **k** (bucket size): Ranges from 10-30, where `k = 10 + 20*churn_rate`
/// - **α** (parallelism): Ranges from 2-5, where `α = 2 + 3*failure_rate`
///
/// Higher churn/failure rates trigger larger k and α values to maintain
/// routing resilience and lookup success probability.
pub(crate) struct AdaptiveParams {
    /// Current k parameter (bucket size), ranges from 10 to 30.
    k: usize,
    /// Parallelism factor for lookups, ranges from 2 to 5.
    alpha: usize,
    /// Sliding window of recent churn observations (true = success, false = failure).
    churn_history: VecDeque<bool>,
}

impl AdaptiveParams {
    /// Create new adaptive parameters with initial k and alpha values.
    pub fn new(k: usize, alpha: usize) -> Self {
        Self {
            k,
            alpha: alpha.clamp(2, 5),
            churn_history: VecDeque::new(),
        }
    }

    /// Record a churn observation and update k and alpha if needed.
    ///
    /// Returns true if k was changed.
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
    pub fn current_k(&self) -> usize {
        self.k
    }

    /// Get the current alpha (parallelism) parameter.
    pub fn current_alpha(&self) -> usize {
        self.alpha
    }
}

// ============================================================================
// Telemetry
// ============================================================================

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
