use std::collections::VecDeque;
use tracing::info;

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

#[derive(Clone, Debug, Default)]
pub struct TelemetrySnapshot {
    pub tier_centroids: Vec<f32>,
    pub tier_counts: Vec<usize>,
    pub pressure: f32,
    pub stored_keys: usize,
    pub replication_factor: usize,
    pub concurrency: usize,
}
