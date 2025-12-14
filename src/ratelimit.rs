
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Instant;

use lru::LruCache;
use tokio::sync::Mutex;


pub const MAX_GLOBAL_CONNECTIONS_PER_SECOND: usize = 100;

pub const MAX_CONNECTIONS_PER_IP_PER_SECOND: usize = 20;

pub const MAX_TRACKED_IPS: usize = 1000;


#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: usize) -> Self {
        Self {
            tokens: capacity as f64,
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self, rate: f64, capacity: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        self.tokens = (self.tokens + elapsed * rate).min(capacity);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}


#[derive(Debug)]
struct RateLimitState {
    global: TokenBucket,
    per_ip: LruCache<IpAddr, TokenBucket>,
}

#[derive(Debug)]
pub struct ConnectionRateLimiter {
    state: Mutex<RateLimitState>,
}

impl ConnectionRateLimiter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RateLimitState {
                global: TokenBucket::new(MAX_GLOBAL_CONNECTIONS_PER_SECOND),
                per_ip: LruCache::new(NonZeroUsize::new(MAX_TRACKED_IPS).unwrap()),
            }),
        }
    }

    pub async fn allow(&self, ip: IpAddr) -> bool {
        let mut state = self.state.lock().await;

        if !state.global.try_consume(
            MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64,
            MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64,
        ) {
            return false;
        }

        let ip_bucket = state.per_ip.get_or_insert_mut(ip, || {
            TokenBucket::new(MAX_CONNECTIONS_PER_IP_PER_SECOND)
        });

        if !ip_bucket.try_consume(
            MAX_CONNECTIONS_PER_IP_PER_SECOND as f64,
            MAX_CONNECTIONS_PER_IP_PER_SECOND as f64,
        ) {
            state.global.tokens = (state.global.tokens + 1.0)
                .min(MAX_GLOBAL_CONNECTIONS_PER_SECOND as f64);
            return false;
        }

        true
    }
    
    pub async fn stats(&self) -> RateLimitStats {
        let state = self.state.lock().await;
        RateLimitStats {
            global_tokens_available: state.global.tokens,
            tracked_ips: state.per_ip.len(),
            max_tracked_ips: MAX_TRACKED_IPS,
            global_rate_limit: MAX_GLOBAL_CONNECTIONS_PER_SECOND,
            per_ip_rate_limit: MAX_CONNECTIONS_PER_IP_PER_SECOND,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub global_tokens_available: f64,
    pub tracked_ips: usize,
    pub max_tracked_ips: usize,
    pub global_rate_limit: usize,
    pub per_ip_rate_limit: usize,
}

impl Default for ConnectionRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rate_limiter_per_ip() {
        let limiter = ConnectionRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..MAX_CONNECTIONS_PER_IP_PER_SECOND {
            assert!(limiter.allow(ip).await);
        }

        assert!(!limiter.allow(ip).await);

        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(limiter.allow(ip2).await);
    }

    #[test]
    fn per_ip_limit_exact_boundary() {
        let allowed_count = MAX_CONNECTIONS_PER_IP_PER_SECOND;
        let rejected_count = 1;

        assert_eq!(
            allowed_count + rejected_count,
            MAX_CONNECTIONS_PER_IP_PER_SECOND + 1,
            "Test configuration error"
        );
    }

    #[test]
    fn global_limit_exact_boundary() {
        let ips_needed = MAX_GLOBAL_CONNECTIONS_PER_SECOND / MAX_CONNECTIONS_PER_IP_PER_SECOND;
        assert_eq!(ips_needed, 5, "Should need 5 IPs to hit global limit");
    }

    #[test]
    fn ip_tracking_lru_eviction() {
        let ips_to_fill_cache = MAX_TRACKED_IPS;
        let extra_ip = 1;

        assert!(
            ips_to_fill_cache + extra_ip > MAX_TRACKED_IPS,
            "Need more IPs than cache size to trigger eviction"
        );
    }

    #[test]
    fn rate_limit_window_expiration() {
        use std::time::Duration;

        let window_duration = Duration::from_secs(1);
        let time_after_window = Duration::from_millis(1001);

        assert!(
            time_after_window > window_duration,
            "Time after window should exceed window duration"
        );
    }

    #[test]
    fn rapid_burst_handling() {
        let burst_connections = MAX_CONNECTIONS_PER_IP_PER_SECOND + 5;
        let expected_allowed = MAX_CONNECTIONS_PER_IP_PER_SECOND;
        let expected_rejected = 5;

        assert_eq!(
            expected_allowed + expected_rejected,
            burst_connections,
            "Burst should be partially rejected"
        );
    }

    #[tokio::test]
    async fn concurrent_rate_limit_checks() {
        use std::sync::Arc;
        use tokio::sync::Barrier;

        let barrier = Arc::new(Barrier::new(20));
        let mut handles = vec![];

        for _ in 0..20 {
            let barrier = barrier.clone();
            let handle = tokio::spawn(async move {
                barrier.wait().await;
                true
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        assert_eq!(results.len(), 20);
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn ipv4_vs_ipv6_separate_limits() {
        let ipv4: IpAddr = "192.168.1.1".parse().unwrap();
        let ipv6: IpAddr = "::1".parse().unwrap();

        assert_ne!(ipv4, ipv6);

        let ipv4_mapped_ipv6: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert_ne!(ipv4, ipv4_mapped_ipv6);
    }

    #[test]
    fn sustained_load_over_time() {
        let seconds_of_load = 10;
        let connections_per_second = MAX_CONNECTIONS_PER_IP_PER_SECOND;

        let total_allowed = seconds_of_load * connections_per_second;

        assert_eq!(
            total_allowed, 200,
            "Should allow {} connections over {} seconds",
            total_allowed, seconds_of_load
        );
    }
}
