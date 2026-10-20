use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;

/// Unanswered queries in a row before a resolver is parked.
///
/// Even a healthy resolver often can't answer for a broken domain, so one or two misses
/// shouldn't be enough.
pub(crate) const PARK_AFTER_FAILURES: u64 = 3;

/// How long a resolver stays parked.
/// Each new failure doubles it, up to the maximum.
const MIN_PARK_DURATION: Duration = Duration::from_secs(5);
const MAX_PARK_DURATION: Duration = Duration::from_secs(60);

fn park_duration(consecutive_failures: u64) -> Duration {
    let doublings = consecutive_failures
        .saturating_sub(PARK_AFTER_FAILURES)
        .min(16) as u32;
    MIN_PARK_DURATION
        .saturating_mul(1 << doublings)
        .min(MAX_PARK_DURATION)
}

/// Statistics for a single resolver
#[derive(Debug, Clone)]
pub struct ResolverStats {
    /// Moving average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Number of successful queries
    pub success_count: u64,
    /// Number of failed queries
    pub failure_count: u64,
    /// Number of timed out queries
    pub timeout_count: u64,
    /// Failures and timeouts since the resolver last answered
    pub consecutive_failures: u64,
    /// Last time this resolver was used
    pub last_used: SystemTime,
    /// Weight factor for the moving average (between 0 and 1)
    /// Lower values give more weight to historical data
    weight_factor: f64,
    /// The resolver gets no queries until then
    parked_until: Option<Instant>,
}

impl ResolverStats {
    /// Create a new ResolverStats with default values
    pub fn new() -> Self {
        Self {
            avg_response_time_ms: 0.0,
            success_count: 0,
            failure_count: 0,
            timeout_count: 0,
            consecutive_failures: 0,
            last_used: SystemTime::now(),
            weight_factor: 0.2, // 20% weight to new values
            parked_until: None,
        }
    }

    /// Update the moving average response time
    pub fn update_response_time(&mut self, response_time: Duration) {
        // Keep sub-millisecond precision, since 0.0 means that nothing was measured yet
        let response_time_ms = response_time.as_nanos() as f64 / 1_000_000.0;

        if self.avg_response_time_ms == 0.0 {
            // First measurement
            self.avg_response_time_ms = response_time_ms;
        } else {
            // Update moving average
            self.avg_response_time_ms = (1.0 - self.weight_factor) * self.avg_response_time_ms
                + self.weight_factor * response_time_ms;
        }
    }

    /// Record a successful query
    pub fn record_success(&mut self, response_time: Duration) {
        self.success_count = self.success_count.saturating_add(1);
        self.clear_failures();
        self.update_response_time(response_time);
    }

    /// Record a failed query
    pub fn record_failure(&mut self) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.add_failure();
    }

    /// Record a timed out query
    pub fn record_timeout(&mut self) {
        self.timeout_count = self.timeout_count.saturating_add(1);
        self.add_failure();
    }

    /// Record an answer that can't be timed, such as the reply to a retry
    pub fn clear_failures(&mut self) {
        self.consecutive_failures = 0;
        self.parked_until = None;
        self.last_used = SystemTime::now();
    }

    fn add_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_used = SystemTime::now();
        if self.consecutive_failures >= PARK_AFTER_FAILURES {
            self.parked_until = Some(Instant::now() + park_duration(self.consecutive_failures));
        }
    }

    fn is_parked(&self) -> bool {
        self.parked_until
            .is_some_and(|until| Instant::now() < until)
    }

    fn record_query_sent(&mut self) {
        if self.parked_until.is_some() && !self.is_parked() {
            self.parked_until = Some(Instant::now() + park_duration(self.consecutive_failures));
        }
    }
}

impl Default for ResolverStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Global statistics for the DNS server
#[derive(Debug, Clone)]
pub struct GlobalStats {
    /// Total number of queries processed
    pub total_queries: u64,
    /// Total number of successful queries
    pub total_successful: u64,
    /// Total number of failed queries
    pub total_failed: u64,
    /// Total number of timed out queries
    pub total_timeouts: u64,
    /// Total number of client queries received
    pub client_queries: u64,
    /// Total number of cache hits
    pub cache_hits: u64,
    /// Total number of cache misses
    pub cache_misses: u64,
    /// Count of UDP receive errors
    pub udp_receive_errors: u64,
    /// Count of TCP accept errors
    pub tcp_accept_errors: u64,
    /// Map of resolver addresses to their stats
    pub resolver_stats: HashMap<SocketAddr, ResolverStats>,
}

impl GlobalStats {
    /// Create a new GlobalStats with default values
    pub fn new() -> Self {
        Self {
            total_queries: 0,
            total_successful: 0,
            total_failed: 0,
            total_timeouts: 0,
            client_queries: 0,
            cache_hits: 0,
            cache_misses: 0,
            udp_receive_errors: 0,
            tcp_accept_errors: 0,
            resolver_stats: HashMap::new(),
        }
    }

    /// Record a successful query for a resolver
    pub fn record_success(&mut self, resolver: SocketAddr, response_time: Duration) {
        self.total_queries = self.total_queries.saturating_add(1);
        self.total_successful = self.total_successful.saturating_add(1);

        let stats = self.resolver_stats.entry(resolver).or_default();
        stats.record_success(response_time);
    }

    /// Record a failed query for a resolver
    pub fn record_failure(&mut self, resolver: SocketAddr) {
        self.total_queries = self.total_queries.saturating_add(1);
        self.total_failed = self.total_failed.saturating_add(1);

        let stats = self.resolver_stats.entry(resolver).or_default();
        stats.record_failure();
    }

    /// Record a timed out query for a resolver
    pub fn record_timeout(&mut self, resolver: SocketAddr) {
        self.total_queries = self.total_queries.saturating_add(1);
        self.total_timeouts = self.total_timeouts.saturating_add(1);

        let stats = self.resolver_stats.entry(resolver).or_default();
        stats.record_timeout();
    }

    /// Record an answer that can't be timed, such as the reply to a retry
    pub fn clear_failures(&mut self, resolver: SocketAddr) {
        if let Some(stats) = self.resolver_stats.get_mut(&resolver) {
            stats.clear_failures();
        }
    }

    /// Record that a query is about to be sent to a resolver.
    ///
    /// If the resolver's parking time is over, this query is a trial.
    /// Other queries stay away until we know how it went, in case the resolver is still down.
    pub fn record_query_sent(&mut self, resolver: SocketAddr) {
        if let Some(stats) = self.resolver_stats.get_mut(&resolver) {
            stats.record_query_sent();
        }
    }

    /// Get statistics for a specific resolver
    pub fn get_resolver_stats(&self, resolver: &SocketAddr) -> Option<&ResolverStats> {
        self.resolver_stats.get(resolver)
    }

    /// Record a client query
    pub fn record_client_query(&mut self) {
        self.client_queries = self.client_queries.saturating_add(1);
    }

    /// Record a cache hit
    pub fn record_cache_hit(&mut self) {
        self.cache_hits = self.cache_hits.saturating_add(1);
    }

    /// Record a cache miss
    pub fn record_cache_miss(&mut self) {
        self.cache_misses = self.cache_misses.saturating_add(1);
    }

    /// Increment the UDP receive errors counter
    pub fn increment_udp_receive_errors(&mut self) {
        self.udp_receive_errors = self.udp_receive_errors.saturating_add(1);
    }

    /// Increment the TCP accept errors counter
    pub fn increment_tcp_accept_errors(&mut self) {
        self.tcp_accept_errors = self.tcp_accept_errors.saturating_add(1);
    }

    /// Get a list of resolvers sorted by response time (fastest first)
    ///
    /// Resolvers that keep failing are left out for a while.
    pub fn get_resolvers_by_speed(&self) -> Vec<(SocketAddr, f64)> {
        let mut resolvers: Vec<(SocketAddr, f64)> = self
            .resolver_stats
            .iter()
            .filter(|(_, stats)| stats.success_count > 0 && !stats.is_parked())
            .map(|(addr, stats)| (*addr, stats.avg_response_time_ms))
            .collect();

        // Sort by response time (ascending)
        resolvers.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        resolvers
    }

    /// Checks whether every resolver missed enough queries in a row to be considered down
    pub fn all_resolvers_failing(&self) -> bool {
        !self.resolver_stats.is_empty()
            && self
                .resolver_stats
                .values()
                .all(|stats| stats.consecutive_failures >= PARK_AFTER_FAILURES)
    }
}

impl Default for GlobalStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for GlobalStats
#[derive(Debug, Clone)]
pub struct SharedStats {
    inner: Arc<Mutex<GlobalStats>>,
}

impl SharedStats {
    /// Create a new SharedStats
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(GlobalStats::new())),
        }
    }

    /// Record a successful query
    pub async fn record_success(&self, resolver: SocketAddr, response_time: Duration) {
        let mut stats = self.inner.lock().await;
        stats.record_success(resolver, response_time);
    }

    /// Record a failed query
    pub async fn record_failure(&self, resolver: SocketAddr) {
        let mut stats = self.inner.lock().await;
        stats.record_failure(resolver);
    }

    /// Record a timed out query
    pub async fn record_timeout(&self, resolver: SocketAddr) {
        let mut stats = self.inner.lock().await;
        stats.record_timeout(resolver);
    }

    /// Record an answer that can't be timed, such as the reply to a retry
    pub async fn clear_failures(&self, resolver: SocketAddr) {
        let mut stats = self.inner.lock().await;
        stats.clear_failures(resolver);
    }

    /// Record that a query is about to be sent to a resolver
    pub async fn record_query_sent(&self, resolver: SocketAddr) {
        let mut stats = self.inner.lock().await;
        stats.record_query_sent(resolver);
    }

    /// Get a snapshot of the global stats
    pub async fn get_stats(&self) -> GlobalStats {
        let stats = self.inner.lock().await;
        stats.clone()
    }

    /// Record a client query
    pub async fn record_client_query(&self) {
        let mut stats = self.inner.lock().await;
        stats.record_client_query();
    }

    /// Record a cache hit
    pub async fn record_cache_hit(&self) {
        let mut stats = self.inner.lock().await;
        stats.record_cache_hit();
    }

    /// Record a cache miss
    pub async fn record_cache_miss(&self) {
        let mut stats = self.inner.lock().await;
        stats.record_cache_miss();
    }

    /// Get a list of resolvers sorted by response time (fastest first)
    pub async fn get_resolvers_by_speed(&self) -> Vec<(SocketAddr, f64)> {
        let stats = self.inner.lock().await;
        stats.get_resolvers_by_speed()
    }

    /// Checks whether every resolver missed enough queries in a row to be considered down
    pub async fn all_resolvers_failing(&self) -> bool {
        let stats = self.inner.lock().await;
        stats.all_resolvers_failing()
    }

    /// Increment the UDP receive errors counter
    pub async fn increment_udp_receive_errors(&self) {
        let mut stats = self.inner.lock().await;
        stats.increment_udp_receive_errors();
    }

    /// Increment the TCP accept errors counter
    pub async fn increment_tcp_accept_errors(&self) {
        let mut stats = self.inner.lock().await;
        stats.increment_tcp_accept_errors();
    }
}

impl Default for SharedStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_counter_saturation() {
        let mut stats = GlobalStats::new();

        // Set counters near maximum
        stats.total_queries = u64::MAX - 1;
        stats.cache_hits = u64::MAX - 1;

        // These should saturate instead of overflowing
        stats.record_client_query();
        stats.record_cache_hit();

        assert_eq!(stats.client_queries, 1);
        assert_eq!(stats.cache_hits, u64::MAX);

        // One more increment should still be at MAX
        stats.record_cache_hit();
        assert_eq!(stats.cache_hits, u64::MAX);
    }

    #[test]
    fn test_resolver_stats_saturation() {
        let mut stats = ResolverStats::new();

        // Set counters near maximum
        stats.success_count = u64::MAX - 1;
        stats.failure_count = u64::MAX - 1;
        stats.timeout_count = u64::MAX - 1;

        // These should saturate instead of overflowing
        stats.record_success(Duration::from_secs(1));
        stats.record_failure();
        stats.record_timeout();

        assert_eq!(stats.success_count, u64::MAX);
        assert_eq!(stats.failure_count, u64::MAX);
        assert_eq!(stats.timeout_count, u64::MAX);
    }

    #[test]
    fn test_sub_millisecond_samples_are_averaged() {
        let mut stats = ResolverStats::new();
        for _ in 0..100 {
            stats.record_success(Duration::from_micros(400));
        }
        stats.record_success(Duration::from_millis(100));

        assert!((stats.avg_response_time_ms - 20.32).abs() < 0.01);
    }

    #[test]
    fn test_failing_resolver_is_parked_for_a_while() {
        let mut stats = GlobalStats::new();
        let fast: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let slow: SocketAddr = "192.0.2.2:53".parse().unwrap();
        stats.record_success(fast, Duration::from_millis(10));
        stats.record_success(slow, Duration::from_millis(50));
        let without_fast = vec![(slow, 50.0)];

        for _ in 1..PARK_AFTER_FAILURES {
            stats.record_timeout(fast);
        }
        assert_eq!(stats.get_resolvers_by_speed().len(), 2);
        stats.record_timeout(fast);
        assert_eq!(stats.get_resolvers_by_speed(), without_fast);

        // When the time is up, it gets one trial query, not all of them
        stats.resolver_stats.get_mut(&fast).unwrap().parked_until = Some(Instant::now());
        assert_eq!(stats.get_resolvers_by_speed().len(), 2);
        stats.record_query_sent(slow);
        assert_eq!(stats.get_resolvers_by_speed().len(), 2);
        stats.record_query_sent(fast);
        assert_eq!(stats.get_resolvers_by_speed(), without_fast);

        stats.record_success(fast, Duration::from_millis(10));
        assert_eq!(stats.get_resolvers_by_speed().len(), 2);

        // Each failed trial doubles the wait
        assert_eq!(park_duration(PARK_AFTER_FAILURES), MIN_PARK_DURATION);
        assert_eq!(
            park_duration(PARK_AFTER_FAILURES + 1),
            MIN_PARK_DURATION * 2
        );
        assert_eq!(park_duration(u64::MAX), MAX_PARK_DURATION);
    }

    #[test]
    fn test_resolvers_are_failing_until_one_answers() {
        let mut stats = GlobalStats::new();
        let first: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let second: SocketAddr = "192.0.2.2:53".parse().unwrap();
        assert!(!stats.all_resolvers_failing());

        for _ in 1..PARK_AFTER_FAILURES {
            stats.record_timeout(first);
        }
        assert!(!stats.all_resolvers_failing());
        stats.record_timeout(first);
        assert!(stats.all_resolvers_failing());
        stats.record_success(second, Duration::from_millis(10));
        assert!(!stats.all_resolvers_failing());
    }
}
