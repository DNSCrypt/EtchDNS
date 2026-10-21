use sieve_cache::SyncSieveCache;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use crate::dns_key::DNSKey;

/// Default number of queries whose failures are remembered
pub const DEFAULT_FAILURE_CACHE_SIZE: usize = 1024;

/// Default delay after a first failure, in seconds
pub const DEFAULT_FAILURE_BACKOFF_MIN: u64 = 1;

/// Default longest delay after repeated failures, in seconds
pub const DEFAULT_FAILURE_BACKOFF_MAX: u64 = 30;

/// Longest delay that can be configured, in seconds
pub const FAILURE_BACKOFF_LIMIT: u64 = 300;

/// How long a server is left alone after it failed a query
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailurePolicy {
    /// Number of queries whose failures are remembered, 0 to remember none
    pub cache_size: usize,
    /// Delay after the first failure
    pub backoff_min: Duration,
    /// Each new failure doubles the delay, up to this one
    pub backoff_max: Duration,
}

impl FailurePolicy {
    /// Checks the settings, with delays in seconds
    pub fn new(cache_size: usize, backoff_min: u64, backoff_max: u64) -> Result<Self, String> {
        if backoff_min < 1 || backoff_min > backoff_max || backoff_max > FAILURE_BACKOFF_LIMIT {
            return Err(format!(
                "Invalid failure backoff: {backoff_min} to {backoff_max} seconds. \
                 Must satisfy 1 <= failure_backoff_min <= failure_backoff_max <= {FAILURE_BACKOFF_LIMIT}"
            ));
        }
        Ok(Self {
            cache_size,
            backoff_min: Duration::from_secs(backoff_min),
            backoff_max: Duration::from_secs(backoff_max),
        })
    }
}

impl Default for FailurePolicy {
    fn default() -> Self {
        Self {
            cache_size: DEFAULT_FAILURE_CACHE_SIZE,
            backoff_min: Duration::from_secs(DEFAULT_FAILURE_BACKOFF_MIN),
            backoff_max: Duration::from_secs(DEFAULT_FAILURE_BACKOFF_MAX),
        }
    }
}

/// How a server failed a query
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    ServFail,
    Timeout,
}

/// The recent failures of one server for one query
#[derive(Debug, Clone, Copy)]
struct FailureSlot {
    backoff: Duration,
    retry_at: Instant,
    /// Without a new failure until then, the next one starts again with the shortest delay
    forget_at: Instant,
}

impl FailureSlot {
    fn after(previous: Option<FailureSlot>, now: Instant, policy: &FailurePolicy) -> Self {
        let backoff = match previous.filter(|slot| now < slot.forget_at) {
            Some(slot) => slot.backoff.saturating_mul(2).min(policy.backoff_max),
            None => policy.backoff_min,
        };
        // On overflow, retry at once rather than panic or wait forever
        let retry_at = now.checked_add(backoff).unwrap_or(now);
        let forget_at = retry_at.checked_add(policy.backoff_max).unwrap_or(retry_at);
        Self {
            backoff,
            retry_at,
            forget_at,
        }
    }
}

/// What the failure cache knows about a query
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FailureState {
    /// The servers that can get the query now
    pub eligible: Vec<SocketAddr>,
    /// When no server can get the query, the time when the first one can
    pub retry_at: Option<Instant>,
    /// Whether a server failed the query recently
    pub recent_failure: bool,
}

/// Recent failures, by query and by upstream server.
///
/// A server that failed a query gets it again only after a delay, which doubles with each new failure, up to a maximum.
/// Other servers can still get the query, and the server can still get other queries.
///
/// Each query has one slot per server, so the memory use is bounded.
/// An evicted query only loses its history.
#[derive(Clone)]
pub struct FailureCache {
    entries: SyncSieveCache<DNSKey, Box<[Option<FailureSlot>]>>,
    upstream_servers: Arc<[SocketAddr]>,
    policy: FailurePolicy,
}

impl FailureCache {
    /// Returns None if the policy remembers no failures
    pub fn new(policy: FailurePolicy, upstream_servers: Arc<[SocketAddr]>) -> Option<Self> {
        let entries = SyncSieveCache::new(policy.cache_size).ok()?;
        Some(Self {
            entries,
            upstream_servers,
            policy,
        })
    }

    /// Tells which servers can get the query now.
    ///
    /// The query counts as recently used, but its delays stay the same.
    pub fn state(&self, key: &DNSKey, now: Instant) -> FailureState {
        self.entries
            .with_lock(|inner| self.state_of(inner.get(key).map(|slots| &slots[..]), now))
    }

    fn state_of(&self, slots: Option<&[Option<FailureSlot>]>, now: Instant) -> FailureState {
        let mut state = FailureState::default();
        let mut retry_at = None;
        for (index, &server) in self.upstream_servers.iter().enumerate() {
            let slot = slots
                .and_then(|slots| slots[index])
                .filter(|slot| now < slot.forget_at);
            match slot {
                Some(slot) if now < slot.retry_at => {
                    state.recent_failure = true;
                    retry_at =
                        Some(retry_at.map_or(slot.retry_at, |at: Instant| at.min(slot.retry_at)));
                }
                Some(_) => {
                    state.recent_failure = true;
                    state.eligible.push(server);
                }
                None => state.eligible.push(server),
            }
        }
        if state.eligible.is_empty() {
            state.retry_at = retry_at;
        }
        state
    }

    /// Records that a server failed the query.
    ///
    /// Returns when the first server can get the query again, if no server can get it now.
    pub fn record_failure(
        &self,
        key: &DNSKey,
        server: SocketAddr,
        kind: FailureKind,
        now: Instant,
    ) -> Option<Instant> {
        let index = self.index(server)?;
        let slot_count = self.upstream_servers.len();
        let (backoff, retry_at) = self.entries.with_lock(|inner| {
            if let Some(slots) = inner.get_mut(key) {
                let slot = FailureSlot::after(slots[index], now, &self.policy);
                slots[index] = Some(slot);
                return (slot.backoff, self.state_of(Some(slots), now).retry_at);
            }
            // A new entry is not marked as used, so that queries in use stay longer
            let slot = FailureSlot::after(None, now, &self.policy);
            let mut slots = vec![None; slot_count].into_boxed_slice();
            slots[index] = Some(slot);
            let retry_at = self.state_of(Some(&slots), now).retry_at;
            inner.insert(key.clone(), slots);
            (slot.backoff, retry_at)
        });
        log::debug!(
            "{server} failed the query for {} ({kind:?}), next query in {backoff:?}",
            key.name
        );
        retry_at
    }

    /// Forgets the failures of a server for the query, after a useful answer
    pub fn record_success(&self, key: &DNSKey, server: SocketAddr) {
        let Some(index) = self.index(server) else {
            return;
        };
        self.entries.with_lock(|inner| {
            let Some(slots) = inner.get_mut(key) else {
                return;
            };
            slots[index] = None;
            if slots.iter().all(Option::is_none) {
                inner.remove(key);
            }
        });
    }

    /// Keeps only the queries for which `keep` returns true
    pub fn retain(&self, mut keep: impl FnMut(&DNSKey) -> bool) {
        self.entries
            .with_lock(|inner| inner.retain(|key, _| keep(key)));
    }

    /// Forgets every failure
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Number of queries with a recent failure
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Maximum number of queries with a recent failure
    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    fn index(&self, server: SocketAddr) -> Option<usize> {
        let index = self.upstream_servers.iter().position(|s| *s == server);
        if index.is_none() {
            log::error!("{server} is not a configured upstream server");
        }
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn servers() -> Arc<[SocketAddr]> {
        Arc::new([
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        ])
    }

    fn key(name: &str) -> DNSKey {
        DNSKey::new(name.to_string(), 1, 1, false).unwrap()
    }

    fn cache(cache_size: usize) -> FailureCache {
        let policy = FailurePolicy {
            cache_size,
            ..FailurePolicy::default()
        };
        FailureCache::new(policy, servers()).unwrap()
    }

    /// The delay before `server` gets the query again
    fn delay(cache: &FailureCache, key: &DNSKey, server: SocketAddr, now: Instant) -> Duration {
        let mut delay = Duration::ZERO;
        while !cache.state(key, now + delay).eligible.contains(&server) {
            delay += Duration::from_millis(500);
        }
        delay
    }

    #[test]
    fn test_policy_limits() {
        assert_eq!(
            FailurePolicy::new(1024, 1, 30).unwrap(),
            FailurePolicy::default()
        );
        assert!(FailurePolicy::new(0, 1, 30).is_ok());
        assert!(FailurePolicy::new(10, 1, 300).is_ok());
        for (min, max) in [(0, 30), (31, 30), (1, 301)] {
            assert!(FailurePolicy::new(10, min, max).is_err());
        }
        let disabled = FailurePolicy {
            cache_size: 0,
            ..FailurePolicy::default()
        };
        assert!(FailureCache::new(disabled, servers()).is_none());
    }

    #[test]
    fn test_delay_doubles_up_to_the_maximum() {
        let cache = cache(10);
        let key = key("example.com");
        let server = servers()[0];
        let mut now = Instant::now();
        for expected in [1, 2, 4, 8, 16, 30, 30] {
            cache.record_failure(&key, server, FailureKind::Timeout, now);
            let delay = delay(&cache, &key, server, now);
            assert_eq!(delay, Duration::from_secs(expected));
            now += delay;
        }
    }

    #[test]
    fn test_reads_do_not_change_the_delay() {
        let cache = cache(10);
        let key = key("example.com");
        let server = servers()[0];
        let now = Instant::now();
        cache.record_failure(&key, server, FailureKind::ServFail, now);
        for _ in 0..100 {
            cache.state(&key, now + Duration::from_millis(900));
        }

        assert_eq!(delay(&cache, &key, server, now), Duration::from_secs(1));
        cache.record_failure(
            &key,
            server,
            FailureKind::ServFail,
            now + Duration::from_secs(1),
        );
        assert_eq!(
            delay(&cache, &key, server, now + Duration::from_secs(1)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn test_history_is_forgotten_after_a_quiet_period() {
        let cache = cache(10);
        let key = key("example.com");
        let server = servers()[0];
        let now = Instant::now();
        cache.record_failure(&key, server, FailureKind::Timeout, now);
        cache.record_failure(
            &key,
            server,
            FailureKind::Timeout,
            now + Duration::from_secs(1),
        );
        assert!(
            cache
                .state(&key, now + Duration::from_secs(3))
                .recent_failure
        );

        // The retry was possible at 3s, and the history lasts the maximum delay after that
        let later = now + Duration::from_secs(33);
        assert!(!cache.state(&key, later).recent_failure);
        cache.record_failure(&key, server, FailureKind::Timeout, later);
        assert_eq!(delay(&cache, &key, server, later), Duration::from_secs(1));
    }

    #[test]
    fn test_a_failing_server_does_not_hold_back_the_others() {
        let cache = cache(10);
        let key = key("example.com");
        let [first, second] = [servers()[0], servers()[1]];
        let now = Instant::now();
        assert_eq!(
            cache.record_failure(&key, first, FailureKind::ServFail, now),
            None
        );

        let state = cache.state(&key, now);
        assert_eq!(state.eligible, vec![second]);
        assert_eq!(state.retry_at, None);
        assert!(state.recent_failure);

        // Once no server is left, the earliest retry comes back
        let retry_at = cache.record_failure(
            &key,
            second,
            FailureKind::Timeout,
            now + Duration::from_millis(300),
        );
        assert_eq!(retry_at, Some(now + Duration::from_secs(1)));
        let state = cache.state(&key, now + Duration::from_millis(500));
        assert!(state.eligible.is_empty());
        assert_eq!(state.retry_at, Some(now + Duration::from_secs(1)));

        cache.record_success(&key, first);
        assert_eq!(cache.state(&key, now).eligible, vec![first]);
        cache.record_success(&key, second);
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_query_variants_have_their_own_history() {
        let cache = cache(10);
        let key = key("example.com");
        let server = servers()[0];
        let now = Instant::now();
        cache.record_failure(&key, server, FailureKind::ServFail, now);

        let mut variants = vec![key.clone(), key.clone(), key.clone(), key.clone()];
        variants[0].name = "www.example.com".to_string();
        variants[1].qtype = 28;
        variants[2].dnssec = true;
        variants[3].recursion_desired = true;
        let mut with_subnet = key.clone();
        with_subnet.set_client_subnet("192.0.2.1", 24, 56);
        variants.push(with_subnet);
        for variant in variants {
            assert_eq!(cache.state(&variant, now).eligible.len(), 2, "{variant:?}");
        }
        assert_eq!(cache.state(&key, now).eligible.len(), 1);
    }

    #[test]
    fn test_queries_in_use_are_kept() {
        let cache = cache(2);
        let server = servers()[0];
        let now = Instant::now();
        let hot = key("hot.example");
        cache.record_failure(&hot, server, FailureKind::Timeout, now);
        cache.record_failure(&key("cold1.example"), server, FailureKind::Timeout, now);

        // A request for the hot query marks it, so the next insertion evicts the other one
        cache.state(&hot, now);
        cache.record_failure(&key("cold2.example"), server, FailureKind::Timeout, now);

        assert_eq!((cache.size(), cache.capacity()), (2, 2));
        assert!(cache.state(&hot, now).recent_failure);
        assert!(!cache.state(&key("cold1.example"), now).recent_failure);
    }
}
