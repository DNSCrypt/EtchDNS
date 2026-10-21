use futures::future::BoxFuture;
use log::{error, warn};
use slabigator::Slab;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;

use crate::cache::CachedResponse;
use crate::dns_key::DNSKey;
use crate::dns_parser::EdnsClientSubnet;
use crate::errors::{DnsError, EtchDnsResult};
use crate::failure_cache::{FailureCache, FailureKind, FailurePolicy, FailureState};
use crate::load_balancer::LoadBalancingStrategy;
use crate::resolver::{
    AttemptError, AttemptFlags, AttemptOutcome, AttemptProgress, AttemptRequest,
};

/// Maximum number of receivers for a single query
const MAX_RECEIVERS: usize = 100;

/// Response from a DNS query
#[derive(Clone)]
pub struct DnsResponse {
    /// The raw DNS response data
    pub data: Vec<u8>,
    /// Error message if the query failed
    pub error: Option<String>,
    /// Set on a SERVFAIL when no upstream server can get the query for a while
    pub failure_freshness: Option<FailureFreshness>,
}

impl DnsResponse {
    /// A response to send to the client
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            error: None,
            failure_freshness: None,
        }
    }

    /// No response for the client, because of this error
    pub fn failed(error: String) -> Self {
        Self {
            data: Vec::new(),
            error: Some(error),
            failure_freshness: None,
        }
    }
}

/// How long an HTTP cache may keep a SERVFAIL
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureFreshness {
    /// No upstream server gets the query before then
    pub retry_at: tokio::time::Instant,
    /// Whether every client that sends the same request gets this failure
    pub shared: bool,
}

/// Manager for in-flight DNS queries
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct QueryManager {
    /// Map of in-flight queries
    /// Key: DNSKey representing the query
    /// Value: InflightQuery containing the task and slab ID
    in_flight_queries: Arc<Mutex<HashMap<DNSKey, InflightQuery>>>,

    /// Slab for tracking the order of in-flight queries
    /// Each entry contains the DNSKey of a query
    query_slab: Arc<Mutex<Slab<DNSKey>>>,

    /// Maximum number of in-flight queries allowed
    max_inflight_queries: usize,

    /// Maximum time (in seconds) to wait for a response from an upstream server
    server_timeout: u64,

    /// Maximum DNS packet size
    dns_packet_len_max: usize,

    /// Global statistics tracker
    stats: Option<Arc<crate::stats::SharedStats>>,

    /// Load balancing strategy
    load_balancing_strategy: LoadBalancingStrategy,

    /// Upstream servers, each with a single entry
    upstream_servers: Arc<[SocketAddr]>,

    /// How long a server is left alone after it failed a query
    failure_policy: FailurePolicy,

    /// Recent failures, by query and by upstream server
    failure_cache: Option<FailureCache>,

    /// DNS cache
    cache: Option<crate::cache::SyncDnsCache>,

    /// Whether this server is authoritative for DNS responses
    /// If false, TTLs in cached responses will be adjusted based on remaining time
    authoritative_dns: bool,

    /// List of allowed zones
    /// If set, only queries for domains in this list will be processed
    allowed_zones: Option<crate::allowed_zones::AllowedZones>,

    /// List of nonexistent zones
    /// If set, queries for domains in this list will return NXDOMAIN directly
    nx_zones: Option<crate::nx_zones::NxZones>,

    /// Grace period in seconds to serve stale (expired) cache entries when upstream servers fail
    /// If 0, stale entries will not be served
    serve_stale_grace_time: u64,

    /// TTL in seconds to use when serving stale cache entries
    serve_stale_ttl: u32,

    /// TTL in seconds to use for negative DNS responses when no TTL is available
    negative_cache_ttl: u32,

    /// Minimum TTL in seconds for cached DNS responses
    min_cache_ttl: u32,

    /// Hooks for customizing DNS query processing
    hooks: Option<Arc<crate::hooks::SharedHooks>>,

    /// Query logger for logging DNS queries to a file
    query_logger: Option<Arc<crate::query_logger::QueryLogger>>,

    /// Whether EDNS-client-subnet is enabled
    enable_ecs: bool,

    /// IPv4 prefix length for EDNS-client-subnet
    ecs_prefix_v4: u8,

    /// IPv6 prefix length for EDNS-client-subnet
    ecs_prefix_v6: u8,

    /// Enable protection against DNS spoofing attacks
    spoof_protection: bool,
}

/// Represents a task handling a DNS query
struct QueryTask {
    /// The task handle
    task_handle: JoinHandle<()>,
    /// The sender for broadcasting the response to all interested clients
    response_sender: broadcast::Sender<DnsResponse>,
}

/// In-flight query information
struct InflightQuery {
    /// The task handling the query
    task: QueryTask,

    /// The slab identifier for this query
    slab_id: u32,
}

/// What to do with a query that the cache can't answer
enum Admission<'a> {
    /// The same query is in flight, so its response will do
    Join {
        receiver: broadcast::Receiver<DnsResponse>,
        recent_failure: bool,
    },
    /// A task that just finished cached an answer
    Cached(DnsResponse),
    /// Every upstream server failed this query recently, and the first one can get it then
    Suppressed(tokio::time::Instant),
    /// A new task can send the query to one of these servers
    Start {
        in_flight_queries: tokio::sync::MutexGuard<'a, HashMap<DNSKey, InflightQuery>>,
        query_slab: tokio::sync::MutexGuard<'a, Slab<DNSKey>>,
        candidates: Vec<SocketAddr>,
        recent_failure: bool,
    },
}

/// What an attempt tells about its upstream server, for the failure cache
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum History {
    Unchanged,
    Failed(SocketAddr, FailureKind),
    Answered(SocketAddr),
}

/// What a task learned, to publish when it finishes
struct Completion {
    response: DnsResponse,
    /// An answer for the cache
    cached: Option<CachedResponse>,
    history: History,
}

impl Completion {
    fn new(response: DnsResponse) -> Self {
        Self {
            response,
            cached: None,
            history: History::Unchanged,
        }
    }
}

impl QueryManager {
    /// Create a new QueryManager with statistics tracking
    pub fn new(
        max_inflight_queries: usize,
        server_timeout: u64,
        dns_packet_len_max: usize,
        stats: Arc<crate::stats::SharedStats>,
        load_balancing_strategy: LoadBalancingStrategy,
        authoritative_dns: bool,
        serve_stale_grace_time: u64,
        serve_stale_ttl: u32,
        negative_cache_ttl: u32,
        min_cache_ttl: u32,
        enable_ecs: bool,
        ecs_prefix_v4: u8,
        ecs_prefix_v6: u8,
        spoof_protection: bool,
    ) -> Self {
        Self {
            in_flight_queries: Arc::new(Mutex::new(HashMap::new())),
            query_slab: {
                // Try with requested capacity first
                let slab = if let Ok(s) = Slab::with_capacity(max_inflight_queries) {
                    s
                } else {
                    // Log the failure and try with half capacity
                    error!(
                        "Failed to create query slab with requested capacity of {max_inflight_queries} entries"
                    );
                    let smaller_capacity = std::cmp::max(100, max_inflight_queries / 2);
                    warn!(
                        "Falling back to smaller query slab capacity: {smaller_capacity} entries"
                    );

                    if let Ok(s) = Slab::with_capacity(smaller_capacity) {
                        s
                    } else {
                        // Log the failure and try with minimal capacity
                        error!(
                            "Failed to create query slab with reduced capacity of {smaller_capacity} entries"
                        );
                        let minimal_capacity = 10; // Absolute minimum that should work
                        warn!(
                            "Falling back to minimal query slab capacity: {minimal_capacity} entries"
                        );

                        match Slab::with_capacity(minimal_capacity) {
                            Ok(s) => s,
                            Err(e) => {
                                // Last resort - try with capacity 1
                                error!(
                                    "Critical error: Failed to allocate even minimal query slab with {minimal_capacity} entries: {e}"
                                );
                                warn!(
                                    "Attempting with capacity 1 - performance will be severely degraded"
                                );

                                Slab::with_capacity(1).unwrap_or_else(|e2| {
                                    // This should never happen with capacity 1, but just in case
                                    panic!("Fatal error: Cannot allocate even a trivial slab with 1 entry. System is likely out of memory: {e2}")
                                })
                            }
                        }
                    }
                };

                Arc::new(Mutex::new(slab))
            },
            max_inflight_queries,
            server_timeout,
            dns_packet_len_max,
            stats: Some(stats),
            load_balancing_strategy,
            upstream_servers: Arc::new([]),
            failure_policy: FailurePolicy::default(),
            failure_cache: None,
            cache: None, // Initialize cache as None, will be set later
            authoritative_dns,
            allowed_zones: None, // Initialize allowed_zones as None, will be set later if needed
            nx_zones: None,      // Initialize nx_zones as None, will be set later if needed
            serve_stale_grace_time,
            serve_stale_ttl,
            negative_cache_ttl,
            min_cache_ttl,
            hooks: None,        // Initialize hooks as None, will be set later if needed
            query_logger: None, // Initialize query_logger as None, will be set later if needed
            enable_ecs,
            ecs_prefix_v4,
            ecs_prefix_v6,
            spoof_protection,
        }
    }

    /// A manager without cache, filters, or stale answers, for tests
    #[cfg(test)]
    pub(crate) fn for_tests(
        server_timeout: u64,
        dns_packet_len_max: usize,
        spoof_protection: bool,
    ) -> Self {
        let mut manager = Self::new(
            10,
            server_timeout,
            dns_packet_len_max,
            Arc::new(crate::stats::SharedStats::new()),
            LoadBalancingStrategy::Random,
            false,
            0,
            30,
            1,
            1,
            false,
            24,
            56,
            spoof_protection,
        );
        manager.set_upstream_servers(vec!["192.0.2.53:53".parse().unwrap()]);
        manager
    }

    /// Set the statistics tracker
    #[allow(dead_code)]
    pub fn set_stats(&mut self, stats: Arc<crate::stats::SharedStats>) {
        self.stats = Some(stats);
    }

    /// Set the upstream servers.
    ///
    /// A server listed twice gets a single entry, so that it has a single failure history.
    pub fn set_upstream_servers(&mut self, upstream_servers: Vec<SocketAddr>) {
        let mut unique: Vec<SocketAddr> = Vec::with_capacity(upstream_servers.len());
        for upstream in upstream_servers {
            // An IPv4-mapped IPv6 address reaches the same server as the IPv4 address
            let upstream = match upstream {
                SocketAddr::V6(v6) => v6
                    .ip()
                    .to_ipv4_mapped()
                    .map_or(upstream, |v4| SocketAddr::new(v4.into(), v6.port())),
                SocketAddr::V4(_) => upstream,
            };
            if !unique.contains(&upstream) {
                unique.push(upstream);
            }
        }
        self.upstream_servers = unique.into();
        self.failure_cache = FailureCache::new(self.failure_policy, self.upstream_servers.clone());
    }

    /// Get the upstream servers, each with a single entry
    pub fn get_upstream_servers(&self) -> Arc<[SocketAddr]> {
        self.upstream_servers.clone()
    }

    /// Set how long upstream servers are left alone after they failed a query
    pub fn set_failure_policy(&mut self, failure_policy: FailurePolicy) {
        self.failure_policy = failure_policy;
        self.failure_cache = FailureCache::new(failure_policy, self.upstream_servers.clone());
    }

    /// Get the recent failures of the upstream servers
    pub fn get_failure_cache(&self) -> Option<FailureCache> {
        self.failure_cache.clone()
    }

    /// Set the DNS cache
    pub fn set_cache(&mut self, cache: crate::cache::SyncDnsCache) {
        self.cache = Some(cache);
    }

    /// Set the allowed zones
    pub fn set_allowed_zones(&mut self, allowed_zones: crate::allowed_zones::AllowedZones) {
        self.allowed_zones = Some(allowed_zones);
    }

    /// Set the nonexistent zones
    pub fn set_nx_zones(&mut self, nx_zones: crate::nx_zones::NxZones) {
        self.nx_zones = Some(nx_zones);
    }

    /// Set the hooks
    pub fn set_hooks(&mut self, hooks: Arc<crate::hooks::SharedHooks>) {
        self.hooks = Some(hooks);
    }

    /// Set the query logger
    pub fn set_query_logger(&mut self, query_logger: Arc<crate::query_logger::QueryLogger>) {
        self.query_logger = Some(query_logger);
    }

    /// Get the statistics tracker
    pub fn get_stats(&self) -> Option<Arc<crate::stats::SharedStats>> {
        self.stats.clone()
    }

    /// Get the hooks
    #[allow(dead_code)]
    pub fn get_hooks(&self) -> Option<Arc<crate::hooks::SharedHooks>> {
        self.hooks.clone()
    }

    /// Submit a query with client address and get a receiver for the response
    ///
    /// If the query is already in flight, this will add a new receiver to the existing query.
    /// If the query is not in flight, this will create a new task to handle the query.
    /// If the maximum number of in-flight queries has been reached, this will return an error.
    pub async fn submit_query_with_client(
        &self,
        key: DNSKey,
        query_data: Vec<u8>,
        resolver: impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static,
        client_addr: &str,
    ) -> EtchDnsResult<broadcast::Receiver<DnsResponse>> {
        // Log the query if query logging is enabled
        if let Some(query_logger) = &self.query_logger {
            let _ = query_logger.log_query(&key, client_addr).await;
        }

        let client_ip = match client_addr.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr.ip().to_string(),
            Err(_) => match client_addr.parse::<std::net::IpAddr>() {
                Ok(ip) => ip.to_string(),
                Err(_) => {
                    warn!("Unable to parse client address: {client_addr}, using 'unknown'");
                    "unknown".to_string()
                }
            },
        };

        // Call the internal implementation with client IP
        self.submit_query_internal_with_client(key, query_data, resolver, &client_ip)
            .await
    }

    /// Submit a query and get a receiver for the response
    ///
    /// If the query is already in flight, this will add a new receiver to the existing query.
    /// If the query is not in flight, this will create a new task to handle the query.
    /// If the maximum number of in-flight queries has been reached, this will return an error.
    #[allow(dead_code)]
    pub async fn submit_query(
        &self,
        key: DNSKey,
        query_data: Vec<u8>,
        resolver: impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static,
    ) -> EtchDnsResult<broadcast::Receiver<DnsResponse>> {
        // Log the query if query logging is enabled
        if let Some(query_logger) = &self.query_logger {
            // Use a fake client address if not available
            let client_addr = "unknown";
            let _ = query_logger.log_query(&key, client_addr).await;
        }

        // Call the internal implementation with a default client IP
        self.submit_query_internal_with_client(key, query_data, resolver, "unknown")
            .await
    }

    /// Internal implementation of submit_query with client IP
    async fn submit_query_internal_with_client(
        &self,
        mut key: DNSKey,
        mut query_data: Vec<u8>,
        resolver: impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static,
        client_ip: &str,
    ) -> EtchDnsResult<broadcast::Receiver<DnsResponse>> {
        // A client's cookie must not reach the upstream server or other clients
        crate::dns_parser::remove_edns_option(
            &mut query_data,
            crate::dns_parser::EDNS_OPTION_COOKIE,
        )?;

        if self.enable_ecs {
            key.set_client_subnet(client_ip, self.ecs_prefix_v4, self.ecs_prefix_v6);
        }
        if self.authoritative_dns {
            key.ignore_resolver_flags();
            crate::dns_parser::clear_resolver_flags(&mut query_data)?;
        }

        // Record client query in stats
        if let Some(stats) = &self.stats {
            stats.record_client_query().await;
        }

        // Handle domain filtering (ANY query, nonexistent domains, allowed zones)
        if let Some(filtered_response) = self.check_domain_filters(&key, &query_data).await {
            return Ok(filtered_response);
        }

        // Process WebAssembly hooks
        if let Some(hook_response) = self.process_hooks(&key, client_ip, &query_data).await {
            return Ok(hook_response);
        }

        // Check if the response is in the cache
        if let Some(cache_response) = self.check_cache(&key, &query_data).await {
            return Ok(cache_response);
        }

        let (receiver, recent_failure) = match self.admit(&key).await {
            Admission::Join {
                receiver,
                recent_failure,
            } => (Ok(receiver), recent_failure),
            Admission::Cached(response) => return Ok(Self::receiver_with_response(response)),
            Admission::Suppressed(retry_at) => {
                return Ok(self.suppressed_response(&key, &query_data, retry_at).await);
            }
            Admission::Start {
                mut in_flight_queries,
                mut query_slab,
                candidates,
                recent_failure,
            } => {
                // Create a new task to handle the query
                let (task, receiver) = self
                    .create_query_task(key.clone(), query_data, candidates, resolver)
                    .await;

                // Add the key to the front of the slab to track its age
                match query_slab.push_front(key.clone()) {
                    Ok(slab_id) => {
                        // Successfully added to slab, now add to the in-flight map
                        let inflight_query = InflightQuery { task, slab_id };
                        in_flight_queries.insert(key.clone(), inflight_query);

                        // No need to track in-flight queries counter, as we directly access slab length instead

                        log::debug!(
                            "Added query to slab and in-flight map, slab size: {}, map size: {}",
                            query_slab.len(),
                            in_flight_queries.len()
                        );

                        (Ok(receiver), recent_failure)
                    }
                    Err(e) => {
                        log::error!("Failed to add query to slab: {e}");
                        // Since we couldn't add to the slab, we won't add to the in-flight map either
                        // This ensures they stay in sync
                        (
                            Err(DnsError::Other(format!("Failed to add query to slab: {e}")).into()),
                            recent_failure,
                        )
                    }
                }
            }
        };

        // After recent failures, answer with stale data now, and let the query in flight refresh it
        let stale_response = if self.serve_stale_grace_time > 0
            && (recent_failure || self.all_resolvers_failing().await)
        {
            self.serve_stale(&key, "recent upstream failures")
        } else {
            None
        };

        stale_response.map_or(receiver, |response| {
            Ok(Self::receiver_with_response(response))
        })
    }

    /// Tells which upstream servers can get the query now
    fn failure_state(&self, key: &DNSKey) -> FailureState {
        match &self.failure_cache {
            Some(failure_cache) => failure_cache.state(key, tokio::time::Instant::now()),
            None => FailureState {
                eligible: self.upstream_servers.to_vec(),
                ..FailureState::default()
            },
        }
    }

    async fn all_resolvers_failing(&self) -> bool {
        match &self.stats {
            Some(stats) => stats.all_resolvers_failing().await,
            None => false,
        }
    }

    /// Answers a query that every upstream server failed recently, without asking them again
    async fn suppressed_response(
        &self,
        key: &DNSKey,
        query_data: &[u8],
        retry_at: tokio::time::Instant,
    ) -> broadcast::Receiver<DnsResponse> {
        if let Some(stats) = &self.stats {
            stats.record_failure_cache_hit().await;
        }
        let response = self
            .serve_stale(key, "recent failures of every upstream server")
            .unwrap_or_else(|| {
                log::debug!(
                    "Every upstream server failed the query for {} recently, returning SERVFAIL",
                    key.name
                );
                self.servfail(query_data, Some(retry_at))
            });
        Self::receiver_with_response(response)
    }

    /// Creates a SERVFAIL for the query, that HTTP caches may keep until `retry_at`
    fn servfail(&self, query_data: &[u8], retry_at: Option<tokio::time::Instant>) -> DnsResponse {
        DnsResponse {
            failure_freshness: retry_at.map(|retry_at| self.failure_freshness(retry_at)),
            ..Self::synthesized_response(
                query_data,
                crate::dns_processor::DNS_RCODE_SERVFAIL,
                self.authoritative_dns,
                None,
            )
        }
    }

    fn failure_freshness(&self, retry_at: tokio::time::Instant) -> FailureFreshness {
        FailureFreshness {
            retry_at,
            // A subnet derived from the client's address is not part of the HTTP request
            shared: !self.enable_ecs,
        }
    }

    /// Get the number of in-flight queries
    pub async fn in_flight_count(&self) -> usize {
        let query_slab = self.query_slab.lock().await;
        query_slab.len()
    }

    /// Get the server timeout in seconds
    pub fn get_server_timeout(&self) -> u64 {
        self.server_timeout
    }

    /// Get the maximum DNS packet size
    pub fn get_dns_packet_len_max(&self) -> usize {
        self.dns_packet_len_max
    }

    /// Helper function to create a simple DNS response with flags and send it
    fn create_and_send_response_with_flags(
        query_data: &[u8],
        rcode: u8,
        authoritative_dns: bool,
        log_msg: Option<&str>,
    ) -> broadcast::Receiver<DnsResponse> {
        Self::receiver_with_response(Self::synthesized_response(
            query_data,
            rcode,
            authoritative_dns,
            log_msg,
        ))
    }

    /// Creates a simple DNS response, with the flags of our mode
    fn synthesized_response(
        query_data: &[u8],
        rcode: u8,
        authoritative_dns: bool,
        log_msg: Option<&str>,
    ) -> DnsResponse {
        // Create the basic DNS response
        let mut dns_response =
            crate::dns_processor::create_dns_response(query_data, rcode, log_msg);

        // Set the appropriate DNS response flags
        crate::dns_processor::set_response_flags(&mut dns_response, authoritative_dns);

        DnsResponse::new(dns_response)
    }

    /// Creates a new query task to handle a DNS query
    /// Returns a tuple (QueryTask, receiver) for the task
    async fn create_query_task(
        &self,
        key: DNSKey,
        query_data: Vec<u8>,
        candidates: Vec<SocketAddr>,
        resolver: impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static,
    ) -> (QueryTask, broadcast::Receiver<DnsResponse>) {
        log::debug!("Creating a new task to handle query for {}", key.name);

        // Create a broadcast channel for communicating responses
        let (response_sender, receiver) = broadcast::channel(MAX_RECEIVERS);
        let response_sender_clone = response_sender.clone();

        // Clone necessery values for the task
        let self_clone = self.clone();

        // Create the task
        let task_handle = tokio::spawn(async move {
            let completion = self_clone
                .resolve(&key, query_data, &candidates, &resolver)
                .await;
            self_clone
                .finish_query(&key, &response_sender_clone, completion)
                .await;
        });

        // Create and return the QueryTask
        let task = QueryTask {
            task_handle,
            response_sender,
        };

        (task, receiver)
    }

    /// Sends the query upstream, and prepares the response and what to remember
    async fn resolve(
        &self,
        key: &DNSKey,
        query_data: Vec<u8>,
        candidates: &[SocketAddr],
        resolver: &impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome>,
    ) -> Completion {
        let Some((outcome, progress)) = self
            .run_attempt(
                candidates,
                query_data.clone(),
                key.client_subnet.clone(),
                resolver,
            )
            .await
        else {
            log::error!("No upstream server to send the query for {} to", key.name);
            return Completion::new(self.servfail(&query_data, None));
        };
        let upstream = outcome.upstream;
        let result = outcome
            .result
            .and_then(|response_data| self.sanitize_response(key, response_data));
        match result {
            Ok(response_data) => {
                let rcode = crate::dns_parser::rcode(&response_data);
                // A truncated reply is not a full answer. After a forged datagram, even a SERVFAIL is not held against the server.
                let history = match rcode {
                    _ if crate::dns_parser::is_truncated(&response_data) => History::Unchanged,
                    crate::dns_processor::DNS_RCODE_SERVFAIL if progress.spoof_fallback => {
                        History::Unchanged
                    }
                    crate::dns_processor::DNS_RCODE_SERVFAIL => {
                        History::Failed(upstream, FailureKind::ServFail)
                    }
                    crate::dns_processor::DNS_RCODE_NOERROR
                    | crate::dns_processor::DNS_RCODE_NXDOMAIN => History::Answered(upstream),
                    _ => History::Unchanged,
                };

                if rcode == crate::dns_processor::DNS_RCODE_SERVFAIL
                    && let Some(stale_response) = self.serve_stale(key, "SERVFAIL response")
                {
                    return Completion {
                        response: stale_response,
                        cached: None,
                        history,
                    };
                }

                let cached = self
                    .cache
                    .as_ref()
                    .and_then(|_| self.prepare_cache_entry(key, &response_data));

                // Set AA and RA flags based on authoritative_dns setting
                let mut response_data_with_flags = response_data;

                // Set the appropriate DNS response flags
                crate::dns_processor::set_response_flags(
                    &mut response_data_with_flags,
                    self.authoritative_dns,
                );

                // Create a successful response
                Completion {
                    response: DnsResponse::new(response_data_with_flags),
                    cached,
                    history,
                }
            }
            Err(e) => {
                // Log the error
                log::debug!("Failed to resolve DNS query with {upstream}: {e}");

                // Only a server that got the query and stayed silent is held responsible
                let history = if e == AttemptError::BudgetExpired
                    && progress.sent
                    && !progress.spoof_fallback
                {
                    History::Failed(upstream, FailureKind::Timeout)
                } else {
                    History::Unchanged
                };
                let response = self
                    .serve_stale(key, &format!("upstream error: {e}"))
                    .unwrap_or_else(|| self.servfail(&query_data, None));
                Completion {
                    response,
                    cached: None,
                    history,
                }
            }
        }
    }

    /// Runs one attempt with an upstream server chosen among the candidates, or returns None if there is none.
    ///
    /// The attempt gets `server_timeout` seconds in all, retries included.
    async fn run_attempt(
        &self,
        candidates: &[SocketAddr],
        query: Vec<u8>,
        effective_ecs: Option<EdnsClientSubnet>,
        resolver: &impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome>,
    ) -> Option<(AttemptOutcome, AttemptFlags)> {
        let stats = self.stats.as_deref();
        let upstream = crate::load_balancer::select_upstream_server(
            candidates,
            self.load_balancing_strategy,
            stats,
        )
        .await?;
        log::debug!("Selected upstream server: {upstream}");

        let progress = Arc::new(AttemptProgress::default());
        let now = tokio::time::Instant::now();
        let deadline = now
            .checked_add(std::time::Duration::from_secs(self.server_timeout))
            // About 30 years, which is as good as no deadline
            .unwrap_or_else(|| now + std::time::Duration::from_secs(30 * 365 * 86400));
        let request = AttemptRequest {
            query,
            effective_ecs,
            upstream,
            deadline,
            progress: progress.clone(),
        };
        let mut outcome = progress
            .run_until(deadline, upstream, stats, resolver(request))
            .await;
        if outcome.upstream != upstream {
            log::error!(
                "Got an outcome for {} instead of {upstream}",
                outcome.upstream
            );
            outcome = AttemptOutcome {
                upstream,
                result: Err(AttemptError::Local(
                    "Outcome for another upstream server".to_string(),
                )),
            };
        }
        Some((outcome, progress.flags()))
    }

    /// Checks an upstream response, and removes what must not be cached or passed on
    fn sanitize_response(
        &self,
        key: &DNSKey,
        mut response_data: Vec<u8>,
    ) -> Result<Vec<u8>, AttemptError> {
        let rejected = |e: DnsError| AttemptError::Rejected(e.to_string());
        crate::dns_parser::validate_dns_response(&response_data).map_err(rejected)?;
        // The upstream server's cookie must not be cached or passed on
        crate::dns_parser::remove_edns_option(
            &mut response_data,
            crate::dns_parser::EDNS_OPTION_COOKIE,
        )
        .map_err(rejected)?;
        if self.authoritative_dns {
            let removed = crate::dns_parser::remove_out_of_bailiwick_glue(&mut response_data)
                .map_err(rejected)?;
            if removed > 0 {
                log::debug!(
                    "Removed {removed} out-of-bailiwick records from the referral for {}",
                    key.name
                );
            }
        }
        Ok(response_data)
    }

    /// Answers with the cached entry if it's still within the serve-stale grace period
    fn serve_stale(&self, key: &DNSKey, reason: &str) -> Option<DnsResponse> {
        if self.serve_stale_grace_time == 0 {
            return None;
        }
        let cached_response = self.cache.as_ref()?.get(key)?;
        let expired_for = std::time::SystemTime::now()
            .duration_since(cached_response.expires_at)
            .unwrap_or_default();
        if expired_for.as_secs() > self.serve_stale_grace_time {
            return None;
        }
        log::debug!("Serving stale entry for {} after {reason}", key.name);

        let mut response_data = cached_response.data;
        if let Err(e) = crate::dns_parser::change_ttl(&mut response_data, self.serve_stale_ttl) {
            log::debug!("Failed to update TTL in stale response: {e}");
        }

        // Resolvers may reject an authoritative server's answer if AA isn't set
        crate::dns_processor::set_response_flags(&mut response_data, self.authoritative_dns);

        Some(DnsResponse::new(response_data))
    }

    fn receiver_with_response(response: DnsResponse) -> broadcast::Receiver<DnsResponse> {
        let (response_sender, receiver) = broadcast::channel(1);
        if let Err(e) = response_sender.send(response) {
            log::debug!("Failed to send DNS response: {e}");
        }
        receiver
    }

    /// Decides what to do with a query that the cache can't answer, and handles query limits.
    ///
    /// The failures and the cache are read under the lock, so that a client sees what a finished task published.
    async fn admit(&self, key: &DNSKey) -> Admission<'_> {
        let mut in_flight_queries = self.in_flight_queries.lock().await;
        let failures = self.failure_state(key);

        // Check if the query is already in flight
        if let Some(inflight_query) = in_flight_queries.get(key) {
            // Query is already in flight, subscribe to the response
            return Admission::Join {
                receiver: inflight_query.task.response_sender.subscribe(),
                recent_failure: failures.recent_failure,
            };
        }
        if let Some(response) = self.fresh_cached_response(key) {
            return Admission::Cached(response);
        }
        if let Some(retry_at) = failures.retry_at {
            return Admission::Suppressed(retry_at);
        }

        // Check if we've reached the maximum number of in-flight queries
        let mut query_slab = self.query_slab.lock().await;

        if in_flight_queries.len() >= self.max_inflight_queries {
            log::warn!(
                "Maximum number of in-flight queries ({}) reached, aborting oldest query",
                self.max_inflight_queries
            );

            // Find the oldest query to abort (the one at the back of the slab)
            #[allow(clippy::single_match)]
            match query_slab.pop_back() {
                Some(oldest_key) => {
                    // Get the task from the map and remove it
                    match in_flight_queries.remove(&oldest_key) {
                        Some(inflight_query) => {
                            // Abort the task
                            inflight_query.task.task_handle.abort();

                            // Create an empty response with error message
                            let error_msg = "Query aborted due to maximum in-flight queries limit";
                            let empty_response = DnsResponse::failed(error_msg.to_string());

                            // Ignore errors when sending - this can happen if all receivers have been dropped
                            let _ = inflight_query.task.response_sender.send(empty_response);

                            log::info!("Aborted and removed oldest in-flight query");
                        }
                        None => {
                            // This should not happen if the map and slab are in sync
                            log::error!(
                                "Map and slab out of sync: key found in slab but not in map"
                            );

                            // Try to find any entry in the map to remove
                            self.remove_random_query(&mut in_flight_queries).await;
                        }
                    }
                }
                None => {
                    // This should not happen if the map and slab are in sync
                    log::error!("Map and slab out of sync: map has entries but slab is empty");

                    // Try to find any entry in the map to remove
                    self.remove_random_query(&mut in_flight_queries).await;
                }
            }
        }

        Admission::Start {
            in_flight_queries,
            query_slab,
            candidates: failures.eligible,
            recent_failure: failures.recent_failure,
        }
    }

    /// Removes a random query from the in-flight queries map when map/slab are out of sync
    async fn remove_random_query(
        &self,
        in_flight_queries: &mut tokio::sync::MutexGuard<'_, HashMap<DNSKey, InflightQuery>>,
    ) {
        // First, get a key to remove
        let random_key_opt = in_flight_queries.keys().next().cloned();

        if let Some(random_key) = random_key_opt {
            // Get and remove the task
            if let Some(inflight_query) = in_flight_queries.remove(&random_key) {
                // Abort the task
                inflight_query.task.task_handle.abort();

                // Create an empty response with error message
                let error_msg = "Query aborted due to maximum in-flight queries limit";
                let empty_response = DnsResponse::failed(error_msg.to_string());

                let _ = inflight_query.task.response_sender.send(empty_response);

                log::warn!("Aborted and removed a random query due to map/slab inconsistency");
            }
        }
    }

    /// Checks if a response for this query is in the cache
    /// Returns Some(receiver) if a valid cache entry is found, None otherwise
    async fn check_cache(
        &self,
        key: &DNSKey,
        _query_data: &[u8],
    ) -> Option<broadcast::Receiver<DnsResponse>> {
        // Check if cache is enabled
        self.cache.as_ref()?;
        if let Some(response) = self.fresh_cached_response(key) {
            log::debug!("Cache hit for query: {}", key.name);

            // Record cache hit in stats
            if let Some(stats) = &self.stats {
                stats.record_cache_hit().await;
            }
            return Some(Self::receiver_with_response(response));
        }

        // Expired entries count as misses
        log::debug!("Cache miss for query: {}", key.name);
        if let Some(stats) = &self.stats {
            stats.record_cache_miss().await;
        }
        None
    }

    /// Answers from the cache, if the cached response has not expired
    fn fresh_cached_response(&self, key: &DNSKey) -> Option<DnsResponse> {
        let cached_response = self.cache.as_ref()?.get(key)?;
        if cached_response.is_expired() {
            return None;
        }

        // Create a successful response from the cached data
        let mut response_data = cached_response.data;

        // If not authoritative, adjust the TTL based on remaining time
        if !self.authoritative_dns {
            let elapsed = std::time::SystemTime::now()
                .duration_since(cached_response.cached_at)
                .unwrap_or_default()
                .as_secs()
                .min(u32::MAX as u64) as u32;

            if let Err(e) = crate::dns_parser::decrement_ttl(&mut response_data, elapsed) {
                log::debug!("Failed to update TTL in cached response: {e}");
            } else {
                log::debug!("Adjusted cached response TTLs by {elapsed} seconds");
            }
        }

        // Set the appropriate DNS response flags
        crate::dns_processor::set_response_flags(&mut response_data, self.authoritative_dns);

        Some(DnsResponse::new(response_data))
    }

    /// Prepares the cache entry for a response, if the response can be cached
    fn prepare_cache_entry(&self, key: &DNSKey, response_data: &[u8]) -> Option<CachedResponse> {
        // Other codes are about the query or the server, not the name, so other clients
        // must not get them
        let rcode = crate::dns_parser::rcode(response_data);
        if rcode != crate::dns_processor::DNS_RCODE_NOERROR
            && rcode != crate::dns_processor::DNS_RCODE_NXDOMAIN
        {
            log::debug!("Not caching response with RCODE {rcode} for {}", key.name);
            return None;
        }
        if crate::dns_parser::is_truncated(response_data) {
            log::debug!("Not caching truncated response for {}", key.name);
            return None;
        }

        let extracted_ttl = match crate::dns_parser::extract_cache_ttl(response_data) {
            Ok(Some(ttl)) => ttl,
            Ok(None) => self.negative_cache_ttl,
            Err(e) => {
                log::debug!("Not caching response with an invalid TTL: {e}");
                return None;
            }
        };

        let ttl = std::cmp::max(extracted_ttl, self.min_cache_ttl);

        let mut cached_data = response_data.to_vec();
        if let Err(e) =
            crate::dns_parser::cap_negative_response_ttl(&mut cached_data, extracted_ttl)
        {
            log::debug!("Not caching response with an invalid SOA TTL: {e}");
            return None;
        }
        let ttl_duration = std::time::Duration::from_secs(ttl as u64);
        let cached_response = CachedResponse::new(cached_data, ttl_duration);

        if ttl > extracted_ttl {
            log::debug!(
                "Caching DNS response with minimum TTL: {ttl} seconds (original TTL was {extracted_ttl} seconds)"
            );
        } else {
            log::debug!("Caching DNS response with TTL: {ttl} seconds");
        }
        Some(cached_response)
    }

    /// Processes WebAssembly hooks for a query
    /// Returns Some(receiver) if a hook interrupts normal processing, None if processing should continue
    async fn process_hooks(
        &self,
        key: &DNSKey,
        client_ip: &str,
        query_data: &[u8],
    ) -> Option<broadcast::Receiver<DnsResponse>> {
        // Check if hooks are configured
        if let Some(hooks) = &self.hooks {
            let hook_result = hooks.hook_client_query_received(
                &key.name, key.qtype, key.qclass, client_ip, query_data,
            );

            // Handle different hook return codes
            match hook_result {
                0 => {
                    // Continue normal processing
                    log::debug!("Hook returned 0, continuing normal processing");
                    None
                }
                -1 => {
                    // Return a minimal response with REFUSED rcode
                    log::debug!("Hook returned -1, returning REFUSED response");

                    let log_msg = format!("Query refused by hook: {}", key.name);
                    let receiver = Self::create_and_send_response_with_flags(
                        query_data,
                        crate::dns_processor::DNS_RCODE_REFUSED,
                        self.authoritative_dns,
                        Some(&log_msg),
                    );

                    Some(receiver)
                }
                _ => {
                    // For other values, return an empty response with an error message
                    log::debug!(
                        "Hook returned unexpected value: {hook_result}, returning error response"
                    );

                    Some(Self::receiver_with_response(DnsResponse::failed(format!(
                        "Query processing interrupted by hook (code: {hook_result})"
                    ))))
                }
            }
        } else {
            // No hooks configured, continue normal processing
            None
        }
    }

    /// Checks if a query should be filtered based on domain restrictions
    /// Returns Some(receiver) if the query should be filtered, None if processing should continue
    async fn check_domain_filters(
        &self,
        key: &DNSKey,
        query_data: &[u8],
    ) -> Option<broadcast::Receiver<DnsResponse>> {
        // Check if the query is of type ANY (255)
        if key.qtype == crate::dns_parser::DNS_TYPE_ANY {
            let log_msg = format!(
                "Received query of type ANY for {}, returning NOTIMP",
                key.name
            );

            let receiver = Self::create_and_send_response_with_flags(
                query_data,
                crate::dns_processor::DNS_RCODE_NOTIMP,
                self.authoritative_dns,
                Some(&log_msg),
            );

            return Some(receiver);
        }

        if key.qclass == crate::dns_parser::DNS_CLASS_CH {
            let log_msg = format!("Received CHAOS query for {}, returning REFUSED", key.name);

            let receiver = Self::create_and_send_response_with_flags(
                query_data,
                crate::dns_processor::DNS_RCODE_REFUSED,
                self.authoritative_dns,
                Some(&log_msg),
            );

            return Some(receiver);
        }

        // Check if the query is for a nonexistent domain
        if let Some(nx_zones) = &self.nx_zones
            && nx_zones.is_nonexistent(&key.name)
        {
            log::debug!("Query for nonexistent domain: {}", key.name);

            let log_msg = format!("Query for nonexistent domain: {}", key.name);
            let receiver = Self::create_and_send_response_with_flags(
                query_data,
                crate::dns_processor::DNS_RCODE_NXDOMAIN,
                self.authoritative_dns,
                Some(&log_msg),
            );

            return Some(receiver);
        }

        // Check if the query is allowed based on the domain name
        if let Some(allowed_zones) = &self.allowed_zones
            && !allowed_zones.is_allowed(&key.name)
        {
            log::warn!("Query rejected: {} is not in allowed zones", key.name);

            let log_msg = format!("Query rejected: {} is not in allowed zones", key.name);
            let receiver = Self::create_and_send_response_with_flags(
                query_data,
                crate::dns_processor::DNS_RCODE_REFUSED,
                self.authoritative_dns,
                Some(&log_msg),
            );

            return Some(receiver);
        }

        // Query passed all filters, continue processing
        None
    }

    /// Publishes what a finished task learned, removes the task, and sends its response to the waiting clients.
    ///
    /// This happens under the in-flight lock, so a client either joins in time or sees the new cache and failures.
    /// A replaced task, for instance one aborted for a newer one, changes nothing.
    async fn finish_query(
        &self,
        key: &DNSKey,
        response_sender: &broadcast::Sender<DnsResponse>,
        completion: Completion,
    ) {
        // We need to acquire both locks to ensure atomicity
        let mut in_flight_queries = self.in_flight_queries.lock().await;
        let mut query_slab = self.query_slab.lock().await;

        let owned = in_flight_queries.get(key).is_some_and(|inflight_query| {
            inflight_query
                .task
                .response_sender
                .same_channel(response_sender)
        });
        if !owned {
            log::debug!("Dropping the result of a replaced query for {}", key.name);
            return;
        }

        if let (Some(cache), Some(cached)) = (&self.cache, completion.cached) {
            cache.insert(key.clone(), cached);
        }
        let mut response = completion.response;
        if let Some(failure_cache) = &self.failure_cache {
            match completion.history {
                History::Failed(upstream, kind) => {
                    let retry_at = failure_cache.record_failure(
                        key,
                        upstream,
                        kind,
                        tokio::time::Instant::now(),
                    );
                    // Once no server can get the query, HTTP caches may keep the SERVFAIL until one can
                    if let Some(retry_at) = retry_at
                        && response.error.is_none()
                        && crate::dns_parser::rcode(&response.data)
                            == crate::dns_processor::DNS_RCODE_SERVFAIL
                    {
                        response.failure_freshness = Some(self.failure_freshness(retry_at));
                    }
                }
                History::Answered(upstream) => failure_cache.record_success(key, upstream),
                History::Unchanged => {}
            }
        }

        if let Some(inflight_query) = in_flight_queries.remove(key) {
            // Remove from the slab using the stored slab ID
            match query_slab.remove(inflight_query.slab_id) {
                Ok(_) => {
                    log::debug!(
                        "Successfully removed query from both map and slab, slab size: {}, map size: {}",
                        query_slab.len(),
                        in_flight_queries.len()
                    );
                }
                Err(e) => {
                    log::error!("Failed to remove query from slab: {e}");
                    log::warn!("Map and slab may be out of sync due to slab removal error");
                }
            }
        }

        if let Err(e) = response_sender.send(response) {
            // This can happen if all receivers have been dropped
            log::debug!("Failed to send DNS response: {e}");
        }
    }

    /// Get whether spoof protection is enabled
    pub fn get_spoof_protection(&self) -> bool {
        self.spoof_protection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CachedResponse, create_dns_cache};
    use crate::dns_key::DNSKey;
    use crate::dns_parser::{EXAMPLE_COM_ANSWER, EXAMPLE_COM_QUERY};
    use crate::stats::SharedStats;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Test that stale cache entries are served when upstream resolver fails
    #[tokio::test]
    async fn test_serve_stale_on_upstream_error() {
        // Create a query manager with serve_stale enabled
        let stats = Arc::new(SharedStats::new());
        let mut query_manager = QueryManager::new(
            100, // max_inflight_queries
            2,   // server_timeout (short for testing)
            512, // dns_packet_len_max
            stats,
            LoadBalancingStrategy::Random,
            false, // authoritative_dns
            3600,  // serve_stale_grace_time (1 hour)
            300,   // serve_stale_ttl (5 minutes)
            60,    // negative_cache_ttl
            1,     // min_cache_ttl
            false, // enable_ecs
            24,    // ecs_prefix_v4
            56,    // ecs_prefix_v6
            true,  // spoof_protection
        );

        query_manager.set_upstream_servers(vec!["192.0.2.53:53".parse().unwrap()]);

        // Create and set a cache
        let cache = create_dns_cache(100);
        query_manager.set_cache(cache.clone());

        // Create a DNS key for testing
        let key = DNSKey {
            name: "example.com.".to_string(),
            qtype: 1,  // A record
            qclass: 1, // IN
            dnssec: false,
            recursion_desired: true,
            checking_disabled: false,
            authenticated_data: false,
            client_subnet: None,
        };

        // Create a fake DNS response (just some valid-looking data)
        let fake_response = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: response, no error
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answers: 1
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question section (example.com A IN)
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // null terminator
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name pointer to question
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
            0x00, 0x04, // Data length: 4
            0x5d, 0xb8, 0xd8, 0x22, // IP: 93.184.216.34
        ];

        // Add an expired cache entry (expired 100 seconds ago, but within grace period)
        let expiry_time = std::time::SystemTime::now() - Duration::from_secs(100);
        let cached_response = CachedResponse {
            data: fake_response.clone(),
            cached_at: expiry_time - Duration::from_secs(60),
            expires_at: expiry_time,
        };
        cache.insert(key.clone(), cached_response);

        // Create a simple DNS query packet for example.com
        let query_data = vec![
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // null terminator
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        // Create a resolver that always fails (simulates timeout/error)

        // Submit the query with the failing resolver
        let mut receiver = query_manager
            .submit_query_with_client(key.clone(), query_data, failing_resolver, "127.0.0.1:12345")
            .await
            .expect("Failed to submit query");

        // Wait for the response
        let response = receiver.recv().await.expect("Failed to receive response");

        // Verify that we got the stale entry, not an error
        assert!(
            response.error.is_none(),
            "Expected no error, but got: {:?}",
            response.error
        );
        assert!(
            !response.data.is_empty(),
            "Expected stale data, but got empty response"
        );

        // Verify the response data matches our cached entry
        assert_eq!(
            response.data.len(),
            fake_response.len(),
            "Response data length mismatch"
        );
    }

    /// Test that errors are returned when no stale cache entry is available
    #[tokio::test]
    async fn test_error_when_no_stale_cache() {
        // Create a query manager with serve_stale enabled
        let stats = Arc::new(SharedStats::new());
        let mut query_manager = QueryManager::new(
            100,
            2,
            512,
            stats,
            LoadBalancingStrategy::Random,
            false,
            3600, // serve_stale_grace_time
            300,
            60,
            1,
            false,
            24,
            56,
            true,
        );

        query_manager.set_upstream_servers(vec!["192.0.2.53:53".parse().unwrap()]);

        // Create and set a cache (but don't add any entries)
        let cache = create_dns_cache(100);
        query_manager.set_cache(cache);

        // Create a DNS key
        let key = DNSKey {
            name: "example.com.".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec: false,
            recursion_desired: true,
            checking_disabled: false,
            authenticated_data: false,
            client_subnet: None,
        };

        // Create a query packet
        let query_data = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        // Create a failing resolver

        // Submit the query
        let mut receiver = query_manager
            .submit_query_with_client(key, query_data, failing_resolver, "127.0.0.1:12345")
            .await
            .expect("Failed to submit query");

        // Wait for the response
        let response = receiver.recv().await.expect("Failed to receive response");

        // Without a stale entry to fall back to, the client gets a SERVFAIL
        assert!(response.error.is_none());
        assert_eq!(
            crate::dns_parser::rcode(&response.data),
            crate::dns_processor::DNS_RCODE_SERVFAIL
        );
    }

    /// Test that expired cache entries outside grace period are not served
    #[tokio::test]
    async fn test_no_serve_stale_outside_grace_period() {
        // Create a query manager with short grace period
        let stats = Arc::new(SharedStats::new());
        let mut query_manager = QueryManager::new(
            100,
            2,
            512,
            stats,
            LoadBalancingStrategy::Random,
            false,
            60, // serve_stale_grace_time: only 60 seconds
            300,
            60,
            1,
            false,
            24,
            56,
            true,
        );

        query_manager.set_upstream_servers(vec!["192.0.2.53:53".parse().unwrap()]);

        // Create and set a cache
        let cache = create_dns_cache(100);
        query_manager.set_cache(cache.clone());

        // Create a DNS key
        let key = DNSKey {
            name: "example.com.".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec: false,
            recursion_desired: true,
            checking_disabled: false,
            authenticated_data: false,
            client_subnet: None,
        };

        // Create a fake response
        let fake_response = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d,
            0xb8, 0xd8, 0x22,
        ];

        // Add a cache entry that expired 120 seconds ago (outside grace period)
        let expiry_time = std::time::SystemTime::now() - Duration::from_secs(120);
        let cached_response = CachedResponse {
            data: fake_response,
            cached_at: expiry_time - Duration::from_secs(60),
            expires_at: expiry_time,
        };
        cache.insert(key.clone(), cached_response);

        // Create a query packet
        let query_data = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        // Create a resolver that returns SERVFAIL
        let failing_resolver = fake_resolver(|mut data: Vec<u8>| {
            crate::dns_parser::set_qr(&mut data, true).unwrap();
            crate::dns_parser::set_rcode(&mut data, crate::dns_processor::DNS_RCODE_SERVFAIL)
                .unwrap();
            Box::pin(async move { Ok(data) }) as Answer
        });

        // Submit the query
        let mut receiver = query_manager
            .submit_query_with_client(key, query_data, failing_resolver, "127.0.0.1:12345")
            .await
            .expect("Failed to submit query");

        // Wait for the response
        let response = receiver.recv().await.expect("Failed to receive response");

        assert!(response.error.is_none());
        assert_eq!(
            crate::dns_parser::rcode(&response.data),
            crate::dns_processor::DNS_RCODE_SERVFAIL,
            "Expected the upstream SERVFAIL instead of stale data"
        );
    }

    #[test]
    fn test_uncacheable_responses_are_not_cached() {
        let manager = QueryManager::for_tests(1, 512, true);
        let key = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();
        let mut response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        // Truncated, then FORMERR, SERVFAIL, NOTIMP and REFUSED
        for flags in [
            [0x83, 0x80],
            [0x81, 0x81],
            [0x81, 0x82],
            [0x81, 0x84],
            [0x81, 0x85],
        ] {
            response[2..4].copy_from_slice(&flags);
            assert!(manager.prepare_cache_entry(&key, &response).is_none());
        }
    }

    #[test]
    fn test_negative_response_uses_soa_minimum_for_cache_expiry() {
        let manager = QueryManager::for_tests(1, 512, true);
        let key = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();

        let cached = manager
            .prepare_cache_entry(
                &key,
                crate::dns_parser::NEGATIVE_RESPONSE_WITH_SOA_TTL_3600_MINIMUM_60,
            )
            .unwrap();
        assert_eq!(
            cached.expires_at.duration_since(cached.cached_at).unwrap(),
            Duration::from_secs(60)
        );
        assert_eq!(
            crate::dns_parser::extract_min_ttl(&cached.data).unwrap(),
            Some(60)
        );
    }

    #[tokio::test]
    async fn test_out_of_bailiwick_glue_is_removed_in_authoritative_mode() {
        // What ns1.xvps.ne.jp sent for blog.alice.poc.debiru.net: a referral to
        // ns.lavoscore.org, with an address for it from a zone someone else created there
        let hex = concat!(
            "12348000000100000001000204626c6f6705616c69636503706f6306646562697275036e6574",
            "0000010001c00c000200010000012c0012026e73096c61766f73636f7265036f726700",
            "c037000100010000012c00049d7095f3",
            "0000290690000000000000",
        );
        let referral: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let query = crate::dns_parser::recover_question_from_response(&referral).unwrap();
        let key = DNSKey::from_packet(&query).unwrap();

        // The address goes away, the OPT record stays
        for (authoritative_dns, arcount) in [(false, 2), (true, 1)] {
            let mut query_manager = QueryManager::for_tests(1, 512, true);
            query_manager.authoritative_dns = authoritative_dns;
            let cache = create_dns_cache(10);
            query_manager.set_cache(cache.clone());

            let upstream_response = referral.clone();
            let resolver = fake_resolver(move |_data: Vec<u8>| {
                Box::pin(std::future::ready(Ok(upstream_response.clone()))) as Answer
            });
            let mut receiver = query_manager
                .submit_query_with_client(key.clone(), query.clone(), resolver, "192.0.2.1:5353")
                .await
                .unwrap();
            let response = receiver.recv().await.unwrap();

            assert_eq!(crate::dns_parser::arcount(&response.data), arcount);
            assert_eq!(
                crate::dns_parser::arcount(&cache.get(&key).unwrap().data),
                arcount
            );
        }
    }

    #[tokio::test]
    async fn test_chaos_queries_are_refused() {
        let query_manager = QueryManager::for_tests(1, 512, true);
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'v',
            b'e', b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd', 0x00, 0x00, 0x10,
            0x00, 0x03,
        ];
        let key = DNSKey::from_packet(&query).unwrap();
        let echo_resolver = fake_resolver(|mut data: Vec<u8>| {
            crate::dns_parser::set_qr(&mut data, true).unwrap();
            Box::pin(std::future::ready(Ok(data))) as Answer
        });

        let mut receiver = query_manager
            .submit_query_with_client(key, query, echo_resolver, "192.0.2.1:5353")
            .await
            .unwrap();
        let response = receiver.recv().await.unwrap();

        assert_eq!(
            crate::dns_parser::rcode(&response.data),
            crate::dns_processor::DNS_RCODE_REFUSED
        );
    }

    #[tokio::test]
    async fn test_client_joining_a_finishing_query_gets_its_response() {
        let query_manager = QueryManager::for_tests(5, 512, true);
        let query = EXAMPLE_COM_QUERY.to_vec();
        let key = DNSKey::from_packet(&query).unwrap();

        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let release_rx = std::sync::Mutex::new(Some(release_rx));
        let delayed_resolver = fake_resolver(move |mut data: Vec<u8>| {
            let release = release_rx.lock().unwrap().take();
            Box::pin(async move {
                if let Some(release) = release {
                    let _ = release.await;
                }
                crate::dns_parser::set_qr(&mut data, true).unwrap();
                Ok(data)
            }) as Answer
        });
        let _first = query_manager
            .submit_query_with_client(
                key.clone(),
                query.clone(),
                delayed_resolver,
                "192.0.2.1:5353",
            )
            .await
            .unwrap();

        // The second client waits for the lock while the first query finishes,
        // so it joins right as the response goes out.
        let in_flight_guard = query_manager.in_flight_queries.lock().await;
        let second_manager = query_manager.clone();
        let mut second = tokio_test::task::spawn(async move {
            let mut receiver = second_manager
                .submit_query_with_client(key, query, failing_resolver, "192.0.2.2:5353")
                .await
                .unwrap();
            receiver.recv().await
        });
        assert!(second.poll().is_pending());
        release_tx.send(()).unwrap();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        drop(in_flight_guard);
        assert!(second.poll().is_pending());
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        let std::task::Poll::Ready(response) = second.poll() else {
            panic!("the second client is still waiting");
        };
        let response = response.expect("the second client must receive the shared response");
        assert!(response.error.is_none());
        assert!(crate::dns_parser::is_response(&response.data));
    }

    type Answer = BoxFuture<'static, Result<Vec<u8>, AttemptError>>;

    /// A resolver that gives the query to `respond` instead of sending it
    fn fake_resolver(
        respond: impl Fn(Vec<u8>) -> Answer + Send + Sync + 'static,
    ) -> impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static {
        move |request: AttemptRequest| {
            request.progress.mark_sent();
            let answer = respond(request.query);
            Box::pin(async move {
                AttemptOutcome {
                    upstream: request.upstream,
                    result: answer.await,
                }
            })
        }
    }

    /// Ends a fake attempt at once with this result
    fn outcome(
        request: &AttemptRequest,
        result: Result<Vec<u8>, AttemptError>,
    ) -> BoxFuture<'static, AttemptOutcome> {
        Box::pin(std::future::ready(AttemptOutcome {
            upstream: request.upstream,
            result,
        }))
    }

    fn failing_resolver(request: AttemptRequest) -> BoxFuture<'static, AttemptOutcome> {
        outcome(
            &request,
            Err(AttemptError::Local("no network in tests".to_string())),
        )
    }

    /// Lets the other tasks run until they wait for something
    async fn let_tasks_run() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// A resolver that answers SERVFAIL once released, and counts its attempts
    fn delayed_servfail_resolver(
        attempts: &Arc<AtomicUsize>,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static,
    ) {
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let release_rx = std::sync::Mutex::new(Some(release_rx));
        let attempts = attempts.clone();
        let resolver = fake_resolver(move |mut data: Vec<u8>| {
            attempts.fetch_add(1, Ordering::SeqCst);
            let release = release_rx.lock().unwrap().take();
            Box::pin(async move {
                if let Some(release) = release {
                    let _ = release.await;
                }
                crate::dns_parser::set_qr(&mut data, true).unwrap();
                crate::dns_parser::set_rcode(&mut data, SERVFAIL).unwrap();
                Ok(data)
            }) as Answer
        });
        (release_tx, resolver)
    }

    /// A manager that serves stale answers, with an expired answer to `EXAMPLE_COM_QUERY` in its cache
    fn manager_with_expired_entry(
        authoritative_dns: bool,
    ) -> (QueryManager, crate::cache::SyncDnsCache, DNSKey) {
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        query_manager.authoritative_dns = authoritative_dns;
        query_manager.serve_stale_grace_time = 3600;
        let cache = create_dns_cache(10);
        query_manager.set_cache(cache.clone());
        let mut key = DNSKey::from_packet(EXAMPLE_COM_QUERY).unwrap();
        if authoritative_dns {
            key.ignore_resolver_flags();
        }
        let expires_at = std::time::SystemTime::now() - Duration::from_secs(60);
        let expired = CachedResponse {
            data: EXAMPLE_COM_ANSWER.to_vec(),
            cached_at: expires_at - Duration::from_secs(60),
            expires_at,
        };
        cache.insert(key.clone(), expired);
        (query_manager, cache, key)
    }

    #[tokio::test]
    async fn test_stale_answer_keeps_the_authoritative_flags() {
        let (query_manager, _, key) = manager_with_expired_entry(true);
        let mut receiver = query_manager
            .submit_query_with_client(
                key,
                EXAMPLE_COM_QUERY.to_vec(),
                failing_resolver,
                "192.0.2.1:5353",
            )
            .await
            .unwrap();

        let flags = crate::dns_parser::flags(&receiver.recv().await.unwrap().data);
        assert_ne!(flags & 0x0400, 0, "AA must be set");
        assert_eq!(flags & 0x0080, 0, "RA must not be set");
    }

    #[tokio::test]
    async fn test_stale_answer_does_not_wait_for_failing_upstream_servers() {
        let (query_manager, cache, key) = manager_with_expired_entry(false);
        let stats = query_manager.get_stats().unwrap();
        for _ in 0..crate::stats::PARK_AFTER_FAILURES {
            stats.record_timeout("192.0.2.53:53".parse().unwrap()).await;
        }

        // The upstream server stays silent until we release it
        let release = Arc::new(tokio::sync::Notify::new());
        let resolver = {
            let release = release.clone();
            fake_resolver(move |_data: Vec<u8>| {
                let release = release.clone();
                Box::pin(async move {
                    release.notified().await;
                    Ok(EXAMPLE_COM_ANSWER.to_vec())
                }) as Answer
            })
        };
        let mut receiver = query_manager
            .submit_query_with_client(
                key.clone(),
                EXAMPLE_COM_QUERY.to_vec(),
                resolver,
                "192.0.2.1:5353",
            )
            .await
            .unwrap();

        let response = receiver
            .try_recv()
            .expect("the stale answer must not wait for the upstream server");
        assert_eq!(
            crate::dns_parser::extract_min_ttl(&response.data).unwrap(),
            Some(query_manager.serve_stale_ttl)
        );

        // The entry is refreshed in the background
        release.notify_one();
        for _ in 0..100 {
            if !cache.get(&key).unwrap().is_expired() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!cache.get(&key).unwrap().is_expired());
    }

    #[tokio::test]
    async fn test_expired_entry_waits_for_the_upstream_server() {
        let (query_manager, _, key) = manager_with_expired_entry(false);
        let resolver = fake_resolver(|_data: Vec<u8>| {
            Box::pin(std::future::ready(Ok(EXAMPLE_COM_ANSWER.to_vec()))) as Answer
        });
        let mut receiver = query_manager
            .submit_query_with_client(key, EXAMPLE_COM_QUERY.to_vec(), resolver, "192.0.2.1:5353")
            .await
            .unwrap();

        let response = receiver.recv().await.unwrap();
        assert_eq!(
            crate::dns_parser::extract_min_ttl(&response.data).unwrap(),
            Some(60)
        );
    }

    #[tokio::test]
    async fn test_authoritative_answer_is_shared_by_queries_with_different_flags() {
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        query_manager.authoritative_dns = true;
        query_manager.set_cache(create_dns_cache(10));

        let upstream_queries = Arc::new(AtomicUsize::new(0));
        // RD, CD and AD together, then none, then one at a time
        for flags in [
            [0x01, 0x30],
            [0x00, 0x00],
            [0x01, 0x00],
            [0x00, 0x10],
            [0x00, 0x20],
        ] {
            let mut query = EXAMPLE_COM_QUERY.to_vec();
            query[2..4].copy_from_slice(&flags);
            let key = DNSKey::from_packet(&query).unwrap();
            let resolver = {
                let upstream_queries = upstream_queries.clone();
                fake_resolver(move |data: Vec<u8>| {
                    upstream_queries.fetch_add(1, Ordering::SeqCst);
                    // The answer echoes the flags the upstream server got, and claims AD
                    let mut answer = EXAMPLE_COM_ANSWER.to_vec();
                    answer[2..4].copy_from_slice(&data[2..4]);
                    crate::dns_parser::set_qr(&mut answer, true).unwrap();
                    crate::dns_parser::set_ad(&mut answer, true).unwrap();
                    Box::pin(std::future::ready(Ok(answer))) as Answer
                })
            };
            let mut receiver = query_manager
                .submit_query_with_client(key, query, resolver, "192.0.2.1:5353")
                .await
                .unwrap();

            let response = receiver.recv().await.unwrap();
            assert_eq!(crate::dns_parser::flags(&response.data) & 0x0130, 0);
        }

        assert_eq!(upstream_queries.load(Ordering::SeqCst), 1);
    }

    fn answering_resolver(request: AttemptRequest) -> BoxFuture<'static, AttemptOutcome> {
        request.progress.mark_sent();
        outcome(&request, Ok(EXAMPLE_COM_ANSWER.to_vec()))
    }

    async fn ask(
        query_manager: &QueryManager,
        query: &[u8],
        resolver: impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static,
    ) -> DnsResponse {
        let key = DNSKey::from_packet(query).unwrap();
        let mut receiver = query_manager
            .submit_query_with_client(key, query.to_vec(), resolver, "192.0.2.1:5353")
            .await
            .unwrap();
        receiver.recv().await.unwrap()
    }

    #[tokio::test]
    async fn test_upstream_selection_does_not_hold_the_in_flight_lock() {
        let query_manager = QueryManager::for_tests(5, 512, true);
        let stats = query_manager.get_stats().unwrap();
        let key = DNSKey::from_packet(EXAMPLE_COM_QUERY).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver = counting_answer_resolver(&attempts);
        let mut receiver = query_manager
            .submit_query_with_client(
                key.clone(),
                EXAMPLE_COM_QUERY.to_vec(),
                resolver,
                "192.0.2.1:5353",
            )
            .await
            .unwrap();

        // The task is admitted, and waits for the stats to choose an upstream server
        let stats_guard = stats.lock().await;
        let_tasks_run().await;
        assert!(
            query_manager
                .in_flight_queries
                .try_lock()
                .expect("the in-flight lock must be free during the selection")
                .contains_key(&key)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        drop(stats_guard);
        assert!(receiver.recv().await.unwrap().error.is_none());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_outcome_must_come_from_the_chosen_upstream() {
        let query_manager = QueryManager::for_tests(5, 512, true);
        let impostor = |request: AttemptRequest| {
            assert_eq!(request.upstream, "192.0.2.53:53".parse().unwrap());
            Box::pin(std::future::ready(AttemptOutcome {
                upstream: "198.51.100.53:53".parse().unwrap(),
                result: Ok(EXAMPLE_COM_ANSWER.to_vec()),
            })) as BoxFuture<'static, AttemptOutcome>
        };

        let response = ask(&query_manager, EXAMPLE_COM_QUERY, impostor).await;

        assert_eq!(crate::dns_parser::rcode(&response.data), SERVFAIL);
        assert!(response.failure_freshness.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_attempt_is_stopped_at_the_deadline() {
        let upstream: SocketAddr = "192.0.2.53:53".parse().unwrap();
        // Whether or not the resolver sent the query before it stalled
        for sends in [true, false] {
            let query_manager = QueryManager::for_tests(5, 512, true);
            let stats = query_manager.get_stats().unwrap();
            let silent = move |request: AttemptRequest| {
                if sends {
                    request.progress.mark_sent();
                }
                Box::pin(std::future::pending()) as BoxFuture<'static, AttemptOutcome>
            };
            let started = tokio::time::Instant::now();

            let response = ask(&query_manager, EXAMPLE_COM_QUERY, silent).await;

            assert_eq!(started.elapsed(), Duration::from_secs(5));
            assert_eq!(crate::dns_parser::rcode(&response.data), SERVFAIL);
            // Only a server that got the query is in backoff, so only then may HTTP caches keep the SERVFAIL
            assert_eq!(response.failure_freshness.is_some(), sends);
            let snapshot = stats.get_stats().await;
            if sends {
                // The resolver could not record its first miss, so the query manager did it
                let resolver = snapshot.get_resolver_stats(&upstream).unwrap();
                assert_eq!(resolver.timeout_count, 1);
                assert_eq!(resolver.budget_expiration_count, 1);
            } else {
                assert!(snapshot.get_resolver_stats(&upstream).is_none());
            }
        }
    }

    // The answer to the retry must arrive before the deadline, so the time is real
    #[tokio::test]
    async fn test_first_miss_lets_other_queries_use_stale_answers() {
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            // The first datagram gets no answer, and the retry only gets one once released
            let mut packet = vec![0u8; 4096];
            let mut release = Some(release_rx);
            for datagram in 0.. {
                let Ok((length, client)) = upstream_socket.recv_from(&mut packet).await else {
                    break;
                };
                let mut response = packet[..length].to_vec();
                crate::dns_parser::set_qr(&mut response, true).unwrap();
                match datagram {
                    0 => continue,
                    1 => release.take().unwrap().await.unwrap(),
                    _ => {}
                }
                upstream_socket.send_to(&response, client).await.unwrap();
            }
        });
        let (mut query_manager, _, stale_key) = manager_with_expired_entry(false);
        query_manager.server_timeout = 4;
        query_manager.set_upstream_servers(vec![upstream]);
        let stats = query_manager.get_stats().unwrap();
        for _ in 1..crate::stats::PARK_AFTER_FAILURES {
            stats.record_timeout(upstream).await;
        }
        let resolver = || {
            crate::resolver::create_resolver(crate::resolver::UpstreamClient {
                server_timeout: 4,
                dns_packet_len_max: 512,
                spoof_protection: true,
                stats: Some(stats.clone()),
            })
        };

        // A query for another name gets no answer to its first datagram
        let mut other_query = EXAMPLE_COM_QUERY.to_vec();
        other_query[21..24].copy_from_slice(b"org");
        let mut first = query_manager
            .submit_query_with_client(
                DNSKey::from_packet(&other_query).unwrap(),
                other_query,
                resolver(),
                "192.0.2.1:5353",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert!(stats.all_resolvers_failing().await);

        // Before its deadline, an expired entry is already served without waiting
        let mut second = query_manager
            .submit_query_with_client(
                stale_key,
                EXAMPLE_COM_QUERY.to_vec(),
                resolver(),
                "192.0.2.2:5353",
            )
            .await
            .unwrap();
        let response = second
            .try_recv()
            .expect("the stale answer must not wait for the upstream server");
        assert_eq!(
            crate::dns_parser::extract_min_ttl(&response.data).unwrap(),
            Some(query_manager.serve_stale_ttl)
        );

        // The answer to the retry clears the failures
        release_tx.send(()).unwrap();
        assert!(first.recv().await.unwrap().error.is_none());
        assert!(!stats.all_resolvers_failing().await);
    }

    #[tokio::test]
    async fn test_attempt_gets_the_subnet_of_the_cache_key() {
        let derived = crate::dns_parser::EdnsClientSubnet {
            family: 1,
            source_prefix_length: 24,
            scope_prefix_length: 0,
            address: vec![192, 0, 2],
        };
        let mut client_query = EXAMPLE_COM_QUERY.to_vec();
        crate::dns_parser::add_edns_client_subnet(&mut client_query, "198.51.100.7", 24, 56, 1232)
            .unwrap();
        let from_client = crate::dns_parser::extract_edns_client_subnet(&client_query).unwrap();

        for (enable_ecs, query, expected) in [
            (false, EXAMPLE_COM_QUERY.to_vec(), None),
            (false, client_query.clone(), from_client),
            (true, EXAMPLE_COM_QUERY.to_vec(), Some(derived.clone())),
            (true, client_query, Some(derived.clone())),
        ] {
            let mut query_manager = QueryManager::for_tests(5, 512, true);
            query_manager.enable_ecs = enable_ecs;
            let seen = Arc::new(std::sync::Mutex::new(None));
            let resolver = {
                let seen = seen.clone();
                move |request: AttemptRequest| {
                    *seen.lock().unwrap() = Some(request.effective_ecs.clone());
                    answering_resolver(request)
                }
            };
            let key = DNSKey::from_packet(&query).unwrap();
            let mut receiver = query_manager
                .submit_query_with_client(key, query, resolver, "192.0.2.129:5353")
                .await
                .unwrap();
            receiver.recv().await.unwrap();

            assert_eq!(seen.lock().unwrap().take(), Some(expected));
        }
    }

    const SERVFAIL: u8 = crate::dns_processor::DNS_RCODE_SERVFAIL;
    const UPSTREAM: &str = "192.0.2.53:53";

    /// A resolver that answers with an empty response with this RCODE, and counts its attempts
    fn rcode_resolver(
        rcode: u8,
        attempts: &Arc<AtomicUsize>,
    ) -> impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static {
        let attempts = attempts.clone();
        fake_resolver(move |mut data: Vec<u8>| {
            attempts.fetch_add(1, Ordering::SeqCst);
            crate::dns_parser::set_qr(&mut data, true).unwrap();
            crate::dns_parser::set_rcode(&mut data, rcode).unwrap();
            Box::pin(std::future::ready(Ok(data))) as Answer
        })
    }

    /// A resolver that answers `EXAMPLE_COM_QUERY`, and counts its attempts
    fn counting_answer_resolver(
        attempts: &Arc<AtomicUsize>,
    ) -> impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static {
        let attempts = attempts.clone();
        move |request| {
            attempts.fetch_add(1, Ordering::SeqCst);
            answering_resolver(request)
        }
    }

    /// Lets the background tasks finish
    async fn settle(query_manager: &QueryManager) {
        for _ in 0..100 {
            if query_manager.in_flight_count().await == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("a query is still in flight");
    }

    fn example_key() -> DNSKey {
        DNSKey::from_packet(EXAMPLE_COM_QUERY).unwrap()
    }

    #[tokio::test]
    async fn test_replaced_task_publishes_nothing() {
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        let cache = create_dns_cache(10);
        query_manager.set_cache(cache.clone());
        let key = example_key();

        // The query in flight belongs to a newer task
        let (replacement_sender, mut replacement_receiver) = broadcast::channel(1);
        let replacement_task = tokio::spawn(std::future::pending::<()>());
        {
            let mut in_flight_queries = query_manager.in_flight_queries.lock().await;
            let slab_id = query_manager
                .query_slab
                .lock()
                .await
                .push_front(key.clone())
                .unwrap();
            let task = QueryTask {
                task_handle: replacement_task,
                response_sender: replacement_sender.clone(),
            };
            in_flight_queries.insert(key.clone(), InflightQuery { task, slab_id });
        }
        let completion = || Completion {
            response: DnsResponse::new(EXAMPLE_COM_ANSWER.to_vec()),
            cached: query_manager.prepare_cache_entry(&key, EXAMPLE_COM_ANSWER),
            history: History::Failed(UPSTREAM.parse().unwrap(), FailureKind::Timeout),
        };

        let (old_sender, _old_receiver) = broadcast::channel(1);
        query_manager
            .finish_query(&key, &old_sender, completion())
            .await;

        assert!(cache.get(&key).is_none());
        assert!(!query_manager.failure_state(&key).recent_failure);
        assert!(
            query_manager
                .in_flight_queries
                .lock()
                .await
                .contains_key(&key)
        );
        assert_eq!(query_manager.in_flight_count().await, 1);
        assert!(replacement_receiver.try_recv().is_err());

        // The owner publishes everything
        query_manager
            .finish_query(&key, &replacement_sender, completion())
            .await;

        assert!(cache.get(&key).is_some());
        assert!(query_manager.failure_state(&key).recent_failure);
        assert!(query_manager.in_flight_queries.lock().await.is_empty());
        assert_eq!(query_manager.in_flight_count().await, 0);
        assert!(replacement_receiver.try_recv().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn test_failed_query_waits_for_its_retry_delay() {
        let query_manager = QueryManager::for_tests(5, 512, true);
        let attempts = Arc::new(AtomicUsize::new(0));
        for delay in [1, 2, 4] {
            let response = ask(
                &query_manager,
                EXAMPLE_COM_QUERY,
                rcode_resolver(SERVFAIL, &attempts),
            )
            .await;
            assert_eq!(crate::dns_parser::rcode(&response.data), SERVFAIL);
            let after_attempt = attempts.load(Ordering::SeqCst);

            // Until then, clients get a SERVFAIL at once, and they don't make the delay longer
            for _ in 0..10 {
                let response = ask(
                    &query_manager,
                    EXAMPLE_COM_QUERY,
                    rcode_resolver(SERVFAIL, &attempts),
                )
                .await;
                assert_eq!(crate::dns_parser::rcode(&response.data), SERVFAIL);
            }
            assert_eq!(attempts.load(Ordering::SeqCst), after_attempt);
            tokio::time::advance(Duration::from_secs(delay)).await;
        }

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        let stats = query_manager.get_stats().unwrap().get_stats().await;
        assert_eq!(stats.failure_cache_hits, 30);
    }

    #[tokio::test]
    async fn test_waiting_client_sees_a_failure_published_before_it() {
        let query_manager = QueryManager::for_tests(5, 512, true);
        let key = example_key();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (release_tx, delayed_servfail) = delayed_servfail_resolver(&attempts);
        let mut first = query_manager
            .submit_query_with_client(
                key.clone(),
                EXAMPLE_COM_QUERY.to_vec(),
                delayed_servfail,
                "192.0.2.1:5353",
            )
            .await
            .unwrap();

        // The task gets its SERVFAIL, and waits for the lock to publish it
        let in_flight_guard = query_manager.in_flight_queries.lock().await;
        release_tx.send(()).unwrap();
        let_tasks_run().await;

        // The second client didn't see the failure yet, and waits for the lock after the task
        let second_manager = query_manager.clone();
        let second_resolver = rcode_resolver(SERVFAIL, &attempts);
        let mut second = tokio_test::task::spawn(async move {
            let mut receiver = second_manager
                .submit_query_with_client(
                    key,
                    EXAMPLE_COM_QUERY.to_vec(),
                    second_resolver,
                    "192.0.2.2:5353",
                )
                .await
                .unwrap();
            receiver.recv().await
        });
        assert!(second.poll().is_pending());
        drop(in_flight_guard);
        let_tasks_run().await;

        let std::task::Poll::Ready(response) = second.poll() else {
            panic!("the second client is still waiting");
        };
        assert_eq!(crate::dns_parser::rcode(&response.unwrap().data), SERVFAIL);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            crate::dns_parser::rcode(&first.recv().await.unwrap().data),
            SERVFAIL
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_one_attempt_when_the_retry_delay_ends() {
        let query_manager = QueryManager::for_tests(5, 512, true);
        let attempts = Arc::new(AtomicUsize::new(0));
        ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            rcode_resolver(SERVFAIL, &attempts),
        )
        .await;
        tokio::time::advance(Duration::from_secs(1)).await;

        // Several clients arrive together when the delay is over
        let release = Arc::new(tokio::sync::Notify::new());
        let mut receivers = Vec::new();
        for client in 1..=5 {
            let resolver = {
                let attempts = attempts.clone();
                let release = release.clone();
                fake_resolver(move |_data: Vec<u8>| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    let release = release.clone();
                    Box::pin(async move {
                        release.notified().await;
                        Ok(EXAMPLE_COM_ANSWER.to_vec())
                    }) as Answer
                })
            };
            let receiver = query_manager
                .submit_query_with_client(
                    example_key(),
                    EXAMPLE_COM_QUERY.to_vec(),
                    resolver,
                    &format!("192.0.2.{client}:5353"),
                )
                .await
                .unwrap();
            receivers.push(receiver);
        }
        let_tasks_run().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        release.notify_one();
        for mut receiver in receivers {
            let response = receiver.recv().await.unwrap();
            assert_eq!(crate::dns_parser::rcode(&response.data), 0);
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_useful_answer_resets_the_failures() {
        let query_manager = QueryManager::for_tests(5, 512, true);
        let key = example_key();
        let attempts = Arc::new(AtomicUsize::new(0));
        for delay in [1, 2] {
            ask(
                &query_manager,
                EXAMPLE_COM_QUERY,
                rcode_resolver(SERVFAIL, &attempts),
            )
            .await;
            tokio::time::advance(Duration::from_secs(delay)).await;
        }

        let response = ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            counting_answer_resolver(&attempts),
        )
        .await;
        assert_eq!(&response.data[4..], &EXAMPLE_COM_ANSWER[4..]);
        assert!(!query_manager.failure_state(&key).recent_failure);

        // The next failure starts again with the shortest delay
        ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            rcode_resolver(SERVFAIL, &attempts),
        )
        .await;
        tokio::time::advance(Duration::from_secs(1)).await;
        ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            rcode_resolver(SERVFAIL, &attempts),
        )
        .await;
        assert_eq!(attempts.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn test_fresh_answer_ignores_failures() {
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        let cache = create_dns_cache(10);
        query_manager.set_cache(cache.clone());
        let key = example_key();
        cache.insert(
            key.clone(),
            CachedResponse::new(EXAMPLE_COM_ANSWER.to_vec(), Duration::from_secs(60)),
        );
        query_manager.get_failure_cache().unwrap().record_failure(
            &key,
            UPSTREAM.parse().unwrap(),
            FailureKind::Timeout,
            tokio::time::Instant::now(),
        );
        let attempts = Arc::new(AtomicUsize::new(0));

        let response = ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            counting_answer_resolver(&attempts),
        )
        .await;

        assert_eq!(crate::dns_parser::rcode(&response.data), 0);
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        let stats = query_manager.get_stats().unwrap().get_stats().await;
        assert_eq!((stats.cache_hits, stats.failure_cache_hits), (1, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn test_stale_answer_while_the_upstream_server_fails() {
        let (query_manager, _, _) = manager_with_expired_entry(false);
        let attempts = Arc::new(AtomicUsize::new(0));
        let is_stale = |response: &DnsResponse| {
            crate::dns_parser::extract_min_ttl(&response.data).unwrap()
                == Some(query_manager.serve_stale_ttl)
        };

        // The client gets the stale answer instead of the SERVFAIL
        let response = ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            rcode_resolver(SERVFAIL, &attempts),
        )
        .await;
        assert!(is_stale(&response));

        // During the delay, the stale answer comes without a refresh
        for _ in 0..5 {
            let response = ask(
                &query_manager,
                EXAMPLE_COM_QUERY,
                rcode_resolver(SERVFAIL, &attempts),
            )
            .await;
            assert!(is_stale(&response));
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        // After the delay, the stale answer still comes at once, and a refresh fails in the background
        tokio::time::advance(Duration::from_secs(1)).await;
        let mut receiver = query_manager
            .submit_query_with_client(
                example_key(),
                EXAMPLE_COM_QUERY.to_vec(),
                rcode_resolver(SERVFAIL, &attempts),
                "192.0.2.1:5353",
            )
            .await
            .unwrap();
        assert!(is_stale(&receiver.try_recv().unwrap()));
        settle(&query_manager).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // That failure doubled the delay
        tokio::time::advance(Duration::from_secs(1)).await;
        ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            rcode_resolver(SERVFAIL, &attempts),
        )
        .await;
        settle(&query_manager).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            rcode_resolver(SERVFAIL, &attempts),
        )
        .await;
        settle(&query_manager).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_failing_upstream_does_not_hold_back_the_other_one() {
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        let servers: Vec<SocketAddr> = vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        ];
        query_manager.set_upstream_servers(servers.clone());
        let tried = Arc::new(std::sync::Mutex::new(Vec::new()));
        let servfail = || {
            let tried = tried.clone();
            move |request: AttemptRequest| {
                tried.lock().unwrap().push(request.upstream);
                let mut data = request.query.clone();
                crate::dns_parser::set_qr(&mut data, true).unwrap();
                crate::dns_parser::set_rcode(&mut data, SERVFAIL).unwrap();
                request.progress.mark_sent();
                outcome(&request, Ok(data))
            }
        };

        // HTTP caches may only keep the SERVFAIL once no server can get the query
        let mut retry_at = None;
        for expected_freshness in [false, true, true] {
            let response = ask(&query_manager, EXAMPLE_COM_QUERY, servfail()).await;
            assert_eq!(crate::dns_parser::rcode(&response.data), SERVFAIL);
            assert_eq!(response.failure_freshness.is_some(), expected_freshness);
            if let Some(freshness) = response.failure_freshness {
                // Later SERVFAILs keep the same deadline
                assert_eq!(
                    *retry_at.get_or_insert(freshness.retry_at),
                    freshness.retry_at
                );
            }
        }

        // The second query goes to the other server, and the third one to none
        let mut tried = tried.lock().unwrap().clone();
        tried.sort();
        assert_eq!(tried, servers);
    }

    #[tokio::test]
    async fn test_only_server_failures_are_remembered() {
        let mut nxdomain = EXAMPLE_COM_QUERY.to_vec();
        crate::dns_parser::set_flags(&mut nxdomain, 0x8183).unwrap();
        let mut zero_ttl = EXAMPLE_COM_ANSWER.to_vec();
        zero_ttl[35..39].fill(0);
        let mut truncated = EXAMPLE_COM_ANSWER.to_vec();
        crate::dns_parser::set_tc(&mut truncated, true).unwrap();
        let mut truncated_servfail = EXAMPLE_COM_QUERY.to_vec();
        crate::dns_parser::set_flags(&mut truncated_servfail, 0x8382).unwrap();
        let rcode = |rcode: u8| {
            let mut response = EXAMPLE_COM_QUERY.to_vec();
            crate::dns_parser::set_qr(&mut response, true).unwrap();
            crate::dns_parser::set_rcode(&mut response, rcode).unwrap();
            response
        };
        let servfail = rcode(SERVFAIL);

        let answers = [
            nxdomain,
            rcode(0),
            zero_ttl,
            truncated,
            truncated_servfail,
            rcode(crate::dns_processor::DNS_RCODE_FORMERR),
            rcode(crate::dns_processor::DNS_RCODE_NOTIMP),
            rcode(crate::dns_processor::DNS_RCODE_REFUSED),
        ];
        let errors = [
            AttemptError::Local(String::new()),
            AttemptError::Rejected(String::new()),
            AttemptError::Transport(String::new()),
        ];
        let mut cases = vec![
            (Ok(servfail.clone()), true, false, true),
            // After a forged datagram, nothing counts against the server
            (Ok(servfail), true, true, false),
            (Err(AttemptError::BudgetExpired), true, true, false),
            (Err(AttemptError::BudgetExpired), true, false, true),
            // A timeout before the first send is not the server's fault
            (Err(AttemptError::BudgetExpired), false, false, false),
        ];
        let not_failures = answers
            .into_iter()
            .map(Ok)
            .chain(errors.into_iter().map(Err));
        cases.extend(not_failures.map(|result| (result, true, false, false)));

        for (result, sent, spoof_fallback, remembered) in cases {
            let query_manager = QueryManager::for_tests(5, 512, true);
            let resolver = move |request: AttemptRequest| {
                if sent {
                    request.progress.mark_sent();
                }
                if spoof_fallback {
                    request.progress.mark_spoof_fallback();
                }
                outcome(&request, result.clone())
            };

            let response = ask(&query_manager, EXAMPLE_COM_QUERY, resolver).await;

            assert_eq!(
                query_manager.failure_state(&example_key()).recent_failure,
                remembered,
                "{:?} {spoof_fallback}",
                response.data
            );
            // With a single server, a remembered failure means that no server can get the query
            assert_eq!(response.failure_freshness.is_some(), remembered);
        }
    }

    #[tokio::test]
    async fn test_disabled_failure_cache_asks_every_time() {
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        query_manager.set_failure_policy(FailurePolicy {
            cache_size: 0,
            ..FailurePolicy::default()
        });
        assert!(query_manager.get_failure_cache().is_none());
        let attempts = Arc::new(AtomicUsize::new(0));

        for _ in 0..3 {
            let response = ask(
                &query_manager,
                EXAMPLE_COM_QUERY,
                rcode_resolver(SERVFAIL, &attempts),
            )
            .await;
            assert_eq!(crate::dns_parser::rcode(&response.data), SERVFAIL);
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_global_outage_without_history_still_asks() {
        let query_manager = QueryManager::for_tests(5, 512, true);
        let stats = query_manager.get_stats().unwrap();
        for _ in 0..crate::stats::PARK_AFTER_FAILURES {
            stats.record_timeout(UPSTREAM.parse().unwrap()).await;
        }
        assert!(stats.all_resolvers_failing().await);
        let attempts = Arc::new(AtomicUsize::new(0));

        ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            counting_answer_resolver(&attempts),
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_relayed_and_synthesized_servfails_agree() {
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        query_manager.authoritative_dns = true;

        // A SERVFAIL with an extended error, Network Error (23), and the flags of a resolver
        let mut upstream_servfail = EXAMPLE_COM_QUERY.to_vec();
        crate::dns_parser::set_flags(&mut upstream_servfail, 0x8182).unwrap();
        crate::dns_parser::add_edns_section(&mut upstream_servfail, 1232).unwrap();
        let ede = [0x00, 0x0f, 0x00, 0x02, 0x00, 0x17];
        let rdlen = upstream_servfail.len() - 2;
        upstream_servfail[rdlen..].copy_from_slice(&(ede.len() as u16).to_be_bytes());
        upstream_servfail.extend_from_slice(&ede);
        let has_ede = |packet: &[u8]| packet.windows(ede.len()).any(|window| window == ede);
        let resolver = fake_resolver(move |_data: Vec<u8>| {
            Box::pin(std::future::ready(Ok(upstream_servfail.clone()))) as Answer
        });
        let attempts = Arc::new(AtomicUsize::new(0));

        let relayed = ask(&query_manager, EXAMPLE_COM_QUERY, resolver).await;
        let synthesized = ask(
            &query_manager,
            EXAMPLE_COM_QUERY,
            rcode_resolver(SERVFAIL, &attempts),
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert!(has_ede(&relayed.data));
        assert!(!has_ede(&synthesized.data));
        for response in [relayed, synthesized] {
            assert_eq!(crate::dns_parser::rcode(&response.data), SERVFAIL);
            let flags = crate::dns_parser::flags(&response.data);
            assert_ne!(flags & 0x0400, 0, "AA must be set");
            assert_eq!(flags & 0x0080, 0, "RA must not be set");
        }
    }

    #[test]
    fn test_upstream_server_listed_twice_has_one_entry() {
        let addrs = |servers: &[&str]| -> Vec<SocketAddr> {
            servers.iter().map(|s| s.parse().unwrap()).collect()
        };
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        query_manager.set_upstream_servers(addrs(&[
            "[2001:DB8::1]:53",
            "[2001:db8::1]:053",
            "192.0.2.1:53",
            "[::ffff:192.0.2.1]:53",
            "192.0.2.1:5353",
            "[fe80::1%2]:53",
        ]));

        // The scope of a link-local address stays
        assert_eq!(
            *query_manager.get_upstream_servers(),
            addrs(&[
                "[2001:db8::1]:53",
                "192.0.2.1:53",
                "192.0.2.1:5353",
                "[fe80::1%2]:53"
            ])
        );
    }

    #[tokio::test]
    async fn test_waiting_client_uses_stale_data_after_a_new_failure() {
        let (mut query_manager, _, key) = manager_with_expired_entry(false);
        query_manager.set_upstream_servers(vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        ]);
        let (release_tx, delayed_servfail) =
            delayed_servfail_resolver(&Arc::new(AtomicUsize::new(0)));
        let _first = query_manager
            .submit_query_with_client(
                key.clone(),
                EXAMPLE_COM_QUERY.to_vec(),
                delayed_servfail,
                "192.0.2.1:5353",
            )
            .await
            .unwrap();

        // The first task fails, and waits for the lock to publish its failure
        let in_flight_guard = query_manager.in_flight_queries.lock().await;
        release_tx.send(()).unwrap();
        let_tasks_run().await;

        // Two more clients see no failure yet, so they wait for the lock too.
        // The first one starts a refresh with the other server, which never answers, and the second one joins it.
        let silent = |request: AttemptRequest| {
            request.progress.mark_sent();
            Box::pin(std::future::pending()) as BoxFuture<'static, AttemptOutcome>
        };
        let mut clients: Vec<_> = (2..=3)
            .map(|client| {
                let query_manager = query_manager.clone();
                let key = key.clone();
                tokio_test::task::spawn(async move {
                    let mut receiver = query_manager
                        .submit_query_with_client(
                            key,
                            EXAMPLE_COM_QUERY.to_vec(),
                            silent,
                            &format!("192.0.2.{client}:5353"),
                        )
                        .await
                        .unwrap();
                    receiver.recv().await
                })
            })
            .collect();
        for client in &mut clients {
            assert!(client.poll().is_pending());
        }
        drop(in_flight_guard);
        let_tasks_run().await;

        // After the failure, both get the stale answer at once, while the other server is asked
        for client in &mut clients {
            let std::task::Poll::Ready(response) = client.poll() else {
                panic!("a client waits for the other server");
            };
            assert_eq!(
                crate::dns_parser::extract_min_ttl(&response.unwrap().data).unwrap(),
                Some(query_manager.serve_stale_ttl)
            );
        }
        assert_eq!(query_manager.in_flight_count().await, 1);
    }

    #[tokio::test]
    async fn test_huge_server_timeout_does_not_panic() {
        let mut query_manager = QueryManager::for_tests(5, 512, true);
        query_manager.server_timeout = u64::MAX;

        // A panic in the task would leave the client waiting forever
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            ask(&query_manager, EXAMPLE_COM_QUERY, answering_resolver),
        )
        .await
        .expect("the query must not hang");

        assert_eq!(crate::dns_parser::rcode(&response.data), 0);
    }
}
