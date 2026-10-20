use log::{error, warn};
use slabigator::Slab;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;

use crate::dns_key::DNSKey;
use crate::errors::{DnsError, DnsResult, EtchDnsResult};
use crate::load_balancer::LoadBalancingStrategy;

/// Maximum number of receivers for a single query
const MAX_RECEIVERS: usize = 100;

/// Response from a DNS query
#[derive(Clone)]
pub struct DnsResponse {
    /// The raw DNS response data
    pub data: Vec<u8>,
    /// Error message if the query failed
    pub error: Option<String>,
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
        Self::new(
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
        )
    }

    /// Set the statistics tracker
    #[allow(dead_code)]
    pub fn set_stats(&mut self, stats: Arc<crate::stats::SharedStats>) {
        self.stats = Some(stats);
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
        resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        + Send
        + Sync
        + 'static,
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
        resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        + Send
        + Sync
        + 'static,
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
        resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        + Send
        + Sync
        + 'static,
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

        // If every upstream server is failing, answer with stale data now, and let the query below refresh it
        let stale_response = if self.serve_stale_grace_time > 0
            && let Some(stats) = &self.stats
            && stats.all_resolvers_failing().await
        {
            self.serve_stale(&key, "recent upstream failures")
        } else {
            None
        };

        let receiver = match self.manage_in_flight_queries(&key).await {
            Ok((mut in_flight_queries, mut query_slab)) => {
                // Create a new task to handle the query
                let (task, receiver) = self
                    .create_query_task(key.clone(), query_data, resolver)
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

                        Ok(receiver)
                    }
                    Err(e) => {
                        log::error!("Failed to add query to slab: {e}");
                        // Since we couldn't add to the slab, we won't add to the in-flight map either
                        // This ensures they stay in sync
                        Err(DnsError::Other(format!("Failed to add query to slab: {e}")).into())
                    }
                }
            }
            Err(e) => {
                if let Some(receiver) = e.into_receiver() {
                    // Query is already in flight, return the receiver
                    Ok(receiver)
                } else {
                    // Some other error occurred
                    Err(DnsError::Other("Failed to manage in-flight queries".to_string()).into())
                }
            }
        };

        stale_response.map_or(receiver, |response| {
            Ok(Self::receiver_with_response(response))
        })
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

    /// Get the load balancing strategy
    pub fn get_load_balancing_strategy(&self) -> LoadBalancingStrategy {
        self.load_balancing_strategy
    }

    /// Helper function to create a simple DNS response with flags and send it
    fn create_and_send_response_with_flags(
        query_data: &[u8],
        rcode: u8,
        authoritative_dns: bool,
        log_msg: Option<&str>,
    ) -> broadcast::Receiver<DnsResponse> {
        // Create the basic DNS response
        let mut dns_response =
            crate::dns_processor::create_dns_response(query_data, rcode, log_msg);

        // Set the appropriate DNS response flags
        crate::dns_processor::set_response_flags(&mut dns_response, authoritative_dns);

        Self::receiver_with_response(DnsResponse {
            data: dns_response,
            error: None,
        })
    }

    /// Creates a new query task to handle a DNS query
    /// Returns a tuple (QueryTask, receiver) for the task
    async fn create_query_task(
        &self,
        key: DNSKey,
        query_data: Vec<u8>,
        resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        + Send
        + Sync
        + 'static,
    ) -> (QueryTask, broadcast::Receiver<DnsResponse>) {
        log::debug!("Creating a new task to handle query for {}", key.name);

        // Create a broadcast channel for communicating responses
        let (response_sender, receiver) = broadcast::channel(MAX_RECEIVERS);
        let response_sender_clone = response_sender.clone();

        // Clone necessery values for the task
        let key_clone = key.clone();
        let in_flight_queries_arc = self.in_flight_queries.clone();
        let query_slab_arc = self.query_slab.clone();
        let server_timeout = self.server_timeout;
        let self_clone = self.clone();

        // Create the task
        let task_handle = tokio::spawn(async move {
            // Create a timeout for the resolver
            let timeout_duration = std::time::Duration::from_secs(server_timeout);

            // Resolve the query with a timeout
            let response = 'resolve: {
                match tokio::time::timeout(timeout_duration, resolver(query_data.clone())).await {
                    Ok(result) => {
                        // The resolver completed within the timeout
                        let result = result.and_then(|mut response_data| {
                            crate::dns_parser::validate_dns_response(&response_data)?;
                            // The upstream server's cookie must not be cached or passed on
                            crate::dns_parser::remove_edns_option(
                                &mut response_data,
                                crate::dns_parser::EDNS_OPTION_COOKIE,
                            )?;
                            if self_clone.authoritative_dns {
                                let removed = crate::dns_parser::remove_out_of_bailiwick_glue(
                                    &mut response_data,
                                )?;
                                if removed > 0 {
                                    log::debug!(
                                        "Removed {removed} out-of-bailiwick records from the referral for {}",
                                        key_clone.name
                                    );
                                }
                            }
                            Ok(response_data)
                        });
                        match result {
                            Ok(response_data) => {
                                if crate::dns_parser::rcode(&response_data)
                                    == crate::dns_processor::DNS_RCODE_SERVFAIL
                                    && let Some(stale_response) =
                                        self_clone.serve_stale(&key_clone, "SERVFAIL response")
                                {
                                    break 'resolve stale_response;
                                }

                                if let Some(cache) = &self_clone.cache {
                                    self_clone.cache_dns_response(
                                        cache,
                                        &key_clone,
                                        &response_data,
                                    );
                                }

                                // Set AA and RA flags based on authoritative_dns setting
                                let mut response_data_with_flags = response_data.clone();

                                // Set the appropriate DNS response flags
                                crate::dns_processor::set_response_flags(
                                    &mut response_data_with_flags,
                                    self_clone.authoritative_dns,
                                );

                                // Create a successful response
                                DnsResponse {
                                    data: response_data_with_flags,
                                    error: None,
                                }
                            }
                            Err(e) => {
                                // Log the error
                                log::debug!("Failed to resolve DNS query: {e}");

                                self_clone
                                    .serve_stale(&key_clone, &format!("upstream error: {e}"))
                                    .unwrap_or_else(|| DnsResponse {
                                        data: Vec::new(),
                                        error: Some(format!("DNS query failed: {e}")),
                                    })
                            }
                        }
                    }
                    Err(_) => {
                        // The resolver timed out
                        log::debug!("DNS query timed out after {server_timeout} seconds");

                        self_clone
                            .serve_stale(&key_clone, "timeout")
                            .unwrap_or_else(|| DnsResponse {
                                data: Vec::new(),
                                error: Some(format!(
                                    "DNS query timed out after {server_timeout} seconds"
                                )),
                            })
                    }
                }
            };

            Self::finish_query(
                &key_clone,
                response,
                &response_sender_clone,
                &in_flight_queries_arc,
                &query_slab_arc,
            )
            .await;
        });

        // Create and return the QueryTask
        let task = QueryTask {
            task_handle,
            response_sender,
        };

        (task, receiver)
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

        Some(DnsResponse {
            data: response_data,
            error: None,
        })
    }

    fn receiver_with_response(response: DnsResponse) -> broadcast::Receiver<DnsResponse> {
        let (response_sender, receiver) = broadcast::channel(1);
        if let Err(e) = response_sender.send(response) {
            log::debug!("Failed to send DNS response: {e}");
        }
        receiver
    }

    /// Manages in-flight queries and handles query limits
    /// Returns Ok(locks) if a new query should be created, or Err with a receiver if the query is already in flight
    async fn manage_in_flight_queries(
        &self,
        key: &DNSKey,
    ) -> Result<
        (
            tokio::sync::MutexGuard<'_, HashMap<DNSKey, InflightQuery>>,
            tokio::sync::MutexGuard<'_, Slab<DNSKey>>,
        ),
        DnsError,
    > {
        let mut in_flight_queries = self.in_flight_queries.lock().await;

        // Check if the query is already in flight
        if let Some(inflight_query) = in_flight_queries.get(key) {
            // Query is already in flight, subscribe to the response
            let receiver = inflight_query.task.response_sender.subscribe();
            return Err(DnsError::AlreadyInFlight(receiver));
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
                            let empty_response = DnsResponse {
                                data: Vec::new(),
                                error: Some(error_msg.to_string()),
                            };

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

        Ok((in_flight_queries, query_slab))
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
                let empty_response = DnsResponse {
                    data: Vec::new(),
                    error: Some(error_msg.to_string()),
                };

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
        if let Some(cache) = &self.cache {
            if let Some(cached_response) = cache.get(key) {
                // Check if the cached response has expired
                if !cached_response.is_expired() {
                    log::debug!("Cache hit for query: {}", key.name);

                    // Record cache hit in stats
                    if let Some(stats) = &self.stats {
                        stats.record_cache_hit().await;
                    }

                    // Create a successful response from the cached data
                    let mut response_data = cached_response.data.clone();

                    // If not authoritative, adjust the TTL based on remaining time
                    if !self.authoritative_dns {
                        let elapsed = std::time::SystemTime::now()
                            .duration_since(cached_response.cached_at)
                            .unwrap_or_default()
                            .as_secs()
                            .min(u32::MAX as u64) as u32;

                        if let Err(e) =
                            crate::dns_parser::decrement_ttl(&mut response_data, elapsed)
                        {
                            log::debug!("Failed to update TTL in cached response: {e}");
                        } else {
                            log::debug!("Adjusted cached response TTLs by {elapsed} seconds");
                        }
                    }

                    // Set the appropriate DNS response flags
                    crate::dns_processor::set_response_flags(
                        &mut response_data,
                        self.authoritative_dns,
                    );

                    return Some(Self::receiver_with_response(DnsResponse {
                        data: response_data,
                        error: None,
                    }));
                } else {
                    log::debug!(
                        "Cache hit for query: {}, but response has expired",
                        key.name
                    );
                    // Record cache miss in stats (expired entries count as misses)
                    if let Some(stats) = &self.stats {
                        stats.record_cache_miss().await;
                    }
                }
            } else {
                log::debug!("Cache miss for query: {}", key.name);
                // Record cache miss in stats
                if let Some(stats) = &self.stats {
                    stats.record_cache_miss().await;
                }
            }
        }

        // No valid cache entry found, continue normal processing
        None
    }

    /// Helper function to cache a DNS response
    fn cache_dns_response(
        &self,
        cache: &crate::cache::SyncDnsCache,
        key: &DNSKey,
        response_data: &[u8],
    ) {
        // Other codes are about the query or the server, not the name, so other clients
        // must not get them
        let rcode = crate::dns_parser::rcode(response_data);
        if rcode != crate::dns_processor::DNS_RCODE_NOERROR
            && rcode != crate::dns_processor::DNS_RCODE_NXDOMAIN
        {
            log::debug!("Not caching response with RCODE {rcode} for {}", key.name);
            return;
        }
        if crate::dns_parser::is_truncated(response_data) {
            log::debug!("Not caching truncated response for {}", key.name);
            return;
        }

        let extracted_ttl = match crate::dns_parser::extract_cache_ttl(response_data) {
            Ok(Some(ttl)) => ttl,
            Ok(None) => self.negative_cache_ttl,
            Err(e) => {
                log::debug!("Not caching response with an invalid TTL: {e}");
                return;
            }
        };

        let ttl = std::cmp::max(extracted_ttl, self.min_cache_ttl);

        let mut cached_data = response_data.to_vec();
        if let Err(e) =
            crate::dns_parser::cap_negative_response_ttl(&mut cached_data, extracted_ttl)
        {
            log::debug!("Not caching response with an invalid SOA TTL: {e}");
            return;
        }
        let ttl_duration = std::time::Duration::from_secs(ttl as u64);
        let cached_response = crate::cache::CachedResponse::new(cached_data, ttl_duration);

        cache.insert(key.clone(), cached_response);

        if ttl > extracted_ttl {
            log::debug!(
                "Stored DNS response in cache with minimum TTL: {ttl} seconds (original TTL was {extracted_ttl} seconds)"
            );
        } else {
            log::debug!("Stored DNS response in cache with TTL: {ttl} seconds");
        }
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

                    Some(Self::receiver_with_response(DnsResponse {
                        data: Vec::new(),
                        error: Some(format!(
                            "Query processing interrupted by hook (code: {hook_result})"
                        )),
                    }))
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

    /// Removes a finished query and sends its response to every client waiting for it.
    ///
    /// Both happen under the in-flight lock, so a client either joins in time to get the
    /// response or no longer finds the query and starts a new one.
    async fn finish_query(
        key: &DNSKey,
        response: DnsResponse,
        response_sender: &broadcast::Sender<DnsResponse>,
        in_flight_queries_arc: &Arc<Mutex<HashMap<DNSKey, InflightQuery>>>,
        query_slab_arc: &Arc<Mutex<Slab<DNSKey>>>,
    ) {
        // We need to acquire both locks to ensure atomicity
        let mut in_flight_queries = in_flight_queries_arc.lock().await;
        let mut query_slab = query_slab_arc.lock().await;

        // Check if the key exists in the map
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
        } else {
            // Not found in the map
            log::warn!("Attempted to remove non-existent query from map");
        }

        if let Err(e) = response_sender.send(response) {
            // This can happen if all receivers have been dropped
            log::debug!("Failed to send DNS response: {e}");
        }
    }

    /// Get whether EDNS-client-subnet is enabled
    pub fn get_enable_ecs(&self) -> bool {
        self.enable_ecs
    }

    /// Get the IPv4 prefix length for EDNS-client-subnet
    pub fn get_ecs_prefix_v4(&self) -> u8 {
        self.ecs_prefix_v4
    }

    /// Get the IPv6 prefix length for EDNS-client-subnet
    pub fn get_ecs_prefix_v6(&self) -> u8 {
        self.ecs_prefix_v6
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

        // Verify that we got an error (no stale cache to fall back to)
        assert!(
            response.error.is_some(),
            "Expected an error when no stale cache is available"
        );
        assert!(
            response.data.is_empty(),
            "Expected empty data when no stale cache is available"
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
        let failing_resolver = |mut data: Vec<u8>| {
            crate::dns_parser::set_qr(&mut data, true).unwrap();
            crate::dns_parser::set_rcode(&mut data, crate::dns_processor::DNS_RCODE_SERVFAIL)
                .unwrap();
            Box::pin(async move { Ok(data) })
                as futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        };

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
        let cache = create_dns_cache(10);
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
            manager.cache_dns_response(&cache, &key, &response);
            assert!(cache.get(&key).is_none());
        }
    }

    #[test]
    fn test_negative_response_uses_soa_minimum_for_cache_expiry() {
        let manager = QueryManager::for_tests(1, 512, true);
        let cache = create_dns_cache(10);
        let key = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();

        manager.cache_dns_response(
            &cache,
            &key,
            crate::dns_parser::NEGATIVE_RESPONSE_WITH_SOA_TTL_3600_MINIMUM_60,
        );

        let cached = cache.get(&key).unwrap();
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
            let resolver = move |_data: Vec<u8>| {
                Box::pin(std::future::ready(Ok(upstream_response.clone())))
                    as futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
            };
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
        let echo_resolver = |mut data: Vec<u8>| {
            crate::dns_parser::set_qr(&mut data, true).unwrap();
            Box::pin(std::future::ready(Ok(data)))
                as futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        };

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
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let key = DNSKey::from_packet(&query).unwrap();

        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let release_rx = std::sync::Mutex::new(Some(release_rx));
        let delayed_resolver = move |mut data: Vec<u8>| {
            let release = release_rx.lock().unwrap().take();
            Box::pin(async move {
                if let Some(release) = release {
                    let _ = release.await;
                }
                crate::dns_parser::set_qr(&mut data, true).unwrap();
                Ok(data)
            }) as futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        };
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

    const EXAMPLE_COM_QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    /// Answers `EXAMPLE_COM_QUERY` with a 60-second TTL
    const EXAMPLE_COM_ANSWER: &[u8] = &[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1,
    ];

    fn failing_resolver(_data: Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>> {
        Box::pin(async { Err(DnsError::UpstreamTimeout) })
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
            move |_data: Vec<u8>| {
                let release = release.clone();
                Box::pin(async move {
                    release.notified().await;
                    Ok(EXAMPLE_COM_ANSWER.to_vec())
                }) as futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
            }
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
        let resolver = |_data: Vec<u8>| {
            Box::pin(std::future::ready(Ok(EXAMPLE_COM_ANSWER.to_vec())))
                as futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        };
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
                move |data: Vec<u8>| {
                    upstream_queries.fetch_add(1, Ordering::SeqCst);
                    // The answer echoes the flags the upstream server got, and claims AD
                    let mut answer = EXAMPLE_COM_ANSWER.to_vec();
                    answer[2..4].copy_from_slice(&data[2..4]);
                    crate::dns_parser::set_qr(&mut answer, true).unwrap();
                    crate::dns_parser::set_ad(&mut answer, true).unwrap();
                    Box::pin(std::future::ready(Ok(answer)))
                        as futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
                }
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
}
