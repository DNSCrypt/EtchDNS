use crate::connection_slots::ClientSlots;
use crate::stats::{GlobalStats, SharedStats};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, server::conn::http1};
use hyper_util::rt::TokioIo;
use log::info;
use std::convert::Infallible;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

// Global server start time to calculate uptime
static START_TIME: OnceLock<SystemTime> = OnceLock::new();

/// Initialize the server start time if not already set
fn init_start_time() -> SystemTime {
    *START_TIME.get_or_init(SystemTime::now)
}

/// Format metrics as text
fn format_metrics(
    stats: &GlobalStats,
    active_inflight_queries: usize,
    active_udp_clients: usize,
    active_tcp_clients: usize,
    cache_size: Option<usize>,
    cache_capacity: Option<usize>,
    failure_cache_size: Option<usize>,
    failure_cache_capacity: Option<usize>,
) -> String {
    let mut output = String::new();

    // Initialize start time
    let start_time = init_start_time();

    // Uptime in seconds
    let uptime_secs = match SystemTime::now().duration_since(start_time) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    };

    output.push_str("# HELP etchdns_uptime_seconds Time since server startup in seconds\n");
    output.push_str("# TYPE etchdns_uptime_seconds counter\n");
    output.push_str(&format!("etchdns_uptime_seconds {}\n", uptime_secs));

    // Global metrics
    output.push_str("# HELP etchdns_total_queries Total number of DNS queries processed\n");
    output.push_str("# TYPE etchdns_total_queries counter\n");
    output.push_str(&format!("etchdns_total_queries {}\n", stats.total_queries));

    output.push_str("# HELP etchdns_successful_queries Total number of successful DNS queries\n");
    output.push_str("# TYPE etchdns_successful_queries counter\n");
    output.push_str(&format!(
        "etchdns_successful_queries {}\n",
        stats.total_successful
    ));

    output.push_str("# HELP etchdns_failed_queries Total number of failed DNS queries\n");
    output.push_str("# TYPE etchdns_failed_queries counter\n");
    output.push_str(&format!("etchdns_failed_queries {}\n", stats.total_failed));

    output.push_str(
        "# HELP etchdns_timeout_queries Total number of upstream queries without an answer to their first datagram in time\n",
    );
    output.push_str("# TYPE etchdns_timeout_queries counter\n");
    output.push_str(&format!(
        "etchdns_timeout_queries {}\n",
        stats.total_timeouts
    ));

    output.push_str(
        "# HELP etchdns_upstream_budget_expirations Total number of upstream queries still unanswered at the end of server_timeout\n",
    );
    output.push_str("# TYPE etchdns_upstream_budget_expirations counter\n");
    output.push_str(&format!(
        "etchdns_upstream_budget_expirations {}\n",
        stats.budget_expirations
    ));

    output.push_str("# HELP etchdns_client_queries Total number of client DNS queries received\n");
    output.push_str("# TYPE etchdns_client_queries counter\n");
    output.push_str(&format!(
        "etchdns_client_queries {}\n",
        stats.client_queries
    ));

    output.push_str("# HELP etchdns_cache_hits Total number of DNS cache hits\n");
    output.push_str("# TYPE etchdns_cache_hits counter\n");
    output.push_str(&format!("etchdns_cache_hits {}\n", stats.cache_hits));

    output.push_str("# HELP etchdns_cache_misses Total number of DNS cache misses\n");
    output.push_str("# TYPE etchdns_cache_misses counter\n");
    output.push_str(&format!("etchdns_cache_misses {}\n", stats.cache_misses));

    // Cache size and capacity
    if let Some(size) = cache_size {
        output.push_str("# HELP etchdns_cache_size Current number of entries in the DNS cache\n");
        output.push_str("# TYPE etchdns_cache_size gauge\n");
        output.push_str(&format!("etchdns_cache_size {}\n", size));
    }

    if let Some(capacity) = cache_capacity {
        output.push_str("# HELP etchdns_cache_capacity Maximum capacity of the DNS cache\n");
        output.push_str("# TYPE etchdns_cache_capacity gauge\n");
        output.push_str(&format!("etchdns_cache_capacity {}\n", capacity));
    }

    output.push_str(
        "# HELP etchdns_failure_cache_hits Total number of client queries answered without asking, because every upstream server failed them recently\n",
    );
    output.push_str("# TYPE etchdns_failure_cache_hits counter\n");
    output.push_str(&format!(
        "etchdns_failure_cache_hits {}\n",
        stats.failure_cache_hits
    ));

    if let Some(size) = failure_cache_size {
        output.push_str(
            "# HELP etchdns_failure_cache_size Current number of queries with recent upstream failures\n",
        );
        output.push_str("# TYPE etchdns_failure_cache_size gauge\n");
        output.push_str(&format!("etchdns_failure_cache_size {}\n", size));
    }

    if let Some(capacity) = failure_cache_capacity {
        output.push_str(
            "# HELP etchdns_failure_cache_capacity Maximum number of queries with recent upstream failures\n",
        );
        output.push_str("# TYPE etchdns_failure_cache_capacity gauge\n");
        output.push_str(&format!("etchdns_failure_cache_capacity {}\n", capacity));
    }

    // Calculate and output cache hit rate if we have both hits and misses
    if stats.cache_hits > 0 || stats.cache_misses > 0 {
        let total = stats.cache_hits + stats.cache_misses;
        let hit_rate = if total > 0 {
            stats.cache_hits as f64 / total as f64
        } else {
            0.0
        };

        output.push_str("# HELP etchdns_cache_hit_rate Cache hit rate (hits / total lookups)\n");
        output.push_str("# TYPE etchdns_cache_hit_rate gauge\n");
        output.push_str(&format!("etchdns_cache_hit_rate {:.4}\n", hit_rate));

        // Cache utilization (size/capacity ratio)
        if let (Some(size), Some(capacity)) = (cache_size, cache_capacity)
            && capacity > 0
        {
            output.push_str(
                "# HELP etchdns_cache_utilization_ratio Cache utilization (size/capacity ratio)\n",
            );
            output.push_str("# TYPE etchdns_cache_utilization_ratio gauge\n");
            output.push_str(&format!(
                "etchdns_cache_utilization_ratio {:.4}\n",
                size as f64 / capacity as f64
            ));
        }
    }

    output.push_str("# HELP etchdns_active_udp_clients Current number of active UDP clients\n");
    output.push_str("# TYPE etchdns_active_udp_clients gauge\n");
    output.push_str(&format!(
        "etchdns_active_udp_clients {}\n",
        active_udp_clients
    ));

    output.push_str("# HELP etchdns_active_tcp_clients Current number of active TCP clients\n");
    output.push_str("# TYPE etchdns_active_tcp_clients gauge\n");
    output.push_str(&format!(
        "etchdns_active_tcp_clients {}\n",
        active_tcp_clients
    ));

    output.push_str(
        "# HELP etchdns_active_inflight_queries Current number of active in-flight queries\n",
    );
    output.push_str("# TYPE etchdns_active_inflight_queries gauge\n");
    output.push_str(&format!(
        "etchdns_active_inflight_queries {}\n",
        active_inflight_queries
    ));

    output.push_str("# HELP etchdns_udp_receive_errors Total number of UDP receive errors\n");
    output.push_str("# TYPE etchdns_udp_receive_errors counter\n");
    output.push_str(&format!(
        "etchdns_udp_receive_errors {}\n",
        stats.udp_receive_errors
    ));

    output.push_str("# HELP etchdns_tcp_accept_errors Total number of TCP accept errors\n");
    output.push_str("# TYPE etchdns_tcp_accept_errors counter\n");
    output.push_str(&format!(
        "etchdns_tcp_accept_errors {}\n",
        stats.tcp_accept_errors
    ));

    // Total active clients
    let total_active_clients = active_udp_clients + active_tcp_clients;
    output.push_str("# HELP etchdns_active_clients Total number of active clients (UDP + TCP)\n");
    output.push_str("# TYPE etchdns_active_clients gauge\n");
    output.push_str(&format!(
        "etchdns_active_clients {}\n",
        total_active_clients
    ));

    // Query rates
    if uptime_secs > 0 {
        output.push_str(
            "# HELP etchdns_query_rate_per_second Average queries per second since startup\n",
        );
        output.push_str("# TYPE etchdns_query_rate_per_second gauge\n");
        output.push_str(&format!(
            "etchdns_query_rate_per_second {:.3}\n",
            stats.total_queries as f64 / uptime_secs as f64
        ));
    }

    // DNS error ratio
    if stats.total_queries > 0 {
        let error_ratio =
            (stats.total_failed + stats.total_timeouts) as f64 / stats.total_queries as f64;
        output.push_str("# HELP etchdns_error_ratio Ratio of failed queries to total queries\n");
        output.push_str("# TYPE etchdns_error_ratio gauge\n");
        output.push_str(&format!("etchdns_error_ratio {:.4}\n", error_ratio));
    }

    // Per-resolver metrics
    output.push_str("# HELP etchdns_resolver_response_time_ms Average response time in milliseconds per resolver\n");
    output.push_str("# TYPE etchdns_resolver_response_time_ms gauge\n");

    output.push_str(
        "# HELP etchdns_resolver_success_count Number of successful queries per resolver\n",
    );
    output.push_str("# TYPE etchdns_resolver_success_count counter\n");

    output
        .push_str("# HELP etchdns_resolver_failure_count Number of failed queries per resolver\n");
    output.push_str("# TYPE etchdns_resolver_failure_count counter\n");

    output.push_str(
        "# HELP etchdns_resolver_timeout_count Number of timed out queries per resolver\n",
    );
    output.push_str("# TYPE etchdns_resolver_timeout_count counter\n");

    output.push_str(
        "# HELP etchdns_resolver_budget_expiration_count Number of queries still unanswered at the end of server_timeout per resolver\n",
    );
    output.push_str("# TYPE etchdns_resolver_budget_expiration_count counter\n");

    output.push_str("# HELP etchdns_resolver_last_used_timestamp Last time the resolver was used (Unix timestamp)\n");
    output.push_str("# TYPE etchdns_resolver_last_used_timestamp gauge\n");

    // Add metrics for each resolver
    for (addr, stats) in &stats.resolver_stats {
        let addr_str = addr.to_string().replace(':', "_");

        output.push_str(&format!(
            "etchdns_resolver_response_time_ms{{resolver=\"{}\"}} {:.3}\n",
            addr_str, stats.avg_response_time_ms
        ));

        output.push_str(&format!(
            "etchdns_resolver_success_count{{resolver=\"{}\"}} {}\n",
            addr_str, stats.success_count
        ));

        output.push_str(&format!(
            "etchdns_resolver_failure_count{{resolver=\"{}\"}} {}\n",
            addr_str, stats.failure_count
        ));

        output.push_str(&format!(
            "etchdns_resolver_timeout_count{{resolver=\"{}\"}} {}\n",
            addr_str, stats.timeout_count
        ));

        output.push_str(&format!(
            "etchdns_resolver_budget_expiration_count{{resolver=\"{}\"}} {}\n",
            addr_str, stats.budget_expiration_count
        ));

        // Calculate resolver error ratio
        let total_resolver_queries =
            stats.success_count + stats.failure_count + stats.timeout_count;
        if total_resolver_queries > 0 {
            let resolver_error_ratio =
                (stats.failure_count + stats.timeout_count) as f64 / total_resolver_queries as f64;
            output.push_str(&format!(
                "etchdns_resolver_error_ratio{{resolver=\"{}\"}} {:.4}\n",
                addr_str, resolver_error_ratio
            ));
        }

        // Format the last_used timestamp
        let last_used_ts = time_format::from_system_time(stats.last_used).unwrap_or_default();
        output.push_str(&format!(
            "etchdns_resolver_last_used_timestamp{{resolver=\"{}\", time=\"{}\"}} {}\n",
            addr_str,
            time_format::format_iso8601_local(last_used_ts)
                .unwrap_or_else(|_| "unknown".to_string()),
            last_used_ts,
        ));
    }

    output
}

/// Handle HTTP requests
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    stats: Arc<SharedStats>,
    metrics_path: String,
    query_manager: Option<Arc<crate::query_manager::QueryManager>>,
    udp_clients: Option<ClientSlots>,
    tcp_clients: Option<ClientSlots>,
    dns_cache: Option<Arc<crate::cache::SyncDnsCache>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();

    if path == metrics_path {
        // Get the current stats
        let current_stats = stats.get_stats().await;

        // Get the number of in-flight queries from the query manager if available
        let active_inflight_queries = match &query_manager {
            Some(qm) => qm.in_flight_count().await,
            None => 0, // Default to 0 if query manager isn't available
        };

        let active_udp_clients = udp_clients.as_ref().map_or(0, |slots| slots.lock().len());
        let active_tcp_clients = tcp_clients.as_ref().map_or(0, |slots| slots.lock().len());

        // Get cache metrics if available
        let (cache_size, cache_capacity) = match &dns_cache {
            Some(cache) => (Some(cache.len()), Some(cache.capacity())),
            None => (None, None),
        };
        let failure_cache = query_manager.as_ref().and_then(|qm| qm.get_failure_cache());
        let (failure_cache_size, failure_cache_capacity) = match &failure_cache {
            Some(failure_cache) => (Some(failure_cache.size()), Some(failure_cache.capacity())),
            None => (None, None),
        };

        // Format the metrics
        let metrics_text = format_metrics(
            &current_stats,
            active_inflight_queries,
            active_udp_clients,
            active_tcp_clients,
            cache_size,
            cache_capacity,
            failure_cache_size,
            failure_cache_capacity,
        );

        // Return the metrics
        Ok(Response::new(Full::new(Bytes::from(metrics_text))))
    } else {
        // Return 404 for any other path
        let mut response = Response::new(Full::new(Bytes::from("Not Found")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        Ok(response)
    }
}

/// Start the HTTP metrics server
pub async fn start_metrics_server(
    listener: TcpListener,
    metrics_path: String,
    stats: Arc<SharedStats>,
    max_connections: usize,
    query_manager: Option<Arc<crate::query_manager::QueryManager>>,
    udp_clients: Option<ClientSlots>,
    tcp_clients: Option<ClientSlots>,
    dns_cache: Option<Arc<crate::cache::SyncDnsCache>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_start_time();

    let addr = listener.local_addr()?;
    info!("Metrics server listening on {addr}, path: {metrics_path}");

    // Create a semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_connections));

    // Accept connections
    loop {
        // Accept a connection
        let (stream, _) = crate::net::accept_with_retry(&listener, "metrics").await;
        let io = TokioIo::new(stream);

        // Clone the stats and metrics path for this connection
        let stats = stats.clone();
        let metrics_path = metrics_path.clone();
        let semaphore = semaphore.clone();
        let query_manager = query_manager.clone();
        let udp_clients = udp_clients.clone();
        let tcp_clients = tcp_clients.clone();
        let dns_cache = dns_cache.clone();

        // Spawn a task to handle the connection
        tokio::spawn(async move {
            // Try to acquire a permit from the semaphore
            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    // Too many connections, reject this one
                    return;
                }
            };

            // Handle the connection
            let service = hyper::service::service_fn(move |req| {
                let stats = stats.clone();
                let metrics_path = metrics_path.clone();
                let query_manager = query_manager.clone();
                let udp_clients = udp_clients.clone();
                let tcp_clients = tcp_clients.clone();
                let dns_cache = dns_cache.clone();
                async move {
                    handle_request(
                        req,
                        stats,
                        metrics_path,
                        query_manager,
                        udp_clients,
                        tcp_clients,
                        dns_cache,
                    )
                    .await
                }
            });

            if let Ok(Err(err)) = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                http1::Builder::new().serve_connection(io, service),
            )
            .await
            {
                // Log any errors
                log::error!("Error serving connection: {err}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_uptime_counts_from_server_start() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = start_metrics_server(
            listener,
            "/metrics".to_string(),
            Arc::new(SharedStats::new()),
            1,
            None,
            None,
            None,
            None,
        );

        // Runs until the server waits for its first connection
        assert!(futures::FutureExt::now_or_never(server).is_none());
        assert!(START_TIME.get().is_some());
    }

    #[test]
    fn test_failure_metrics_are_exported() {
        let mut stats = GlobalStats::new();
        let resolver = "192.0.2.1:53".parse().unwrap();
        stats.record_timeout(resolver);
        stats.record_budget_expiration(resolver);
        stats.record_failure_cache_hit();

        let metrics = format_metrics(&stats, 0, 0, 0, None, None, Some(3), Some(1024));

        for line in [
            "etchdns_timeout_queries 1",
            "etchdns_upstream_budget_expirations 1",
            "etchdns_failure_cache_hits 1",
            "etchdns_failure_cache_size 3",
            "etchdns_failure_cache_capacity 1024",
            "etchdns_resolver_timeout_count{resolver=\"192.0.2.1_53\"} 1",
            "etchdns_resolver_budget_expiration_count{resolver=\"192.0.2.1_53\"} 1",
        ] {
            assert!(metrics.lines().any(|l| l == line), "{line}");
        }
    }
}
