#![allow(clippy::too_many_arguments)]

use async_trait::async_trait;
use clap::Parser;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use ip_validator::{IpRange, IpValidator};

mod allowed_zones;
mod cache;
mod connection_slots;
mod control;
mod dns_key;
mod dns_key_test;
mod dns_parser;
mod dns_processor;
mod doh;
mod errors;
mod failure_cache;
mod hooks;
mod ip_validator;
mod load_balancer;
mod metrics;
mod net;
mod nx_zones;
mod probe;
mod query_logger;
mod query_manager;
mod rate_limiter;
mod resolver;
mod stats;

// Use our error types
use connection_slots::{ClientSlots, ConnectionSlots};
use dns_processor::DnsQueryProcessor;
use errors::{EtchDnsError, EtchDnsResult};
use probe::probe_server;
use query_manager::QueryManager;
use stats::SharedStats;

#[macro_use]
extern crate bpf;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "An efficient caching DNS proxy")]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
}

/// Configuration structure for the application
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    log_level: String,

    /// Addresses to listen on (array of "ip:port" strings)
    #[serde(default = "default_listen_addresses")]
    listen_addresses: Vec<String>,

    /// Addresses to listen on for DNS-over-HTTPS (DoH) (array of "ip:port" strings)
    #[serde(default = "default_doh_listen_addresses")]
    doh_listen_addresses: Vec<String>,

    /// Maximum length of DNS packet in bytes
    #[serde(default = "default_packet_size")]
    dns_packet_len_max: usize,

    /// Maximum number of UDP queries handled at the same time
    #[serde(default = "default_max_udp_clients")]
    max_udp_clients: usize,

    /// Maximum number of open TCP connections
    #[serde(default = "default_max_tcp_clients")]
    max_tcp_clients: usize,

    /// Maximum number of simultaneous in-flight queries
    #[serde(default = "default_max_inflight_queries")]
    max_inflight_queries: usize,

    /// Maximum time (in seconds) to wait for a response from an upstream server
    #[serde(default = "default_server_timeout")]
    server_timeout: u64,

    /// Upstream DNS servers to forward queries to (array of "ip:port" strings)
    #[serde(default = "default_upstream_servers")]
    upstream_servers: Vec<String>,

    /// Load balancing strategy for upstream DNS servers
    /// Options: "random", "fastest", "p2" (power-of-two-choices)
    #[serde(default = "default_load_balancing_strategy")]
    load_balancing_strategy: String,

    /// Optional address for the HTTP metrics server (ip:port)
    #[serde(default)]
    metrics_address: Option<String>,

    /// Optional URL path for the metrics endpoint (e.g., "/metrics")
    #[serde(default = "default_metrics_path")]
    metrics_path: String,

    /// Time window in seconds for UDP rate limiting
    /// Set to 0 to disable rate limiting for UDP
    #[serde(default = "default_udp_rate_limit_window")]
    udp_rate_limit_window: u64,

    /// Maximum number of queries allowed per client IP in the UDP window
    #[serde(default = "default_udp_rate_limit_count")]
    udp_rate_limit_count: u32,

    /// Maximum number of client IPs to track for UDP rate limiting
    #[serde(default = "default_udp_rate_limit_max_clients")]
    udp_rate_limit_max_clients: usize,

    /// Time window in seconds for TCP rate limiting
    /// Set to 0 to disable rate limiting for TCP
    #[serde(default = "default_tcp_rate_limit_window")]
    tcp_rate_limit_window: u64,

    /// Maximum number of queries allowed per client IP in the TCP window
    #[serde(default = "default_tcp_rate_limit_count")]
    tcp_rate_limit_count: u32,

    /// Maximum number of client IPs to track for TCP rate limiting
    #[serde(default = "default_tcp_rate_limit_max_clients")]
    tcp_rate_limit_max_clients: usize,

    /// Time window in seconds for DoH rate limiting
    /// Set to 0 to disable rate limiting for DoH
    #[serde(default = "default_doh_rate_limit_window")]
    doh_rate_limit_window: u64,

    /// Maximum number of queries allowed per client IP in the DoH window
    #[serde(default = "default_doh_rate_limit_count")]
    doh_rate_limit_count: u32,

    /// Maximum number of client IPs to track for DoH rate limiting
    #[serde(default = "default_doh_rate_limit_max_clients")]
    doh_rate_limit_max_clients: usize,

    /// Maximum number of concurrent connections to the HTTP metrics server
    #[serde(default = "default_max_metrics_connections")]
    max_metrics_connections: usize,

    /// Whether to enable strict IP validation
    #[serde(default)]
    enable_strict_ip_validation: bool,

    /// List of blocked IP ranges (in CIDR notation, e.g., "192.168.0.0/16")
    #[serde(default)]
    blocked_ip_ranges: Vec<String>,

    /// Block private IP address ranges
    #[serde(default = "default_block_private_ip_ranges")]
    block_private_ips: bool,

    /// Block loopback IP address ranges
    #[serde(default = "default_block_loopback_ip_ranges")]
    block_loopback_ips: bool,

    /// Minimum port to allow from clients
    #[serde(default = "default_min_client_port")]
    min_client_port: u16,

    /// Maximum number of concurrent connections to the DoH server
    #[serde(default = "default_max_doh_connections")]
    max_doh_connections: usize,

    /// Addresses to listen on for the HTTP control server (array of "ip:port" strings)
    #[serde(default = "default_control_listen_addresses")]
    control_listen_addresses: Vec<String>,

    /// Maximum number of concurrent connections to the HTTP control server
    #[serde(default = "default_max_control_connections")]
    max_control_connections: usize,

    /// Base path for the control API endpoints
    #[serde(default = "default_control_path")]
    control_path: String,

    /// Interval between DNS server probes in seconds (0 to disable)
    #[serde(default = "default_probe_interval")]
    probe_interval: u64,

    /// Size of the DNS cache in number of entries
    #[serde(default = "default_cache_size")]
    cache_size: usize,

    /// Whether this server is authoritative for DNS responses
    /// If false (default), TTLs in cached responses will be adjusted based on remaining time
    #[serde(default = "default_authoritative_dns")]
    authoritative_dns: bool,

    /// Path to a file containing allowed zones
    /// If set, only queries for domains in this file will be processed
    #[serde(default)]
    allowed_zones_file: Option<String>,

    /// Path to a file containing nonexistent zones
    /// If set, queries for domains in this file will return NXDOMAIN directly
    #[serde(default)]
    nx_zones_file: Option<String>,

    /// Grace period in seconds to serve stale (expired) cache entries when upstream servers fail
    /// Set to 0 to disable serving stale entries (default: 0)
    #[serde(default = "default_serve_stale_grace_time")]
    serve_stale_grace_time: u64,

    /// TTL in seconds to use when serving stale cache entries
    /// This is the TTL that will be set in the response (default: 30)
    #[serde(default = "default_serve_stale_ttl")]
    serve_stale_ttl: u32,

    /// TTL in seconds to use for negative DNS responses when no TTL is available
    /// This is used when extract_min_ttl() doesn't return a TTL (default: 1)
    #[serde(default = "default_negative_cache_ttl")]
    negative_cache_ttl: u32,

    /// Minimum TTL in seconds for cached DNS responses
    /// This is the minimum time a valid response will be stored in the cache (default: 1)
    #[serde(default = "default_min_cache_ttl")]
    min_cache_ttl: u32,

    /// Number of queries whose upstream failures are remembered (0 to remember none)
    #[serde(default = "default_failure_cache_size")]
    failure_cache_size: usize,

    /// Seconds before a server gets a query that it failed again, after the first failure
    #[serde(default = "default_failure_backoff_min")]
    failure_backoff_min: u64,

    /// Each new failure doubles the delay, up to this number of seconds
    #[serde(default = "default_failure_backoff_max")]
    failure_backoff_max: u64,

    /// Path to a WebAssembly file containing hook implementations
    /// If set, the hooks will be loaded from this file
    #[serde(default)]
    #[cfg(feature = "hooks")]
    hooks_wasm_file: Option<String>,

    /// This field is a placeholder when hooks feature is disabled
    #[serde(default, skip)]
    #[cfg(not(feature = "hooks"))]
    hooks_wasm_file: Option<String>,

    /// Enable WASI support for WebAssembly hooks
    /// If true, the WebAssembly module will have access to WASI system calls
    #[serde(default)]
    #[cfg(feature = "hooks")]
    hooks_wasm_wasi: bool,

    /// This field is a placeholder when hooks feature is disabled
    #[serde(default, skip)]
    #[cfg(not(feature = "hooks"))]
    hooks_wasm_wasi: bool,

    /// Path to a file to log DNS queries to
    /// If not set, query logging is disabled
    #[serde(default)]
    query_log_file: Option<String>,

    /// Whether to include timestamp in query log
    #[serde(default = "default_query_log_include_timestamp")]
    query_log_include_timestamp: bool,

    /// Whether to include client address in query log
    #[serde(default = "default_query_log_include_client_addr")]
    query_log_include_client_addr: bool,

    /// Whether to include query type in query log
    #[serde(default = "default_query_log_include_query_type")]
    query_log_include_query_type: bool,

    /// Whether to include query class in query log
    #[serde(default = "default_query_log_include_query_class")]
    query_log_include_query_class: bool,

    /// Maximum size in bytes before rotating log files (0 to disable size-based rotation)
    #[serde(default = "default_query_log_rotation_size")]
    query_log_rotation_size: usize,

    /// Time interval for log rotation ("hourly", "daily", "weekly", "monthly")
    #[serde(default = "default_query_log_rotation_interval")]
    query_log_rotation_interval: String,

    /// Number of rotated log files to keep
    #[serde(default = "default_query_log_rotation_count")]
    query_log_rotation_count: usize,

    /// Whether to compress rotated log files
    #[serde(default = "default_query_log_compression")]
    query_log_compression: bool,

    /// Username to drop privileges to after binding to sockets
    /// If not set, privileges will not be dropped
    #[serde(default)]
    user: Option<String>,

    /// Group to drop privileges to after binding to sockets
    /// If not set, the primary group of the user will be used
    #[serde(default)]
    group: Option<String>,

    /// Directory to chroot to after binding to sockets
    /// If not set, chroot will not be performed
    #[serde(default)]
    chroot: Option<String>,

    /// Enable EDNS-client-subnet support
    /// If true, client IP information will be included in upstream queries
    #[serde(default = "default_enable_ecs")]
    enable_ecs: bool,

    /// IPv4 prefix length to use for EDNS-client-subnet
    /// This controls how much of the client's IPv4 address is sent to upstream servers
    /// Recommended values: 24 (send first 24 bits, hiding the last 8 bits)
    #[serde(default = "default_ecs_prefix_v4")]
    ecs_prefix_v4: u8,

    /// IPv6 prefix length to use for EDNS-client-subnet
    /// This controls how much of the client's IPv6 address is sent to upstream servers
    /// Recommended values: 56 (send first 56 bits, hiding the last 72 bits)
    #[serde(default = "default_ecs_prefix_v6")]
    ecs_prefix_v6: u8,

    /// Enable protection against DNS spoofing attacks by falling back to TCP
    /// when receiving UDP responses with wrong transaction IDs
    /// This helps mitigate DNS cache poisoning attempts by using secure TCP transport
    /// Note: Only applies to UDP queries; TCP is inherently secure against spoofing
    #[serde(default = "default_spoof_protection")]
    spoof_protection: bool,
}

// Default values for configuration
fn default_listen_addresses() -> Vec<String> {
    vec!["0.0.0.0:10000".to_string()]
}

fn default_doh_listen_addresses() -> Vec<String> {
    Vec::new() // Empty by default, DoH is disabled
}

fn default_packet_size() -> usize {
    4096
}

fn default_max_udp_clients() -> usize {
    1000
}

fn default_max_tcp_clients() -> usize {
    1000
}

fn default_max_inflight_queries() -> usize {
    500
}

fn default_server_timeout() -> u64 {
    5 // 5 seconds default timeout
}

fn default_upstream_servers() -> Vec<String> {
    vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()]
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_max_metrics_connections() -> usize {
    5
}

fn default_max_doh_connections() -> usize {
    10 // Default to 10 concurrent DoH connections
}

fn default_control_listen_addresses() -> Vec<String> {
    Vec::new() // Empty by default, control server is disabled
}

fn default_max_control_connections() -> usize {
    5 // Default to 5 concurrent control connections
}

fn default_control_path() -> String {
    "/control".to_string() // Default control API base path
}

fn default_load_balancing_strategy() -> String {
    "fastest".to_string()
}

fn default_probe_interval() -> u64 {
    60 // 60 seconds default probe interval
}

fn default_cache_size() -> usize {
    10000 // 10,000 entries default cache size
}

fn default_authoritative_dns() -> bool {
    false // Default is false, meaning TTLs will be adjusted
}

fn default_serve_stale_grace_time() -> u64 {
    0 // 0 seconds means disabled by default
}

fn default_serve_stale_ttl() -> u32 {
    30 // 30 seconds default TTL for stale entries
}

fn default_udp_rate_limit_window() -> u64 {
    1 // 1 second window for UDP rate limiting
}

fn default_udp_rate_limit_count() -> u32 {
    100 // Allow 100 queries per second per client IP for UDP
}

fn default_tcp_rate_limit_window() -> u64 {
    5 // 5 second window for TCP rate limiting
}

fn default_tcp_rate_limit_count() -> u32 {
    20 // Allow 20 queries per 5 seconds per client IP for TCP
}

fn default_udp_rate_limit_max_clients() -> usize {
    10000 // Track up to 10,000 client IPs for UDP rate limiting
}

fn default_tcp_rate_limit_max_clients() -> usize {
    5000 // Track up to 5,000 client IPs for TCP rate limiting
}

fn default_doh_rate_limit_window() -> u64 {
    10 // 10 second window for DoH rate limiting
}

fn default_doh_rate_limit_count() -> u32 {
    30 // Allow 30 queries per 10 seconds per client IP for DoH
}

fn default_doh_rate_limit_max_clients() -> usize {
    5000 // Track up to 5,000 client IPs for DoH rate limiting
}

fn default_log_level() -> String {
    "info".to_string() // Default log level is INFO
}

fn default_negative_cache_ttl() -> u32 {
    1 // Default TTL for negative responses is 1 second
}

fn default_min_cache_ttl() -> u32 {
    1 // Default minimum TTL for cached responses is 1 second
}

fn default_failure_cache_size() -> usize {
    failure_cache::DEFAULT_FAILURE_CACHE_SIZE
}

fn default_failure_backoff_min() -> u64 {
    failure_cache::DEFAULT_FAILURE_BACKOFF_MIN
}

fn default_failure_backoff_max() -> u64 {
    failure_cache::DEFAULT_FAILURE_BACKOFF_MAX
}

fn default_query_log_include_timestamp() -> bool {
    true // Include timestamp in query log by default
}

fn default_query_log_include_client_addr() -> bool {
    true // Include client address in query log by default
}

fn default_query_log_include_query_type() -> bool {
    true // Include query type in query log by default
}

fn default_query_log_include_query_class() -> bool {
    false // Don't include query class in query log by default
}

fn default_query_log_rotation_size() -> usize {
    0 // Disable size-based rotation by default
}

fn default_query_log_rotation_interval() -> String {
    "daily".to_string() // Rotate logs daily by default
}

fn default_query_log_rotation_count() -> usize {
    7 // Keep 7 rotated log files by default
}

fn default_query_log_compression() -> bool {
    false // Don't compress rotated log files by default
}

fn default_enable_ecs() -> bool {
    false // EDNS-client-subnet is disabled by default
}

fn default_ecs_prefix_v4() -> u8 {
    24 // Send first 24 bits of IPv4 address (hide last 8 bits)
}

fn default_ecs_prefix_v6() -> u8 {
    56 // Send first 56 bits of IPv6 address (hide last 72 bits)
}

fn default_spoof_protection() -> bool {
    true // Enable spoof protection by default for security
}

fn default_block_private_ip_ranges() -> bool {
    true // Block private IP ranges by default
}

fn default_block_loopback_ip_ranges() -> bool {
    true // Block loopback IP ranges by default
}

fn default_min_client_port() -> u16 {
    1024 // Privileged ports are below 1024
}

impl Config {
    /// Load configuration from a TOML file
    fn from_file(path: &PathBuf) -> EtchDnsResult<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            EtchDnsError::ConfigReadError(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;

        let config: Config = toml::from_str(&content).map_err(|e| {
            EtchDnsError::ConfigParseError(format!(
                "Failed to parse config file {}: {}",
                path.display(),
                e
            ))
        })?;

        // Validate the configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> EtchDnsResult<()> {
        // Validate log level
        match self.log_level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => {
                return Err(EtchDnsError::Other(format!(
                    "Invalid log level: {}. Must be one of: trace, debug, info, warn, error",
                    self.log_level
                )));
            }
        }

        if !(512..=dns_parser::DNS_MAX_PACKET_SIZE).contains(&self.dns_packet_len_max) {
            return Err(EtchDnsError::Other(format!(
                "Invalid DNS packet size: {}. Must be between 512 and {} bytes",
                self.dns_packet_len_max,
                dns_parser::DNS_MAX_PACKET_SIZE,
            )));
        }

        // Check max_inflight_queries limits
        if self.max_inflight_queries < 1 {
            return Err(EtchDnsError::Other(format!(
                "Invalid max_inflight_queries: {}. Must be at least 1",
                self.max_inflight_queries
            )));
        }

        if self.max_udp_clients == 0 || self.max_tcp_clients == 0 {
            return Err(EtchDnsError::Other(
                "max_udp_clients and max_tcp_clients must be greater than 0".to_string(),
            ));
        }
        if self.cache_size == 0 {
            return Err(EtchDnsError::Other(
                "cache_size must be greater than 0".to_string(),
            ));
        }
        if !self.doh_listen_addresses.is_empty() && self.max_doh_connections == 0 {
            return Err(EtchDnsError::Other(
                "max_doh_connections must be greater than 0 when DoH is enabled".to_string(),
            ));
        }
        if self.metrics_address.is_some() && self.max_metrics_connections == 0 {
            return Err(EtchDnsError::Other(
                "max_metrics_connections must be greater than 0 when metrics are enabled"
                    .to_string(),
            ));
        }
        if !self.control_listen_addresses.is_empty() && self.max_control_connections == 0 {
            return Err(EtchDnsError::Other(
                "max_control_connections must be greater than 0 when control is enabled"
                    .to_string(),
            ));
        }

        // Check server_timeout limits
        if self.server_timeout < 1 {
            return Err(EtchDnsError::Other(format!(
                "Invalid server_timeout: {}. Must be at least 1 second",
                self.server_timeout
            )));
        }

        // Validate each listen address
        for addr_str in &self.listen_addresses {
            addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid socket address {addr_str}: {e}"))
            })?;
        }

        // Validate each DoH listen address
        for addr_str in &self.doh_listen_addresses {
            addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid DoH socket address {addr_str}: {e}"))
            })?;
        }

        // Validate each control server listen address
        for addr_str in &self.control_listen_addresses {
            addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!(
                    "Invalid control server socket address {addr_str}: {e}"
                ))
            })?;
        }

        if let Some(addr_str) = &self.metrics_address {
            addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid metrics socket address {addr_str}: {e}"))
            })?;
        }

        if self.upstream_servers.is_empty() {
            return Err(EtchDnsError::Other(
                "At least one upstream server must be configured".to_string(),
            ));
        }
        for addr_str in &self.upstream_servers {
            addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid upstream socket address {addr_str}: {e}"))
            })?;
        }

        for cidr in &self.blocked_ip_ranges {
            IpRange::from_cidr(cidr).map_err(|e| {
                EtchDnsError::Other(format!("Invalid blocked IP range {cidr}: {e}"))
            })?;
        }

        if self.group.is_some() && self.user.is_none() {
            return Err(EtchDnsError::Other(
                "User must be specified when group is set".to_string(),
            ));
        }

        if !matches!(
            self.query_log_rotation_interval.as_str(),
            "hourly" | "daily" | "weekly" | "monthly" | "never"
        ) {
            return Err(EtchDnsError::Other(format!(
                "Invalid query_log_rotation_interval: {}",
                self.query_log_rotation_interval
            )));
        }

        if self.metrics_address.is_some() && !self.metrics_path.starts_with('/') {
            return Err(EtchDnsError::Other(
                "metrics_path must start with '/' when metrics are enabled".to_string(),
            ));
        }
        if !self.control_listen_addresses.is_empty() && !self.control_path.starts_with('/') {
            return Err(EtchDnsError::Other(
                "control_path must start with '/' when control is enabled".to_string(),
            ));
        }

        self.failure_policy()?;

        // Validate the load balancing strategy
        self.load_balancing_strategy
            .parse::<load_balancer::LoadBalancingStrategy>()
            .map_err(|e| EtchDnsError::Other(format!("Invalid load balancing strategy: {e}")))?;

        // Validate rate limiting parameters
        if self.udp_rate_limit_window > 0 && self.udp_rate_limit_count == 0 {
            return Err(EtchDnsError::Other(
                "Invalid udp_rate_limit_count: must be greater than 0 when UDP rate limiting is enabled".to_string(),
            ));
        }

        if self.tcp_rate_limit_window > 0 && self.tcp_rate_limit_count == 0 {
            return Err(EtchDnsError::Other(
                "Invalid tcp_rate_limit_count: must be greater than 0 when TCP rate limiting is enabled".to_string(),
            ));
        }

        if self.udp_rate_limit_window > 0 && self.udp_rate_limit_max_clients == 0 {
            return Err(EtchDnsError::Other(
                "Invalid udp_rate_limit_max_clients: must be greater than 0 when UDP rate limiting is enabled".to_string(),
            ));
        }

        if self.tcp_rate_limit_window > 0 && self.tcp_rate_limit_max_clients == 0 {
            return Err(EtchDnsError::Other(
                "Invalid tcp_rate_limit_max_clients: must be greater than 0 when TCP rate limiting is enabled".to_string(),
            ));
        }

        // Validate EDNS-client-subnet parameters
        if self.enable_ecs {
            if self.ecs_prefix_v4 > 32 {
                return Err(EtchDnsError::Other(format!(
                    "Invalid ecs_prefix_v4: {}. Must be between 0 and 32",
                    self.ecs_prefix_v4
                )));
            }
            if self.ecs_prefix_v6 > 128 {
                return Err(EtchDnsError::Other(format!(
                    "Invalid ecs_prefix_v6: {}. Must be between 0 and 128",
                    self.ecs_prefix_v6
                )));
            }
        }

        // Validate DoH rate limiting parameters
        if self.doh_rate_limit_window > 0 && self.doh_rate_limit_count == 0 {
            return Err(EtchDnsError::Other(
                "Invalid doh_rate_limit_count: must be greater than 0 when DoH rate limiting is enabled".to_string(),
            ));
        }

        if self.doh_rate_limit_window > 0 && self.doh_rate_limit_max_clients == 0 {
            return Err(EtchDnsError::Other(
                "Invalid doh_rate_limit_max_clients: must be greater than 0 when DoH rate limiting is enabled".to_string(),
            ));
        }

        // Validate privilege dropping parameters
        if let Some(chroot_dir) = &self.chroot {
            // Check if the chroot directory exists
            if !std::path::Path::new(chroot_dir).exists() {
                return Err(EtchDnsError::Other(format!(
                    "Chroot directory '{chroot_dir}' does not exist"
                )));
            }

            // If user is not set but chroot is, that's an error
            if self.user.is_none() {
                return Err(EtchDnsError::Other(
                    "User must be specified when chroot is enabled".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// How long upstream servers are left alone after they failed a query
    fn failure_policy(&self) -> EtchDnsResult<failure_cache::FailurePolicy> {
        failure_cache::FailurePolicy::new(
            self.failure_cache_size,
            self.failure_backoff_min,
            self.failure_backoff_max,
        )
        .map_err(EtchDnsError::Other)
    }

    /// Parse the listen addresses into SocketAddr objects
    fn socket_addrs(&self) -> EtchDnsResult<Vec<SocketAddr>> {
        let mut addrs = Vec::new();

        for addr_str in &self.listen_addresses {
            let addr = addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid socket address {addr_str}: {e}"))
            })?;
            addrs.push(addr);
        }

        Ok(addrs)
    }

    /// Parse the DoH listen addresses into SocketAddr objects
    fn doh_socket_addrs(&self) -> EtchDnsResult<Vec<SocketAddr>> {
        let mut addrs = Vec::new();

        for addr_str in &self.doh_listen_addresses {
            let addr = addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid DoH socket address {addr_str}: {e}"))
            })?;
            addrs.push(addr);
        }

        Ok(addrs)
    }

    /// Parse the control server listen addresses into SocketAddr objects
    fn control_socket_addrs(&self) -> EtchDnsResult<Vec<SocketAddr>> {
        let mut addrs = Vec::new();

        for addr_str in &self.control_listen_addresses {
            let addr = addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!(
                    "Invalid control server socket address {addr_str}: {e}"
                ))
            })?;
            addrs.push(addr);
        }

        Ok(addrs)
    }
}

async fn bind_tcp_listener(
    addr: SocketAddr,
    service: &str,
) -> EtchDnsResult<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        EtchDnsError::SocketBindError(std::io::Error::new(
            e.kind(),
            format!("Failed to bind {service} listener to {addr}: {e}"),
        ))
    })
}

/// Runs a client task in the background.
/// The task is stopped if a newer client takes its place.
///
/// Returns `false` if there is no room for the client.
fn spawn_in_slot(
    slots: &ClientSlots,
    addr: SocketAddr,
    task: impl Future<Output = ()> + Send + 'static,
) -> bool {
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let Some(slot) = ConnectionSlots::register(slots, addr.ip(), cancel_tx) else {
        return false;
    };
    tokio::spawn(async move {
        let _slot = slot;
        tokio::select! {
            _ = task => {}
            _ = cancel_rx => debug!("Client {addr} was replaced by a newer client"),
        }
    });
    true
}

/// Trait for different types of clients
#[async_trait]
trait Client {
    /// Process a DNS query
    async fn process_query(&self);
}

struct UdpResponseSender {
    socket: Arc<UdpSocket>,
    #[cfg(target_os = "openbsd")]
    send_lock: Mutex<()>,
}

impl UdpResponseSender {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            #[cfg(target_os = "openbsd")]
            send_lock: Mutex::new(()),
        }
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        // OpenBSD can return EWOULDBLOCK for concurrent sends without a later writable event.
        #[cfg(target_os = "openbsd")]
        let _guard = self.send_lock.lock().await;
        self.socket.send_to(data, addr).await
    }
}

/// Structure to handle UDP clients
#[derive(Clone)]
struct UDPClient {
    sender: Arc<UdpResponseSender>,

    /// The client's address
    addr: SocketAddr,

    /// The data received from the client
    data: Vec<u8>,

    /// The maximum UDP response size for this client
    max_udp_response_size: usize,

    /// The query manager for aggregating identical DNS queries
    query_manager: Arc<QueryManager>,
}

/// Structure to handle TCP clients
#[derive(Clone)]
struct TCPClient {
    /// The client's address
    addr: SocketAddr,

    /// The data received from the client
    data: Vec<u8>,

    /// The query manager for aggregating identical DNS queries
    query_manager: Arc<QueryManager>,

    /// The TCP stream to write responses to
    stream: Arc<Mutex<TcpStream>>,
}

/// The largest UDP response that the client accepts, from the EDNS0 size of its query
fn max_udp_response_size(query: &[u8]) -> usize {
    match dns_parser::extract_edns0_max_size(query) {
        Ok(Some(size)) => usize::from(size).max(dns_parser::DNS_MAX_UDP_PACKET_SIZE),
        _ => dns_parser::DNS_MAX_UDP_PACKET_SIZE,
    }
}

impl UDPClient {
    /// Create a new UDPClient
    fn new(
        sender: Arc<UdpResponseSender>,
        data: Vec<u8>,
        addr: SocketAddr,
        query_manager: Arc<QueryManager>,
    ) -> Self {
        Self {
            sender,
            addr,
            max_udp_response_size: max_udp_response_size(&data),
            data,
            query_manager,
        }
    }
}

impl TCPClient {
    /// Create a new TCPClient
    fn new(
        data: Vec<u8>,
        addr: SocketAddr,
        query_manager: Arc<QueryManager>,
        stream: Arc<Mutex<TcpStream>>,
    ) -> Self {
        Self {
            addr,
            data,
            query_manager,
            stream,
        }
    }
}

/// Process a TCP connection
///
/// This function reads DNS queries from a TCP connection and processes them.
/// It handles the TCP-specific aspects of DNS, including the 2-byte length field.
///
/// # Arguments
///
/// * `stream` - The TCP stream to read from and write to
/// * `addr` - The client's address
/// * `query_manager` - The query manager for aggregating identical DNS queries
/// * `dns_packet_len_max` - The maximum DNS packet size
/// * `server_timeout` - The timeout for TCP connections in seconds
///
/// # Returns
///
/// This function returns when the TCP connection is closed or times out.
async fn process_tcp_connection(
    stream: TcpStream,
    addr: SocketAddr,
    query_manager: Arc<QueryManager>,
    dns_packet_len_max: usize,
    server_timeout: u64,
    rate_limiter: Option<Arc<rate_limiter::RateLimiter>>,
) {
    // Create a shared stream for the client
    let stream_arc = Arc::new(Mutex::new(stream));

    // Create a buffer for reading the length field
    let mut len_buf = [0u8; 2];

    // Set the timeout duration
    let timeout_duration = Duration::from_secs(server_timeout);

    // Main loop for processing queries on this connection
    loop {
        // Read the 2-byte length field with timeout
        // Since this is only 2 bytes, we can use read_exact() here
        // The risk of DoS is minimal for such a small read
        let read_result = tokio::time::timeout(timeout_duration, async {
            let mut stream = stream_arc.lock().await;
            stream.read_exact(&mut len_buf).await
        })
        .await;

        // Check if the operation timed out
        match read_result {
            Ok(read_exact_result) => {
                match read_exact_result {
                    Ok(_) => {
                        // Convert the length field to a u16
                        let len = ((len_buf[0] as u16) << 8) | (len_buf[1] as u16);
                        debug!("TCP client {addr} sent a query of length {len}");

                        // Check if the length is valid
                        if len as usize > dns_packet_len_max {
                            debug!(
                                "TCP client {addr} sent a query with length {len} which exceeds the maximum of {dns_packet_len_max}"
                            );
                            break;
                        }

                        // Read the query with timeout using multiple read() calls
                        // to prevent DoS attacks where a malicious client sends one byte at a time
                        let query_read_result = tokio::time::timeout(timeout_duration, async {
                            let mut stream = stream_arc.lock().await;
                            let mut query_buf = vec![0u8; len as usize];
                            let mut total_bytes_read = 0;
                            let min_read_size = 512;

                            while total_bytes_read < len as usize {
                                let bytes_remaining = len as usize - total_bytes_read;

                                // Read into the appropriate slice of the buffer
                                match stream.read(&mut query_buf[total_bytes_read..]).await {
                                    Ok(bytes_read) => {
                                        if bytes_read == 0 {
                                            // Connection closed prematurely
                                            return (Err(std::io::Error::new(
                                                std::io::ErrorKind::UnexpectedEof,
                                                format!("TCP connection closed unexpectedly after reading {total_bytes_read} of {len} bytes")
                                            )), query_buf);
                                        }

                                        // Check if we're getting small reads (potential DoS)
                                        // Only enforce minimum read size if we're not near the end
                                        if bytes_read < min_read_size && bytes_remaining > min_read_size {
                                            debug!(
                                                "Small TCP read detected from client {addr} ({bytes_read} bytes). This could be inefficient."
                                            );
                                        }

                                        total_bytes_read += bytes_read;
                                        debug!("Read {bytes_read} bytes from client {addr}, total so far: {total_bytes_read}/{len}");
                                    },
                                    Err(e) => {
                                        return (Err(e), query_buf);
                                    }
                                }
                            }

                            (Ok(()), query_buf)
                        })
                        .await;

                        match query_read_result {
                            Ok((read_result, query_buf)) => {
                                match read_result {
                                    Ok(_) => {
                                        debug!("Read {len} bytes from TCP client {addr}");

                                        if let Some(limiter) = &rate_limiter
                                            && !limiter.is_allowed(addr.ip()).await
                                        {
                                            warn!(
                                                "Rate limit exceeded for TCP client {addr}, closing connection"
                                            );
                                            break;
                                        }

                                        // Create a new TCPClient without cloning the query buffer
                                        let client = TCPClient::new(
                                            query_buf,
                                            addr,
                                            query_manager.clone(),
                                            stream_arc.clone(),
                                        );

                                        // Process the client query directly
                                        client.process_query().await;
                                        debug!("Completed processing task for TCP client {addr}");
                                    }
                                    Err(e) if net::is_peer_gone(&e) => {
                                        debug!(
                                            "TCP client {addr} went away while sending a query: {e}"
                                        );
                                        break;
                                    }
                                    Err(e) => {
                                        error!("Failed to read query from TCP client {addr}: {e}");
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                debug!(
                                    "TCP connection from {addr} timed out after {server_timeout} seconds"
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        if net::is_peer_gone(&e) {
                            debug!("TCP client {addr} closed the connection: {e}");
                        } else {
                            error!("Failed to read length from TCP client {addr}: {e}");
                        }
                        break;
                    }
                }
            }
            Err(_) => {
                debug!("TCP connection from {addr} timed out after {server_timeout} seconds");
                break;
            }
        }
    }

    debug!("TCP connection handler for client {addr} exiting");
}

// Use the DnsQueryProcessor trait from dns_processor.rs

// Implement the DnsQueryProcessor trait for both client types
impl DnsQueryProcessor for TCPClient {}
impl DnsQueryProcessor for UDPClient {}

#[async_trait]
impl Client for TCPClient {
    async fn process_query(&self) {
        // Process the DNS query
        let client_addr = self.addr.to_string();

        // Create a future for the DNS query processing
        let query_future =
            self.process_dns_query(&self.data, &client_addr, "TCP", &self.query_manager);

        // Apply a timeout of twice the server_timeout to the query future
        let server_timeout = self.query_manager.get_server_timeout();
        let timeout_duration = std::time::Duration::from_secs(server_timeout * 2);
        let response_opt = match tokio::time::timeout(timeout_duration, query_future).await {
            Ok(response) => response,
            Err(_) => {
                debug!(
                    "TCP query for client {} timed out after {} seconds",
                    self.addr,
                    server_timeout * 2
                );
                None
            }
        };

        if let Some((response_data, _)) = response_opt {
            // For TCP, we need to prepend the 2-byte length field
            let response_len = response_data.len() as u16;
            let mut tcp_response = Vec::with_capacity(response_data.len() + 2);
            tcp_response.push((response_len >> 8) as u8);
            tcp_response.push(response_len as u8);
            tcp_response.extend_from_slice(&response_data);

            // Send the response back to the client
            let mut stream = self.stream.lock().await;
            let write_timeout = Duration::from_secs(server_timeout);
            match tokio::time::timeout(write_timeout, stream.write_all(&tcp_response)).await {
                Ok(Ok(_)) => {
                    debug!(
                        "Sent {} bytes back to TCP client {}",
                        response_data.len(),
                        self.addr
                    );
                    debug!("Response successfully sent to client {}", self.addr);
                }
                Ok(Err(e)) if net::is_peer_gone(&e) => {
                    debug!(
                        "TCP client {} went away before getting its response: {e}",
                        self.addr
                    );
                }
                Ok(Err(e)) => {
                    error!("Failed to send response to TCP client {}: {}", self.addr, e);
                    debug!("Error details: {e:?}");
                }
                Err(_) => {
                    debug!("TCP client {} stopped reading its responses", self.addr);
                    // A partly sent response would garble every later one
                    let _ = stream.shutdown().await;
                }
            }
        }
    }
}

#[async_trait]
impl Client for UDPClient {
    async fn process_query(&self) {
        // Process the DNS query
        let client_addr = self.addr.to_string();

        // Create a future for the DNS query processing
        let query_future =
            self.process_dns_query(&self.data, &client_addr, "UDP", &self.query_manager);

        // Apply a timeout of twice the server_timeout to the query future
        let server_timeout = self.query_manager.get_server_timeout();
        let timeout_duration = std::time::Duration::from_secs(server_timeout * 2);
        let response_opt = match tokio::time::timeout(timeout_duration, query_future).await {
            Ok(response) => response,
            Err(_) => {
                debug!(
                    "UDP query for client {} timed out after {} seconds",
                    self.addr,
                    server_timeout * 2
                );
                None
            }
        };

        if let Some((mut response_data, _)) = response_opt {
            // Check if the response exceeds the maximum UDP response size
            if response_data.len() > self.max_udp_response_size {
                debug!(
                    "Response size ({} bytes) exceeds maximum UDP response size ({} bytes), truncating",
                    response_data.len(),
                    self.max_udp_response_size
                );

                // Truncate the response
                match dns_parser::truncate_dns_packet(
                    &response_data,
                    Some(self.max_udp_response_size),
                    false,
                ) {
                    Ok(truncated_data) => {
                        debug!(
                            "Truncated response from {} bytes to {} bytes",
                            response_data.len(),
                            truncated_data.len()
                        );
                        response_data = truncated_data;
                    }
                    Err(e) => {
                        error!("Failed to truncate response: {e}");
                        debug!("Error details: {e:?}");
                        // Continue with the original response
                    }
                }
            }

            // Send the response back to the client
            if let Err(e) = self.sender.send_to(&response_data, self.addr).await {
                error!("Failed to send response to UDP client {}: {}", self.addr, e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> EtchDnsResult<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Load configuration from file
    let config = Config::from_file(&args.config)?;

    // Initialize the logger with the configured log level
    let log_level = config.log_level.to_lowercase();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&log_level)).init();

    debug!("Command line arguments: {args:?}");
    debug!("Loaded configuration: {config:?}");

    // Log startup information at INFO level
    info!("Starting EtchDNS server");
    info!("Log level: {}", config.log_level);

    // Log listening addresses
    for addr in &config.listen_addresses {
        info!("Listening on: {addr} (UDP/TCP)");
    }

    // Log DoH addresses if configured
    if !config.doh_listen_addresses.is_empty() {
        for addr in &config.doh_listen_addresses {
            info!("Listening on: {addr} (DoH)");
        }
    } else {
        info!("DoH server is disabled");
    }

    // Log metrics server if configured
    if let Some(addr) = &config.metrics_address {
        info!(
            "Metrics server enabled on: {}, path: {}",
            addr, config.metrics_path
        );
    } else {
        info!("Metrics server is disabled");
    }

    // Log cache information
    info!("DNS cache size: {} entries", config.cache_size);
    if config.failure_cache_size > 0 {
        info!(
            "Failure cache size: {} queries, retry delays from {} to {} seconds",
            config.failure_cache_size, config.failure_backoff_min, config.failure_backoff_max
        );
    } else {
        info!("Failure cache is disabled");
    }

    // Log load balancing strategy
    info!(
        "Load balancing strategy: {}",
        config.load_balancing_strategy
    );

    // Log spoof protection status
    if config.spoof_protection {
        info!("DNS spoofing protection: ENABLED (TCP fallback on UDP transaction ID mismatch)");
    } else {
        info!("DNS spoofing protection: DISABLED");
    }

    // Log domain filtering information
    if let Some(file) = &config.allowed_zones_file {
        info!("Domain filtering enabled with allowed zones file: {file}");
    }

    // Log NX domains information
    if let Some(file) = &config.nx_zones_file {
        info!("NX domains filtering enabled with file: {file}");
    }

    // Log rate limiting information
    if config.udp_rate_limit_window > 0 {
        info!(
            "UDP rate limiting: {} queries per {} seconds",
            config.udp_rate_limit_count, config.udp_rate_limit_window
        );
    } else {
        info!("UDP rate limiting is disabled");
    }

    if config.tcp_rate_limit_window > 0 {
        info!(
            "TCP rate limiting: {} queries per {} seconds",
            config.tcp_rate_limit_count, config.tcp_rate_limit_window
        );
    } else {
        info!("TCP rate limiting is disabled");
    }

    if !config.doh_listen_addresses.is_empty() && config.doh_rate_limit_window > 0 {
        info!(
            "DoH rate limiting: {} queries per {} seconds",
            config.doh_rate_limit_count, config.doh_rate_limit_window
        );
    }

    // Get the socket addresses to bind to (Arc for sharing)
    let socket_addrs = Arc::new(config.socket_addrs()?);

    // Create vectors to store all the sockets
    let mut udp_sockets = Vec::new();
    let mut tcp_listeners = Vec::new();

    // Bind to each address
    for socket_addr in socket_addrs.iter() {
        // Bind UDP socket
        let udp_socket = UdpSocket::bind(socket_addr).await.map_err(|e| {
            EtchDnsError::SocketBindError(std::io::Error::new(
                e.kind(),
                format!("Failed to bind UDP socket to {}: {}", socket_addr, e),
            ))
        })?;
        info!(
            "Listening on UDP: {}",
            udp_socket.local_addr().map_err(|e| {
                EtchDnsError::SocketBindError(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to get local address for UDP socket bound to {}: {}",
                        socket_addr, e
                    ),
                ))
            })?
        );
        let upstream_socket_fd = udp_socket.as_raw_fd();
        let filter = bpfprog!(8,72 0 0 4,53 0 5 17,72 0 0 12,21 0 3 1,72 0 0 18,37 1 0 1,6 0 0 262144,6 0 0 0);
        bpf::attach_filter(upstream_socket_fd, filter).ok();
        udp_socket.set_tos_v4(0x10).ok();

        // Create a shareable UDP socket
        udp_sockets.push(Arc::new(udp_socket));

        // Bind TCP listener
        let tcp_listener = bind_tcp_listener(*socket_addr, "TCP").await?;
        info!(
            "Listening on TCP: {}",
            tcp_listener.local_addr().map_err(|e| {
                EtchDnsError::SocketBindError(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to get local address for TCP listener bound to {}: {}",
                        socket_addr, e
                    ),
                ))
            })?
        );

        // Create a shareable TCP listener
        tcp_listeners.push(Arc::new(tcp_listener));
    }

    // Log the buffer capacity
    debug!(
        "Using buffer capacity of {} bytes for each socket",
        config.dns_packet_len_max
    );

    debug!(
        "Using a maximum of {} UDP clients and {} TCP clients",
        config.max_udp_clients, config.max_tcp_clients
    );
    let udp_clients: ClientSlots = Arc::new(ConnectionSlots::new(config.max_udp_clients).into());
    let tcp_clients: ClientSlots = Arc::new(ConnectionSlots::new(config.max_tcp_clients).into());

    // Create global statistics tracker
    let global_stats = Arc::new(SharedStats::new());
    debug!("Created global statistics tracker");

    // Create a Hooks structure
    let mut hooks = Arc::new(hooks::SharedHooks::new());
    debug!("Created hooks structure");

    // Create an IP validator with the configured settings
    let mut validator = IpValidator::new();

    // Add all the custom blocked IP ranges
    for cidr in &config.blocked_ip_ranges {
        match IpRange::from_cidr(cidr) {
            Ok(range) => {
                validator = validator.add_blocked_range(range);
            }
            Err(e) => {
                warn!("Invalid IP range format {cidr}: {e}");
            }
        }
    }

    // Set the allowed port range
    validator = validator.allow_ports(config.min_client_port, 65535);

    // Set private IP address blocking
    if !config.block_private_ips {
        validator = validator.allow_private();
    }

    // Set loopback IP address blocking
    if !config.block_loopback_ips {
        validator = validator.allow_loopback();
    }

    let ip_validator = Arc::new(validator);

    debug!(
        "Created IP validator with {} blocked ranges",
        config.blocked_ip_ranges.len()
    );

    // Create a query logger if configured
    let query_logger = Arc::new(query_logger::QueryLogger::new(
        config.query_log_file.clone(),
        config.query_log_include_timestamp,
        config.query_log_include_client_addr,
        config.query_log_include_query_type,
        config.query_log_include_query_class,
        config.query_log_rotation_size,
        config.query_log_rotation_interval.clone(),
        config.query_log_rotation_count,
        config.query_log_compression,
    ));

    if let Some(log_file) = &config.query_log_file {
        info!("Query logging enabled to file: {log_file}");
    }

    // Load WebAssembly hooks if specified and hooks feature is enabled
    if let Some(wasm_file) = &config.hooks_wasm_file {
        info!("Loading WebAssembly hooks from file: {wasm_file}");
        #[cfg(feature = "hooks")]
        {
            info!(
                "WebAssembly WASI support is {}",
                if config.hooks_wasm_wasi {
                    "enabled"
                } else {
                    "disabled"
                }
            );
        }
        match hooks::Hooks::with_wasm_file(wasm_file, config.hooks_wasm_wasi) {
            Ok(wasm_hooks) => {
                // Replace the default hooks with the WebAssembly hooks
                hooks = Arc::new(hooks::SharedHooks::with_hooks(wasm_hooks));
                debug!("Successfully loaded WebAssembly hooks");
            }
            Err(e) => {
                error!("Failed to load WebAssembly hooks: {e}");
                // Continue with default hooks
            }
        }
    }

    // Create a DNS cache with the configured capacity
    let cache_capacity = config.cache_size;
    let dns_cache = Arc::new(cache::create_dns_cache(cache_capacity));
    debug!("Created DNS cache with capacity of {cache_capacity} entries");

    // Create rate limiters for UDP and TCP if enabled
    let udp_rate_limiter = if config.udp_rate_limit_window > 0 {
        let limiter = Arc::new(rate_limiter::RateLimiter::new(
            config.udp_rate_limit_window,
            config.udp_rate_limit_count,
            config.udp_rate_limit_max_clients,
        ));
        debug!(
            "Created UDP rate limiter with window of {} seconds, limit of {} queries per client IP, and max of {} client IPs",
            config.udp_rate_limit_window,
            config.udp_rate_limit_count,
            config.udp_rate_limit_max_clients
        );
        Some(limiter)
    } else {
        debug!("UDP rate limiting is disabled");
        None
    };

    let tcp_rate_limiter = if config.tcp_rate_limit_window > 0 {
        let limiter = Arc::new(rate_limiter::RateLimiter::new(
            config.tcp_rate_limit_window,
            config.tcp_rate_limit_count,
            config.tcp_rate_limit_max_clients,
        ));
        debug!(
            "Created TCP rate limiter with window of {} seconds, limit of {} queries per client IP, and max of {} client IPs",
            config.tcp_rate_limit_window,
            config.tcp_rate_limit_count,
            config.tcp_rate_limit_max_clients
        );
        Some(limiter)
    } else {
        debug!("TCP rate limiting is disabled");
        None
    };

    // Create a rate limiter for DoH if enabled
    let doh_rate_limiter = if config.doh_rate_limit_window > 0 {
        let limiter = Arc::new(rate_limiter::RateLimiter::new(
            config.doh_rate_limit_window,
            config.doh_rate_limit_count,
            config.doh_rate_limit_max_clients,
        ));
        debug!(
            "Created DoH rate limiter with window of {} seconds, limit of {} queries per client IP, and max of {} client IPs",
            config.doh_rate_limit_window,
            config.doh_rate_limit_count,
            config.doh_rate_limit_max_clients
        );
        Some(limiter)
    } else {
        debug!("DoH rate limiting is disabled");
        None
    };

    // Create a query manager for aggregating identical DNS queries
    let max_inflight_queries = config.max_inflight_queries;
    let server_timeout = config.server_timeout;
    let dns_packet_len_max = config.dns_packet_len_max;

    // Parse the load balancing strategy
    let load_balancing_strategy = config
        .load_balancing_strategy
        .parse::<load_balancer::LoadBalancingStrategy>()
        .unwrap_or_else(|_| {
            warn!(
                "Invalid load balancing strategy: {}, using fastest",
                config.load_balancing_strategy
            );
            load_balancer::LoadBalancingStrategy::Fastest
        });

    let mut query_manager = QueryManager::new(
        max_inflight_queries,
        server_timeout,
        dns_packet_len_max,
        global_stats.clone(),
        load_balancing_strategy,
        config.authoritative_dns,
        config.serve_stale_grace_time,
        config.serve_stale_ttl,
        config.negative_cache_ttl,
        config.min_cache_ttl,
        config.enable_ecs,
        config.ecs_prefix_v4,
        config.ecs_prefix_v6,
        config.spoof_protection,
    );

    query_manager.set_failure_policy(config.failure_policy()?);

    let upstream_servers = config
        .upstream_servers
        .iter()
        .map(|addr| addr.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| EtchDnsError::Other(format!("Invalid upstream socket address: {e}")))?;
    query_manager.set_upstream_servers(upstream_servers);

    // Set the DNS cache in the query manager
    query_manager.set_cache((*dns_cache).clone());

    // Set the hooks in the query manager
    query_manager.set_hooks(hooks.clone());

    // Set the query logger in the query manager
    query_manager.set_query_logger(query_logger.clone());

    // Load allowed zones if configured
    if let Some(allowed_zones_file) = &config.allowed_zones_file {
        match allowed_zones::AllowedZones::load_from_file(allowed_zones_file) {
            Ok(zones) => {
                let zone_count = zones.len();
                query_manager.set_allowed_zones(zones);
                info!("Loaded {zone_count} allowed zones from {allowed_zones_file}");
            }
            Err(e) => {
                error!("Failed to load allowed zones from {allowed_zones_file}: {e}");
                return Err(EtchDnsError::ConfigParseError(format!(
                    "Failed to load allowed zones file: {e}"
                )));
            }
        }
    }

    // Load nonexistent zones if configured
    if let Some(nx_zones_file) = &config.nx_zones_file {
        match nx_zones::NxZones::load_from_file(nx_zones_file) {
            Ok(zones) => {
                let zone_count = zones.len();
                query_manager.set_nx_zones(zones);
                info!("Loaded {zone_count} nonexistent zones from {nx_zones_file}");
            }
            Err(e) => {
                error!("Failed to load nonexistent zones from {nx_zones_file}: {e}");
                return Err(EtchDnsError::ConfigParseError(format!(
                    "Failed to load nonexistent zones file: {e}"
                )));
            }
        }
    }

    let query_manager = Arc::new(query_manager);
    debug!(
        "Created query manager with a maximum of {max_inflight_queries} in-flight queries, {server_timeout} second timeout, {dns_packet_len_max} byte packet size, and '{load_balancing_strategy}' load balancing strategy"
    );

    // These may use privileged ports, so they must be bound before dropping privileges
    let metrics_listener = match &config.metrics_address {
        Some(metrics_addr) => {
            let metrics_addr = metrics_addr.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid metrics address {metrics_addr}: {e}"))
            })?;
            Some(bind_tcp_listener(metrics_addr, "metrics").await?)
        }
        None => None,
    };
    let mut doh_listeners = Vec::new();
    for doh_addr in config.doh_socket_addrs()? {
        doh_listeners.push(bind_tcp_listener(doh_addr, "DoH").await?);
    }
    let mut control_listeners = Vec::new();
    for control_addr in config.control_socket_addrs()? {
        control_listeners.push(bind_tcp_listener(control_addr, "control").await?);
    }

    // Drop privileges if configured
    if let Some(username) = &config.user {
        info!("Dropping privileges to user: {username}");

        // Create a new privdrop instance
        let pd = privdrop::PrivDrop::default();

        // Build the privilege drop configuration
        let mut pd = pd.user(username);

        // Set the group if specified
        if let Some(group) = &config.group {
            info!("Using group: {group}");
            pd = pd.group(group);
        }

        // Set chroot if specified
        if let Some(chroot_dir) = &config.chroot {
            info!("Using chroot directory: {chroot_dir}");
            pd = pd.chroot(chroot_dir);
        }

        // Apply the privilege drop
        match pd.apply() {
            Ok(_) => {
                info!("Successfully dropped privileges");
            }
            Err(e) => {
                let error_msg = format!("Failed to drop privileges: {e}");
                error!("{error_msg}");
                return Err(EtchDnsError::PrivilegeDropError(error_msg));
            }
        }
    } else {
        warn!(
            "Running with full privileges. Consider setting 'user' in config.toml for better security."
        );
    }

    // Create a vector of tasks
    let mut tasks = Vec::new();

    // Start the server prober if probe_interval is greater than 0
    if config.probe_interval > 0 {
        info!(
            "Starting server prober with interval of {} seconds and timeout of {} seconds",
            config.probe_interval, config.server_timeout
        );

        // Clone the values we need for the prober
        let upstream_servers = query_manager.get_upstream_servers();
        let stats = global_stats.clone();
        let probe_interval = config.probe_interval;
        let server_timeout = config.server_timeout;

        // Create a task for the server prober
        let prober_task = tokio::spawn(async move {
            // Create a ticker that fires at the specified interval
            let mut interval = tokio::time::interval(Duration::from_secs(probe_interval));

            loop {
                // Wait for the next tick
                interval.tick().await;

                // Probe all servers
                debug!("Probing all upstream DNS servers");

                for &addr in upstream_servers.iter() {
                    // Probe the server
                    match probe_server(addr, server_timeout).await {
                        Ok(response_time) => {
                            debug!("Probe to {addr} completed in {response_time:.2?}");

                            // Record the success in stats
                            stats.record_success(addr, response_time).await;
                        }
                        Err(e) => {
                            warn!("Probe to {addr} failed: {e}");

                            // Record the failure in stats
                            stats.record_failure(addr).await;
                        }
                    }
                }
            }
        });

        // Add the prober task to the list of tasks
        tasks.push(prober_task);
    }

    // Start the HTTP metrics server if configured
    if let Some(metrics_listener) = metrics_listener {
        // Clone the values we need for the metrics server
        let metrics_path = config.metrics_path.clone();
        let stats = global_stats.clone();
        let max_metrics_connections = config.max_metrics_connections;
        let metrics_query_manager = query_manager.clone();
        let metrics_udp_clients = udp_clients.clone();
        let metrics_tcp_clients = tcp_clients.clone();
        let metrics_dns_cache = dns_cache.clone();

        // Create a task for the metrics server
        let metrics_task = tokio::spawn(async move {
            if let Err(e) = metrics::start_metrics_server(
                metrics_listener,
                metrics_path,
                stats,
                max_metrics_connections,
                Some(metrics_query_manager),
                Some(metrics_udp_clients),
                Some(metrics_tcp_clients),
                Some(metrics_dns_cache),
            )
            .await
            {
                error!("Metrics server error: {e}");
            }
        });

        // Add the metrics task to the list of tasks
        tasks.push(metrics_task);
    }

    // Start the DoH servers if configured
    for doh_listener in doh_listeners {
        // Clone the values we need for the DoH server
        let query_manager = query_manager.clone();
        let server_timeout = config.server_timeout;
        let dns_packet_len_max = config.dns_packet_len_max;
        let max_connections = config.max_doh_connections;
        let doh_rate_limiter = doh_rate_limiter.clone();

        // Clone the IP validator for this task
        let doh_ip_validator = ip_validator.clone();

        // Create a task for the DoH server
        let doh_task = tokio::spawn(async move {
            if let Err(e) = doh::start_doh_server(
                doh_listener,
                query_manager,
                server_timeout,
                dns_packet_len_max,
                max_connections,
                doh_rate_limiter,
                Some(doh_ip_validator),
                config.enable_strict_ip_validation,
            )
            .await
            {
                error!("DoH server error: {e}");
            }
        });

        // Add the DoH task to the list of tasks
        tasks.push(doh_task);
    }

    // Start the control servers if configured
    for control_listener in control_listeners {
        // Clone the values we need for the control server
        let control_path = config.control_path.clone();
        let max_connections = config.max_control_connections;
        let dns_cache = Some(dns_cache.clone());
        let failure_cache = query_manager.get_failure_cache();
        let stats = Some(global_stats.clone());

        // Create a task for the control server
        let control_task = tokio::spawn(async move {
            if let Err(e) = control::start_control_server(
                control_listener,
                control_path,
                max_connections,
                dns_cache,
                failure_cache,
                stats,
            )
            .await
            {
                error!("Control server error: {e}");
            }
        });

        // Add the control task to the list of tasks
        tasks.push(control_task);
    }

    // Clone the configuration values we need for the tasks
    let dns_packet_len_max = config.dns_packet_len_max;

    // Create a task for each UDP socket
    for (i, socket) in udp_sockets.iter().enumerate() {
        let socket = socket.clone();
        let response_sender = Arc::new(UdpResponseSender::new(socket.clone()));
        let all_socket_addrs = socket_addrs.clone();
        let socket_addr = (*all_socket_addrs)[i];
        let udp_clients = udp_clients.clone();
        let query_manager = query_manager.clone();
        let udp_rate_limiter = udp_rate_limiter.clone();
        // Clone the ip validator for this task
        let task_ip_validator = ip_validator.clone();
        let stats = global_stats.clone();

        // Create a task for this UDP socket
        let task = tokio::spawn(async move {
            // Create a buffer for this task
            let mut buf = vec![0u8; dns_packet_len_max];

            // Main receive loop for this socket
            loop {
                // Log that we're waiting for a packet
                debug!("Waiting for incoming UDP packets on {socket_addr}...");

                // Wait for a packet
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        debug!("Received packet of size {len} bytes from UDP client {addr}");

                        // Apply IP validation to the client address based on configuration
                        if config.enable_strict_ip_validation {
                            // Use the full IP validator with all restrictions
                            match task_ip_validator.validate_ip(addr.ip()) {
                                Ok(_) => {
                                    // Check port as a separate step for better logging
                                    if let Err(e) = task_ip_validator.validate_port(addr.port()) {
                                        warn!("Disallowing query from UDP client {addr}: {e}");
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    warn!("Disallowing query from UDP client {addr}: {e}");
                                    continue;
                                }
                            }
                        } else {
                            // Even with strict validation disabled, still perform basic validation

                            // Validate client source port is >= 1024
                            if addr.port() < 1024 {
                                warn!(
                                    "Disallowing query from UDP client {addr} with reserved port {}, dropping query",
                                    addr.port()
                                );
                                continue;
                            }
                        }

                        // Check rate limit for UDP client if enabled
                        if let Some(rate_limiter) = &udp_rate_limiter {
                            // Extract the client IP address
                            let client_ip = addr.ip();

                            // Check if the client is allowed to make a query
                            if !rate_limiter.is_allowed(client_ip).await {
                                warn!("Rate limit exceeded for UDP client {addr}, dropping query");
                                continue;
                            }
                        }

                        // Clone the data for the task
                        let data = buf[..len].to_vec();
                        debug!("Cloned packet data for processing");

                        let response_sender = response_sender.clone();
                        debug!("Spawning new task to handle UDP client {addr}");

                        // Create a new UDPClient
                        let client =
                            UDPClient::new(response_sender, data, addr, query_manager.clone());

                        let task = async move {
                            debug!("Started processing task for UDP client {addr}");
                            client.process_query().await;
                            debug!("Completed processing task for UDP client {addr}");
                        };
                        if !spawn_in_slot(&udp_clients, addr, task) {
                            warn!("Maximum UDP client count reached, dropping query from {addr}");
                        }
                    }
                    Err(e) => {
                        error!("Failed to receive packet on UDP {socket_addr}: {e}");

                        // Add a small delay before trying again to prevent spinning the CPU
                        // if there's a persistent error condition
                        tokio::time::sleep(Duration::from_millis(10)).await;

                        // Increment error counter for monitoring
                        stats.increment_udp_receive_errors().await;
                    }
                }
            }
        });

        tasks.push(task);
    }

    // Clone the socket addresses vector to use in the TCP tasks
    let tcp_socket_addrs = socket_addrs.clone();

    // Create a task for each TCP listener
    for (i, listener) in tcp_listeners.iter().enumerate() {
        let listener = listener.clone();
        let all_socket_addrs = tcp_socket_addrs.clone();
        let socket_addr = (*all_socket_addrs)[i];
        let tcp_clients = tcp_clients.clone();
        let query_manager = query_manager.clone();
        let tcp_rate_limiter = tcp_rate_limiter.clone();

        // Clone the ip validator for this task
        let task_ip_validator = ip_validator.clone();
        let stats = global_stats.clone();

        // Create a task for this TCP listener
        let task = tokio::spawn(async move {
            // Main accept loop for this listener
            loop {
                // Log that we're waiting for a connection
                debug!("Waiting for incoming TCP connections on {socket_addr}...");

                // Wait for a connection
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("Accepted TCP connection from {addr}");

                        // Apply IP validation to the client address based on configuration
                        if config.enable_strict_ip_validation {
                            // Use the full IP validator with all restrictions
                            match task_ip_validator.validate_ip(addr.ip()) {
                                Ok(_) => {
                                    // Check port as a separate step for better logging
                                    if let Err(e) = task_ip_validator.validate_port(addr.port()) {
                                        warn!("Disallowing connection from TCP client {addr}: {e}");
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    warn!("Disallowing connection from TCP client {addr}: {e}");
                                    continue;
                                }
                            }
                        } else {
                            // Even with strict validation disabled, still perform basic validation

                            // Validate client source port is >= 1024
                            if addr.port() < 1024 {
                                warn!(
                                    "Disallowing connection from TCP client {addr} with reserved port {}, dropping connection",
                                    addr.port()
                                );
                                continue;
                            }
                        }

                        // Clone the necessary values for the task
                        let query_manager = query_manager.clone();
                        let tcp_rate_limiter = tcp_rate_limiter.clone();

                        let task = async move {
                            debug!("Started TCP connection handler for client {addr}");
                            process_tcp_connection(
                                stream,
                                addr,
                                query_manager,
                                dns_packet_len_max,
                                server_timeout,
                                tcp_rate_limiter,
                            )
                            .await;
                            debug!("Completed TCP connection handler for client {addr}");
                        };
                        if !spawn_in_slot(&tcp_clients, addr, task) {
                            warn!(
                                "Maximum TCP client count reached, dropping connection from {addr}"
                            );
                        }
                    }
                    Err(e) => {
                        net::handle_accept_error(&e, "DNS TCP").await;
                        stats.increment_tcp_accept_errors().await;
                    }
                }
            }
        });

        tasks.push(task);
    }

    if tasks.is_empty() {
        return Err(EtchDnsError::Other(
            "No server or probe tasks were configured".to_string(),
        ));
    }

    let (result, _, _) = futures::future::select_all(tasks).await;
    match result {
        Ok(()) => Err(EtchDnsError::Other(
            "A server task exited unexpectedly".to_string(),
        )),
        Err(e) => {
            error!("Task error: {e}");
            Err(EtchDnsError::Other(format!("Task error: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[cfg(target_os = "openbsd")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_udp_responses_keep_sending() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sender = Arc::new(UdpResponseSender::new(socket));
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let drain = tokio::spawn(async move {
            let mut packet = [0; 4096];
            loop {
                receiver.recv_from(&mut packet).await.unwrap();
            }
        });

        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut sends = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let sender = sender.clone();
            let barrier = barrier.clone();
            sends.spawn(async move {
                barrier.wait().await;
                for _ in 0..10_000 {
                    assert_eq!(sender.send_to(&[0; 4096], destination).await.unwrap(), 4096);
                }
            });
        }

        let result = tokio::time::timeout(Duration::from_secs(60), async {
            while let Some(result) = sends.join_next().await {
                result.unwrap();
            }
        })
        .await;
        sends.abort_all();
        drain.abort();
        let _ = drain.await;
        result.expect("concurrent UDP replies stopped making progress");
    }

    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    // Test function to check port validation
    #[test]
    fn test_udp_port_validation() {
        // Valid port (>= 1024)
        let valid_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2053);
        // Invalid port (< 1024)
        let invalid_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53);

        // Client with valid port should pass validation
        assert!(valid_addr.port() >= 1024);
        // Client with invalid port should fail validation
        assert!(invalid_addr.port() < 1024);
    }

    #[test]
    fn test_example_configuration_is_valid() {
        let config: Config = toml::from_str(include_str!("../etchdns.toml")).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_failure_policy_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(
            config.failure_policy().unwrap(),
            failure_cache::FailurePolicy::default()
        );

        let config: Config = toml::from_str("failure_cache_size = 0").unwrap();
        assert_eq!(config.failure_policy().unwrap().cache_size, 0);
    }

    #[test]
    fn test_invalid_configuration_is_rejected() {
        assert!(toml::from_str::<Config>("unknown_setting = true").is_err());

        let mut config: Config = toml::from_str("").unwrap();
        config.max_udp_clients = 0;
        assert!(config.validate().is_err());

        let mut config: Config = toml::from_str("").unwrap();
        config.upstream_servers = vec!["not an address".to_string()];
        assert!(config.validate().is_err());

        let mut config: Config = toml::from_str("").unwrap();
        config.blocked_ip_ranges = vec!["not a network".to_string()];
        assert!(config.validate().is_err());

        let mut config: Config = toml::from_str("").unwrap();
        config.failure_backoff_min = 31;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_configured_packet_limit_cannot_exceed_parser_limit() {
        let mut config: Config = toml::from_str("").unwrap();
        config.dns_packet_len_max = dns_parser::DNS_MAX_PACKET_SIZE;
        assert!(config.validate().is_ok());

        config.dns_packet_len_max += 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_small_edns_udp_size_is_treated_as_512() {
        let mut packet = query();
        dns_parser::add_edns_section(&mut packet, 1).unwrap();

        assert_eq!(max_udp_response_size(&packet), 512);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_tcp_client_that_never_reads_is_disconnected() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            // Answer every query with 200 A records, about 3 KB
            let mut packet = vec![0u8; 4096];
            while let Ok((_, client)) = upstream.recv_from(&mut packet).await {
                let mut response = packet[..query().len()].to_vec();
                dns_parser::set_flags(&mut response, 0x8180).unwrap();
                dns_parser::set_ancount(&mut response, 200).unwrap();
                dns_parser::set_arcount(&mut response, 0).unwrap();
                for i in 0..200u8 {
                    response.extend_from_slice(&[
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, i,
                    ]);
                }
                upstream.send_to(&response, client).await.unwrap();
            }
        });

        let listener_socket = tokio::net::TcpSocket::new_v4().unwrap();
        listener_socket.set_send_buffer_size(4096).unwrap();
        listener_socket
            .bind("127.0.0.1:0".parse().unwrap())
            .unwrap();
        let listener = listener_socket.listen(1).unwrap();
        let client_socket = tokio::net::TcpSocket::new_v4().unwrap();
        client_socket.set_recv_buffer_size(4096).unwrap();
        let mut client = client_socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server_stream, peer) = listener.accept().await.unwrap();
        let mut query_manager = QueryManager::for_tests(1, 4096, true);
        query_manager.set_upstream_servers(vec![upstream_addr]);

        let handler = tokio::spawn(process_tcp_connection(
            server_stream,
            peer,
            Arc::new(query_manager),
            4096,
            1,
            None,
        ));

        // Ask for far more data than the socket buffers can hold, and never read it
        let mut pipelined = Vec::new();
        for _ in 0..500 {
            pipelined.extend_from_slice(&(query().len() as u16).to_be_bytes());
            pipelined.extend_from_slice(&query());
        }
        client.write_all(&pipelined).await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_secs(20), handler)
                .await
                .is_ok()
        );
    }
}
