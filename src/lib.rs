#![allow(clippy::too_many_arguments)]

// Export modules that need to be accessible from fuzzing tests
pub mod allowed_zones;
pub mod cache;
pub mod connection_slots;
pub mod control;
pub mod dns_key;
pub mod dns_parser;
pub mod dns_processor;
pub mod doh;
pub mod errors;
pub mod failure_cache;
pub mod hooks;
pub mod ip_validator;
pub mod load_balancer;
pub mod metrics;
pub mod net;
pub mod nx_zones;
pub mod probe;
pub mod query_logger;
pub mod query_manager;
pub mod rate_limiter;
pub mod resolver;
pub mod stats;

// Re-export error types for convenience
pub use errors::{DnsError, EtchDnsError, EtchDnsResult};
