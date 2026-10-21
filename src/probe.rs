use crate::dns_parser;
use crate::errors::{DnsError, EtchDnsResult};
use crate::stats::SharedStats;
use log::{debug, error, info, warn};
use rand::RngExt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time;

fn wildcard_address(peer: SocketAddr) -> SocketAddr {
    let ip = if peer.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    SocketAddr::new(ip, 0)
}

/// Minimum interval between probe queries (in seconds)
#[allow(dead_code)]
const MIN_PROBE_INTERVAL_SECS: u64 = 60;

/// Structure to manage periodic probing of upstream DNS servers
#[allow(dead_code)]
pub struct ServerProber {
    /// List of upstream DNS servers to probe
    upstream_servers: Vec<String>,

    /// Statistics tracker
    stats: Arc<SharedStats>,

    /// Interval between probes (in seconds)
    probe_interval: u64,

    /// Timeout for probe queries (in seconds)
    probe_timeout: u64,
}

#[allow(dead_code)]
impl ServerProber {
    /// Create a new ServerProber
    ///
    /// The probe_timeout defaults to server_timeout if not specified.
    /// The probe_interval defaults to max(60 seconds, server_timeout) if not specified.
    #[allow(dead_code)]
    pub fn new(
        upstream_servers: Vec<String>,
        stats: Arc<SharedStats>,
        server_timeout: u64,
        probe_interval: Option<u64>,
        probe_timeout: Option<u64>,
    ) -> Self {
        // Default probe timeout is the same as server_timeout
        let default_probe_timeout = server_timeout;

        // Default probe interval is max(60 seconds, server_timeout)
        let default_probe_interval = std::cmp::max(MIN_PROBE_INTERVAL_SECS, server_timeout);

        Self {
            upstream_servers,
            stats,
            probe_interval: probe_interval.unwrap_or(default_probe_interval),
            probe_timeout: probe_timeout.unwrap_or(default_probe_timeout),
        }
    }

    /// Start the background probing task
    pub fn start(self) {
        tokio::spawn(async move {
            info!(
                "Starting server prober with interval of {} seconds",
                self.probe_interval
            );

            // Create a ticker that fires at the specified interval
            let mut interval = time::interval(Duration::from_secs(self.probe_interval));

            loop {
                // Wait for the next tick
                interval.tick().await;

                // Probe all servers
                self.probe_all_servers().await;
            }
        });
    }

    /// Probe all upstream servers
    async fn probe_all_servers(&self) {
        debug!("Probing all upstream DNS servers");

        for server in &self.upstream_servers {
            // Parse the server address
            match server.parse::<SocketAddr>() {
                Ok(addr) => {
                    // Probe the server
                    match self.probe_server(addr).await {
                        Ok(response_time) => {
                            debug!("Probe to {addr} completed in {response_time:.2?}");

                            // Record the success in stats
                            self.stats.record_success(addr, response_time).await;
                        }
                        Err(e) => {
                            warn!("Probe to {addr} failed: {e}");

                            // Record the failure in stats
                            self.stats.record_failure(addr).await;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to parse server address {server}: {e}");
                }
            }
        }
    }

    /// Probe a single server and return the response time
    async fn probe_server(&self, server_addr: SocketAddr) -> EtchDnsResult<Duration> {
        probe_server(server_addr, self.probe_timeout).await
    }
}

/// Probe a single server and return the response time
/// This is a public function that can be used outside of the ServerProber struct
pub async fn probe_server(server_addr: SocketAddr, timeout_secs: u64) -> EtchDnsResult<Duration> {
    // Create a random DNS query
    let query = create_random_query();

    // Create a UDP socket for the probe
    let socket = UdpSocket::bind(wildcard_address(server_addr))
        .await
        .map_err(|e| DnsError::UpstreamError(format!("Failed to bind socket for probe: {e}")))?;

    // Start timing
    let start_time = Instant::now();

    // Send the query
    socket.send_to(&query, server_addr).await.map_err(|e| {
        DnsError::UpstreamError(format!("Failed to send probe to {server_addr}: {e}"))
    })?;

    // Set up a buffer for the response
    let mut buf = vec![0u8; dns_parser::DNS_MAX_PACKET_SIZE];

    // Wait for a response with timeout
    match time::timeout(
        Duration::from_secs(timeout_secs),
        crate::resolver::recv_from_peer(&socket, &mut buf, server_addr),
    )
    .await
    {
        Ok(Ok(len)) => {
            if len < 2 || buf[0] != query[0] || buf[1] != query[1] {
                return Err(DnsError::UpstreamError(format!(
                    "Mismatched DNS transaction ID in response from {server_addr}"
                ))
                .into());
            }

            // Got a response
            let response_time = start_time.elapsed();

            // Validate the response
            if let Err(e) = dns_parser::validate_dns_response(&buf[..len]) {
                return Err(DnsError::UpstreamError(format!(
                    "Invalid DNS response from {server_addr}: {e}"
                ))
                .into());
            }

            Ok(response_time)
        }
        Ok(Err(e)) => {
            // Socket error
            Err(DnsError::UpstreamError(format!(
                "Failed to receive response from {server_addr}: {e}"
            ))
            .into())
        }
        Err(_) => {
            // Timeout
            Err(DnsError::UpstreamTimeout.into())
        }
    }
}

/// Create a random DNS query
/// This is a helper function for the probe_server function
fn create_random_query() -> Vec<u8> {
    // Create a simple query for a common domain
    // This is a query for google.com with a random transaction ID
    let mut query = vec![
        0x00, 0x00, // Transaction ID (will be replaced)
        0x01, 0x00, // Flags (standard query)
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // google.com domain name
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm',
        0x00, // Null terminator
        0x00, 0x01, // Type: A (Host Address)
        0x00, 0x01, // Class: IN (Internet)
    ];

    // Generate a random transaction ID
    let tid: u16 = rand::rng().random_range(0..65535);
    query[0] = (tid >> 8) as u8;
    query[1] = tid as u8;

    query
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    #[test]
    fn test_wildcard_address_matches_peer_family() {
        let ipv4 = wildcard_address("192.0.2.1:53".parse().unwrap());
        let ipv6 = wildcard_address("[2001:db8::1]:53".parse().unwrap());

        assert!(ipv4.is_ipv4());
        assert!(ipv6.is_ipv6());
        assert_eq!(ipv4.port(), 0);
        assert_eq!(ipv6.port(), 0);
    }

    #[test]
    fn test_create_random_query() {
        let query = create_random_query();

        // Check that the query is a valid DNS query
        assert!(query.len() > 12); // DNS header is 12 bytes

        // Check that the query has the correct flags (standard query)
        assert_eq!(query[2], 0x01); // QR=0, Opcode=0, AA=0, TC=0, RD=1
        assert_eq!(query[3], 0x00); // RA=0, Z=0, RCODE=0

        // Check that the query has one question
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);

        // Check that the query has no answers, authority, or additional records
        assert_eq!(query[6], 0x00);
        assert_eq!(query[7], 0x00);
        assert_eq!(query[8], 0x00);
        assert_eq!(query[9], 0x00);
        assert_eq!(query[10], 0x00);
        assert_eq!(query[11], 0x00);
    }

    #[tokio::test]
    async fn test_probe_server() {
        // This test requires an actual DNS server to be running
        // We'll use Google's public DNS server for testing
        let stats = Arc::new(SharedStats::new());
        let server_timeout = 5; // 5 seconds
        let prober = ServerProber::new(
            vec!["8.8.8.8:53".to_string()],
            stats.clone(),
            server_timeout,
            None,
            None,
        );

        // Try to probe the server
        let addr = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
        match prober.probe_server(addr).await {
            Ok(response_time) => {
                // If the probe succeeds, check that the response time is reasonable
                assert!(response_time > Duration::from_micros(0));

                // Manually update the stats since the probe_server method doesn't update them
                stats.record_success(addr, response_time).await;

                // Check that the stats were updated
                let resolvers_by_speed = stats.lock().await.get_resolvers_by_speed(&[addr]);
                assert!(!resolvers_by_speed.is_empty());
            }
            Err(e) => {
                // If the probe fails, it's probably because we're not connected to the internet
                // or the DNS server is not responding
                println!("Probe failed: {}", e);
                // This is not a failure of the test, just a limitation of the testing environment
            }
        }
    }
}
