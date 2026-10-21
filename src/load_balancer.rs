use crate::stats::{GlobalStats, SharedStats};
use log::debug;
use rand::{RngExt, rng};
use std::net::SocketAddr;
use std::str::FromStr;

/// Load balancing strategy for selecting upstream DNS servers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalancingStrategy {
    /// Select a random server
    Random,
    /// Select the fastest server based on response time statistics
    #[default]
    Fastest,
    /// Power of two choices: select the faster of two randomly chosen servers
    PowerOfTwo,
}

impl FromStr for LoadBalancingStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "random" => Ok(LoadBalancingStrategy::Random),
            "fastest" => Ok(LoadBalancingStrategy::Fastest),
            "p2" | "power-of-two" | "poweroftwo" => Ok(LoadBalancingStrategy::PowerOfTwo),
            _ => Err(format!(
                "Invalid load balancing strategy: {s}. Valid options are: random, fastest, p2"
            )),
        }
    }
}

impl std::fmt::Display for LoadBalancingStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadBalancingStrategy::Random => write!(f, "random"),
            LoadBalancingStrategy::Fastest => write!(f, "fastest"),
            LoadBalancingStrategy::PowerOfTwo => write!(f, "p2"),
        }
    }
}

/// Selects an upstream server among the candidates.
///
/// The stats stay locked from the choice to the trial reservation, so that two queries can't both take the trial of a parked server.
pub async fn select_upstream_server(
    candidates: &[SocketAddr],
    strategy: LoadBalancingStrategy,
    stats: Option<&SharedStats>,
) -> Option<SocketAddr> {
    match stats {
        Some(stats) => choose_upstream_server(candidates, strategy, Some(&mut *stats.lock().await)),
        None => choose_upstream_server(candidates, strategy, None),
    }
}

/// Picks an upstream server among the candidates, and records that a query is going to it.
///
/// Parked servers are only picked when every candidate is parked.
pub fn choose_upstream_server(
    candidates: &[SocketAddr],
    strategy: LoadBalancingStrategy,
    stats: Option<&mut GlobalStats>,
) -> Option<SocketAddr> {
    let unparked: Vec<SocketAddr> = candidates
        .iter()
        .filter(|addr| !stats.as_ref().is_some_and(|stats| stats.is_parked(addr)))
        .copied()
        .collect();
    let candidates = if unparked.is_empty() {
        candidates
    } else {
        &unparked
    };
    let server = pick_upstream_server(candidates, strategy, stats.as_deref())?;
    if let Some(stats) = stats {
        stats.record_query_sent(server);
    }
    Some(server)
}

fn pick_upstream_server(
    upstream_servers: &[SocketAddr],
    strategy: LoadBalancingStrategy,
    stats: Option<&GlobalStats>,
) -> Option<SocketAddr> {
    if upstream_servers.is_empty() {
        return None;
    }

    // If there's only one server, return it
    if upstream_servers.len() == 1 {
        return Some(upstream_servers[0]);
    }

    match strategy {
        LoadBalancingStrategy::Random => {
            // Use a simple random index
            let index = rng().random_range(0..upstream_servers.len());
            Some(upstream_servers[index])
        }
        LoadBalancingStrategy::Fastest => {
            // If we don't have stats, fall back to random
            let Some(stats) = stats else {
                debug!("No stats available for fastest strategy, falling back to random");
                let index = rng().random_range(0..upstream_servers.len());
                return Some(upstream_servers[index]);
            };

            // If we don't have any stats for the candidates yet, fall back to random
            let Some(&(addr, _)) = stats.get_resolvers_by_speed(upstream_servers).first() else {
                debug!("No resolver stats available yet, falling back to random");
                let index = rng().random_range(0..upstream_servers.len());
                return Some(upstream_servers[index]);
            };
            debug!("Selected fastest server: {addr}");
            Some(addr)
        }
        LoadBalancingStrategy::PowerOfTwo => {
            // If we don't have stats, fall back to random
            let Some(stats) = stats else {
                debug!("No stats available for p2 strategy, falling back to random");
                let index = rng().random_range(0..upstream_servers.len());
                return Some(upstream_servers[index]);
            };

            // Only the candidates count, so that a faster server in backoff doesn't make them look slow
            let resolvers_by_speed = stats.get_resolvers_by_speed(upstream_servers);

            // If we don't have any stats for the candidates yet, fall back to random
            if resolvers_by_speed.is_empty() {
                debug!("No resolver stats available yet, falling back to random");
                let index = rng().random_range(0..upstream_servers.len());
                return Some(upstream_servers[index]);
            }

            // Get the fastest server's response time
            let fastest_time = resolvers_by_speed[0].1;

            // Calculate the threshold (50% slower than the fastest)
            let threshold = fastest_time * 1.5;

            // Create a list of eligible servers (not more than 50% slower than the fastest)
            let mut eligible_servers: Vec<SocketAddr> = Vec::new();

            for &server in upstream_servers {
                // Find this server in the resolvers_by_speed list
                if let Some((_, response_time)) =
                    resolvers_by_speed.iter().find(|(a, _)| *a == server)
                {
                    // Check if this server is within the threshold
                    if *response_time <= threshold {
                        eligible_servers.push(server);
                        debug!(
                            "Server {server} with response time {response_time}ms is eligible (threshold: {threshold}ms)"
                        );
                    } else {
                        debug!(
                            "Server {server} with response time {response_time}ms is too slow (threshold: {threshold}ms)"
                        );
                    }
                } else if stats.get_resolver_stats(&server).is_none() {
                    eligible_servers.push(server);
                    debug!("Server {server} has no stats, including it as eligible");
                } else {
                    debug!("Server {server} has no successful probes, excluding it");
                }
            }

            // If we have no eligible servers, fall back to random selection from all servers
            if eligible_servers.is_empty() {
                debug!("No eligible servers found, falling back to random selection");
                let index = rng().random_range(0..upstream_servers.len());
                return Some(upstream_servers[index]);
            }

            // If we have only one eligible server, return it
            if eligible_servers.len() == 1 {
                debug!("Only one eligible server found: {}", eligible_servers[0]);
                return Some(eligible_servers[0]);
            }

            // We have at least two eligible servers, choose two randomly and pick the faster one
            let mut rng = rng();

            // To ensure we get a good distribution, we'll use a different approach
            // Shuffle the eligible servers using Fisher-Yates algorithm and take the first two
            let mut indices: Vec<usize> = (0..eligible_servers.len()).collect();

            // Fisher-Yates shuffle: for each position i, swap with a random position j >= i
            for i in 0..indices.len() {
                let j = rng.random_range(i..indices.len());
                indices.swap(i, j);
            }

            let server1 = eligible_servers[indices[0]];
            let server2 = eligible_servers[indices[1]];

            debug!("P2 randomly selected servers: {server1} and {server2}");

            // Get the stats for both servers
            let stats1 = stats.get_resolver_stats(&server1);
            let stats2 = stats.get_resolver_stats(&server2);

            // Compare the response times
            match (stats1, stats2) {
                (Some(s1), Some(s2)) => {
                    // Compare response times
                    if s1.avg_response_time_ms <= s2.avg_response_time_ms {
                        debug!(
                            "P2 selected server: {} ({}ms)",
                            server1, s1.avg_response_time_ms
                        );
                        Some(server1)
                    } else {
                        debug!(
                            "P2 selected server: {} ({}ms)",
                            server2, s2.avg_response_time_ms
                        );
                        Some(server2)
                    }
                }
                (Some(_), None) => {
                    debug!("P2 selected server: {server1} (no stats for {server2})");
                    Some(server1)
                }
                (None, Some(_)) => {
                    debug!("P2 selected server: {server2} (no stats for {server1})");
                    Some(server2)
                }
                (None, None) => {
                    // If we don't have stats for either server, choose randomly
                    debug!("No stats for either server, choosing randomly");
                    let index = rng.random_range(0..2);
                    if index == 0 {
                        Some(server1)
                    } else {
                        Some(server2)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{PARK_AFTER_FAILURES, SharedStats};
    use std::time::Duration;

    fn addrs(servers: &[&str]) -> Vec<SocketAddr> {
        servers.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[tokio::test]
    async fn test_random_strategy() {
        let upstream_servers = addrs(&["127.0.0.1:53", "127.0.0.2:53", "127.0.0.3:53"]);

        let server =
            select_upstream_server(&upstream_servers, LoadBalancingStrategy::Random, None).await;

        assert!(server.is_some());
        assert!(upstream_servers.contains(&server.unwrap()));
    }

    #[tokio::test]
    async fn test_fastest_strategy() {
        let upstream_servers = addrs(&["127.0.0.1:53", "127.0.0.2:53", "127.0.0.3:53"]);

        // Create stats with 127.0.0.2:53 as the fastest
        let stats = SharedStats::new();

        // Add some stats
        let addr1 = upstream_servers[0];
        let addr2 = upstream_servers[1];
        let addr3 = upstream_servers[2];

        stats.record_success(addr1, Duration::from_millis(50)).await;
        stats.record_success(addr2, Duration::from_millis(10)).await; // Fastest
        stats.record_success(addr3, Duration::from_millis(30)).await;

        let server = select_upstream_server(
            &upstream_servers,
            LoadBalancingStrategy::Fastest,
            Some(&stats),
        )
        .await;

        assert_eq!(server, Some(addr2));
    }

    #[tokio::test]
    async fn test_failed_only_resolver_is_not_fastest() {
        let upstream_servers = addrs(&["127.0.0.1:53", "127.0.0.2:53"]);
        let stats = SharedStats::new();
        let failed = upstream_servers[0];
        let healthy = upstream_servers[1];
        stats.record_failure(failed).await;
        stats
            .record_success(healthy, Duration::from_millis(10))
            .await;

        let fastest = select_upstream_server(
            &upstream_servers,
            LoadBalancingStrategy::Fastest,
            Some(&stats),
        )
        .await;
        let p2 = select_upstream_server(
            &upstream_servers,
            LoadBalancingStrategy::PowerOfTwo,
            Some(&stats),
        )
        .await;

        assert_eq!(fastest, Some(healthy));
        assert_eq!(p2, Some(healthy));
    }

    #[tokio::test]
    async fn test_p2_strategy() {
        // Enable debug logging for this test
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        // For this test, we'll directly test the filtering logic
        // by creating a list of servers with specific response times

        let upstream_servers = addrs(&[
            "127.0.0.1:53", // Slow (50ms)
            "127.0.0.2:53", // Fastest (10ms)
            "127.0.0.3:53", // Too slow (30ms)
            "127.0.0.4:53", // Eligible (14ms)
        ]);

        // Create stats
        let stats = SharedStats::new();

        // Add some stats
        let addr1 = upstream_servers[0];
        let addr2 = upstream_servers[1];
        let addr3 = upstream_servers[2];
        let addr4 = upstream_servers[3];

        // Server 2 is the fastest (10ms)
        // Server 3 is 3x slower (30ms) - should be excluded (>50% slower)
        // Server 1 is 5x slower (50ms) - should be excluded (>50% slower)
        // Server 4 is 1.4x slower (14ms) - should be included (<50% slower)
        for _ in 0..10 {
            stats.record_success(addr1, Duration::from_millis(50)).await;
            stats.record_success(addr2, Duration::from_millis(10)).await; // Fastest
            stats.record_success(addr3, Duration::from_millis(30)).await;
            stats.record_success(addr4, Duration::from_millis(14)).await; // Within 50% threshold
        }

        // Print the resolvers by speed to debug
        let resolvers_by_speed = stats.lock().await.get_resolvers_by_speed(&upstream_servers);
        println!("Resolvers by speed:");
        for (addr, time) in &resolvers_by_speed {
            println!("  {} -> {}ms", addr, time);
        }

        // Calculate the threshold
        let fastest_time = resolvers_by_speed[0].1;
        let threshold = fastest_time * 1.5;
        println!(
            "Fastest time: {}ms, Threshold: {}ms",
            fastest_time, threshold
        );

        // Verify that our implementation correctly identifies eligible servers
        // by directly checking the eligible_servers list

        // Create a mock implementation that exposes the eligible_servers list
        struct MockLoadBalancer;

        impl MockLoadBalancer {
            async fn get_eligible_servers(
                upstream_servers: &[SocketAddr],
                stats: &SharedStats,
            ) -> Vec<SocketAddr> {
                let resolvers_by_speed =
                    stats.lock().await.get_resolvers_by_speed(upstream_servers);

                if resolvers_by_speed.is_empty() {
                    return Vec::new();
                }

                let fastest_time = resolvers_by_speed[0].1;
                let threshold = fastest_time * 1.5;

                let mut eligible_servers: Vec<SocketAddr> = Vec::new();

                for &server in upstream_servers {
                    if let Some((_, response_time)) =
                        resolvers_by_speed.iter().find(|(a, _)| *a == server)
                    {
                        if *response_time <= threshold {
                            eligible_servers.push(server);
                        }
                    } else {
                        eligible_servers.push(server);
                    }
                }

                eligible_servers
            }
        }

        // Get the list of eligible servers
        let eligible_servers =
            MockLoadBalancer::get_eligible_servers(&upstream_servers, &stats).await;

        // Print the eligible servers
        println!("Eligible servers:");
        for server in &eligible_servers {
            println!("  {}", server);
        }

        // Verify that only servers 2 and 4 are eligible
        assert_eq!(eligible_servers.len(), 2);
        assert!(eligible_servers.contains(&addr2));
        assert!(eligible_servers.contains(&addr4));

        // Now run the actual power-of-two-choices strategy multiple times
        // and verify that both eligible servers are selected at least once
        let iterations = 1000; // Increase iterations for more reliable results
        let mut selected_servers = std::collections::HashMap::new();

        for _ in 0..iterations {
            let server = select_upstream_server(
                &upstream_servers,
                LoadBalancingStrategy::PowerOfTwo,
                Some(&stats),
            )
            .await;

            assert!(server.is_some());
            let selected = server.unwrap();

            // Only servers 2 and 4 should be selected (within 50% threshold)
            assert!(selected == addr2 || selected == addr4);

            *selected_servers.entry(selected).or_insert(0) += 1;
        }

        // Print the selection counts
        println!("Server selection counts:");
        for (server, count) in &selected_servers {
            println!("  {} selected {} times", server, count);
        }

        // Verify that the fastest server is selected
        assert!(selected_servers.contains_key(&addr2));
    }

    #[tokio::test]
    async fn test_p2_strategy_one_eligible() {
        let upstream_servers = addrs(&["127.0.0.1:53", "127.0.0.2:53", "127.0.0.3:53"]);

        // Create stats with 127.0.0.2:53 as the fastest
        let stats = SharedStats::new();

        // Add some stats
        let addr1 = upstream_servers[0];
        let addr2 = upstream_servers[1];
        let addr3 = upstream_servers[2];

        // Server 2 is the fastest (10ms)
        // Server 1 is 6x slower (60ms) - should be excluded (>50% slower)
        // Server 3 is 8x slower (80ms) - should be excluded (>50% slower)
        stats.record_success(addr1, Duration::from_millis(60)).await;
        stats.record_success(addr2, Duration::from_millis(10)).await; // Fastest
        stats.record_success(addr3, Duration::from_millis(80)).await;

        // Run the test multiple times
        for _ in 0..10 {
            let server = select_upstream_server(
                &upstream_servers,
                LoadBalancingStrategy::PowerOfTwo,
                Some(&stats),
            )
            .await;

            // Only the fastest server should be selected since it's the only eligible one
            assert_eq!(server, Some(addr2));
        }
    }

    #[tokio::test]
    async fn test_parked_servers_are_avoided_by_every_strategy() {
        let servers = addrs(&["192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"]);
        let (parked, healthy, excluded) = (servers[0], servers[1], servers[2]);
        // The third server is not a candidate, for instance because of a recent failure
        let candidates = [parked, healthy];
        for strategy in [
            LoadBalancingStrategy::Random,
            LoadBalancingStrategy::Fastest,
            LoadBalancingStrategy::PowerOfTwo,
        ] {
            let stats = SharedStats::new();
            stats.record_success(parked, Duration::from_millis(1)).await;
            stats
                .record_success(healthy, Duration::from_millis(50))
                .await;
            stats
                .record_success(excluded, Duration::from_millis(1))
                .await;
            for _ in 0..PARK_AFTER_FAILURES {
                stats.record_timeout(parked).await;
            }
            for _ in 0..20 {
                let server = select_upstream_server(&candidates, strategy, Some(&stats)).await;
                assert_eq!(server, Some(healthy), "{strategy}");
            }

            // When every candidate is parked, one of them still gets the query
            for _ in 0..PARK_AFTER_FAILURES {
                stats.record_timeout(healthy).await;
            }
            for _ in 0..20 {
                let server = select_upstream_server(&candidates, strategy, Some(&stats)).await;
                assert!(candidates.contains(&server.unwrap()), "{strategy}");
            }
        }
    }

    #[tokio::test]
    async fn test_p2_threshold_only_compares_candidates() {
        let servers = addrs(&["192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"]);
        let (excluded, healthy, failing) = (servers[0], servers[1], servers[2]);
        let stats = SharedStats::new();
        stats
            .record_success(excluded, Duration::from_millis(1))
            .await;
        stats
            .record_success(healthy, Duration::from_millis(10))
            .await;
        stats.record_failure(failing).await;

        // The fastest server is not a candidate, for instance because of a recent failure
        let candidates = [healthy, failing];
        for _ in 0..50 {
            let server = select_upstream_server(
                &candidates,
                LoadBalancingStrategy::PowerOfTwo,
                Some(&stats),
            )
            .await;
            assert_eq!(server, Some(healthy));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_trial_is_reserved_when_the_server_is_picked() {
        let servers = addrs(&["192.0.2.1:53", "192.0.2.2:53"]);
        let (recovering, healthy) = (servers[0], servers[1]);
        let stats = SharedStats::new();
        stats
            .record_success(recovering, Duration::from_millis(1))
            .await;
        stats
            .record_success(healthy, Duration::from_millis(50))
            .await;
        for _ in 0..PARK_AFTER_FAILURES {
            stats.record_timeout(recovering).await;
        }

        // Once the parking time is over, only the first query is a trial
        tokio::time::advance(Duration::from_secs(60)).await;
        let strategy = LoadBalancingStrategy::Fastest;
        let first = select_upstream_server(&servers, strategy, Some(&stats)).await;
        let second = select_upstream_server(&servers, strategy, Some(&stats)).await;

        assert_eq!((first, second), (Some(recovering), Some(healthy)));
    }

    #[tokio::test]
    async fn test_from_str() {
        assert_eq!(
            LoadBalancingStrategy::from_str("random").unwrap(),
            LoadBalancingStrategy::Random
        );
        assert_eq!(
            LoadBalancingStrategy::from_str("fastest").unwrap(),
            LoadBalancingStrategy::Fastest
        );
        assert_eq!(
            LoadBalancingStrategy::from_str("p2").unwrap(),
            LoadBalancingStrategy::PowerOfTwo
        );
        assert_eq!(
            LoadBalancingStrategy::from_str("power-of-two").unwrap(),
            LoadBalancingStrategy::PowerOfTwo
        );
        assert_eq!(
            LoadBalancingStrategy::from_str("poweroftwo").unwrap(),
            LoadBalancingStrategy::PowerOfTwo
        );

        assert!(LoadBalancingStrategy::from_str("invalid").is_err());
    }

    #[test]
    fn test_default() {
        assert_eq!(
            LoadBalancingStrategy::default(),
            LoadBalancingStrategy::Fastest
        );
    }
}
