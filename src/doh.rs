use crate::dns_processor::DnsQueryProcessor;
use crate::ip_validator::IpValidator;
use crate::query_manager::{FailureFreshness, QueryManager};
use crate::rate_limiter::RateLimiter;
use libdoh::{CachePolicy, CacheScope, DnsResponse, DoH, DoHError, Globals, Query, Resolver};
use log::{debug, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Answers the queries that libdoh receives over HTTP.
struct DoHHandler {
    query_manager: Arc<QueryManager>,
    rate_limiter: Option<Arc<RateLimiter>>,
    /// Only set when strict IP validation is enabled.
    ip_validator: Option<Arc<IpValidator>>,
}

impl DnsQueryProcessor for DoHHandler {}

impl Resolver for DoHHandler {
    fn allow_connection(&self, client_addr: SocketAddr) -> bool {
        let Some(validator) = &self.ip_validator else {
            return true;
        };
        match validator
            .validate_ip(client_addr.ip())
            .and_then(|_| validator.validate_port(client_addr.port()))
        {
            Ok(_) => true,
            Err(e) => {
                warn!("Disallowing DoH client {client_addr}: {e}");
                false
            }
        }
    }

    async fn resolve(&self, query: Query) -> Result<DnsResponse, DoHError> {
        let client_addr = query.remote_addr;
        if let Some(limiter) = &self.rate_limiter
            && !limiter.is_allowed(client_addr.ip()).await
        {
            warn!("Rate limit exceeded for DoH client {client_addr}");
            return Err(DoHError::TooManyRequests);
        }
        // process_dns_query() already logs errors
        let (packet, failure_freshness) = self
            .process_dns_query(
                &query.packet,
                &client_addr.to_string(),
                "DoH",
                &self.query_manager,
            )
            .await
            .ok_or(DoHError::UpstreamIssue)?;
        let cache = cache_policy(&packet, failure_freshness);
        Ok(DnsResponse { packet, cache })
    }
}

/// Keeps HTTP caches from holding a response longer than its DNS records allow,
/// as RFC 8484 requires.
fn cache_policy(dns_data: &[u8], failure_freshness: Option<FailureFreshness>) -> CachePolicy {
    let (scope, max_age) =
        if crate::dns_parser::rcode(dns_data) == crate::dns_processor::DNS_RCODE_SERVFAIL {
            failure_cache_ttl(dns_data, failure_freshness)
        } else {
            let cache_ttl = crate::dns_parser::extract_cache_ttl(dns_data)
                .ok()
                .flatten()
                .unwrap_or(0);
            (CacheScope::Public, cache_ttl)
        };
    debug!("DoH response with cache TTL: {max_age} seconds");
    CachePolicy {
        max_age,
        scope,
        ..CachePolicy::default()
    }
}

/// How long HTTP caches may keep a SERVFAIL.
///
/// If the upstream servers are failing, it can be kept until we try them again,
/// or less if its records expire sooner.
/// Otherwise, it must not be reused.
fn failure_cache_ttl(
    dns_data: &[u8],
    failure_freshness: Option<FailureFreshness>,
) -> (CacheScope, u32) {
    let Some(failure_freshness) = failure_freshness else {
        return (CacheScope::Private, 0);
    };
    let remaining = failure_freshness
        .retry_at
        .saturating_duration_since(tokio::time::Instant::now())
        .as_secs();
    let mut cache_ttl = u32::try_from(remaining).unwrap_or(u32::MAX);
    if let Ok(Some(record_ttl)) = crate::dns_parser::extract_cache_ttl(dns_data) {
        cache_ttl = cache_ttl.min(record_ttl);
    }
    let scope = if failure_freshness.shared {
        CacheScope::Public
    } else {
        CacheScope::Private
    };
    (scope, cache_ttl)
}

/// Gives DoH requests the same time limit as TCP queries.
///
/// Idle connections are closed after that delay too.
fn request_timeout(server_timeout: u64) -> Duration {
    Duration::from_secs(
        server_timeout
            .saturating_mul(2)
            .clamp(libdoh::MIN_TIMEOUT_SECS, libdoh::MAX_TIMEOUT_SECS),
    )
}

/// Start the DNS-over-HTTPS (DoH) server
pub async fn start_doh_server(
    listener: TcpListener,
    query_manager: Arc<QueryManager>,
    max_connections: usize,
    rate_limiter: Option<Arc<RateLimiter>>,
    ip_validator: Option<Arc<IpValidator>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listener.local_addr()?;
    // Answer on any path, and don't require an Accept header for GET queries.
    // CORS stays off, so that web pages can't query a DoH server on the local network.
    // The JSON API isn't part of RFC 8484.
    let globals = Globals {
        path: None,
        max_clients: max_connections,
        timeout: request_timeout(query_manager.get_server_timeout()),
        max_query_len: query_manager.get_dns_packet_len_max(),
        require_accept: false,
        enable_json: false,
        cors: false,
        ..Globals::default()
    };
    let handler = DoHHandler {
        query_manager,
        rate_limiter,
        ip_validator,
    };
    info!("DoH server listening on {addr}");
    DoH::new(globals, handler).serve(listener).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose};
    use libdoh::DoHType;
    use libdoh::reexports::hyper::HeaderMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn servfail(response: &[u8]) -> Vec<u8> {
        let mut response = response.to_vec();
        crate::dns_parser::set_rcode(&mut response, crate::dns_processor::DNS_RCODE_SERVFAIL)
            .unwrap();
        response
    }

    fn cache_control(response: &[u8], failure_freshness: Option<FailureFreshness>) -> String {
        cache_policy(response, failure_freshness).to_string()
    }

    #[test]
    fn test_http_cache_follows_the_dns_ttls() {
        assert_eq!(
            cache_control(crate::dns_parser::EXAMPLE_COM_ANSWER, None),
            "public, max-age=60"
        );

        // A negative response is cached for the SOA minimum
        assert_eq!(
            cache_control(
                crate::dns_parser::NEGATIVE_RESPONSE_WITH_SOA_TTL_3600_MINIMUM_60,
                None
            ),
            "public, max-age=60"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_servfail_is_fresh_until_a_retry() {
        let retry_in = |seconds, shared| {
            Some(FailureFreshness {
                retry_at: tokio::time::Instant::now() + Duration::from_secs(seconds),
                shared,
            })
        };
        let response = servfail(crate::dns_parser::EXAMPLE_COM_QUERY);
        assert_eq!(cache_control(&response, None), "private, max-age=0");

        // Later requests don't start the delay again
        let freshness = retry_in(30, true);
        assert_eq!(cache_control(&response, freshness), "public, max-age=30");
        tokio::time::advance(Duration::from_millis(10500)).await;
        assert_eq!(cache_control(&response, freshness), "public, max-age=19");
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(cache_control(&response, freshness), "public, max-age=0");

        // Records can only make it shorter.
        // A failure that depends on the client's address is private.
        let response = servfail(crate::dns_parser::NEGATIVE_RESPONSE_WITH_SOA_TTL_3600_MINIMUM_60);
        assert_eq!(
            cache_control(&response, retry_in(300, true)),
            "public, max-age=60"
        );
        assert_eq!(
            cache_control(&response, retry_in(30, false)),
            "private, max-age=30"
        );
    }

    /// An upstream server that answers every query with `rcode`.
    async fn upstream(rcode: u8) -> SocketAddr {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            while let Ok((length, client)) = udp.recv_from(&mut packet).await {
                let mut response = packet[..length].to_vec();
                crate::dns_parser::set_rcode(&mut response, rcode).unwrap();
                crate::dns_parser::set_qr(&mut response, true).unwrap();
                udp.send_to(&response, client).await.unwrap();
            }
        });
        upstream
    }

    #[tokio::test]
    async fn test_servfail_is_a_dns_message() {
        let mut query_manager = QueryManager::for_tests(2, 4096, true);
        query_manager
            .set_failure_policy(crate::failure_cache::FailurePolicy::new(10, 10, 30).unwrap());
        query_manager.set_upstream_servers(vec![
            upstream(crate::dns_processor::DNS_RCODE_SERVFAIL).await,
        ]);
        let handler = DoHHandler {
            query_manager: Arc::new(query_manager),
            rate_limiter: None,
            ip_validator: None,
        };
        // Most DoH clients use ID 0, so that HTTP caches can share responses
        let mut query = crate::dns_parser::EXAMPLE_COM_QUERY.to_vec();
        crate::dns_parser::set_tid(&mut query, 0).unwrap();

        // First the upstream SERVFAIL, then ours while we wait to retry
        for _ in 0..2 {
            let response = handler
                .resolve(Query {
                    packet: query.clone(),
                    kind: DoHType::Standard,
                    remote_addr: "192.0.2.1:443".parse().unwrap(),
                    headers: HeaderMap::new(),
                })
                .await
                .unwrap();
            assert_eq!(response.cache.to_string(), "public, max-age=9");
            assert_eq!(
                crate::dns_parser::rcode(&response.packet),
                crate::dns_processor::DNS_RCODE_SERVFAIL
            );
        }
    }

    /// Sends a request on a new connection, and returns the status, the
    /// lowercased head and the body of the response.
    async fn http(addr: SocketAddr, request: &[u8]) -> (u16, String, Vec<u8>) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = vec![];
        stream.read_to_end(&mut response).await.unwrap();
        let head_len = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("no response")
            + 4;
        let head = String::from_utf8(response[..head_len].to_vec())
            .unwrap()
            .to_ascii_lowercase();
        let status = head[9..12].parse().unwrap();
        (status, head, response[head_len..].to_vec())
    }

    async fn start(
        query_manager: QueryManager,
        rate_limiter: Option<RateLimiter>,
        ip_validator: Option<IpValidator>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(start_doh_server(
            listener,
            Arc::new(query_manager),
            10,
            rate_limiter.map(Arc::new),
            ip_validator.map(Arc::new),
        ));
        addr
    }

    #[tokio::test]
    async fn test_queries_over_http() {
        let mut query_manager = QueryManager::for_tests(2, 4096, true);
        query_manager.set_upstream_servers(vec![
            upstream(crate::dns_processor::DNS_RCODE_NXDOMAIN).await,
        ]);
        let addr = start(query_manager, Some(RateLimiter::new(60, 3, 10)), None).await;
        let query = crate::dns_parser::EXAMPLE_COM_QUERY;
        let dns = general_purpose::URL_SAFE_NO_PAD.encode(query);
        let get = format!(
            "GET /dns-query?dns={dns} HTTP/1.1\r\nHost: localhost\r\n\
             Accept: application/dns-message\r\nConnection: close\r\n\r\n"
        );
        let bare_get =
            format!("GET /?dns={dns} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let post = |headers: &str| {
            let mut post = format!(
                "POST /dns-query HTTP/1.1\r\nHost: localhost\r\n{headers}\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                query.len()
            )
            .into_bytes();
            post.extend(query);
            post
        };
        let typed_post = post("Content-Type: application/dns-message\r\n");

        // Rejected requests don't count against the limit of 3 queries.
        // Unlike a GET without Accept, a POST without Content-Type is rejected.
        let no_query = b"GET /dns-query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        assert_eq!(http(addr, no_query).await.0, 400);
        assert_eq!(http(addr, &post("")).await.0, 415);

        for request in [get.as_bytes(), &typed_post, bare_get.as_bytes()] {
            let (status, head, body) = http(addr, request).await;
            assert_eq!(status, 200, "{head}");
            assert!(head.contains("content-type: application/dns-message\r\n"));
            assert!(head.contains("cache-control: public, max-age=0\r\n"));
            assert!(!head.contains("access-control-allow-origin"));
            assert_eq!(&body[..2], &query[..2]);
            assert_eq!(
                crate::dns_parser::rcode(&body),
                crate::dns_processor::DNS_RCODE_NXDOMAIN
            );
        }
        assert_eq!(http(addr, get.as_bytes()).await.0, 429);
    }

    #[tokio::test]
    async fn test_disallowed_clients_are_disconnected() {
        // Loopback addresses are blocked by default
        let query_manager = QueryManager::for_tests(1, 4096, true);
        let addr = start(query_manager, None, Some(IpValidator::new())).await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut received = vec![];
        let closed = tokio::time::timeout(
            Duration::from_millis(500),
            stream.read_to_end(&mut received),
        )
        .await;
        assert!(matches!(closed, Ok(Ok(0))), "{closed:?}");
    }
}
