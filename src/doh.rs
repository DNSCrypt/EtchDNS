use crate::dns_processor::DnsQueryProcessor;
use crate::query_manager::{FailureFreshness, QueryManager};
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{Method, Request, Response, StatusCode, header, server::conn::http1};
use hyper_util::rt::{TokioIo, TokioTimer};
use log::{debug, error, info, warn};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Handle DNS-over-HTTPS (DoH) requests
///
/// This function handles both GET and POST requests according to RFC 8484.
/// - GET requests should have a 'dns' query parameter with a base64url encoded DNS message
/// - POST requests should have a Content-Type of 'application/dns-message' and the body contains the DNS message
async fn handle_doh_request(
    req: Request<hyper::body::Incoming>,
    query_manager: Arc<QueryManager>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    client_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Check the request method
    match *req.method() {
        // Handle GET requests
        Method::GET => {
            handle_doh_get_request(req, query_manager, dns_packet_len_max, client_addr).await
        }

        // Handle POST requests
        Method::POST => {
            handle_doh_post_request(
                req,
                query_manager,
                server_timeout,
                dns_packet_len_max,
                client_addr,
            )
            .await
        }

        // Handle other methods
        _ => {
            // Method not allowed
            Ok(create_error_response(
                "Method Not Allowed",
                StatusCode::METHOD_NOT_ALLOWED,
            ))
        }
    }
}

/// Handle a DoH GET request
async fn handle_doh_get_request(
    req: Request<hyper::body::Incoming>,
    query_manager: Arc<QueryManager>,
    dns_packet_len_max: usize,
    client_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Extract the 'dns' query parameter
    let uri = req.uri();
    let query = uri.query().unwrap_or("");

    // Parse the query parameters
    let params: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();

    // Find the 'dns' parameter
    let dns_param = params.iter().find(|(name, _)| name == "dns");

    match dns_param {
        Some((_, value)) => {
            // Decode the base64url encoded DNS message
            match general_purpose::URL_SAFE_NO_PAD.decode(value) {
                Ok(dns_message) => {
                    if dns_message.len() > dns_packet_len_max {
                        return Ok(create_error_response(
                            "Payload Too Large: DNS message exceeds configured maximum size",
                            StatusCode::PAYLOAD_TOO_LARGE,
                        ));
                    }
                    // Process the DNS message
                    process_dns_message(dns_message, query_manager, &client_addr).await
                }
                Err(e) => {
                    error!("Failed to decode base64url DNS message: {e}");
                    Ok(create_error_response(
                        "Bad Request: Invalid DNS message encoding",
                        StatusCode::BAD_REQUEST,
                    ))
                }
            }
        }
        None => {
            // Missing 'dns' parameter
            Ok(create_error_response(
                "Bad Request: Missing 'dns' parameter",
                StatusCode::BAD_REQUEST,
            ))
        }
    }
}

/// Handle a DoH POST request
async fn handle_doh_post_request(
    req: Request<hyper::body::Incoming>,
    query_manager: Arc<QueryManager>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    client_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Check the Content-Type header
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if content_type == "application/dns-message" {
        // Limit the size and the time, so that a slow client can't hold its connection forever
        let body = Limited::new(req.into_body(), dns_packet_len_max).collect();
        match tokio::time::timeout(std::time::Duration::from_secs(server_timeout), body).await {
            Err(_) => Ok(create_error_response(
                "Request Timeout: DNS message was not received in time",
                StatusCode::REQUEST_TIMEOUT,
            )),
            Ok(Ok(bytes)) => {
                // Process the DNS message
                process_dns_message(bytes.to_bytes().to_vec(), query_manager, &client_addr).await
            }
            Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
                Ok(create_error_response(
                    "Payload Too Large: DNS message exceeds configured maximum size",
                    StatusCode::PAYLOAD_TOO_LARGE,
                ))
            }
            Ok(Err(e)) => {
                if e.downcast_ref::<hyper::Error>()
                    .is_some_and(is_client_error)
                {
                    debug!("DoH client {client_addr} went away while sending its query: {e}");
                } else {
                    error!("Failed to read request body: {e}");
                }
                Ok(create_error_response(
                    "Bad Request: Failed to read request body",
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
    } else {
        // Invalid Content-Type
        Ok(create_error_response(
            "Bad Request: Content-Type must be application/dns-message",
            StatusCode::BAD_REQUEST,
        ))
    }
}

/// Create an HTTP error response with the specified message and status code
fn create_error_response(message: &str, status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(message.to_string())));
    *response.status_mut() = status;
    response
}

/// Handler for DoH requests
struct DoHHandler;

impl DnsQueryProcessor for DoHHandler {}

/// Process a DNS message received via DoH
async fn process_dns_message(
    dns_message: Vec<u8>,
    query_manager: Arc<QueryManager>,
    client_addr: &SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Create a DoH handler
    let handler = DoHHandler;

    // Process the DNS query using the DnsQueryProcessor trait
    let client_addr_str = client_addr.to_string();
    let result = handler
        .process_dns_query(&dns_message, &client_addr_str, "DoH", &query_manager)
        .await;

    match result {
        Some((response_data, failure_freshness)) => {
            // Create and return a successful response
            Ok(create_dns_response(&response_data, failure_freshness))
        }
        None => {
            // Error already logged in process_dns_query
            Ok(create_error_response(
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// Create a successful HTTP response with DNS message and headers
fn create_dns_response(
    response_data: &[u8],
    failure_freshness: Option<FailureFreshness>,
) -> Response<Full<Bytes>> {
    // Create a response with the DNS message
    let mut http_response = Response::new(Full::new(Bytes::from(response_data.to_vec())));
    http_response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/dns-message"),
    );

    add_cache_headers(&mut http_response, response_data, failure_freshness);

    http_response
}

/// Keeps the HTTP cache within the DNS TTL limits required by RFC 8484.
///
/// A SERVFAIL has its own limit, see `failure_cache_ttl()`.
fn add_cache_headers(
    response: &mut Response<Full<Bytes>>,
    dns_data: &[u8],
    failure_freshness: Option<FailureFreshness>,
) {
    let (scope, cache_ttl) =
        if crate::dns_parser::rcode(dns_data) == crate::dns_processor::DNS_RCODE_SERVFAIL {
            failure_cache_ttl(dns_data, failure_freshness)
        } else {
            let cache_ttl = crate::dns_parser::extract_cache_ttl(dns_data)
                .ok()
                .flatten()
                .unwrap_or(0);
            ("public", cache_ttl)
        };

    let cache_control = format!("{scope}, max-age={cache_ttl}");
    if let Ok(value) = header::HeaderValue::from_str(&cache_control) {
        response.headers_mut().insert(header::CACHE_CONTROL, value);
    }

    let now = std::time::UNIX_EPOCH
        + std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    let expiry_time = now
        .checked_add(std::time::Duration::from_secs(cache_ttl as u64))
        .unwrap_or(now + std::time::Duration::from_secs(86400)); // Default to 24 hours if overflow
    let expiry_http_date = httpdate::fmt_http_date(expiry_time);
    if let Ok(value) = header::HeaderValue::from_str(&expiry_http_date) {
        response.headers_mut().insert(header::EXPIRES, value);
    }

    debug!("DoH response with cache TTL: {cache_ttl} seconds");
}

/// How long HTTP caches may keep a SERVFAIL.
///
/// When no upstream server can get the query, the SERVFAIL may stay until one can.
/// Its records can make this shorter. Otherwise, it must not be reused.
fn failure_cache_ttl(
    dns_data: &[u8],
    failure_freshness: Option<FailureFreshness>,
) -> (&'static str, u32) {
    let Some(failure_freshness) = failure_freshness else {
        return ("private", 0);
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
        "public"
    } else {
        "private"
    };
    (scope, cache_ttl)
}

/// Start the DNS-over-HTTPS (DoH) server
pub async fn start_doh_server(
    listener: TcpListener,
    query_manager: Arc<QueryManager>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    max_connections: usize,
    rate_limiter: Option<Arc<crate::rate_limiter::RateLimiter>>,
    ip_validator: Option<Arc<crate::ip_validator::IpValidator>>,
    enable_strict_ip_validation: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listener.local_addr()?;
    info!("DoH server listening on {addr}");

    // Create a semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_connections));

    // Accept connections
    loop {
        // Accept a connection
        let (stream, client_addr) = crate::net::accept_with_retry(&listener, "DoH").await;
        let io = TokioIo::new(stream);

        // Clone the values we need for this connection
        let query_manager = query_manager.clone();
        let semaphore = semaphore.clone();
        let rate_limiter = rate_limiter.clone();
        let ip_validator = ip_validator.clone();

        // Spawn a task to handle the connection
        tokio::spawn(async move {
            // Validate the client connection
            if !is_client_allowed(client_addr, &ip_validator, enable_strict_ip_validation) {
                return;
            }

            // Try to acquire a permit from the semaphore
            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!("Too many DoH connections, rejecting connection from {client_addr}");
                    return;
                }
            };

            debug!("Accepted DoH connection from {client_addr}");

            // Handle the HTTP connection
            handle_http_connection(
                io,
                client_addr,
                query_manager,
                server_timeout,
                dns_packet_len_max,
                rate_limiter,
            )
            .await;

            debug!("Closed DoH connection from {client_addr}");
        });
    }
}

/// Check if a client connection is allowed based on IP validation.
fn is_client_allowed(
    client_addr: SocketAddr,
    ip_validator: &Option<Arc<crate::ip_validator::IpValidator>>,
    enable_strict_ip_validation: bool,
) -> bool {
    // Apply IP validation if enabled
    if enable_strict_ip_validation {
        match ip_validator {
            Some(validator) => {
                if let Err(e) = validator.validate_ip(client_addr.ip()) {
                    warn!("Disallowing DoH client {client_addr}: {e}");
                    return false;
                }
                if let Err(e) = validator.validate_port(client_addr.port()) {
                    warn!("Disallowing DoH client {client_addr}: {e}");
                    return false;
                }
            }
            None => {
                warn!(
                    "Strict IP validation enabled but no validator configured, rejecting DoH client {client_addr}"
                );
                return false;
            }
        }
    }

    true
}

/// Handle an HTTP connection for DoH
async fn handle_http_connection(
    io: TokioIo<tokio::net::TcpStream>,
    client_addr: SocketAddr,
    query_manager: Arc<QueryManager>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    rate_limiter: Option<Arc<crate::rate_limiter::RateLimiter>>,
) {
    // Create a service function to handle HTTP requests
    let client_addr_clone = client_addr;
    let service = hyper::service::service_fn(move |req| {
        let query_manager = query_manager.clone();
        let client_addr = client_addr_clone;
        let rate_limiter = rate_limiter.clone();

        async move {
            if let Some(limiter) = rate_limiter
                && !limiter.is_allowed(client_addr.ip()).await
            {
                warn!("Rate limit exceeded for DoH client {client_addr}");
                return Ok(create_error_response(
                    "Too Many Requests",
                    StatusCode::TOO_MANY_REQUESTS,
                ));
            }
            handle_doh_request(
                req,
                query_manager,
                server_timeout,
                dns_packet_len_max,
                client_addr,
            )
            .await
        }
    });

    if let Err(err) = http1_builder().serve_connection(io, service).await {
        if is_client_error(&err) {
            debug!("Dropping DoH connection from {client_addr}: {err}");
        } else {
            error!("Error serving DoH connection from {client_addr}: {err}");
        }
    }
}

/// Errors from clients that stay idle, send garbage or hang up.
fn is_client_error(err: &hyper::Error) -> bool {
    (err.is_parse() && !is_hyper_bug(err))
        || err.is_incomplete_message()
        || err.is_timeout()
        || std::error::Error::source(err)
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .is_some_and(crate::net::is_peer_gone)
}

/// Hyper's own bugs also show up as parse errors, but they aren't the client's fault.
fn is_hyper_bug(err: &hyper::Error) -> bool {
    format!("{err:?}").contains("Parse(Internal)")
}

/// The timer lets hyper close connections that never send a request
fn http1_builder() -> http1::Builder {
    let mut builder = http1::Builder::new();
    builder.timer(TokioTimer::new());
    builder
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn test_connection_without_request_is_closed() {
        let (client, server) = tokio::io::duplex(64);
        let service = hyper::service::service_fn(|_req| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        });
        let started = tokio::time::Instant::now();

        let result = tokio::time::timeout(
            Duration::from_secs(3600),
            http1_builder().serve_connection(TokioIo::new(server), service),
        )
        .await;

        assert!(matches!(result, Ok(Err(ref e)) if e.is_timeout()));
        assert!(started.elapsed() >= Duration::from_secs(30));
        drop(client);
    }

    #[tokio::test]
    async fn test_junk_is_a_client_error() {
        use tokio::io::AsyncWriteExt;

        let tls_hello: &[u8] = &[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc];
        let partial_request: &[u8] = b"GET /dns-query?dns=AAAB";
        let partial_body: &[u8] =
            b"POST /dns-query HTTP/1.1\r\nContent-Length: 100\r\n\r\n\x12\x34";
        for (junk, hang_up_abruptly) in [
            (tls_hello, false),
            (partial_request, true),
            (partial_body, false),
            (partial_body, true),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            client.write_all(junk).await.unwrap();
            if hang_up_abruptly {
                client.set_zero_linger().unwrap();
            }
            drop(client);

            let service = hyper::service::service_fn(|req: Request<hyper::body::Incoming>| async {
                let err = req.into_body().collect().await.unwrap_err();
                assert!(is_client_error(&err), "{err:?}");
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
            });
            if let Err(err) = http1_builder()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                assert!(is_client_error(&err), "{err:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_stalled_request_body_does_not_hold_the_connection() {
        use tokio::io::AsyncWriteExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, client_addr) = listener.accept().await.unwrap();
        client
            .write_all(
                b"POST /dns-query HTTP/1.1\r\nHost: localhost\r\n\
                  Content-Type: application/dns-message\r\nContent-Length: 100\r\n\r\n",
            )
            .await
            .unwrap();
        let connection = handle_http_connection(
            TokioIo::new(stream),
            client_addr,
            Arc::new(QueryManager::for_tests(1, 4096, true)),
            1,
            4096,
            None,
        );

        assert!(
            tokio::time::timeout(Duration::from_secs(10), connection)
                .await
                .is_ok()
        );
        drop(client);
    }

    #[test]
    fn test_zero_ttl_answer_is_not_cacheable() {
        let response = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 192, 0,
            2, 1,
        ];

        let http_response = create_dns_response(&response, None);

        assert_eq!(
            http_response.headers()[header::CACHE_CONTROL],
            "public, max-age=0"
        );
    }

    #[test]
    fn test_negative_response_uses_soa_minimum_for_http_cache() {
        let response = create_dns_response(
            crate::dns_parser::NEGATIVE_RESPONSE_WITH_SOA_TTL_3600_MINIMUM_60,
            None,
        );

        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=60"
        );
    }

    fn servfail(response: &[u8]) -> Vec<u8> {
        let mut response = response.to_vec();
        crate::dns_parser::set_rcode(&mut response, crate::dns_processor::DNS_RCODE_SERVFAIL)
            .unwrap();
        response
    }

    fn cache_control(response: &[u8], failure_freshness: Option<FailureFreshness>) -> String {
        let http_response = create_dns_response(response, failure_freshness);
        assert_eq!(
            http_response.headers()[header::CONTENT_TYPE],
            "application/dns-message"
        );
        http_response.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test(start_paused = true)]
    async fn test_servfail_is_fresh_until_a_retry() {
        let mut response = servfail(crate::dns_parser::EXAMPLE_COM_QUERY);
        crate::dns_parser::set_qr(&mut response, true).unwrap();
        let freshness = FailureFreshness {
            retry_at: tokio::time::Instant::now() + Duration::from_secs(30),
            shared: true,
        };

        assert_eq!(
            cache_control(&response, Some(freshness)),
            "public, max-age=30"
        );

        // Later requests don't start the delay again
        tokio::time::advance(Duration::from_millis(10500)).await;
        assert_eq!(
            cache_control(&response, Some(freshness)),
            "public, max-age=19"
        );
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(
            cache_control(&response, Some(freshness)),
            "public, max-age=0"
        );

        // A failure that depends on the client's address is private
        let private = FailureFreshness {
            shared: false,
            ..freshness
        };
        assert_eq!(
            cache_control(&response, Some(private)),
            "private, max-age=0"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_servfail_records_only_shorten_the_freshness() {
        let response = servfail(crate::dns_parser::NEGATIVE_RESPONSE_WITH_SOA_TTL_3600_MINIMUM_60);
        let retry_in = |seconds| FailureFreshness {
            retry_at: tokio::time::Instant::now() + Duration::from_secs(seconds),
            shared: true,
        };

        assert_eq!(cache_control(&response, None), "private, max-age=0");
        assert_eq!(
            cache_control(&response, Some(retry_in(300))),
            "public, max-age=60"
        );
        assert_eq!(
            cache_control(&response, Some(retry_in(30))),
            "public, max-age=30"
        );
    }

    #[tokio::test]
    async fn test_servfail_is_a_dns_message() {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            while let Ok((length, client)) = udp.recv_from(&mut packet).await {
                let mut response = servfail(&packet[..length]);
                crate::dns_parser::set_qr(&mut response, true).unwrap();
                udp.send_to(&response, client).await.unwrap();
            }
        });
        let mut query_manager = QueryManager::for_tests(2, 4096, true);
        query_manager
            .set_failure_policy(crate::failure_cache::FailurePolicy::new(10, 10, 30).unwrap());
        query_manager.set_upstream_servers(vec![upstream]);
        let query_manager = Arc::new(query_manager);
        // Like most DoH clients, with ID 0, so that HTTP caches can reuse the response
        let mut query = crate::dns_parser::EXAMPLE_COM_QUERY.to_vec();
        crate::dns_parser::set_tid(&mut query, 0).unwrap();

        // The SERVFAIL of the upstream server, then ours while it is in backoff
        for _ in 0..2 {
            let response = process_dns_message(
                query.clone(),
                query_manager.clone(),
                &"192.0.2.1:443".parse().unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "public, max-age=9"
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                crate::dns_parser::rcode(&body),
                crate::dns_processor::DNS_RCODE_SERVFAIL
            );
        }
    }
}
