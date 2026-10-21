use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, server::conn::http1};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::cache::SyncDnsCache;
use crate::failure_cache::FailureCache;
use crate::stats::SharedStats;

/// Response structure for API calls
#[derive(Serialize, Deserialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

/// Cache status response structure
#[derive(Serialize, Deserialize)]
struct CacheStatusResponse {
    success: bool,
    size: usize,
    capacity: usize,
    hit_rate: f64,
    hits: u64,
    misses: u64,
    /// None if failures are not remembered
    failure_cache: Option<FailureCacheStatus>,
}

/// The failure cache, with sizes counted in queries
#[derive(Serialize, Deserialize)]
struct FailureCacheStatus {
    size: usize,
    capacity: usize,
    /// Client queries answered without asking the upstream servers that failed them
    hits: u64,
}

/// Check if a domain is within a zone
///
/// For example, if zone is "example.com", then "www.example.com" is within that zone,
/// but "example.org" is not.
fn is_domain_in_zone(domain: &str, zone: &str) -> bool {
    // Normalize both domain and zone (lowercase, no trailing dot)
    let normalized_domain = domain.trim_end_matches('.').to_lowercase();
    let normalized_zone = zone.trim_end_matches('.').to_lowercase();

    // Every name is in the root zone
    if normalized_zone.is_empty() {
        return true;
    }

    // Check if domain equals zone
    if normalized_domain == normalized_zone {
        return true;
    }

    // Check if domain is a subdomain of zone
    // Domain must end with .zone
    normalized_domain.ends_with(&format!(".{normalized_zone}"))
}

/// Handle HTTP requests for the control API
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    control_path: String,
    dns_cache: Option<Arc<SyncDnsCache>>,
    failure_cache: Option<FailureCache>,
    stats: Option<Arc<SharedStats>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let method = req.method();

    // Only match the exact control path or descendants beneath it.
    let is_control_path = path == control_path
        || path
            .strip_prefix(&control_path)
            .map(|suffix| control_path.ends_with('/') || suffix.starts_with('/'))
            .unwrap_or(false);
    if !is_control_path {
        let mut response = Response::new(Full::new(Bytes::from("Not Found")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
    }

    // Remove the control_path prefix to get the actual endpoint
    let endpoint = path
        .strip_prefix(&control_path)
        .unwrap_or("")
        .trim_start_matches('/');

    match (method, endpoint) {
        // GET /status - Return server status
        (&Method::GET, "status") => {
            let response = ApiResponse {
                success: true,
                message: "Server is running".to_string(),
            };
            let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                error!("Failed to serialize API response: {e}");
                r#"{"success":false,"message":"Internal server error"}"#.to_string()
            });

            let mut response = Response::new(Full::new(Bytes::from(json)));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            Ok(response)
        }

        // GET /cache - Return cache status
        (&Method::GET, "cache") => {
            if let Some(cache) = dns_cache {
                // Get cache size and capacity
                let size = cache.len();
                let capacity = cache.capacity();

                // Get cache hit/miss statistics from the stats system
                let (hits, misses, hit_rate, failure_cache_hits) = if let Some(stats_ref) = &stats {
                    let global_stats = stats_ref.get_stats().await;

                    let hits = global_stats.cache_hits;
                    let misses = global_stats.cache_misses;
                    let hit_rate = if hits + misses > 0 {
                        hits as f64 / (hits + misses) as f64
                    } else {
                        0.0
                    };

                    (hits, misses, hit_rate, global_stats.failure_cache_hits)
                } else {
                    // Fallback to placeholder values if stats not available
                    let hits = 0;
                    let misses = 0;
                    let hit_rate = 0.0;
                    (hits, misses, hit_rate, 0)
                };

                let response = CacheStatusResponse {
                    success: true,
                    size,
                    capacity,
                    hit_rate,
                    hits,
                    misses,
                    failure_cache: failure_cache.map(|failure_cache| FailureCacheStatus {
                        size: failure_cache.size(),
                        capacity: failure_cache.capacity(),
                        hits: failure_cache_hits,
                    }),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                Ok(response)
            } else {
                // DNS cache not available
                let response = ApiResponse {
                    success: false,
                    message: "DNS cache not available".to_string(),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(response)
            }
        }

        // DELETE /cache - Clear the DNS cache
        (&Method::DELETE, "cache") => {
            if let Some(cache) = dns_cache {
                // Clear the cache
                cache.clear();
                if let Some(failure_cache) = &failure_cache {
                    failure_cache.clear();
                }

                let cache_size = cache.len();
                info!("DNS cache cleared, current size: {cache_size}");

                let response = ApiResponse {
                    success: true,
                    message: format!("Cache cleared successfully. Current size: {cache_size}"),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                Ok(response)
            } else {
                // DNS cache not available
                let response = ApiResponse {
                    success: false,
                    message: "DNS cache not available".to_string(),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(response)
            }
        }

        // DELETE /cache/zone/<zone> - Clear entries for a specific zone
        (&Method::DELETE, zone_path) if zone_path.starts_with("cache/zone/") => {
            if let Some(cache) = dns_cache {
                // Extract the zone from the path
                let zone = zone_path.strip_prefix("cache/zone/").unwrap_or("");
                if zone.is_empty() {
                    let response = ApiResponse {
                        success: false,
                        message: "Zone parameter is required".to_string(),
                    };
                    let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                        error!("Failed to serialize API response: {e}");
                        r#"{"success":false,"message":"Internal server error"}"#.to_string()
                    });

                    let mut response = Response::new(Full::new(Bytes::from(json)));
                    response.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }

                let normalized_zone = match crate::dns_key::DNSKey::normalize_name(zone) {
                    Ok(zone) => zone,
                    Err(e) => {
                        let mut response = Response::new(Full::new(Bytes::from(format!(
                            "Invalid domain name: {e}"
                        ))));
                        *response.status_mut() = StatusCode::BAD_REQUEST;
                        return Ok(response);
                    }
                };
                let (removed_entries, new_size) = cache.with_lock(|inner| {
                    let initial_size = inner.len();
                    inner.retain(|key, _| !is_domain_in_zone(&key.name, &normalized_zone));
                    let new_size = inner.len();
                    (initial_size.saturating_sub(new_size), new_size)
                });
                if let Some(failure_cache) = &failure_cache {
                    failure_cache.retain(|key| !is_domain_in_zone(&key.name, &normalized_zone));
                }

                info!("Cleared {removed_entries} entries for zone {zone} from DNS cache");

                let response = ApiResponse {
                    success: true,
                    message: format!(
                        "Cleared {removed_entries} entries for zone {zone} from DNS cache. New size: {new_size}"
                    ),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                Ok(response)
            } else {
                // DNS cache not available
                let response = ApiResponse {
                    success: false,
                    message: "DNS cache not available".to_string(),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(response)
            }
        }

        // DELETE /cache/name/<name> - Clear a specific entry
        (&Method::DELETE, name_path) if name_path.starts_with("cache/name/") => {
            if let Some(cache) = dns_cache {
                // Extract the name from the path
                let name = name_path.strip_prefix("cache/name/").unwrap_or("");
                if name.is_empty() {
                    let response = ApiResponse {
                        success: false,
                        message: "Name parameter is required".to_string(),
                    };
                    let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                        error!("Failed to serialize API response: {e}");
                        r#"{"success":false,"message":"Internal server error"}"#.to_string()
                    });

                    let mut response = Response::new(Full::new(Bytes::from(json)));
                    response.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }

                // Use retain to keep only entries that don't match the specified name
                // We need to normalize the name for comparison
                let normalized_name = match crate::dns_key::DNSKey::normalize_name(name) {
                    Ok(name) => name,
                    Err(e) => {
                        // If name normalization fails, return an error response
                        error!("Failed to normalize domain name: {}", e);
                        let response = ApiResponse {
                            success: false,
                            message: format!("Invalid domain name: {}", e),
                        };
                        let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                            error!("Failed to serialize API response: {}", e);
                            r#"{"success":false,"message":"Internal server error"}"#.to_string()
                        });

                        let mut response = Response::new(Full::new(Bytes::from(json)));
                        response.headers_mut().insert(
                            hyper::header::CONTENT_TYPE,
                            hyper::header::HeaderValue::from_static("application/json"),
                        );
                        *response.status_mut() = StatusCode::BAD_REQUEST;
                        return Ok(response);
                    }
                };
                let (removed_entries, new_size) = cache.with_lock(|inner| {
                    let initial_size = inner.len();
                    inner.retain(|key, _| key.name != normalized_name);
                    let new_size = inner.len();
                    (initial_size.saturating_sub(new_size), new_size)
                });
                if let Some(failure_cache) = &failure_cache {
                    failure_cache.retain(|key| key.name != normalized_name);
                }

                info!("Cleared {removed_entries} entries for name {name} from DNS cache");

                let response = ApiResponse {
                    success: true,
                    message: format!(
                        "Cleared {removed_entries} entries for name {name} from DNS cache. New size: {new_size}"
                    ),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                Ok(response)
            } else {
                // DNS cache not available
                let response = ApiResponse {
                    success: false,
                    message: "DNS cache not available".to_string(),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(response)
            }
        }

        // Any other endpoint
        _ => {
            let response = ApiResponse {
                success: false,
                message: "Endpoint not found".to_string(),
            };
            let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                error!("Failed to serialize API response: {e}");
                r#"{"success":false,"message":"Internal server error"}"#.to_string()
            });

            let mut response = Response::new(Full::new(Bytes::from(json)));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
    }
}

/// Start the HTTP control server
pub async fn start_control_server(
    listener: TcpListener,
    control_path: String,
    max_connections: usize,
    dns_cache: Option<Arc<SyncDnsCache>>,
    failure_cache: Option<FailureCache>,
    stats: Option<Arc<SharedStats>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listener.local_addr()?;
    info!("Control server listening on {addr}, base path: {control_path}");

    if dns_cache.is_some() {
        info!(
            "DNS cache control API enabled at {control_path}/cache (GET/DELETE), {control_path}/cache/zone/<zone> (DELETE), and {control_path}/cache/name/<name> (DELETE)"
        );
    } else {
        warn!("DNS cache not available for control API");
    }

    // Create a semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_connections));

    // Accept connections
    loop {
        // Accept a connection
        let (stream, client_addr) = crate::net::accept_with_retry(&listener, "control").await;
        let io = TokioIo::new(stream);

        // Clone the resources for this connection
        let control_path = control_path.clone();
        let semaphore = semaphore.clone();
        let dns_cache = dns_cache.clone();
        let failure_cache = failure_cache.clone();
        let stats = stats.clone();

        // Spawn a task to handle the connection
        tokio::spawn(async move {
            // Try to acquire a permit from the semaphore
            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    // Too many connections, reject this one
                    warn!("Too many control connections, rejecting connection from {client_addr}");
                    return;
                }
            };

            debug!("Accepted control connection from {client_addr}");

            // Handle the connection
            let service = hyper::service::service_fn(move |req| {
                let control_path = control_path.clone();
                let dns_cache = dns_cache.clone();
                let failure_cache = failure_cache.clone();
                let stats = stats.clone();
                async move { handle_request(req, control_path, dns_cache, failure_cache, stats).await }
            });

            if let Ok(Err(err)) = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                http1::Builder::new().serve_connection(io, service),
            )
            .await
            {
                // Log any errors
                error!("Error serving control connection from {client_addr}: {err}");
            }

            debug!("Closed control connection from {client_addr}");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_key::DNSKey;
    use crate::failure_cache::{FailureKind, FailurePolicy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn request(addr: std::net::SocketAddr, method: &str, path: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request =
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn test_cache_deletion_forgets_failures() {
        let upstream = "192.0.2.1:53".parse().unwrap();
        let failure_cache =
            FailureCache::new(FailurePolicy::default(), Arc::new([upstream])).unwrap();
        let fail = |name: &str| {
            let key = DNSKey::new(name.to_string(), 1, 1, false).unwrap();
            failure_cache.record_failure(
                &key,
                upstream,
                FailureKind::Timeout,
                tokio::time::Instant::now(),
            );
        };
        let names = |failure_cache: &FailureCache| {
            let mut names = Vec::new();
            failure_cache.retain(|key| {
                names.push(key.name.clone());
                true
            });
            names.sort();
            names
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(start_control_server(
            listener,
            "/control".to_string(),
            1,
            Some(Arc::new(crate::cache::create_dns_cache(10))),
            Some(failure_cache.clone()),
            Some(Arc::new(SharedStats::new())),
        ));
        for name in [
            "example.com",
            "www.example.com",
            "example.org",
            "www.example.org",
        ] {
            fail(name);
        }

        let status = request(addr, "GET", "/control/cache").await;
        assert!(
            status.contains(r#""failure_cache":{"size":4,"capacity":1024,"hits":0}"#),
            "{status}"
        );

        request(addr, "DELETE", "/control/cache/zone/example.com").await;
        assert_eq!(names(&failure_cache), ["example.org", "www.example.org"]);
        request(addr, "DELETE", "/control/cache/name/example.org").await;
        assert_eq!(names(&failure_cache), ["www.example.org"]);
        request(addr, "DELETE", "/control/cache").await;
        assert!(names(&failure_cache).is_empty());
    }

    #[test]
    fn zone_matching_normalizes_case_and_trailing_dots() {
        assert!(is_domain_in_zone("WWW.Example.COM.", "example.com."));
        assert!(is_domain_in_zone("example.com", "EXAMPLE.COM."));
        assert!(!is_domain_in_zone("notexample.com", "example.com."));
        assert!(is_domain_in_zone("www.example.com", "."));
    }
}
