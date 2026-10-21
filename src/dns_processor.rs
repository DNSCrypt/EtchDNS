use log::debug;

use crate::dns_key::DNSKey;
use crate::dns_parser;
use crate::errors::DnsResult;
use crate::query_manager::FailureFreshness;

/// DNS Response Codes (RCODE)
#[allow(dead_code)]
pub const DNS_RCODE_NOERROR: u8 = 0; // No error
#[allow(dead_code)]
pub const DNS_RCODE_FORMERR: u8 = 1; // Format error
pub const DNS_RCODE_SERVFAIL: u8 = 2; // Server failure
pub const DNS_RCODE_NXDOMAIN: u8 = 3; // Non-existent domain
pub const DNS_RCODE_NOTIMP: u8 = 4; // Not implemented
pub const DNS_RCODE_REFUSED: u8 = 5; // Query refused
pub const DNS_RCODE_BADVERS: u8 = 16; // Bad EDNS version

/// Validates a DNS packet and creates a DNSKey from it.
///
/// Also returns the query without the extra bytes some clients add at the end.
pub fn validate_and_create_key<'a>(
    packet: &'a [u8],
    client_addr: &str,
) -> DnsResult<(DNSKey, &'a [u8])> {
    // Checked first, so that we never answer a response, not even with BADVERS
    if dns_parser::is_response(packet) {
        return Err(crate::errors::DnsError::InvalidPacket(
            "Client packet is a response, not a query".to_string(),
        ));
    }

    let message_len = dns_parser::validate_dns_packet(packet).inspect_err(|e| {
        debug!("Invalid DNS packet from {client_addr}: {e}");
        debug!("Dropping invalid DNS packet without response");
    })?;
    let query = &packet[..message_len];

    // Create a DNSKey from the packet
    match DNSKey::from_packet(query) {
        Ok(key) => Ok((key, query)),
        Err(e) => {
            debug!("Failed to create DNSKey from packet from {client_addr}: {e}");
            debug!("Error details: {e:?}");
            Err(e)
        }
    }
}

/// Logs information about a received DNS packet
pub fn log_received_packet(packet_size: usize, client_addr: &str, protocol: &str) {
    log::debug!("Received {packet_size} bytes from {protocol} client {client_addr}");
}

/// UDP payload size in the OPT record of the responses that we create
const RESPONSE_EDNS_PAYLOAD_SIZE: u16 = 1232;

/// Creates a DNS response with the specified response code.
///
/// The response only keeps the question, and gets an OPT record of our own if the query has one.
pub fn create_dns_response(query_data: &[u8], rcode: u8, log_msg: Option<&str>) -> Vec<u8> {
    // Log the message if provided
    if let Some(msg) = log_msg {
        log::debug!("{msg}");
    }

    let has_edns = matches!(dns_parser::extract_edns_version(query_data), Ok(Some(_)));
    let dnssec_ok = dns_parser::is_dnssec_ok(query_data).unwrap_or(false);

    // Keep the header and the question, so that the client can match the response
    let mut response = match dns_parser::recover_question_from_response(query_data) {
        Ok(question) => question,
        Err(e) => {
            log::debug!("Failed to recover the question for a response: {e}");
            let mut header =
                query_data[..query_data.len().min(dns_parser::DNS_HEADER_SIZE)].to_vec();
            if let Some(counts) = header.get_mut(4..) {
                counts.fill(0);
            }
            header
        }
    };

    // Set QR bit to 1 (response)
    if let Err(e) = dns_parser::set_qr(&mut response, true) {
        log::error!("Failed to set QR bit: {e}");
    }

    // Set the specified RCODE
    if let Err(e) = dns_parser::set_rcode(&mut response, rcode) {
        log::error!("Failed to set RCODE: {e}");
    }
    if let Err(e) = dns_parser::set_ad(&mut response, false) {
        log::error!("Failed to clear AD bit: {e}");
    }
    if let Err(e) = dns_parser::set_tc(&mut response, false) {
        log::error!("Failed to clear TC bit: {e}");
    }

    if has_edns {
        match dns_parser::add_edns_section(&mut response, RESPONSE_EDNS_PAYLOAD_SIZE) {
            Ok(()) => {
                // RFC 3225 asks to copy the DO bit of the query
                if dnssec_ok {
                    let opt_flags = response.len() - 4;
                    response[opt_flags..opt_flags + 2]
                        .copy_from_slice(&dns_parser::DNS_FLAG_DO.to_be_bytes());
                }
            }
            Err(e) => log::error!("Failed to add an OPT record to the response: {e}"),
        }
    }

    response
}

/// Creates a response with a specific RCODE for a query
#[allow(dead_code)]
pub fn create_response_with_rcode(query_data: &[u8], rcode: u8) -> Vec<u8> {
    create_dns_response(query_data, rcode, None)
}

/// Creates a BADVERS response for unsupported EDNS version
pub fn create_badvers_response(query_data: &[u8]) -> Vec<u8> {
    // BADVERS is 16: the header gets its lower 4 bits (0), and the OPT record gets the upper 8 bits (1)
    let mut response = create_dns_response(query_data, DNS_RCODE_BADVERS, None);
    if dns_parser::arcount(&response) == 0
        && let Err(e) = dns_parser::add_edns_section(&mut response, RESPONSE_EDNS_PAYLOAD_SIZE)
    {
        log::error!("Failed to add an OPT record to the BADVERS response: {e}");
        return response;
    }
    let extended_rcode = response.len() - 6;
    response[extended_rcode] = 1;

    response
}

/// Sets the appropriate DNS response flags based on authoritative_dns setting
pub fn set_response_flags(response_data: &mut [u8], authoritative_dns: bool) {
    // Set AA (Authoritative Answer) flag based on authoritative_dns setting
    if let Err(e) = dns_parser::set_aa(response_data, authoritative_dns) {
        log::error!("Failed to set AA bit: {e}");
    }

    // Set RA (Recursion Available) flag based on authoritative_dns setting
    // If authoritative_dns is false, we're a recursive resolver, so RA should be true
    if let Err(e) = dns_parser::set_ra(response_data, !authoritative_dns) {
        log::error!("Failed to set RA bit: {e}");
    }

    // We don't validate authoritative answers, so they shouldn't claim to be validated
    if authoritative_dns && let Err(e) = dns_parser::set_ad(response_data, false) {
        log::error!("Failed to clear AD bit: {e}");
    }
}

/// Trait for processing DNS queries
pub trait DnsQueryProcessor {
    /// Process a DNS query and get a response
    ///
    /// This function handles the common logic for processing a DNS query,
    /// including validating the packet, creating a DNSKey, and submitting
    /// the query to the query manager.
    ///
    /// # Arguments
    ///
    /// * `query_data` - The raw DNS query data
    /// * `client_addr` - A string representation of the client address for logging
    /// * `protocol` - The protocol used (e.g., "UDP", "TCP", "DoH")
    /// * `query_manager` - The query manager for aggregating identical DNS queries
    ///
    /// # Returns
    ///
    /// * `Some((Vec<u8>, Option<FailureFreshness>))` - The response data, and how long HTTP caches may keep it if it is a SERVFAIL
    /// * `None` - If the query could not be processed
    #[allow(async_fn_in_trait)]
    async fn process_dns_query(
        &self,
        query_data: &[u8],
        client_addr: &str,
        protocol: &str,
        query_manager: &std::sync::Arc<crate::query_manager::QueryManager>,
    ) -> Option<(Vec<u8>, Option<FailureFreshness>)> {
        // Log the received packet
        log_received_packet(query_data.len(), client_addr, protocol);

        // Validate the packet and create a DNSKey
        let (dns_key, query_data) = match validate_and_create_key(query_data, client_addr) {
            Ok(validated) => validated,
            Err(e) => {
                // Check if this is an unsupported EDNS version error
                if let crate::errors::DnsError::UnsupportedEdnsVersion { version } = e {
                    debug!(
                        "Unsupported EDNS version {version} from {client_addr}, returning BADVERS"
                    );
                    return Some((create_badvers_response(query_data), None));
                }
                return None; // Error already logged in validate_and_create_key
            }
        };

        let resolver = prepare_resolver(query_manager);

        // Submit the query and handle the response
        submit_query_and_get_response(query_manager, dns_key, query_data, resolver, client_addr)
            .await
    }
}

/// Prepares a resolver function with the settings of the query manager
fn prepare_resolver(
    query_manager: &std::sync::Arc<crate::query_manager::QueryManager>,
) -> impl Fn(
    crate::resolver::AttemptRequest,
) -> futures::future::BoxFuture<'static, crate::resolver::AttemptOutcome>
+ Send
+ Sync
+ 'static {
    crate::resolver::create_resolver(crate::resolver::UpstreamClient {
        server_timeout: query_manager.get_server_timeout(),
        dns_packet_len_max: query_manager.get_dns_packet_len_max(),
        spoof_protection: query_manager.get_spoof_protection(),
        stats: query_manager.get_stats(),
    })
}

/// Submits a query to the query manager and waits for a response
///
/// This function submits a DNS query to the query manager for processing and waits
/// for the response. It handles the communication with the query manager and
/// processes the response when it arrives.
///
/// # Arguments
///
/// * `query_manager` - Reference to the query manager
/// * `dns_key` - The DNS key representing the query
/// * `query_data` - The raw DNS query data
/// * `resolver` - The resolver function to use for upstream queries
/// * `client_addr` - String representation of the client address for logging
///
/// # Returns
///
/// An Option containing the response data and its HTTP freshness if successful, or None if an error occurred
async fn submit_query_and_get_response(
    query_manager: &std::sync::Arc<crate::query_manager::QueryManager>,
    dns_key: DNSKey,
    query_data: &[u8],
    resolver: impl Fn(
        crate::resolver::AttemptRequest,
    ) -> futures::future::BoxFuture<'static, crate::resolver::AttemptOutcome>
    + Send
    + Sync
    + 'static,
    client_addr: &str,
) -> Option<(Vec<u8>, Option<FailureFreshness>)> {
    // Submit the query to the query manager with client address
    match query_manager
        .submit_query_with_client(dns_key, query_data.to_vec(), resolver, client_addr)
        .await
    {
        Ok(mut receiver) => {
            // Wait for the response
            match receiver.recv().await {
                Ok(response) => process_dns_response(response, query_data, client_addr),
                Err(e) => {
                    log::debug!("Failed to receive response from query manager: {e}");
                    log::debug!("Error details: {e:?}");
                    None
                }
            }
        }
        Err(e) => {
            log::debug!("Failed to submit query to query manager: {e}");
            log::debug!("Error details: {e:?}");
            None
        }
    }
}

/// Prepares a response for the client that sent `query_data`.
///
/// The same response can be sent to several clients, or come from the cache.
/// Each client gets its own transaction ID and question case back.
///
/// Returns None if the response can't be sent to this client.
fn process_dns_response(
    response: crate::query_manager::DnsResponse,
    query_data: &[u8],
    client_addr: &str,
) -> Option<(Vec<u8>, Option<FailureFreshness>)> {
    // Check if the response contains an error
    if let Some(error_msg) = response.error {
        // Log the error
        log::debug!("Error in DNS response: {error_msg}");
        log::debug!("Not sending error response to client {client_addr}");
        return None;
    }

    // Get the response data (no need to clone as we own it)
    let mut response_data = response.data;
    if let Err(e) = adapt_to_client(&mut response_data, query_data) {
        log::debug!("Failed to adapt the response for client {client_addr}: {e}");
        return None;
    }
    Some((response_data, response.failure_freshness))
}

fn adapt_to_client(response: &mut Vec<u8>, query: &[u8]) -> DnsResult<()> {
    dns_parser::set_tid(response, dns_parser::tid(query))?;
    dns_parser::copy_rd_cd(response, query)?;
    dns_parser::restore_qname_case(response, query)?;
    if !matches!(dns_parser::extract_edns_client_subnet(query), Ok(Some(_))) {
        dns_parser::remove_edns_option(response, dns_parser::EDNS_OPTION_CLIENT_SUBNET)?;
    }
    Ok(())
}

/// Trait for processing DNS queries
impl DnsQueryProcessor for () {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_parser;

    fn create_test_query_with_edns_version(version: u8) -> Vec<u8> {
        // Create a basic DNS query
        let query = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x01, // ARCOUNT = 1 (for OPT record)
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // Root label
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Additional section - OPT record
            0x00, // Root domain name
            0x00, 0x29, // Type = OPT (41)
            0x04, 0xd0,    // Class = 1232 (UDP payload size)
            0x00,    // Extended RCODE
            version, // EDNS Version
            0x00, 0x00, // Flags
            0x00, 0x00, // RDLEN = 0
        ];
        query
    }

    async fn ask(
        query_manager: &std::sync::Arc<crate::query_manager::QueryManager>,
        query: &[u8],
    ) -> Option<Vec<u8>> {
        ().process_dns_query(query, "127.0.0.1:5353", "UDP", query_manager)
            .await
            .map(|(response, _)| response)
    }

    fn manager(
        spoof_protection: bool,
        upstream_addr: std::net::SocketAddr,
    ) -> crate::query_manager::QueryManager {
        let mut query_manager =
            crate::query_manager::QueryManager::for_tests(2, 1232, spoof_protection);
        query_manager.set_upstream_servers(vec![upstream_addr]);
        query_manager
    }

    #[test]
    fn test_create_badvers_response() {
        // Create a query with EDNS version 1
        let query = create_test_query_with_edns_version(1);

        // Create BADVERS response
        let response = create_badvers_response(&query);

        // Check that it's a response
        assert!(dns_parser::is_response(&response));

        // For extended RCODE 16 (BADVERS), the header RCODE should be 0
        // and the extended part (1) should be in the OPT record
        assert_eq!(dns_parser::rcode(&response), 0);

        // Check that response includes exactly one corrected OPT record
        assert_eq!(dns_parser::arcount(&response), 1);

        // Check that the OPT record has EDNS version 0
        let edns_version = dns_parser::extract_edns_version(&response).unwrap();
        assert_eq!(edns_version, Some(0));

        // Verify the OPT record structure
        // Find the OPT record - it should be at the end
        let response_len = response.len();
        assert!(response_len >= 11); // Should have at least the OPT record

        // The OPT record starts 11 bytes from the end
        let opt_start = response_len - 11;

        // Verify OPT record structure
        assert_eq!(response[opt_start], 0); // Root domain
        assert_eq!(response[opt_start + 1], 0); // Type high byte
        assert_eq!(response[opt_start + 2], 41); // Type low byte (OPT)
        // Skip class (UDP payload size)
        assert_eq!(response[opt_start + 5], 1); // Extended RCODE = 1
        assert_eq!(response[opt_start + 6], 0); // EDNS version = 0
    }

    #[test]
    fn test_unsupported_edns_version_validation() {
        // Test that EDNS version 0 passes validation
        let query_v0 = create_test_query_with_edns_version(0);
        let result = validate_and_create_key(&query_v0, "127.0.0.1:12345");
        assert!(result.is_ok());

        // Test that EDNS version 1 fails validation
        let query_v1 = create_test_query_with_edns_version(1);
        let result = validate_and_create_key(&query_v1, "127.0.0.1:12345");
        assert!(result.is_err());
        match result {
            Err(crate::errors::DnsError::UnsupportedEdnsVersion { version }) => {
                assert_eq!(version, 1);
            }
            _ => panic!("Expected UnsupportedEdnsVersion error"),
        }

        // Test that EDNS version 2 fails validation
        let query_v2 = create_test_query_with_edns_version(2);
        let result = validate_and_create_key(&query_v2, "127.0.0.1:12345");
        assert!(result.is_err());
        match result {
            Err(crate::errors::DnsError::UnsupportedEdnsVersion { version }) => {
                assert_eq!(version, 2);
            }
            _ => panic!("Expected UnsupportedEdnsVersion error"),
        }
    }

    #[test]
    fn test_response_packet_is_not_accepted_as_a_query() {
        let mut packet = create_test_query_with_edns_version(0);
        dns_parser::set_qr(&mut packet, true).unwrap();

        assert!(validate_and_create_key(&packet, "127.0.0.1:12345").is_err());

        let mut packet = create_test_query_with_edns_version(1);
        dns_parser::set_qr(&mut packet, true).unwrap();

        assert!(matches!(
            validate_and_create_key(&packet, "127.0.0.1:12345"),
            Err(crate::errors::DnsError::InvalidPacket(_))
        ));
    }

    #[test]
    fn test_synthetic_response_clears_ad() {
        let mut query = create_test_query_with_edns_version(0);
        query[3] |= 0x20;

        let response = create_dns_response(&query, DNS_RCODE_REFUSED, None);

        assert!(!dns_parser::is_authenticated_data_requested(&response));
    }

    #[test]
    fn test_response_gets_the_rd_and_cd_flags_of_its_query() {
        let query = create_test_query_with_edns_version(0);
        let mut first_query = query.clone();
        first_query[2] &= !0x01;
        first_query[3] |= 0x10;
        let mut response = create_dns_response(&first_query, DNS_RCODE_NOERROR, None);

        adapt_to_client(&mut response, &query).unwrap();

        assert!(dns_parser::is_recursion_desired(&response));
        assert!(!dns_parser::is_checking_disabled(&response));
    }

    #[tokio::test]
    async fn test_disabled_spoof_protection_skips_tcp_fallback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(upstream_addr).await.unwrap();
        tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            let (length, client) = udp.recv_from(&mut packet).await.unwrap();
            packet.truncate(length);
            dns_parser::set_qr(&mut packet, true).unwrap();
            let wrong_tid = dns_parser::tid(&packet).wrapping_add(1);
            dns_parser::set_tid(&mut packet, wrong_tid).unwrap();
            udp.send_to(&packet, client).await.unwrap();
        });
        tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await.unwrap();
            let mut packet = vec![0u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut packet).await.unwrap();
            dns_parser::set_qr(&mut packet, true).unwrap();
            stream.write_all(&length).await.unwrap();
            stream.write_all(&packet).await.unwrap();
        });

        let query_manager = std::sync::Arc::new(manager(false, upstream_addr));
        let query = create_test_query_with_edns_version(0);

        // A NOERROR would mean that the TCP answer was used
        let response = ask(&query_manager, &query).await.unwrap();
        assert_eq!(dns_parser::rcode(&response), DNS_RCODE_SERVFAIL);
    }

    #[tokio::test]
    async fn test_trailing_data_is_answered_but_not_forwarded() {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        let (forwarded_tx, forwarded_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            let (length, client) = udp.recv_from(&mut packet).await.unwrap();
            packet.truncate(length);
            let mut response = packet.clone();
            dns_parser::set_qr(&mut response, true).unwrap();
            udp.send_to(&response, client).await.unwrap();
            forwarded_tx.send(packet).unwrap();
        });

        // Extra bytes at the end that look like an OPT record asking for DNSSEC
        let mut query = create_test_query_with_edns_version(1);
        dns_parser::set_arcount(&mut query, 0).unwrap();
        let opt_flags = query.len() - 4;
        query[opt_flags..opt_flags + 2].copy_from_slice(&dns_parser::DNS_FLAG_DO.to_be_bytes());

        let query_manager = std::sync::Arc::new(manager(true, upstream_addr));
        assert!(ask(&query_manager, &query).await.is_some());

        // The upstream only sees our own OPT record
        let forwarded = forwarded_rx.await.unwrap();
        assert_eq!(
            dns_parser::validate_dns_packet(&forwarded).unwrap(),
            forwarded.len()
        );
        assert_eq!(dns_parser::arcount(&forwarded), 1);
        assert!(!dns_parser::is_dnssec_ok(&forwarded).unwrap());
    }

    fn has_cookie(packet: &[u8]) -> bool {
        let mut stripped = packet.to_vec();
        dns_parser::remove_edns_option(&mut stripped, dns_parser::EDNS_OPTION_COOKIE).unwrap();
        stripped.len() != packet.len()
    }

    #[tokio::test]
    async fn test_cached_response_is_adapted_to_each_client() {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        let (forwarded_tx, forwarded_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            let (length, client) = udp.recv_from(&mut packet).await.unwrap();
            packet.truncate(length);
            let mut response = dns_parser::recover_question_from_response(&packet).unwrap();
            dns_parser::set_qr(&mut response, true).unwrap();
            dns_parser::set_ancount(&mut response, 1).unwrap();
            // The answer name points back to the question
            response.extend_from_slice(&[
                0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 192, 0, 2,
                1,
            ]);
            dns_parser::add_edns_section(&mut response, 1232).unwrap();
            dns_parser::add_cookie(&mut response, b"CLIENT01SERVER01");
            udp.send_to(&response, client).await.unwrap();
            forwarded_tx.send(packet).unwrap();
        });

        let mut query_manager = manager(true, upstream_addr);
        query_manager.set_cache(crate::cache::create_dns_cache(10));
        let query_manager = std::sync::Arc::new(query_manager);
        let mut responses = Vec::new();
        for (tid, name, cookie) in [
            (1u16, b"ExAmPlE", b"CLIENT01"),
            (2, b"eXaMpLe", b"CLIENT02"),
        ] {
            let mut query = create_test_query_with_edns_version(0);
            dns_parser::set_tid(&mut query, tid).unwrap();
            query[13..20].copy_from_slice(name);
            dns_parser::add_cookie(&mut query, cookie);
            let response = ask(&query_manager, &query).await.unwrap();
            assert_eq!(dns_parser::tid(&response), tid);
            assert_eq!(&response[13..20], name);
            assert!(!has_cookie(&response));
            responses.push(response);
        }

        assert!(!has_cookie(&forwarded_rx.await.unwrap()));
        assert_eq!(responses[0][20..], responses[1][20..]);
    }

    #[test]
    fn test_synthetic_responses_only_keep_the_question() {
        // RD, CD, AD and TC, mixed case, DO, a cookie and a client subnet
        let mut query = create_test_query_with_edns_version(0);
        query[2] |= 0x03;
        query[3] |= 0x30;
        query[13..20].copy_from_slice(b"ExAmPlE");
        let opt_flags = query.len() - 4;
        query[opt_flags..opt_flags + 2].copy_from_slice(&dns_parser::DNS_FLAG_DO.to_be_bytes());
        dns_parser::add_cookie(&mut query, b"CLIENT01");
        dns_parser::add_edns_client_subnet(&mut query, "192.0.2.1", 24, 56, 1232).unwrap();
        let question = 12..29;

        for rcode in [
            DNS_RCODE_SERVFAIL,
            DNS_RCODE_REFUSED,
            DNS_RCODE_NOTIMP,
            DNS_RCODE_NXDOMAIN,
        ] {
            let response = create_dns_response(&query, rcode, None);

            dns_parser::validate_dns_response(&response).unwrap();
            assert_eq!(dns_parser::rcode(&response), rcode);
            assert_eq!(dns_parser::tid(&response), dns_parser::tid(&query));
            assert_eq!(&response[question.clone()], &query[question.clone()]);
            assert!(dns_parser::is_recursion_desired(&response));
            assert!(dns_parser::is_checking_disabled(&response));
            assert!(!dns_parser::is_authenticated_data_requested(&response));
            assert!(!dns_parser::is_truncated(&response));
            assert_eq!(dns_parser::ancount(&response), 0);
            assert_eq!(dns_parser::nscount(&response), 0);

            // A single OPT record of our own, with the DO bit of the query
            assert_eq!(dns_parser::arcount(&response), 1);
            assert_eq!(response.len(), question.end + 11);
            assert!(dns_parser::is_dnssec_ok(&response).unwrap());
            assert!(!has_cookie(&response));
            assert_eq!(
                dns_parser::extract_edns_client_subnet(&response).unwrap(),
                None
            );
        }

        // No OPT record for a query without one
        let mut query = query[..question.end].to_vec();
        dns_parser::set_arcount(&mut query, 0).unwrap();
        let response = create_dns_response(&query, DNS_RCODE_SERVFAIL, None);
        assert_eq!(response.len(), question.end);
        assert_eq!(dns_parser::arcount(&response), 0);
    }

    #[test]
    fn test_synthetic_response_to_junk_does_not_panic() {
        for junk in [&[][..], &[0x12, 0x34], &[0xff; 12], &[0xff; 40]] {
            let response = create_dns_response(junk, DNS_RCODE_SERVFAIL, None);
            assert!(response.len() <= dns_parser::DNS_HEADER_SIZE);
        }
    }

    #[tokio::test]
    async fn test_failures_are_adapted_to_each_client() {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        let (forwarded_tx, mut forwarded_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            while let Ok((length, client)) = udp.recv_from(&mut packet).await {
                let mut response = packet[..length].to_vec();
                dns_parser::set_qr(&mut response, true).unwrap();
                dns_parser::set_rcode(&mut response, DNS_RCODE_SERVFAIL).unwrap();
                udp.send_to(&response, client).await.unwrap();
                forwarded_tx.send(()).unwrap();
            }
        });

        let query_manager = std::sync::Arc::new(manager(true, upstream_addr));
        // The first client gets the SERVFAIL of the upstream server, the second one gets ours
        for (tid, name, cookie) in [
            (1u16, b"ExAmPlE", b"CLIENT01"),
            (2, b"eXaMpLe", b"CLIENT02"),
        ] {
            let mut query = create_test_query_with_edns_version(0);
            dns_parser::set_tid(&mut query, tid).unwrap();
            query[13..20].copy_from_slice(name);
            dns_parser::add_cookie(&mut query, cookie);
            let response = ask(&query_manager, &query).await.unwrap();
            assert_eq!(dns_parser::rcode(&response), DNS_RCODE_SERVFAIL);
            assert_eq!(dns_parser::tid(&response), tid);
            assert_eq!(&response[13..20], name);
            assert!(!has_cookie(&response));
        }

        forwarded_rx.recv().await.unwrap();
        assert!(forwarded_rx.try_recv().is_err());
    }
}
