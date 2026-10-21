use futures::future::BoxFuture;
use log::{debug, error, warn};
use parking_lot::Mutex;
use rand::RngExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::dns_parser::{self, EdnsClientSubnet};
use crate::stats::SharedStats;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Waits for a datagram from `peer` and returns its length.
///
/// Packets from anyone else are ignored, so that they can't make the query fail.
pub async fn recv_from_peer(
    socket: &UdpSocket,
    buf: &mut [u8],
    peer: SocketAddr,
) -> std::io::Result<usize> {
    loop {
        let (len, source) = socket.recv_from(buf).await?;
        if source == peer {
            return Ok(len);
        }
        debug!("Ignoring datagram from unexpected source {source}, expected {peer}");
    }
}

/// One query to one upstream server, chosen by the query manager
pub struct AttemptRequest {
    /// The client query, after the query manager's changes
    pub query: Vec<u8>,
    /// The EDNS-client-subnet option of the cache key, which the upstream query must carry
    pub effective_ecs: Option<EdnsClientSubnet>,
    /// The only server that gets the query
    pub upstream: SocketAddr,
    /// The query manager stops the attempt at that time
    pub deadline: Instant,
    /// What the attempt did, for the query manager to read if it stops the attempt
    pub progress: Arc<AttemptProgress>,
}

/// The result of an attempt, and the server that it comes from
pub struct AttemptOutcome {
    pub upstream: SocketAddr,
    pub result: Result<Vec<u8>, AttemptError>,
}

/// Why an attempt brought back no DNS response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError {
    /// A problem on our side, such as a socket error
    Local(String),
    /// A reply that can't be used, for instance because it is for another question
    Rejected(String),
    /// A TCP connection that failed after a UDP reply with the wrong transaction ID
    Transport(String),
    /// The query manager stopped the attempt at its deadline
    BudgetExpired,
}

impl fmt::Display for AttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttemptError::Local(e) => write!(f, "local error: {e}"),
            AttemptError::Rejected(e) => write!(f, "rejected reply: {e}"),
            AttemptError::Transport(e) => write!(f, "TCP fallback failed: {e}"),
            AttemptError::BudgetExpired => write!(f, "no answer in time"),
        }
    }
}

/// A valid reply, kept in case the deadline stops the attempt before it can return it
struct KeptReply {
    packet: Vec<u8>,
    /// None after a retransmission, since the delay is then not a response time
    response_time: Option<Duration>,
    /// Whether the stats know that the server answered
    accounted: bool,
}

/// What an attempt did so far
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttemptFlags {
    /// The first datagram went out
    pub sent: bool,
    /// The stats know that the first datagram got no answer in time
    pub early_miss_recorded: bool,
    /// A reply with the wrong transaction ID sent us to TCP, so the server may not be at fault
    pub spoof_fallback: bool,
}

#[derive(Default)]
struct ProgressState {
    flags: AttemptFlags,
    reply: Option<KeptReply>,
}

/// The progress of an attempt, which the query manager can still read after it stops the attempt
#[derive(Default)]
pub struct AttemptProgress {
    state: Mutex<ProgressState>,
}

impl AttemptProgress {
    pub fn flags(&self) -> AttemptFlags {
        self.state.lock().flags
    }

    pub fn mark_sent(&self) {
        self.state.lock().flags.sent = true;
    }

    pub fn mark_spoof_fallback(&self) {
        self.state.lock().flags.spoof_fallback = true;
    }

    /// Keeps a valid reply, then tells the stats that the server answered.
    ///
    /// If the deadline comes while we wait for the stats, `expire()` still has the reply.
    async fn report_reply(
        &self,
        packet: &[u8],
        response_time: Option<Duration>,
        upstream: SocketAddr,
        stats: Option<&SharedStats>,
    ) {
        self.state.lock().reply = Some(KeptReply {
            packet: packet.to_vec(),
            response_time,
            accounted: false,
        });
        if let Some(stats) = stats {
            self.account_reply(stats, upstream).await;
        }
    }

    /// Records the first unanswered datagram, once
    async fn record_early_miss(&self, stats: &SharedStats, upstream: SocketAddr) {
        if self.state.lock().flags.early_miss_recorded {
            return;
        }
        stats.record_timeout(upstream).await;
        self.state.lock().flags.early_miss_recorded = true;
    }

    /// Tells the stats that the server sent the kept reply, once
    async fn account_reply(&self, stats: &SharedStats, upstream: SocketAddr) {
        let response_time = match &self.state.lock().reply {
            Some(reply) if !reply.accounted => reply.response_time,
            _ => return,
        };
        record_answer(stats, upstream, response_time).await;
        if let Some(reply) = &mut self.state.lock().reply {
            reply.accounted = true;
        }
    }

    /// Runs an attempt, and finishes it with what it did so far if the deadline comes first
    pub async fn run_until(
        &self,
        deadline: Instant,
        upstream: SocketAddr,
        stats: Option<&SharedStats>,
        attempt: impl Future<Output = AttemptOutcome>,
    ) -> AttemptOutcome {
        match tokio::time::timeout_at(deadline, attempt).await {
            Ok(outcome) => outcome,
            Err(_) => {
                debug!("The DNS query to {upstream} ran out of time");
                self.expire(upstream, stats).await
            }
        }
    }

    /// Finishes an attempt stopped at its deadline, with its kept reply if there is one.
    ///
    /// The stats get what the attempt had no time to record.
    async fn expire(&self, upstream: SocketAddr, stats: Option<&SharedStats>) -> AttemptOutcome {
        let flags = self.flags();
        let has_reply = self.state.lock().reply.is_some();
        if let Some(stats) = stats {
            if flags.sent {
                stats.record_budget_expiration(upstream).await;
            }
            self.account_reply(stats, upstream).await;
            if flags.sent && !has_reply && !flags.spoof_fallback {
                self.record_early_miss(stats, upstream).await;
            }
        }
        let result = match self.state.lock().reply.take() {
            Some(reply) => Ok(reply.packet),
            None => Err(AttemptError::BudgetExpired),
        };
        AttemptOutcome { upstream, result }
    }
}

/// Settings for the queries sent to upstream servers
#[derive(Clone)]
pub struct UpstreamClient {
    /// The server timeout, in seconds
    pub server_timeout: u64,
    pub dns_packet_len_max: usize,
    pub spoof_protection: bool,
    pub stats: Option<Arc<SharedStats>>,
}

impl UpstreamClient {
    /// Sends the query to the upstream server of the request, and retries over TCP if needed
    pub async fn attempt(&self, request: AttemptRequest) -> AttemptOutcome {
        let result = self.resolve(&request).await;
        AttemptOutcome {
            upstream: request.upstream,
            result,
        }
    }

    async fn resolve(&self, request: &AttemptRequest) -> Result<Vec<u8>, AttemptError> {
        let upstream_addr = request.upstream;
        let stats = self.stats.as_deref();

        // Log packet details at debug level
        debug!("Processing query with data: {:?}", request.query);

        // Only the message is sent upstream, not the bytes some clients add after it
        let message_len = dns_parser::validate_dns_packet(&request.query)
            .map_err(|e| AttemptError::Local(format!("Invalid DNS packet: {e}")))?;
        let mut query_data = prepare_query(
            &request.query[..message_len],
            self.dns_packet_len_max,
            request.effective_ecs.as_ref(),
        )?;

        // Create a new UDP socket for the upstream connection
        let bind_addr = if upstream_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let upstream_socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            AttemptError::Local(format!(
                "Failed to bind socket for upstream connection: {e}"
            ))
        })?;

        // Generate a random transaction ID
        let random_tid: u16 = rand::rng().random();

        // Store the original transaction ID for verification later
        let original_tid = dns_parser::tid(&query_data);

        // Replace the transaction ID in the query with the random one
        dns_parser::set_tid(&mut query_data, random_tid)
            .map_err(|e| AttemptError::Local(format!("Failed to set transaction ID: {e}")))?;

        debug!("Replaced query transaction ID {original_tid} with random ID {random_tid}");

        // Retransmit after half of the server_timeout, if there is still time
        let initial_timeout = Duration::from_secs(std::cmp::max(1, self.server_timeout / 2));
        debug!("Using initial timeout of {initial_timeout:?}");

        // Receive buffer
        let mut buf = vec![0u8; self.dns_packet_len_max]; // Use the configured maximum DNS packet size

        // Start timing the request
        let start_time = Instant::now();

        // First attempt
        debug!("Sending query to upstream server (first attempt): {upstream_addr}");
        upstream_socket
            .send_to(&query_data, upstream_addr)
            .await
            .map_err(|e| {
                AttemptError::Local(format!(
                    "Failed to send query to upstream server {upstream_addr}: {e}"
                ))
            })?;
        request.progress.mark_sent();

        // Wait for the response with the initial timeout
        let first_deadline = start_time
            .checked_add(initial_timeout)
            .map_or(request.deadline, |end| end.min(request.deadline));
        let recv_future = recv_from_peer(&upstream_socket, &mut buf, upstream_addr);

        match tokio::time::timeout_at(first_deadline, recv_future).await {
            Ok(Ok(len)) => {
                // Successfully received a response within the initial timeout
                let response_time = start_time.elapsed();
                debug!(
                    "Received response of size {len} bytes from upstream server (first attempt): {upstream_addr} in {response_time:?}"
                );

                process_response(
                    &buf[..len],
                    random_tid,
                    upstream_addr,
                    self.spoof_protection,
                    &query_data,
                    Some(response_time),
                    stats,
                    &request.progress,
                )
                .await
            }
            Ok(Err(e)) => {
                // Socket errors are about our socket, not about the server
                error!("Failed to receive response from upstream server {upstream_addr}: {e}");
                Err(AttemptError::Local(format!(
                    "Failed to receive response from upstream server {upstream_addr}: {e}"
                )))
            }
            Err(_) => {
                // Timeout occurred, try again
                debug!(
                    "Timeout waiting for response from upstream server after {initial_timeout:?} (retrying): {upstream_addr}"
                );

                // Counted once per query, and before the retry, so that an answer to the retry can undo it
                if let Some(stats) = stats {
                    request
                        .progress
                        .record_early_miss(stats, upstream_addr)
                        .await;
                }

                // No time left for a retry, so wait for the query manager to stop us
                if Instant::now() >= request.deadline {
                    debug!("No time left to retry the query to {upstream_addr}");
                    return std::future::pending().await;
                }

                // Second attempt
                debug!("Sending query to upstream server (retry attempt): {upstream_addr}");
                upstream_socket
                    .send_to(&query_data, upstream_addr)
                    .await
                    .map_err(|e| {
                        AttemptError::Local(format!(
                            "Failed to send retry query to upstream server {upstream_addr}: {e}"
                        ))
                    })?;

                // Wait for the response until the query manager's deadline
                match recv_from_peer(&upstream_socket, &mut buf, upstream_addr).await {
                    Ok(len) => {
                        // Successfully received a response on the retry
                        debug!(
                            "Received response of size {len} bytes from upstream server (retry attempt): {upstream_addr}"
                        );

                        // The resolver is fine, but this delay is not a real response time
                        process_response(
                            &buf[..len],
                            random_tid,
                            upstream_addr,
                            self.spoof_protection,
                            &query_data,
                            None,
                            stats,
                            &request.progress,
                        )
                        .await
                    }
                    Err(e) => {
                        // Socket error on retry
                        error!(
                            "Failed to receive response from upstream server on retry {upstream_addr}: {e}"
                        );
                        Err(AttemptError::Local(format!(
                            "Failed to receive response from upstream server on retry {upstream_addr}: {e}"
                        )))
                    }
                }
            }
        }
    }
}

/// Sets our EDNS payload size, and the EDNS-client-subnet option of the cache key
fn prepare_query(
    message: &[u8],
    dns_packet_len_max: usize,
    effective_ecs: Option<&EdnsClientSubnet>,
) -> Result<Vec<u8>, AttemptError> {
    let advertised_size = u16::try_from(dns_packet_len_max).unwrap_or(u16::MAX);
    let mut query_data = message.to_vec();
    if let Err(e) = dns_parser::set_edns_max_payload_size(&mut query_data, advertised_size) {
        error!("Failed to set EDNS maximum payload size: {e}");
        debug!("Continuing with original query without EDNS");
        query_data = message.to_vec(); // Revert to original query data
    }

    // The answer is cached for this subnet, so the server must get this subnet
    let carries_effective_ecs = |query_data: &[u8]| {
        dns_parser::extract_edns_client_subnet(query_data)
            .is_ok_and(|ecs| ecs.as_ref() == effective_ecs)
    };
    if !carries_effective_ecs(&query_data) {
        dns_parser::set_edns_client_subnet(&mut query_data, effective_ecs, advertised_size)
            .map_err(|e| AttemptError::Local(format!("Failed to set EDNS-client-subnet: {e}")))?;
        if !carries_effective_ecs(&query_data) {
            return Err(AttemptError::Local(
                "The query doesn't carry the EDNS-client-subnet of its cache key".to_string(),
            ));
        }
        debug!("Set EDNS-client-subnet to {effective_ecs:?}");
    }
    Ok(query_data)
}

/// Tells the stats that the server answered
async fn record_answer(stats: &SharedStats, upstream: SocketAddr, response_time: Option<Duration>) {
    match response_time {
        Some(response_time) => stats.record_success(upstream, response_time).await,
        None => stats.clear_failures(upstream).await,
    }
}

/// Process a DNS response.
///
/// Only a valid answer counts as a success. A bad one is not a failure either, since anyone could have forged it.
async fn process_response(
    response_data: &[u8],
    expected_tid: u16,
    upstream_addr: SocketAddr,
    spoof_protection: bool,
    query_data: &[u8],
    response_time: Option<Duration>,
    stats: Option<&SharedStats>,
    progress: &AttemptProgress,
) -> Result<Vec<u8>, AttemptError> {
    // Verify the transaction ID in the response
    let response_tid = dns_parser::tid(response_data);
    if response_tid != expected_tid {
        if !spoof_protection {
            debug!("Transaction ID mismatch: expected {expected_tid}, got {response_tid}");
            return Err(AttemptError::Rejected(
                "Transaction ID mismatch in response".to_string(),
            ));
        }

        warn!(
            "Potential DNS spoofing detected over UDP from {}: expected transaction ID {}, got {}. Will retry with TCP.",
            upstream_addr, expected_tid, response_tid
        );
        // Anyone can send such a datagram, so what happens next is not the server's fault
        progress.mark_spoof_fallback();
        let tcp_response = retry_with_tcp(query_data, expected_tid, upstream_addr)
            .await
            .inspect_err(|e| warn!("Failed TCP retry after potential spoofing detected: {e}"))?;
        debug!("Successfully received complete response via TCP");
        progress
            .report_reply(&tcp_response, response_time, upstream_addr, stats)
            .await;
        return Ok(tcp_response);
    }
    debug!("Verified response transaction ID: {response_tid}");

    // Validate that the response is a valid DNS response
    if let Err(e) = dns_parser::validate_dns_response(response_data) {
        debug!("Invalid DNS response: {e}");
        return Err(AttemptError::Rejected(format!("Invalid DNS response: {e}")));
    }
    if !dns_parser::questions_match(query_data, response_data)
        .map_err(|e| AttemptError::Rejected(format!("Invalid DNS response: {e}")))?
    {
        return Err(AttemptError::Rejected(
            "Question mismatch in UDP response".to_string(),
        ));
    }
    if !dns_parser::edns_client_subnet_matches(query_data, response_data)
        .map_err(|e| AttemptError::Rejected(format!("Invalid DNS response: {e}")))?
    {
        return Err(AttemptError::Rejected(
            "ECS mismatch in UDP response".to_string(),
        ));
    }

    if dns_parser::is_truncated(response_data) {
        debug!("Retrying with TCP (TC bit set)");

        // The truncated response is better than nothing, even if TCP never answers
        progress
            .report_reply(response_data, response_time, upstream_addr, stats)
            .await;

        // Retry the query using TCP
        return Ok(
            match retry_with_tcp(query_data, expected_tid, upstream_addr).await {
                Ok(tcp_response) => {
                    debug!("Successfully received complete response via TCP");
                    tcp_response
                }
                Err(e) => {
                    warn!(
                        "Failed to get complete response via TCP: {e}, returning truncated UDP response"
                    );
                    response_data.to_vec()
                }
            },
        );
    }

    progress
        .report_reply(response_data, response_time, upstream_addr, stats)
        .await;
    Ok(response_data.to_vec())
}

/// Retry a DNS query using TCP when the UDP response is truncated
async fn retry_with_tcp(
    query_data: &[u8],
    expected_tid: u16,
    upstream_addr: SocketAddr,
) -> Result<Vec<u8>, AttemptError> {
    let tcp_query_data = query_data.to_vec();

    // Create a TCP connection to the upstream server
    debug!("Connecting to upstream DNS server via TCP: {upstream_addr}");
    let mut tcp_stream = tokio::net::TcpStream::connect(upstream_addr)
        .await
        .map_err(|e| {
            AttemptError::Transport(format!("Failed to connect to upstream server via TCP: {e}"))
        })?;

    // Prepare the DNS query for TCP (prepend 2-byte length)
    let query_len = u16::try_from(tcp_query_data.len())
        .map_err(|_| AttemptError::Local("DNS query is too large for TCP framing".to_string()))?;
    let mut tcp_query = Vec::with_capacity(tcp_query_data.len() + 2);
    tcp_query.extend_from_slice(&query_len.to_be_bytes());
    tcp_query.extend_from_slice(&tcp_query_data);

    // Send the query
    debug!("Sending DNS query via TCP to {upstream_addr}");
    tcp_stream
        .write_all(&tcp_query)
        .await
        .map_err(|e| AttemptError::Transport(format!("Failed to send DNS query via TCP: {e}")))?;

    // Read the response length (2 bytes)
    // Since this is only 2 bytes, we can use read_exact() here
    // The risk of DoS is minimal for such a small read
    let mut length_buf = [0u8; 2];
    tcp_stream.read_exact(&mut length_buf).await.map_err(|e| {
        AttemptError::Transport(format!("Failed to read DNS response length via TCP: {e}"))
    })?;

    // Calculate the response length
    let response_len = usize::from(u16::from_be_bytes(length_buf));
    if !(dns_parser::DNS_PACKET_LEN_MIN..=dns_parser::DNS_MAX_PACKET_SIZE).contains(&response_len) {
        return Err(AttemptError::Rejected(format!(
            "Invalid DNS response length via TCP: {response_len}"
        )));
    }

    // Read the response using multiple read() calls to prevent DoS attacks
    // where a malicious client sends one byte at a time
    let mut response_buf = vec![0u8; response_len];
    let mut total_bytes_read = 0;

    // Define minimum read size (except for the last read)
    let min_read_size = 512;

    while total_bytes_read < response_len {
        let bytes_remaining = response_len - total_bytes_read;

        // Read into the appropriate slice of the buffer
        let read_result = tcp_stream.read(&mut response_buf[total_bytes_read..]).await;

        match read_result {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    // Connection closed prematurely
                    return Err(AttemptError::Transport(format!(
                        "TCP connection closed unexpectedly after reading {total_bytes_read} of {response_len} bytes"
                    )));
                }

                // Check if we're getting small reads (potential DoS)
                // Only enforce minimum read size if we're not near the end
                if bytes_read < min_read_size && bytes_remaining > min_read_size {
                    debug!(
                        "Small TCP read detected ({bytes_read} bytes). This could be inefficient."
                    );
                }

                total_bytes_read += bytes_read;
                debug!("Read {bytes_read} bytes, total so far: {total_bytes_read}/{response_len}");
            }
            Err(e) => {
                return Err(AttemptError::Transport(format!(
                    "Failed to read DNS response via TCP after {total_bytes_read} of {response_len} bytes: {e}"
                )));
            }
        }
    }

    // Verify the transaction ID in the response
    let response_tid = dns_parser::tid(&response_buf);
    if response_tid != expected_tid {
        // TCP connections are inherently secure against spoofing due to the three-way handshake
        // Transaction ID mismatches over TCP indicate a protocol error, not a spoofing attempt
        debug!("TCP response transaction ID mismatch: expected {expected_tid}, got {response_tid}");
        return Err(AttemptError::Rejected(
            "Transaction ID mismatch in TCP response".to_string(),
        ));
    }

    // Validate that the response is a valid DNS response
    let invalid = |e| AttemptError::Rejected(format!("Invalid DNS TCP response: {e}"));
    if let Err(e) = dns_parser::validate_dns_response(&response_buf) {
        debug!("Invalid DNS TCP response: {e}");
        return Err(invalid(e));
    }
    if !dns_parser::questions_match(&tcp_query_data, &response_buf).map_err(invalid)? {
        return Err(AttemptError::Rejected(
            "Question mismatch in TCP response".to_string(),
        ));
    }
    if !dns_parser::edns_client_subnet_matches(&tcp_query_data, &response_buf).map_err(invalid)? {
        return Err(AttemptError::Rejected(
            "ECS mismatch in TCP response".to_string(),
        ));
    }

    debug!("Successfully received DNS response via TCP, size: {response_len}");
    Ok(response_buf)
}

/// Creates a resolver function for DNS queries
pub fn create_resolver(
    client: UpstreamClient,
) -> impl Fn(AttemptRequest) -> BoxFuture<'static, AttemptOutcome> + Send + Sync + 'static {
    let client = Arc::new(client);
    move |request| {
        let client = client.clone();
        Box::pin(async move { client.attempt(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{PARK_AFTER_FAILURES, ResolverStats};

    fn query() -> Vec<u8> {
        dns_parser::EXAMPLE_COM_QUERY.to_vec()
    }

    fn client(server_timeout: u64, stats: &Arc<SharedStats>) -> UpstreamClient {
        UpstreamClient {
            server_timeout,
            dns_packet_len_max: 4096,
            spoof_protection: true,
            stats: Some(stats.clone()),
        }
    }

    /// Runs an attempt the way the query manager does, with its deadline
    async fn run(
        client: &UpstreamClient,
        effective_ecs: Option<EdnsClientSubnet>,
        upstream: SocketAddr,
    ) -> (Result<Vec<u8>, AttemptError>, AttemptFlags) {
        let progress = Arc::new(AttemptProgress::default());
        let deadline = Instant::now() + Duration::from_secs(client.server_timeout);
        let request = AttemptRequest {
            query: query(),
            effective_ecs,
            upstream,
            deadline,
            progress: progress.clone(),
        };
        let outcome = progress
            .run_until(
                deadline,
                upstream,
                client.stats.as_deref(),
                client.attempt(request),
            )
            .await;
        assert_eq!(outcome.upstream, upstream);
        (outcome.result, progress.flags())
    }

    async fn resolver_stats(stats: &SharedStats, upstream: SocketAddr) -> ResolverStats {
        stats
            .get_stats()
            .await
            .get_resolver_stats(&upstream)
            .cloned()
            .unwrap_or_default()
    }

    /// Like a real DNS server, the upstream listens for UDP and TCP on the same port
    async fn bind_upstream() -> (UdpSocket, tokio::net::TcpListener, SocketAddr) {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
        (udp, tcp, addr)
    }

    /// Answers the UDP queries with these flags and this transaction ID change, except the first `ignored` ones
    async fn answer_over_udp(udp: UdpSocket, flags: u16, tid_change: u16, ignored: usize) {
        let mut packet = vec![0u8; 4096];
        for datagram in 0.. {
            let Ok((length, client)) = udp.recv_from(&mut packet).await else {
                break;
            };
            if datagram < ignored {
                continue;
            }
            let mut response = packet[..length].to_vec();
            dns_parser::set_flags(&mut response, flags).unwrap();
            let tid = dns_parser::tid(&response).wrapping_add(tid_change);
            dns_parser::set_tid(&mut response, tid).unwrap();
            udp.send_to(&response, client).await.unwrap();
        }
    }

    /// Answers one TCP query with an answer that has no TC flag, once `release` fires
    async fn answer_over_tcp(
        tcp: tokio::net::TcpListener,
        accepted: Option<tokio::sync::oneshot::Sender<()>>,
        release: impl Future<Output = ()>,
    ) {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut packet = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut packet).await.unwrap();
        if let Some(accepted) = accepted {
            accepted.send(()).unwrap();
        }
        release.await;
        dns_parser::set_flags(&mut packet, 0x8180).unwrap();
        stream.write_all(&length).await.unwrap();
        stream.write_all(&packet).await.unwrap();
    }

    /// An upstream server that never answers, outside of Tokio so that paused time doesn't wait for it
    fn silent_upstream() -> (std::net::UdpSocket, SocketAddr) {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let addr = udp.local_addr().unwrap();
        (udp, addr)
    }

    /// Counts the datagrams that reached a silent upstream server
    fn datagrams(udp: &std::net::UdpSocket) -> usize {
        // The kernel may still be delivering them
        std::thread::sleep(Duration::from_millis(100));
        let mut packet = vec![0u8; 4096];
        std::iter::from_fn(|| udp.recv_from(&mut packet).ok()).count()
    }

    #[tokio::test]
    async fn test_upstream_response_question_must_match() {
        let query = query();
        let mut response = query.clone();
        dns_parser::set_qr(&mut response, true).unwrap();
        let upstream = "127.0.0.1:53".parse().unwrap();
        let progress = AttemptProgress::default();

        assert!(
            process_response(
                &response, 0x1234, upstream, true, &query, None, None, &progress
            )
            .await
            .is_ok()
        );

        let qtype_offset = response.len() - 4;
        response[qtype_offset..qtype_offset + 2].copy_from_slice(&[0, 28]);
        assert!(matches!(
            process_response(
                &response, 0x1234, upstream, true, &query, None, None, &progress
            )
            .await,
            Err(AttemptError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn test_tcp_fallback_preserves_ecs() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let mut query = query();
        dns_parser::add_edns_section(&mut query, 1232).unwrap();
        dns_parser::add_edns_client_subnet(&mut query, "192.0.2.129", 24, 56, 1232).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await.unwrap();
            let mut received = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut received).await.unwrap();
            assert!(
                dns_parser::extract_edns_client_subnet(&received)
                    .unwrap()
                    .is_some()
            );
            dns_parser::set_qr(&mut received, true).unwrap();
            stream
                .write_all(&(received.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&received).await.unwrap();
        });

        let response = retry_with_tcp(&query, 0x1234, upstream).await.unwrap();
        server.await.unwrap();
        assert!(
            dns_parser::extract_edns_client_subnet(&response)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_datagram_from_another_source_is_ignored() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            let (length, client) = upstream.recv_from(&mut packet).await.unwrap();
            let stray = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            stray.send_to(b"junk", client).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            packet.truncate(length);
            dns_parser::set_qr(&mut packet, true).unwrap();
            upstream.send_to(&packet, client).await.unwrap();
        });
        let stats = Arc::new(SharedStats::new());

        let (response, _) = run(&client(2, &stats), None, upstream_addr).await;
        server.await.unwrap();

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_answered_retry_clears_the_failure_streak() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            // Drop the first attempt of every query and answer its retry
            for datagram in 1u64.. {
                let Ok((length, client)) = upstream.recv_from(&mut packet).await else {
                    break;
                };
                if datagram % 2 == 0 {
                    let mut response = packet[..length].to_vec();
                    dns_parser::set_qr(&mut response, true).unwrap();
                    upstream.send_to(&response, client).await.unwrap();
                }
            }
        });
        let stats = Arc::new(SharedStats::new());

        for _ in 0..2 {
            assert!(run(&client(2, &stats), None, upstream_addr).await.0.is_ok());
        }

        let resolver = resolver_stats(&stats, upstream_addr).await;
        assert_eq!(resolver.timeout_count, 2);
        assert_eq!(resolver.consecutive_failures, 0);
        assert_eq!(resolver.budget_expiration_count, 0);
    }

    #[tokio::test]
    async fn test_invalid_answer_does_not_unpark_a_resolver() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            // Reply with the right ID, but for a different name
            let mut packet = vec![0u8; 4096];
            let (length, client) = upstream.recv_from(&mut packet).await.unwrap();
            let mut response = packet[..length].to_vec();
            dns_parser::set_qr(&mut response, true).unwrap();
            response[13] = b'f';
            upstream.send_to(&response, client).await.unwrap();
        });
        let stats = Arc::new(SharedStats::new());
        for _ in 0..PARK_AFTER_FAILURES {
            stats.record_timeout(upstream_addr).await;
        }

        let (response, _) = run(&client(2, &stats), None, upstream_addr).await;
        assert!(matches!(response, Err(AttemptError::Rejected(_))));

        let resolver = resolver_stats(&stats, upstream_addr).await;
        assert_eq!(resolver.success_count, 0);
        assert_eq!(resolver.consecutive_failures, PARK_AFTER_FAILURES);
    }

    #[tokio::test]
    async fn test_truncated_answer_is_kept_when_tcp_fails() {
        let (udp, tcp, upstream) = bind_upstream().await;
        drop(tcp);
        tokio::spawn(answer_over_udp(udp, 0x8380, 0, 0));
        let stats = Arc::new(SharedStats::new());

        let (response, _) = run(&client(2, &stats), None, upstream).await;
        assert!(dns_parser::is_truncated(&response.unwrap()));

        let resolver = resolver_stats(&stats, upstream).await;
        assert_eq!(resolver.success_count, 1);
        assert_eq!(resolver.consecutive_failures, 0);
        assert_eq!(resolver.budget_expiration_count, 0);
    }

    #[tokio::test]
    async fn test_wrong_transaction_id_is_retried_over_tcp() {
        let (udp, tcp, upstream) = bind_upstream().await;
        tokio::spawn(answer_over_udp(udp, 0x8180, 1, 0));
        tokio::spawn(answer_over_tcp(tcp, None, async {}));
        let stats = Arc::new(SharedStats::new());

        let (response, progress) = run(&client(2, &stats), None, upstream).await;
        assert!(dns_parser::is_response(&response.unwrap()));
        assert!(progress.spoof_fallback);
    }

    #[tokio::test]
    async fn test_answer_for_another_subnet_is_rejected() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (forwarded_tx, forwarded_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut packet = vec![0u8; 4096];
            let (length, client) = upstream.recv_from(&mut packet).await.unwrap();
            let mut response =
                dns_parser::recover_question_from_response(&packet[..length]).unwrap();
            dns_parser::set_qr(&mut response, true).unwrap();
            dns_parser::add_edns_client_subnet(&mut response, "198.51.100.1", 24, 56, 1232)
                .unwrap();
            upstream.send_to(&response, client).await.unwrap();
            forwarded_tx.send(packet[..length].to_vec()).unwrap();
        });
        let ecs = EdnsClientSubnet {
            family: 1,
            source_prefix_length: 24,
            scope_prefix_length: 0,
            address: vec![192, 0, 2],
        };
        let stats = Arc::new(SharedStats::new());

        let (response, _) = run(&client(2, &stats), Some(ecs.clone()), upstream_addr).await;
        assert!(matches!(response, Err(AttemptError::Rejected(_))));

        // The upstream server got the subnet of the cache key
        let forwarded = forwarded_rx.await.unwrap();
        assert_eq!(
            dns_parser::extract_edns_client_subnet(&forwarded).unwrap(),
            Some(ecs)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_unanswered_attempt_expires_once() {
        for server_timeout in [1, 5] {
            let (udp, upstream) = silent_upstream();
            let stats = Arc::new(SharedStats::new());

            let (response, progress) = run(&client(server_timeout, &stats), None, upstream).await;

            assert_eq!(response, Err(AttemptError::BudgetExpired));
            assert!(progress.sent && progress.early_miss_recorded);
            let resolver = resolver_stats(&stats, upstream).await;
            assert_eq!(resolver.timeout_count, 1);
            assert_eq!(resolver.consecutive_failures, 1);
            assert_eq!(resolver.budget_expiration_count, 1);
            assert_eq!(stats.get_stats().await.total_timeouts, 1);

            // Without time left for a retry, there is no second datagram
            let expected_datagrams = if server_timeout == 1 { 1 } else { 2 };
            assert_eq!(datagrams(&udp), expected_datagrams);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_first_miss_is_recorded_before_the_deadline() {
        let (_udp, upstream) = silent_upstream();
        let stats = Arc::new(SharedStats::new());
        tokio::spawn({
            let client = client(4, &stats);
            async move { run(&client, None, upstream).await }
        });

        tokio::time::sleep(Duration::from_millis(2500)).await;
        let resolver = resolver_stats(&stats, upstream).await;
        assert_eq!(resolver.timeout_count, 1);
        assert_eq!(resolver.budget_expiration_count, 0);
    }

    // A reply could come after the paused clock jumps to the first deadline, so the time is real
    #[tokio::test]
    async fn test_truncated_answer_survives_the_deadline() {
        let (udp, tcp, upstream) = bind_upstream().await;
        tokio::spawn(answer_over_udp(udp, 0x8380, 0, 0));
        tokio::spawn(answer_over_tcp(tcp, None, std::future::pending()));
        let stats = Arc::new(SharedStats::new());

        let (response, _) = run(&client(2, &stats), None, upstream).await;

        assert!(dns_parser::is_truncated(&response.unwrap()));
        let resolver = resolver_stats(&stats, upstream).await;
        assert_eq!(resolver.success_count, 1);
        assert_eq!(resolver.timeout_count, 0);
        assert_eq!(resolver.consecutive_failures, 0);
        assert_eq!(resolver.budget_expiration_count, 1);
    }

    #[tokio::test]
    async fn test_truncated_answer_unparks_before_tcp_completes() {
        // The UDP answer comes for the first datagram, then only for the retry
        for ignored in [0, 1] {
            let (udp, tcp, upstream) = bind_upstream().await;
            let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(answer_over_udp(udp, 0x8380, 0, ignored));
            tokio::spawn(answer_over_tcp(tcp, Some(accepted_tx), async {
                release_rx.await.unwrap();
            }));
            let stats = Arc::new(SharedStats::new());
            stats.record_success(upstream, Duration::from_secs(1)).await;
            for _ in 0..PARK_AFTER_FAILURES {
                stats.record_timeout(upstream).await;
            }
            assert!(stats.get_stats().await.is_parked(&upstream));

            let attempt = tokio::spawn({
                let client = client(5, &stats);
                async move { run(&client, None, upstream).await }
            });
            accepted_rx.await.unwrap();

            let resolver = resolver_stats(&stats, upstream).await;
            assert_eq!(resolver.consecutive_failures, 0);
            assert!(!stats.get_stats().await.is_parked(&upstream));
            let expected_successes = if ignored == 0 { 2 } else { 1 };
            assert_eq!(resolver.success_count, expected_successes);
            // A reply to a retry is not a response time sample
            assert_eq!(resolver.avg_response_time_ms < 1000.0, ignored == 0);

            release_tx.send(()).unwrap();
            let (response, _) = attempt.await.unwrap();
            assert!(!dns_parser::is_truncated(&response.unwrap()));
            let after = resolver_stats(&stats, upstream).await;
            assert_eq!(after.success_count, resolver.success_count);
            assert_eq!(after.avg_response_time_ms, resolver.avg_response_time_ms);
        }
    }

    #[tokio::test]
    async fn test_stalled_tcp_after_wrong_transaction_id_is_not_a_failure() {
        let (udp, tcp, upstream) = bind_upstream().await;
        tokio::spawn(answer_over_udp(udp, 0x8180, 1, 0));
        tokio::spawn(answer_over_tcp(tcp, None, std::future::pending()));
        let stats = Arc::new(SharedStats::new());

        let (response, progress) = run(&client(2, &stats), None, upstream).await;

        assert_eq!(response, Err(AttemptError::BudgetExpired));
        assert!(progress.spoof_fallback);
        let resolver = resolver_stats(&stats, upstream).await;
        assert_eq!(resolver.timeout_count, 0);
        assert_eq!(resolver.failure_count, 0);
        assert_eq!(resolver.consecutive_failures, 0);
        assert_eq!(resolver.budget_expiration_count, 1);
    }

    #[tokio::test]
    async fn test_reply_waiting_for_the_stats_is_kept_at_the_deadline() {
        let (udp, _tcp, upstream) = bind_upstream().await;
        tokio::spawn(answer_over_udp(udp, 0x8180, 0, 0));
        let stats = Arc::new(SharedStats::new());

        // The reply comes at once, but the stats stay locked until after the deadline
        let stats_guard = stats.lock().await;
        let attempt = tokio::spawn({
            let client = client(1, &stats);
            async move { run(&client, None, upstream).await }
        });
        tokio::time::sleep(Duration::from_millis(1200)).await;
        drop(stats_guard);

        let (response, _) = attempt.await.unwrap();
        assert!(dns_parser::is_response(&response.unwrap()));
        let resolver = resolver_stats(&stats, upstream).await;
        assert_eq!(resolver.success_count, 1);
        assert_eq!(resolver.timeout_count, 0);
    }

    #[tokio::test]
    async fn test_refused_tcp_after_wrong_transaction_id_is_not_a_failure() {
        let (udp, tcp, upstream) = bind_upstream().await;
        drop(tcp);
        tokio::spawn(answer_over_udp(udp, 0x8180, 1, 0));
        let stats = Arc::new(SharedStats::new());

        let (response, progress) = run(&client(2, &stats), None, upstream).await;

        assert!(matches!(response, Err(AttemptError::Transport(_))));
        assert!(progress.spoof_fallback);
        let resolver = resolver_stats(&stats, upstream).await;
        assert_eq!(resolver.consecutive_failures, 0);
        assert_eq!(stats.get_stats().await.total_queries, 0);
    }

    #[tokio::test]
    async fn test_socket_error_is_local() {
        // Broadcast needs SO_BROADCAST, so sending fails
        let upstream = "255.255.255.255:53".parse().unwrap();
        let stats = Arc::new(SharedStats::new());

        let (response, progress) = run(&client(2, &stats), None, upstream).await;

        assert!(matches!(response, Err(AttemptError::Local(_))));
        assert!(!progress.sent);
        assert_eq!(stats.get_stats().await.total_queries, 0);
    }

    #[tokio::test]
    async fn test_attempt_stopped_before_sending_is_not_a_miss() {
        let upstream = "192.0.2.1:53".parse().unwrap();
        let stats = SharedStats::new();

        let outcome = AttemptProgress::default()
            .expire(upstream, Some(&stats))
            .await;

        assert_eq!(outcome.result, Err(AttemptError::BudgetExpired));
        assert!(stats.get_stats().await.resolver_stats.is_empty());
    }
}
