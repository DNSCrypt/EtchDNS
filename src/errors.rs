use std::io;
use thiserror::Error;

/// Main error type for the EtchDNS application
#[derive(Debug, Error)]
pub enum EtchDnsError {
    /// Error occurred while parsing configuration
    #[error("Failed to parse configuration: {0}")]
    ConfigParseError(String),

    /// Error occurred while reading configuration file
    #[error("Failed to read configuration file: {0}")]
    ConfigReadError(String),

    /// Error occurred while binding to socket
    #[error("Failed to bind to socket: {0}")]
    SocketBindError(#[source] io::Error),

    /// Error occurred while sending data
    #[error("Failed to send data: {0}")]
    #[allow(dead_code)]
    SendError(#[source] io::Error),

    /// Error occurred while receiving data
    #[error("Failed to receive data: {0}")]
    #[allow(dead_code)]
    ReceiveError(#[source] io::Error),

    /// Error occurred while processing DNS packet
    #[error("DNS packet processing error: {0}")]
    DnsProcessingError(#[from] DnsError),

    /// Error occurred while managing client connections
    #[error("Client management error: {0}")]
    #[allow(dead_code)]
    ClientError(String),

    /// Error occurred while dropping privileges
    #[error("Failed to drop privileges: {0}")]
    PrivilegeDropError(String),

    /// Other errors
    #[error("Other error: {0}")]
    Other(String),
}

/// DNS-specific error types
#[derive(Debug, Error)]
pub enum DnsError {
    /// Error occurred while parsing DNS packet
    #[error("DNS packet parsing error: {0}")]
    #[allow(dead_code)]
    ParseError(String),

    /// Error occurred due to invalid DNS packet format
    #[error("Invalid DNS packet: {0}")]
    InvalidPacket(String),

    /// Error occurred due to unsupported DNS operation
    #[error("Unsupported DNS operation: {0}")]
    UnsupportedOperation(String),

    /// Error occurred due to DNS packet being too short
    #[error("DNS packet too short at offset {offset}")]
    PacketTooShort { offset: usize },

    /// Error occurred due to DNS packet being too large
    #[error("DNS packet too large: {size} bytes (max {max_size} bytes)")]
    PacketTooLarge { size: usize, max_size: usize },

    /// Error occurred due to invalid domain name in DNS packet
    #[error("Invalid domain name: {0}")]
    InvalidDomainName(String),

    /// Error occurred due to domain name label being too long
    #[error("Domain name label too long: {length} bytes (max 63 bytes)")]
    LabelTooLong { length: usize },

    /// Error occurred due to domain name being too long
    #[error("Domain name too long: {length} bytes (max {max_length} bytes)")]
    DomainNameTooLong { length: usize, max_length: usize },

    /// Error occurred due to invalid character in domain name
    #[error("Invalid character '{character}' at position {position} in label '{label}'")]
    InvalidDomainNameCharacter {
        character: char,
        position: usize,
        label: String,
    },

    /// Error occurred due to empty label in domain name
    #[error("Empty label in domain name")]
    EmptyLabel,

    /// Error occurred due to too many compression pointers
    #[error("Too many compression pointers: {count} (max 10)")]
    TooManyCompressionPointers { count: usize },

    /// Error occurred due to invalid compression pointer
    #[error(
        "Invalid compression pointer at offset {offset}: points to {pointer} (packet size: {packet_size})"
    )]
    InvalidCompressionPointer {
        offset: usize,
        pointer: usize,
        packet_size: usize,
    },

    /// Error occurred due to invalid record in DNS packet
    #[error("Invalid record: {0}")]
    InvalidRecord(String),

    /// Error occurred due to invalid question in DNS packet
    #[error("Invalid question: {0}")]
    InvalidQuestion(String),

    /// Error occurred due to invalid EDNS data
    #[error("Invalid EDNS data: {0}")]
    InvalidEdns(String),

    /// Error occurred due to invalid EDNS-client-subnet data
    #[error("Invalid EDNS-client-subnet data: {0}")]
    #[allow(dead_code)]
    InvalidEdnsClientSubnet(String),

    /// Error occurred due to unsupported EDNS version
    #[error("Unsupported EDNS version: {version} (only version 0 is supported)")]
    UnsupportedEdnsVersion { version: u8 },

    /// Error occurred while communicating with upstream DNS server
    #[error("Upstream DNS server error: {0}")]
    UpstreamError(String),

    /// Error occurred due to timeout while waiting for upstream DNS server
    #[error("Upstream DNS server timeout")]
    UpstreamTimeout,

    /// Other DNS-related errors
    #[error("Other DNS error: {0}")]
    Other(String),
}

/// Result type for DNS operations
pub type DnsResult<T> = Result<T, DnsError>;

/// Result type for EtchDNS operations
pub type EtchDnsResult<T> = Result<T, EtchDnsError>;

/// Convert from io::Error to DnsError
impl From<io::Error> for DnsError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut => DnsError::UpstreamTimeout,
            _ => DnsError::Other(error.to_string()),
        }
    }
}

/// Convert from String to DnsError
impl From<String> for DnsError {
    fn from(error: String) -> Self {
        DnsError::Other(error)
    }
}

/// Convert from &str to DnsError
impl From<&str> for DnsError {
    fn from(error: &str) -> Self {
        DnsError::Other(error.to_string())
    }
}
