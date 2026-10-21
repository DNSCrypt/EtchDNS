use std::hash::{Hash, Hasher};

use crate::dns_parser;
use crate::errors::{DnsError, DnsResult};

/// A structure representing a DNS query key for caching purposes.
///
/// This structure contains the normalized query name, query type, query class,
/// and whether DNSSEC is requested. It can be used as a key in a hash map
/// to cache DNS responses.
#[derive(Debug, Clone, Eq)]
pub struct DNSKey {
    /// The normalized query name (lowercase, no trailing dot)
    pub name: String,
    /// The query type (e.g., A, AAAA, MX)
    pub qtype: u16,
    /// The query class (usually IN)
    pub qclass: u16,
    /// Whether DNSSEC is requested
    pub dnssec: bool,
    /// Whether recursive processing is requested
    pub recursion_desired: bool,
    /// Whether DNSSEC validation is disabled
    pub checking_disabled: bool,
    /// Whether the client requests authenticated-data signaling
    pub authenticated_data: bool,
    /// EDNS client subnet carried by the effective query
    pub client_subnet: Option<dns_parser::EdnsClientSubnet>,
}

impl DNSKey {
    /// Creates a new DNSKey with the given parameters
    ///
    /// This function now returns a Result since normalize_name can fail
    pub fn new(name: String, qtype: u16, qclass: u16, dnssec: bool) -> DnsResult<Self> {
        // Normalize the name (lowercase, no trailing dot)
        let normalized_name = Self::normalize_name(&name)?;

        Ok(DNSKey {
            name: normalized_name,
            qtype,
            qclass,
            dnssec,
            recursion_desired: false,
            checking_disabled: false,
            authenticated_data: false,
            client_subnet: None,
        })
    }

    /// Creates a DNSKey from a DNS packet
    pub fn from_packet(packet: &[u8]) -> DnsResult<Self> {
        dns_parser::validate_dns_packet(packet)?;

        let qname_bytes = dns_parser::qname(packet)?;
        let qname = match std::str::from_utf8(&qname_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                return Err(DnsError::InvalidDomainName(
                    "Invalid UTF-8 in query name".to_string(),
                ));
            }
        };

        let (qtype, qclass) = dns_parser::query_type_class(packet)?;
        let mut key = DNSKey::new(qname, qtype, qclass, dns_parser::is_dnssec_ok(packet)?)?;
        key.recursion_desired = dns_parser::is_recursion_desired(packet);
        key.checking_disabled = dns_parser::is_checking_disabled(packet);
        key.authenticated_data = dns_parser::is_authenticated_data_requested(packet);
        key.client_subnet = dns_parser::extract_edns_client_subnet(packet)?;
        Ok(key)
    }

    /// Drops the query flags that don't change an authoritative answer, so that all resolvers share one cache entry.
    pub fn ignore_resolver_flags(&mut self) {
        self.recursion_desired = false;
        self.checking_disabled = false;
        self.authenticated_data = false;
    }

    /// Replaces the ECS part of this key with the subnet sent upstream.
    pub fn set_client_subnet(&mut self, client_ip: &str, prefix_v4: u8, prefix_v6: u8) {
        self.client_subnet = client_ip
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| dns_parser::EdnsClientSubnet::for_client(ip, prefix_v4, prefix_v6));
    }

    /// Normalizes a domain name for consistent caching and comparison
    pub fn normalize_name(name: &str) -> DnsResult<String> {
        if name.len() > crate::dns_parser::DNS_MAX_HOSTNAME_SIZE {
            return Err(DnsError::InvalidDomainName(format!(
                "Name too long: {} bytes (max {})",
                name.len(),
                crate::dns_parser::DNS_MAX_HOSTNAME_SIZE
            )));
        }
        if name.is_empty() || name == "." {
            return Ok(".".to_string());
        }
        if name.starts_with('.') {
            return Err(DnsError::InvalidDomainName(
                "Name cannot start with a dot".to_string(),
            ));
        }
        if name.contains("..") {
            return Err(DnsError::InvalidDomainName(
                "Name contains consecutive dots".to_string(),
            ));
        }
        let name = name.trim_end_matches('.');
        let normalized = name.to_lowercase();
        Ok(normalized)
    }
}

impl PartialEq for DNSKey {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.qtype == other.qtype
            && self.qclass == other.qclass
            && self.dnssec == other.dnssec
            && self.recursion_desired == other.recursion_desired
            && self.checking_disabled == other.checking_disabled
            && self.authenticated_data == other.authenticated_data
            && self.client_subnet == other.client_subnet
    }
}

impl Hash for DNSKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.qtype.hash(state);
        self.qclass.hash(state);
        self.dnssec.hash(state);
        self.recursion_desired.hash(state);
        self.checking_disabled.hash(state);
        self.authenticated_data.hash(state);
        self.client_subnet.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[test]
    fn query_flags_are_part_of_the_key() {
        let base = DNSKey::from_packet(&query()).unwrap();

        let mut no_recursion = query();
        no_recursion[2] &= !0x01;
        assert_ne!(base, DNSKey::from_packet(&no_recursion).unwrap());

        let mut checking_disabled = query();
        checking_disabled[3] |= 0x10;
        assert_ne!(base, DNSKey::from_packet(&checking_disabled).unwrap());

        let mut authenticated_data = query();
        authenticated_data[3] |= 0x20;
        assert_ne!(base, DNSKey::from_packet(&authenticated_data).unwrap());

        let mut dnssec_ok = query();
        dns_parser::add_edns_section(&mut dnssec_ok, 1232).unwrap();
        let opt_start = dnssec_ok.len() - 11;
        dnssec_ok[opt_start + 7] |= 0x80;
        assert_ne!(base, DNSKey::from_packet(&dnssec_ok).unwrap());
    }

    #[test]
    fn effective_client_subnet_is_masked_in_the_key() {
        let mut key = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();
        key.set_client_subnet("192.0.2.129", 25, 56);

        let subnet = key.client_subnet.unwrap();
        assert_eq!(subnet.family, 1);
        assert_eq!(subnet.source_prefix_length, 25);
        assert_eq!(subnet.address, vec![192, 0, 2, 128]);
    }
}
