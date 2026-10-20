use byteorder::{BigEndian, ByteOrder};
use log::debug;
use std::str;

use crate::errors::{DnsError, DnsResult};

// DNS packet constants
pub const DNS_PACKET_LEN_MIN: usize = 12; // Minimum size of a DNS packet (header only)
pub const DNS_HEADER_SIZE: usize = DNS_PACKET_LEN_MIN; // Size of the DNS header
pub const DNS_MAX_PACKET_SIZE: usize = 0x1600; // Maximum size of a DNS packet
pub const DNS_MAX_HOSTNAME_SIZE: usize = 256; // Maximum size of a hostname
pub const DNS_OFFSET_QUESTION: usize = DNS_HEADER_SIZE; // Offset to the question section
pub const DNS_MAX_UDP_PACKET_SIZE: usize = 512; // Standard maximum UDP packet size (RFC 1035)

// DNS record types
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
#[allow(dead_code)]
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_RRSIG: u16 = 46;
pub const DNS_TYPE_ANY: u16 = 255;

#[cfg(test)]
pub(crate) const NEGATIVE_RESPONSE_WITH_SOA_TTL_3600_MINIMUM_60: &[u8] = &[
    0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
    0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x3c,
];

// DNS classes
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_CH: u16 = 3;
pub const DNS_CLASS_ANY: u16 = 255;

// DNSSEC related constants
pub const DNS_FLAG_DO: u16 = 0x8000; // DNSSEC OK flag in OPT record

// EDNS option codes
pub const EDNS_OPTION_CLIENT_SUBNET: u16 = 8; // Client Subnet (RFC 7871)
pub const EDNS_OPTION_COOKIE: u16 = 10; // DNS Cookies (RFC 7873)

// DNS header flags
const DNS_FLAGS_QR: u16 = 1u16 << 15; // Query/Response flag
const DNS_FLAGS_AA: u16 = 1u16 << 10; // Authoritative Answer flag
const DNS_FLAGS_TC: u16 = 1u16 << 9; // Truncation flag
#[allow(dead_code)]
const DNS_FLAGS_RD: u16 = 1u16 << 8; // Recursion Desired
const DNS_FLAGS_RA: u16 = 1u16 << 7; // Recursion Available flag
const DNS_FLAGS_CD: u16 = 1u16 << 4; // Checking Disabled (DNSSEC)
#[allow(dead_code)]
const DNS_FLAGS_AD: u16 = 1u16 << 5; // Authentic Data (DNSSEC)

// DNS opcodes (in bits 11-14 of the flags field)
pub const DNS_OPCODE_QUERY: u8 = 0; // Standard query
#[allow(dead_code)]
pub const DNS_OPCODE_IQUERY: u8 = 1; // Inverse query
#[allow(dead_code)]
pub const DNS_OPCODE_STATUS: u8 = 2; // Server status request
#[allow(dead_code)]
pub const DNS_OPCODE_NOTIFY: u8 = 4; // Zone change notification
#[allow(dead_code)]
pub const DNS_OPCODE_UPDATE: u8 = 5; // Dynamic update

/// Checks that a DNS packet looks valid, and returns the length of the message in it.
///
/// Some clients add extra bytes after the last record.
/// They are allowed, but must be cut off before changing the message, or they could end up
/// being read as records.
pub fn validate_dns_packet(packet: &[u8]) -> DnsResult<usize> {
    // Check minimum packet size
    if packet.len() < DNS_HEADER_SIZE {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    // Check maximum packet size
    if packet.len() > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet.len(),
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }

    // Check opcode - we only support standard queries (opcode 0)
    if !is_response(packet) {
        let op = opcode(packet);
        if op != DNS_OPCODE_QUERY {
            return Err(DnsError::UnsupportedOperation(format!(
                "Unsupported opcode: {op}"
            )));
        }
    }

    // Check that we have at least one question
    let qd_count = qdcount(packet);
    if qd_count == 0 {
        return Err(DnsError::InvalidPacket(
            "No questions in packet".to_string(),
        ));
    }

    // For standard DNS queries, we typically expect exactly one question
    if qd_count > 1 {
        return Err(DnsError::InvalidPacket(
            "Too many questions in packet".to_string(),
        ));
    }

    // Validate the counts make sense for the packet size
    let (an_count, ns_count, ar_count) = (ancount(packet), nscount(packet), arcount(packet));

    // Try to parse the question section
    let mut offset = DNS_HEADER_SIZE;

    // Validate each question section
    for _ in 0..qd_count {
        // Validate the question name
        offset = match skip_name(packet, offset) {
            Ok(new_offset) => new_offset,
            Err(e) => {
                return Err(DnsError::InvalidQuestion(format!(
                    "Invalid question name: {e}"
                )));
            }
        };

        // Ensure there's enough space for QTYPE and QCLASS (4 bytes)
        if packet.len() < offset + 4 {
            return Err(DnsError::InvalidPacket(
                "Packet too short for QTYPE and QCLASS".to_string(),
            ));
        }

        // Read QTYPE and QCLASS
        let qtype_end = offset.checked_add(2).ok_or_else(|| {
            DnsError::InvalidPacket("Integer overflow calculating QTYPE offset".to_string())
        })?;
        let qclass_end = offset.checked_add(4).ok_or_else(|| {
            DnsError::InvalidPacket("Integer overflow calculating QCLASS offset".to_string())
        })?;
        let _qtype = BigEndian::read_u16(&packet[offset..qtype_end]);
        let qclass = BigEndian::read_u16(&packet[qtype_end..qclass_end]);

        // Validate QCLASS (typically IN=1 or ANY=255)
        if qclass != DNS_CLASS_IN && qclass != DNS_CLASS_ANY {
            debug!("Unusual: DNS query with QCLASS={qclass}");
        }

        // Additional validation: extract the query name and validate it
        match qname(packet) {
            Ok(name) => {
                if name.len() > DNS_MAX_HOSTNAME_SIZE {
                    return Err(DnsError::DomainNameTooLong {
                        length: name.len(),
                        max_length: DNS_MAX_HOSTNAME_SIZE,
                    });
                }

                // Validate domain name characters
                let labels: Vec<&[u8]> = name.split(|&c| c == b'.').collect();
                for label in labels {
                    if label.is_empty() {
                        // Skip empty labels (like the root label) in normal domain names
                        // But if it's between other labels (like "example..com"), that's an error
                        if !name.starts_with(b".") && !name.ends_with(b".") && name.len() > 1 {
                            return Err(DnsError::EmptyLabel);
                        }
                        continue;
                    }

                    // Check label length
                    if label.len() > 63 {
                        return Err(DnsError::LabelTooLong {
                            length: label.len(),
                        });
                    }

                    // Validate each character in the label
                    for (i, &c) in label.iter().enumerate() {
                        if !is_valid_domain_name_char(c, i, label.len()) {
                            let label_str = match std::str::from_utf8(label) {
                                Ok(s) => s.to_string(),
                                Err(_) => format!("{label:?}"),
                            };

                            return Err(DnsError::InvalidDomainNameCharacter {
                                character: c as char,
                                position: i,
                                label: label_str,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                return Err(DnsError::InvalidQuestion(format!(
                    "Failed to extract query name: {e}"
                )));
            }
        }

        offset = offset.checked_add(4).ok_or_else(|| {
            DnsError::InvalidPacket("Integer overflow advancing past QTYPE/QCLASS".to_string())
        })?;
    }

    // Try to validate the answer, authority, and additional sections
    // Check for potential overflow when calculating total_rr_count
    let an_count_usize = an_count as usize;
    let ns_count_usize = ns_count as usize;
    let ar_count_usize = ar_count as usize;

    // Check for overflow when adding up the counts
    let total_rr_count = match an_count_usize.checked_add(ns_count_usize) {
        Some(count) => match count.checked_add(ar_count_usize) {
            Some(total) => total,
            None => {
                return Err(DnsError::InvalidPacket(
                    "Integer overflow in resource record count calculation".to_string(),
                ));
            }
        },
        None => {
            return Err(DnsError::InvalidPacket(
                "Integer overflow in resource record count calculation".to_string(),
            ));
        }
    };

    // Validate against maximum sensible number of records
    const MAX_SENSIBLE_RR_COUNT: usize = 1000;
    if total_rr_count > MAX_SENSIBLE_RR_COUNT {
        return Err(DnsError::InvalidPacket(format!(
            "Excessive resource record count: {total_rr_count} (max {MAX_SENSIBLE_RR_COUNT})"
        )));
    }

    if total_rr_count > 0 {
        match traverse_rrs(packet, offset, total_rr_count, |rr_offset| {
            // Validate record type
            // Make sure we have at least 2 bytes to read at rr_offset
            if packet.len() < rr_offset + 2 {
                return Err(DnsError::PacketTooShort { offset: rr_offset });
            }
            let _rr_type = BigEndian::read_u16(&packet[rr_offset..rr_offset + 2]);

            // Validate TTL - make sure we have at least 8 bytes at rr_offset
            if packet.len() < rr_offset + 8 {
                return Err(DnsError::PacketTooShort { offset: rr_offset });
            }
            let ttl = BigEndian::read_u32(&packet[rr_offset + 4..rr_offset + 8]);
            if ttl > 604800 {
                // 7 days in seconds
                debug!("Unusual: DNS record with TTL > 7 days: {ttl} seconds");
            }

            // Validate RDLENGTH - make sure we have at least 10 bytes at rr_offset
            if packet.len() < rr_offset + 10 {
                return Err(DnsError::PacketTooShort { offset: rr_offset });
            }
            let rdlength = BigEndian::read_u16(&packet[rr_offset + 8..rr_offset + 10]) as usize;

            // Check for potential overflow when calculating rr_offset + 10 + rdlength
            let rr_data_end = match rr_offset.checked_add(10) {
                Some(offset_plus_10) => match offset_plus_10.checked_add(rdlength) {
                    Some(end_offset) => end_offset,
                    None => {
                        return Err(DnsError::InvalidRecord(
                            "Integer overflow calculating record data bounds".to_string(),
                        ));
                    }
                },
                None => {
                    return Err(DnsError::InvalidRecord(
                        "Integer overflow calculating record data bounds".to_string(),
                    ));
                }
            };

            if packet.len() < rr_data_end {
                return Err(DnsError::InvalidRecord(format!(
                    "Record data length ({rdlength}) exceeds packet bounds"
                )));
            }

            Ok(())
        }) {
            Ok(_) => (),
            Err(e) => {
                return Err(DnsError::InvalidRecord(format!(
                    "Invalid resource record: {e}"
                )));
            }
        }
    }

    let additional_offset = traverse_rrs(
        packet,
        offset,
        an_count as usize + ns_count as usize,
        |_| Ok(()),
    )?;
    let message_len = validate_edns_records(packet, additional_offset, ar_count as usize)?;

    // Check EDNS version if OPT record is present
    if let Some(edns_version) = extract_edns_version(packet)?
        && edns_version != 0
    {
        return Err(DnsError::UnsupportedEdnsVersion {
            version: edns_version,
        });
    }

    Ok(message_len)
}

fn validate_edns_records(packet: &[u8], mut offset: usize, arcount: usize) -> DnsResult<usize> {
    let mut found_opt = false;

    for _ in 0..arcount {
        let owner_offset = offset;
        let rr_offset = skip_name(packet, owner_offset)?;
        if packet.len().saturating_sub(rr_offset) < 10 {
            return Err(DnsError::PacketTooShort { offset: rr_offset });
        }

        if BigEndian::read_u16(&packet[rr_offset..rr_offset + 2]) == DNS_TYPE_OPT {
            if packet[owner_offset] != 0 {
                return Err(DnsError::InvalidEdns(
                    "OPT record owner must be the root name".to_string(),
                ));
            }
            if found_opt {
                return Err(DnsError::InvalidEdns("Duplicate OPT RR found".to_string()));
            }
            found_opt = true;
        }

        offset = traverse_rrs(packet, owner_offset, 1, |_| Ok(()))?;
    }

    Ok(offset)
}

/// Returns the transaction ID from the DNS packet
#[inline]
pub fn tid(packet: &[u8]) -> u16 {
    if packet.len() < 2 {
        return 0; // Return 0 for malformed packets
    }
    BigEndian::read_u16(&packet[0..2])
}

/// Returns the number of questions in the DNS packet
#[inline]
pub fn qdcount(packet: &[u8]) -> u16 {
    if packet.len() < 6 {
        return 0; // Return 0 for malformed packets
    }
    BigEndian::read_u16(&packet[4..6])
}

/// Returns the number of answer records in the DNS packet
#[inline]
pub fn ancount(packet: &[u8]) -> u16 {
    if packet.len() < 8 {
        return 0; // Return 0 for malformed packets
    }
    BigEndian::read_u16(&packet[6..8])
}

/// Returns the number of authority records in the DNS packet
#[inline]
pub fn nscount(packet: &[u8]) -> u16 {
    if packet.len() < 10 {
        return 0; // Return 0 for malformed packets
    }
    BigEndian::read_u16(&packet[8..10])
}

/// Returns the number of additional records in the DNS packet
#[inline]
pub fn arcount(packet: &[u8]) -> u16 {
    if packet.len() < DNS_PACKET_LEN_MIN {
        return 0; // Return 0 for malformed packets
    }
    BigEndian::read_u16(&packet[10..DNS_PACKET_LEN_MIN])
}

/// Returns the response code from the DNS packet
#[inline]
pub fn rcode(packet: &[u8]) -> u8 {
    if packet.len() < 4 {
        return 2; // Return SERVFAIL (2) for truncated packets
    }
    packet[3] & 0x0F
}

/// Checks if the packet is a response
#[inline]
pub fn is_response(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false; // Not a response if packet is too short
    }
    (BigEndian::read_u16(&packet[2..4]) & DNS_FLAGS_QR) == DNS_FLAGS_QR
}

/// Returns the opcode from the DNS packet
#[inline]
pub fn opcode(packet: &[u8]) -> u8 {
    if packet.len() < 3 {
        return 0; // Return standard query (0) for malformed packets
    }
    (packet[2] >> 3) & 0x0F
}

/// Checks if the packet is a standard query
#[inline]
#[allow(dead_code)]
pub fn is_standard_query(packet: &[u8]) -> bool {
    !is_response(packet) && opcode(packet) == DNS_OPCODE_QUERY
}

/// Checks if the packet has the TC (truncated) bit set
#[inline]
pub fn is_truncated(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false; // Not truncated if packet is too short
    }
    (BigEndian::read_u16(&packet[2..4]) & DNS_FLAGS_TC) == DNS_FLAGS_TC
}

/// Checks if DNSSEC is requested (either DO bit set or CD bit set)
#[allow(dead_code)]
pub fn is_dnssec_requested(packet: &[u8]) -> DnsResult<bool> {
    if packet.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    if is_checking_disabled(packet) {
        return Ok(true);
    }

    is_dnssec_ok(packet)
}

/// Checks whether the DNSSEC OK bit is set in an OPT record.
pub fn is_dnssec_ok(packet: &[u8]) -> DnsResult<bool> {
    if packet.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    // Check for OPT record with DO bit set
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    // Skip the question section
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet_len.saturating_sub(offset) < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    offset = offset.checked_add(4).ok_or_else(|| {
        DnsError::InvalidPacket("Integer overflow skipping QTYPE/QCLASS".to_string())
    })?; // Skip QTYPE and QCLASS

    // Skip answer and authority sections
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(packet, offset, ancount as usize + nscount as usize, |_| {
        Ok(())
    })?;

    // Check additional records for OPT
    let mut dnssec_requested = false;
    traverse_rrs(packet, offset, arcount as usize, |offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype == DNS_TYPE_OPT {
            // OPT record found, check DO bit in flags
            let opt_flags = BigEndian::read_u16(&packet[offset + 6..]);
            if (opt_flags & DNS_FLAG_DO) == DNS_FLAG_DO {
                dnssec_requested = true;
            }
        }
        Ok(())
    })?;

    Ok(dnssec_requested)
}

/// Checks whether recursion is desired.
pub fn is_recursion_desired(packet: &[u8]) -> bool {
    flags(packet) & DNS_FLAGS_RD != 0
}

/// Checks whether DNSSEC validation is disabled.
pub fn is_checking_disabled(packet: &[u8]) -> bool {
    flags(packet) & DNS_FLAGS_CD != 0
}

/// Checks whether the client is interested in authenticated-data signaling.
pub fn is_authenticated_data_requested(packet: &[u8]) -> bool {
    flags(packet) & DNS_FLAGS_AD != 0
}

/// Extracts the query name from a DNS packet
#[allow(dead_code)]
pub fn query_name(packet: &[u8]) -> DnsResult<String> {
    let qname_bytes = qname(packet)?;

    // Validate maximum length before conversion
    if qname_bytes.len() > DNS_MAX_HOSTNAME_SIZE {
        return Err(DnsError::DomainNameTooLong {
            length: qname_bytes.len(),
            max_length: DNS_MAX_HOSTNAME_SIZE,
        });
    }

    let qname_str = match str::from_utf8(&qname_bytes) {
        Ok(s) => s,
        Err(_) => {
            return Err(DnsError::InvalidDomainName(
                "Invalid UTF-8 in query name".to_string(),
            ));
        }
    };

    // Check once more for DoS using large string allocations
    if qname_str.len() > DNS_MAX_HOSTNAME_SIZE {
        return Err(DnsError::DomainNameTooLong {
            length: qname_str.len(),
            max_length: DNS_MAX_HOSTNAME_SIZE,
        });
    }

    Ok(qname_str.to_string())
}

/// Extracts the query type and class from a DNS packet
pub fn query_type_class(packet: &[u8]) -> DnsResult<(u16, u16)> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if qdcount(packet) == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }

    let offset = skip_name(packet, DNS_HEADER_SIZE)?;
    if packet.len() - offset < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    let qtype = BigEndian::read_u16(&packet[offset..]);
    let qclass = BigEndian::read_u16(&packet[offset + 2..]);

    Ok((qtype, qclass))
}

/// Checks whether a DNS response carries the same question as a query.
pub fn questions_match(query: &[u8], response: &[u8]) -> DnsResult<bool> {
    if opcode(query) != opcode(response) {
        return Ok(false);
    }

    let query_name = qname(query)?;
    let response_name = qname(response)?;
    let query_fields = query_type_class(query)?;
    let response_fields = query_type_class(response)?;

    Ok(query_name.eq_ignore_ascii_case(&response_name) && query_fields == response_fields)
}

/// Makes the response question use the same letter case as the query.
///
/// Cached and shared responses keep the case of the first client that asked.
/// Resolvers that randomize the case of their queries reject them.
///
/// Fails if the names don't match.
pub fn restore_qname_case(response: &mut [u8], query: &[u8]) -> DnsResult<()> {
    if qdcount(response) == 0 {
        return Ok(());
    }
    let query_name = &query[DNS_HEADER_SIZE..skip_name(query, DNS_HEADER_SIZE)?];
    let response_name_end = skip_name(response, DNS_HEADER_SIZE)?;
    let response_name = &mut response[DNS_HEADER_SIZE..response_name_end];
    if !response_name.eq_ignore_ascii_case(query_name) {
        return Err(DnsError::InvalidPacket(
            "Response question doesn't match the query".to_string(),
        ));
    }
    response_name.copy_from_slice(query_name);
    Ok(())
}

/// Extracts the minimum TTL from all records in a DNS packet
pub fn extract_min_ttl(packet: &[u8]) -> DnsResult<Option<u32>> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if packet_len > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet_len,
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }
    if qdcount(packet) == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }

    // Skip the question section
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet_len - offset < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    offset += 4; // Skip QTYPE and QCLASS

    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    let total_rr_count = ancount as usize + nscount as usize + arcount as usize;

    if total_rr_count == 0 {
        return Ok(None);
    }

    let mut min_ttl: Option<u32> = None;

    traverse_rrs(packet, offset, total_rr_count, |offset| {
        let rr_type = BigEndian::read_u16(&packet[offset..offset + 2]);
        let ttl = BigEndian::read_u32(&packet[offset + 4..offset + 8]);

        // Ignore OPT records (type 41) when calculating minimum TTL
        if rr_type != DNS_TYPE_OPT {
            min_ttl = match min_ttl {
                None => Some(ttl),
                Some(current_min) => Some(std::cmp::min(current_min, ttl)),
            };
        }
        Ok(())
    })?;

    Ok(min_ttl)
}

/// Returns how long a DNS response may be cached.
///
/// RFC 2308 limits negative responses to the smaller of the authority SOA record TTL and its MINIMUM field.
pub fn extract_cache_ttl(packet: &[u8]) -> DnsResult<Option<u32>> {
    let min_ttl = extract_min_ttl(packet)?;
    if ancount(packet) != 0 {
        return Ok(min_ttl);
    }

    let negative_ttl = extract_negative_ttl(packet)?;
    Ok(match (min_ttl, negative_ttl) {
        (Some(min_ttl), Some(negative_ttl)) => Some(min_ttl.min(negative_ttl)),
        (Some(ttl), None) | (None, Some(ttl)) => Some(ttl),
        (None, None) => None,
    })
}

fn extract_negative_ttl(packet: &[u8]) -> DnsResult<Option<u32>> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if packet_len > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet_len,
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }
    if qdcount(packet) == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }

    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet_len.saturating_sub(offset) < 4 {
        return Err(DnsError::PacketTooShort { offset });
    }
    offset += 4;

    let mut negative_ttl = None;
    traverse_rrs(packet, offset, nscount(packet) as usize, |rr_offset| {
        if BigEndian::read_u16(&packet[rr_offset..rr_offset + 2]) != DNS_TYPE_SOA {
            return Ok(());
        }

        let soa_ttl = BigEndian::read_u32(&packet[rr_offset + 4..rr_offset + 8]);
        let rdlen = BigEndian::read_u16(&packet[rr_offset + 8..rr_offset + 10]) as usize;
        let rdata_offset = rr_offset + 10;
        let rdata_end = rdata_offset + rdlen;

        let rname_offset = skip_name(packet, rdata_offset)?;
        if rname_offset > rdata_end {
            return Err(DnsError::InvalidRecord(
                "SOA MNAME exceeds record data".to_string(),
            ));
        }
        let fields_offset = skip_name(packet, rname_offset)?;
        if fields_offset > rdata_end || rdata_end - fields_offset != 20 {
            return Err(DnsError::InvalidRecord(
                "SOA record must end with five 32-bit fields".to_string(),
            ));
        }

        let minimum = BigEndian::read_u32(&packet[rdata_end - 4..rdata_end]);
        let ttl = soa_ttl.min(minimum);
        negative_ttl = Some(negative_ttl.map_or(ttl, |current: u32| current.min(ttl)));
        Ok(())
    })?;

    Ok(negative_ttl)
}

/// Caps a negative response's SOA TTL so it ages with the cached answer.
pub fn cap_negative_response_ttl(packet: &mut [u8], ttl: u32) -> DnsResult<()> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if packet_len > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet_len,
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }
    if qdcount(packet) == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }
    if ancount(packet) != 0 {
        return Ok(());
    }

    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet_len.saturating_sub(offset) < 4 {
        return Err(DnsError::PacketTooShort { offset });
    }
    offset += 4;

    traverse_rrs_mut(
        packet,
        offset,
        nscount(packet) as usize,
        |packet, rr_offset| {
            if BigEndian::read_u16(&packet[rr_offset..rr_offset + 2]) == DNS_TYPE_SOA {
                let soa_ttl = BigEndian::read_u32(&packet[rr_offset + 4..rr_offset + 8]);
                BigEndian::write_u32(&mut packet[rr_offset + 4..rr_offset + 8], soa_ttl.min(ttl));
            }
            Ok(())
        },
    )?;

    Ok(())
}

/// Changes the TTL of all records in a DNS packet
pub fn change_ttl(packet: &mut [u8], new_ttl: u32) -> DnsResult<()> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if packet_len > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet_len,
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }
    if qdcount(packet) == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }

    // Skip the question section
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet_len - offset < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    offset += 4; // Skip QTYPE and QCLASS

    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    let total_rr_count = ancount as usize + nscount as usize + arcount as usize;

    if total_rr_count == 0 {
        return Ok(());
    }

    traverse_rrs_mut(packet, offset, total_rr_count, |packet, offset| {
        let rr_type = BigEndian::read_u16(&packet[offset..offset + 2]);
        if rr_type != DNS_TYPE_OPT {
            BigEndian::write_u32(&mut packet[offset + 4..offset + 8], new_ttl);
        }
        Ok(())
    })?;

    Ok(())
}

/// Decrements each resource-record TTL by the elapsed cache time.
pub fn decrement_ttl(packet: &mut [u8], elapsed: u32) -> DnsResult<()> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if packet_len > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet_len,
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }
    if qdcount(packet) == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }

    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet_len - offset < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    offset += 4;

    let total_rr_count =
        ancount(packet) as usize + nscount(packet) as usize + arcount(packet) as usize;
    traverse_rrs_mut(packet, offset, total_rr_count, |packet, offset| {
        let rr_type = BigEndian::read_u16(&packet[offset..offset + 2]);
        if rr_type != DNS_TYPE_OPT {
            let ttl = BigEndian::read_u32(&packet[offset + 4..offset + 8]);
            BigEndian::write_u32(
                &mut packet[offset + 4..offset + 8],
                ttl.saturating_sub(elapsed),
            );
        }
        Ok(())
    })?;

    Ok(())
}

// Helper functions

/// Validates a single character in a domain name label
///
/// Allows the LDH (letters, digits, hyphens) set from RFC 1035/1123 plus
/// a leading underscore per RFC 8552 for underscored labels used by SRV,
/// DKIM, DMARC, TLSA and similar record types.
fn is_valid_domain_name_char(c: u8, position: usize, label_len: usize) -> bool {
    let is_letter = c.is_ascii_lowercase() || c.is_ascii_uppercase();
    let is_digit = c.is_ascii_digit();
    let is_hyphen = c == b'-';

    // Leading underscore allowed per RFC 8552 (e.g., _sip._tcp.example.com)
    if position == 0 {
        return is_letter || is_digit || c == b'_';
    }

    // Last character must be a letter or digit
    if position == label_len - 1 {
        return is_letter || is_digit;
    }

    // Middle characters can be letters, digits, or hyphens
    is_letter || is_digit || is_hyphen
}

// This function is now only used in validate_dns_packet

/// Extracts the raw query name from a DNS packet
pub fn qname(packet: &[u8]) -> DnsResult<Vec<u8>> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if qdcount(packet) == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }

    let mut offset = DNS_HEADER_SIZE;
    let mut qname = Vec::with_capacity(DNS_MAX_HOSTNAME_SIZE);

    loop {
        if offset >= packet_len {
            return Err(DnsError::PacketTooShort { offset: 0 });
        }
        match packet[offset] as usize {
            label_len if label_len & 0xc0 == 0xc0 => {
                // Check if we have enough bytes for the compression pointer
                if offset + 1 >= packet_len {
                    return Err(DnsError::PacketTooShort { offset });
                }

                // Compression pointer - not expected in the query name
                let second_byte = packet[offset + 1] as usize;
                return Err(DnsError::InvalidCompressionPointer {
                    offset,
                    pointer: ((label_len & 0x3f) << 8) | second_byte,
                    packet_size: packet_len,
                });
            }
            0 => {
                if qname.is_empty() {
                    qname.push(b'.');
                }
                break;
            }
            label_len => {
                if label_len >= 0x40 {
                    return Err(DnsError::LabelTooLong { length: label_len });
                }
                if packet_len.saturating_sub(offset) <= 1 {
                    return Err(DnsError::PacketTooShort { offset: 0 });
                }
                offset = offset.checked_add(1).ok_or_else(|| {
                    DnsError::InvalidPacket(
                        "Integer overflow advancing past label length byte".to_string(),
                    )
                })?;
                if packet_len.saturating_sub(offset) < label_len {
                    return Err(DnsError::PacketTooShort { offset: 0 });
                }

                if !qname.is_empty() {
                    qname.push(b'.');
                }

                if qname.len() + label_len >= DNS_MAX_HOSTNAME_SIZE {
                    return Err(DnsError::DomainNameTooLong {
                        length: qname.len() + label_len,
                        max_length: DNS_MAX_HOSTNAME_SIZE,
                    });
                }

                let label_end = offset.checked_add(label_len).ok_or_else(|| {
                    DnsError::InvalidPacket("Integer overflow calculating label end".to_string())
                })?;
                // Otherwise the single label "a.b" would look like the two labels "a" and "b"
                if packet[offset..label_end].contains(&b'.') {
                    return Err(DnsError::InvalidDomainName(
                        "Label contains a dot".to_string(),
                    ));
                }
                qname.extend_from_slice(&packet[offset..label_end]);
                offset = label_end;
            }
        }
    }

    Ok(qname)
}

/// Skips over a domain name in a DNS packet
fn skip_name(packet: &[u8], offset: usize) -> DnsResult<usize> {
    let packet_len = packet.len();
    if offset >= packet_len {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    let mut current_offset = offset;
    let mut jumps = 0;
    let mut total_name_len: usize = 0;
    let mut result_offset_after_pointer: Option<usize> = None;

    loop {
        if current_offset >= packet_len {
            return Err(DnsError::PacketTooShort {
                offset: current_offset,
            });
        }
        match packet[current_offset] as usize {
            label_len if label_len & 0xc0 == 0xc0 => {
                // Compression pointer
                if packet_len - current_offset < 2 {
                    return Err(DnsError::PacketTooShort {
                        offset: current_offset,
                    });
                }
                jumps += 1;
                if jumps > 10 {
                    return Err(DnsError::TooManyCompressionPointers { count: jumps });
                }

                // For the return value, we only advance 2 bytes for the first pointer,
                // but still validate the pointer target below.
                if jumps == 1 {
                    // Use checked_add to prevent integer overflow
                    let result_offset = match current_offset.checked_add(2) {
                        Some(offset) => offset,
                        None => {
                            return Err(DnsError::InvalidCompressionPointer {
                                offset: current_offset,
                                pointer: 0,
                                packet_size: packet_len,
                            });
                        }
                    };

                    if result_offset > packet_len {
                        return Err(DnsError::PacketTooShort {
                            offset: current_offset,
                        });
                    }
                    result_offset_after_pointer = Some(result_offset);
                }

                // Follow the pointer - safely extract second byte
                if current_offset + 1 >= packet_len {
                    return Err(DnsError::PacketTooShort {
                        offset: current_offset,
                    });
                }

                // Calculate pointer value with overflow check
                let second_byte = packet[current_offset + 1] as usize;
                let first_part = (label_len & 0x3f) << 8;
                let pointer = match first_part.checked_add(second_byte) {
                    Some(ptr) => ptr,
                    None => {
                        return Err(DnsError::InvalidCompressionPointer {
                            offset: current_offset,
                            pointer: first_part,
                            packet_size: packet_len,
                        });
                    }
                };
                if pointer >= packet_len {
                    return Err(DnsError::InvalidCompressionPointer {
                        offset: current_offset,
                        pointer,
                        packet_size: packet_len,
                    });
                }
                if pointer >= current_offset {
                    return Err(DnsError::InvalidCompressionPointer {
                        offset: current_offset,
                        pointer,
                        packet_size: packet_len,
                    });
                }
                current_offset = pointer;
            }
            0 => {
                if total_name_len.saturating_add(1) > 255 {
                    return Err(DnsError::DomainNameTooLong {
                        length: total_name_len + 1,
                        max_length: 255,
                    });
                }
                // End of domain name
                current_offset = match current_offset.checked_add(1) {
                    Some(offset) => offset,
                    None => {
                        return Err(DnsError::PacketTooShort {
                            offset: current_offset,
                        });
                    }
                };
                break;
            }
            label_len => {
                // Regular label
                if label_len >= 0x40 {
                    return Err(DnsError::LabelTooLong { length: label_len });
                }

                // Make sure we don't have integer underflow in the packet_len - current_offset check
                let remaining_bytes = if current_offset <= packet_len {
                    packet_len - current_offset
                } else {
                    return Err(DnsError::PacketTooShort {
                        offset: current_offset,
                    });
                };

                // Check we have enough bytes for label_len
                if remaining_bytes <= label_len {
                    return Err(DnsError::PacketTooShort {
                        offset: current_offset,
                    });
                }

                // Update the total name length with overflow check
                // Add 1 for the dot between labels (or the length byte in the packet)
                total_name_len = match label_len.checked_add(1) {
                    Some(len) => match total_name_len.checked_add(len) {
                        Some(total) => total,
                        None => {
                            return Err(DnsError::DomainNameTooLong {
                                length: u32::MAX as usize,
                                max_length: DNS_MAX_HOSTNAME_SIZE,
                            });
                        }
                    },
                    None => {
                        return Err(DnsError::DomainNameTooLong {
                            length: u32::MAX as usize,
                            max_length: DNS_MAX_HOSTNAME_SIZE,
                        });
                    }
                };

                // Check if the total name length exceeds the maximum
                if total_name_len > DNS_MAX_HOSTNAME_SIZE {
                    return Err(DnsError::DomainNameTooLong {
                        length: total_name_len,
                        max_length: DNS_MAX_HOSTNAME_SIZE,
                    });
                }

                // Safely advance the offset
                let label_plus_1 = match label_len.checked_add(1) {
                    Some(len) => len,
                    None => {
                        return Err(DnsError::LabelTooLong {
                            length: u32::MAX as usize,
                        });
                    }
                };

                current_offset = match current_offset.checked_add(label_plus_1) {
                    Some(offset) => offset,
                    None => {
                        return Err(DnsError::PacketTooShort {
                            offset: current_offset,
                        });
                    }
                };
            }
        }
    }

    Ok(result_offset_after_pointer.unwrap_or(current_offset))
}

/// Traverses resource records in a DNS packet
/// Traverses resource records in a DNS packet and calls a callback for each record
///
/// This function iterates through a specified number of resource records in a DNS packet,
/// calling the provided callback function for each record. It handles domain name compression
/// and validates record boundaries.
///
/// # Arguments
///
/// * `packet` - The DNS packet data
/// * `offset` - Starting offset in the packet where the resource records begin
/// * `rrcount` - Number of resource records to traverse
/// * `callback` - Function to call for each resource record, receiving the offset of the record
///
/// # Returns
///
/// The final offset after traversing all records, or an error if packet validation fails
fn traverse_rrs<F>(
    packet: &[u8],
    mut offset: usize,
    rrcount: usize,
    mut callback: F,
) -> DnsResult<usize>
where
    F: FnMut(usize) -> DnsResult<()>,
{
    let packet_len = packet.len();

    for _ in 0..rrcount {
        // Skip and validate the domain name in the record
        // skip_name already includes hostname size validation
        offset = skip_name(packet, offset)?;

        // Check if we have enough bytes for the fixed RR header fields (10 bytes)
        if packet_len < offset || packet_len - offset < 10 {
            return Err(DnsError::PacketTooShort { offset });
        }

        // Safely read RDLEN
        if offset + 8 >= packet_len {
            return Err(DnsError::PacketTooShort { offset });
        }
        let rdlen = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;

        // Check for overflow when calculating rr_offset + 10 + rdlen
        let rdata_end = match offset.checked_add(10) {
            Some(offset_plus_10) => match offset_plus_10.checked_add(rdlen) {
                Some(end_offset) => end_offset,
                None => {
                    return Err(DnsError::InvalidRecord(
                        "Integer overflow calculating record data bounds".to_string(),
                    ));
                }
            },
            None => {
                return Err(DnsError::InvalidRecord(
                    "Integer overflow calculating record offset".to_string(),
                ));
            }
        };

        if packet_len < rdata_end {
            return Err(DnsError::InvalidRecord(
                "Record length would exceed packet length".to_string(),
            ));
        }

        callback(offset)?;

        // For certain record types that contain domain names in their RDATA,
        // we should validate those domain names too
        let rr_type = BigEndian::read_u16(&packet[offset..offset + 2]);
        match rr_type {
            DNS_TYPE_NS | DNS_TYPE_CNAME | DNS_TYPE_PTR | DNS_TYPE_MX | DNS_TYPE_SRV
                // These record types contain domain names in their RDATA
                // Check that the RDATA size is reasonable
                if rdlen > DNS_MAX_HOSTNAME_SIZE => {
                    debug!("Large RDATA for domain name record: {rdlen} bytes (type: {rr_type})");
                }
            _ => {}
        }

        // Safely advance the offset
        offset = match offset.checked_add(10) {
            Some(o) => match o.checked_add(rdlen) {
                Some(final_offset) => final_offset,
                None => {
                    return Err(DnsError::InvalidRecord(
                        "Integer overflow calculating next record offset".to_string(),
                    ));
                }
            },
            None => {
                return Err(DnsError::InvalidRecord(
                    "Integer overflow calculating next record offset".to_string(),
                ));
            }
        };
    }

    Ok(offset)
}

/// Traverses resource records in a mutable DNS packet and calls a callback for each record
///
/// This function iterates through a specified number of resource records in a mutable DNS packet,
/// calling the provided callback function for each record. It handles domain name compression
/// and validates record boundaries. Unlike `traverse_rrs`, this function allows modification
/// of the packet data.
///
/// # Arguments
///
/// * `packet` - The mutable DNS packet data
/// * `offset` - Starting offset in the packet where the resource records begin
/// * `rrcount` - Number of resource records to traverse
/// * `callback` - Function to call for each resource record, receiving the packet and offset of the record
///
/// # Returns
///
/// The final offset after traversing all records, or an error if packet validation fails
fn traverse_rrs_mut<F>(
    packet: &mut [u8],
    mut offset: usize,
    rrcount: usize,
    mut callback: F,
) -> DnsResult<usize>
where
    F: FnMut(&mut [u8], usize) -> DnsResult<()>,
{
    let packet_len = packet.len();

    for _ in 0..rrcount {
        // Skip and validate the domain name in the record
        // skip_name already includes hostname size validation
        offset = skip_name(packet, offset)?;

        // Check if we have enough bytes for the fixed RR header fields (10 bytes)
        if packet_len < offset || packet_len - offset < 10 {
            return Err(DnsError::PacketTooShort { offset });
        }

        // Safely read RDLEN
        if offset + 8 >= packet_len {
            return Err(DnsError::PacketTooShort { offset });
        }
        let rdlen = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;

        // Check for overflow when calculating rr_offset + 10 + rdlen
        let rdata_end = match offset.checked_add(10) {
            Some(offset_plus_10) => match offset_plus_10.checked_add(rdlen) {
                Some(end_offset) => end_offset,
                None => {
                    return Err(DnsError::InvalidRecord(
                        "Integer overflow calculating record data bounds".to_string(),
                    ));
                }
            },
            None => {
                return Err(DnsError::InvalidRecord(
                    "Integer overflow calculating record offset".to_string(),
                ));
            }
        };

        if packet_len < rdata_end {
            return Err(DnsError::InvalidRecord(
                "Record length would exceed packet length".to_string(),
            ));
        }

        callback(packet, offset)?;

        // For certain record types that contain domain names in their RDATA,
        // we should validate those domain names too
        let rr_type = BigEndian::read_u16(&packet[offset..offset + 2]);
        match rr_type {
            DNS_TYPE_NS | DNS_TYPE_CNAME | DNS_TYPE_PTR | DNS_TYPE_MX | DNS_TYPE_SRV
                // These record types contain domain names in their RDATA
                // Check that the RDATA size is reasonable
                if rdlen > DNS_MAX_HOSTNAME_SIZE => {
                    debug!("Large RDATA for domain name record: {rdlen} bytes (type: {rr_type})");
                }
            _ => {}
        }

        // Safely advance the offset
        offset = match offset.checked_add(10) {
            Some(o) => match o.checked_add(rdlen) {
                Some(final_offset) => final_offset,
                None => {
                    return Err(DnsError::InvalidRecord(
                        "Integer overflow calculating next record offset".to_string(),
                    ));
                }
            },
            None => {
                return Err(DnsError::InvalidRecord(
                    "Integer overflow calculating next record offset".to_string(),
                ));
            }
        };
    }

    Ok(offset)
}

/// Adds an EDNS section to a DNS packet
pub fn add_edns_section(packet: &mut Vec<u8>, max_payload_size: u16) -> DnsResult<()> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if packet.len() > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet.len(),
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }
    if extract_edns_version(packet)?.is_some() {
        return Err(DnsError::InvalidEdns(
            "Packet already contains an OPT record".to_string(),
        ));
    }

    // Create the OPT record
    let opt_rr: [u8; 11] = [
        0,                             // Root domain name
        (DNS_TYPE_OPT >> 8) as u8,     // TYPE = OPT (41), high byte
        DNS_TYPE_OPT as u8,            // TYPE = OPT (41), low byte
        (max_payload_size >> 8) as u8, // UDP payload size, high byte
        max_payload_size as u8,        // UDP payload size, low byte
        0,                             // Higher bits of extended RCODE and flags
        0,                             // EDNS version and flags
        0,                             // EDNS version and flags
        0,                             // Reserved
        0,                             // RDLEN, high byte
        0,                             // RDLEN, low byte
    ];

    // Make sure the packet won't be too large
    if DNS_MAX_PACKET_SIZE - packet.len() < opt_rr.len() {
        return Err(DnsError::PacketTooLarge {
            size: packet.len(),
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }

    // Increment the Additional Records count
    let arcount_offset = 10; // Offset of ARCOUNT in DNS header
    let mut arcount = BigEndian::read_u16(&packet[arcount_offset..arcount_offset + 2]);
    if arcount == 0xffff {
        return Err(DnsError::InvalidPacket(
            "Too many additional records".to_string(),
        ));
    }
    arcount += 1;
    BigEndian::write_u16(&mut packet[arcount_offset..arcount_offset + 2], arcount);

    // Add the OPT record
    packet.extend_from_slice(&opt_rr);

    Ok(())
}

/// Adds an EDNS-client-subnet option to an existing OPT record in a DNS packet
///
/// This function adds an EDNS-client-subnet option to an existing OPT record in a DNS packet.
/// If no OPT record exists, it will first add one with the specified maximum payload size.
///
/// # Arguments
///
/// * `packet` - The DNS packet to add the EDNS-client-subnet option to
/// * `client_ip` - The client IP address to include in the subnet option
/// * `prefix_v4` - The prefix length for IPv4 addresses (1-32)
/// * `prefix_v6` - The prefix length for IPv6 addresses (1-128)
/// * `max_payload_size` - The maximum payload size to use if adding a new OPT record
///
/// # Returns
///
/// * `Ok(())` - If the option was added successfully
/// * `Err(e)` - If there was an error adding the option
///
/// # RFC 7871 - Client Subnet in DNS Queries
///
/// This implements the EDNS-client-subnet option as defined in RFC 7871.
/// The option includes:
/// - FAMILY: Address family (1 for IPv4, 2 for IPv6)
/// - SOURCE PREFIX-LENGTH: Length of the prefix of the address to include
/// - SCOPE PREFIX-LENGTH: Set to 0 in queries, indicates how much of the address was used in responses
/// - ADDRESS: The truncated IP address (only including the prefix)
pub fn add_edns_client_subnet(
    packet: &mut Vec<u8>,
    client_ip: &str,
    prefix_v4: u8,
    prefix_v6: u8,
    max_payload_size: u16,
) -> DnsResult<()> {
    // Validate the client IP address
    let ip_addr = match client_ip.parse::<std::net::IpAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            debug!("Invalid client IP address for EDNS-client-subnet: {client_ip}");
            return Ok(()); // Silently ignore invalid IP addresses
        }
    };

    // Determine if we need to add an OPT record first
    let mut has_opt_record = false;
    let mut opt_record_offset = 0;
    let mut opt_record_rdlen_offset = 0;

    // Skip the question section
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    offset += 4; // Skip QTYPE and QCLASS

    // Skip answer and authority sections
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(packet, offset, ancount as usize + nscount as usize, |_| {
        Ok(())
    })?;

    // Check additional records for OPT
    traverse_rrs(packet, offset, arcount as usize, |rr_offset| {
        let qtype = BigEndian::read_u16(&packet[rr_offset..]);
        if qtype == DNS_TYPE_OPT {
            has_opt_record = true;
            opt_record_offset = rr_offset;
            opt_record_rdlen_offset = rr_offset + 8; // RDLEN is at offset 8 in the OPT record
        }
        Ok(())
    })?;

    // If no OPT record exists, add one
    if !has_opt_record {
        add_edns_section(packet, max_payload_size)?;

        // Now find the OPT record we just added
        offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
        offset += 4; // Skip QTYPE and QCLASS

        // Skip answer and authority sections
        offset = traverse_rrs(packet, offset, ancount as usize + nscount as usize, |_| {
            Ok(())
        })?;

        // Find the OPT record in the additional section
        traverse_rrs(packet, offset, arcount as usize + 1, |rr_offset| {
            let qtype = BigEndian::read_u16(&packet[rr_offset..]);
            if qtype == DNS_TYPE_OPT {
                has_opt_record = true;
                opt_record_offset = rr_offset;
                opt_record_rdlen_offset = rr_offset + 8; // RDLEN is at offset 8 in the OPT record
            }
            Ok(())
        })?;
    }

    // If we still don't have an OPT record, something went wrong
    if !has_opt_record {
        return Err(DnsError::InvalidEdns(
            "Failed to add OPT record".to_string(),
        ));
    }

    remove_edns_option(packet, EDNS_OPTION_CLIENT_SUBNET)?;
    let rdlen_offset = opt_record_rdlen_offset;
    let rdlen = BigEndian::read_u16(&packet[rdlen_offset..rdlen_offset + 2]) as usize;
    let rdata_offset = rdlen_offset + 2;

    // Create the EDNS-client-subnet option
    let mut ecs_option = Vec::new();

    // Determine family, source prefix length, and address bytes based on IP type
    let (family, source_prefix_length, address_bytes) = match ip_addr {
        std::net::IpAddr::V4(ipv4) => {
            if prefix_v4 > 32 {
                return Err(DnsError::InvalidEdns(format!(
                    "Invalid ECS prefix length {prefix_v4} for IPv4"
                )));
            }
            let bytes = ipv4.octets();
            (1u16, prefix_v4, bytes.to_vec())
        }
        std::net::IpAddr::V6(ipv6) => {
            if prefix_v6 > 128 {
                return Err(DnsError::InvalidEdns(format!(
                    "Invalid ECS prefix length {prefix_v6} for IPv6"
                )));
            }
            let bytes = ipv6.octets();
            (2u16, prefix_v6, bytes.to_vec())
        }
    };

    // Calculate how many bytes we need to represent the prefix
    let address_byte_count = (source_prefix_length as usize).div_ceil(8);

    // Truncate the address bytes to the specified prefix length
    let mut truncated_address = address_bytes[..address_byte_count].to_vec();

    // If we're not using all bits in the last byte, mask it
    if address_byte_count > 0 && source_prefix_length % 8 != 0 {
        let last_byte_index = address_byte_count - 1;
        let mask = 0xffu8 << (8 - (source_prefix_length % 8));
        truncated_address[last_byte_index] &= mask;
    }

    // Build the option
    // OPTION-CODE (CLIENT-SUBNET)
    ecs_option.push((EDNS_OPTION_CLIENT_SUBNET >> 8) as u8);
    ecs_option.push(EDNS_OPTION_CLIENT_SUBNET as u8);

    // OPTION-LENGTH
    let option_length = 4 + truncated_address.len(); // 2 for family, 1 for source prefix length, 1 for scope prefix length, plus address bytes
    ecs_option.push((option_length >> 8) as u8);
    ecs_option.push(option_length as u8);

    // FAMILY
    ecs_option.push((family >> 8) as u8);
    ecs_option.push(family as u8);

    // SOURCE PREFIX-LENGTH
    ecs_option.push(source_prefix_length);

    // SCOPE PREFIX-LENGTH (always 0 in queries)
    ecs_option.push(0);

    // ADDRESS
    ecs_option.extend_from_slice(&truncated_address);

    // Make sure the packet won't be too large
    if DNS_MAX_PACKET_SIZE.saturating_sub(packet.len()) < ecs_option.len() {
        return Err(DnsError::PacketTooLarge {
            size: packet.len(),
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }

    // Update the RDLEN in the OPT record
    let new_rdlen = rdlen + ecs_option.len();
    BigEndian::write_u16(
        &mut packet[rdlen_offset..rdlen_offset + 2],
        new_rdlen as u16,
    );

    // Add the option to the end of the OPT record
    packet.splice(rdata_offset + rdlen..rdata_offset + rdlen, ecs_option);

    Ok(())
}

/// Sets the EDNS maximum payload size in a DNS packet
pub fn set_edns_max_payload_size(packet: &mut Vec<u8>, max_payload_size: u16) -> DnsResult<()> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if packet_len > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet_len,
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }
    if qdcount(packet) == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }

    // Skip the question section
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet_len - offset < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    offset += 4; // Skip QTYPE and QCLASS

    // Skip answer and authority sections
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(packet, offset, ancount as usize + nscount as usize, |_| {
        Ok(())
    })?;

    // Check additional records for OPT
    let mut edns_payload_set = false;

    traverse_rrs_mut(packet, offset, arcount as usize, |packet, offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype == DNS_TYPE_OPT {
            if edns_payload_set {
                return Err(DnsError::InvalidEdns("Duplicate OPT RR found".to_string()));
            }
            BigEndian::write_u16(&mut packet[offset + 2..], max_payload_size);
            edns_payload_set = true;
        }
        Ok(())
    })?;

    // If no EDNS record was found, add one
    if !edns_payload_set {
        add_edns_section(packet, max_payload_size)?;
    }

    Ok(())
}

/// Extracts the EDNS version from a DNS packet
///
/// The EDNS version is stored in byte 3 of the TTL field in OPT records.
/// Returns None if no OPT record is found, or Some(version) if found.
pub fn extract_edns_version(packet: &[u8]) -> DnsResult<Option<u8>> {
    let packet_len = packet.len();
    if packet_len <= DNS_OFFSET_QUESTION {
        return Ok(None);
    }

    // Skip the question section
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet_len - offset < 4 {
        return Ok(None);
    }
    offset += 4; // Skip QTYPE and QCLASS

    // Skip answer and authority sections
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(packet, offset, ancount as usize + nscount as usize, |_| {
        Ok(())
    })?;

    // Check additional records for OPT
    let mut edns_version = None;

    traverse_rrs(packet, offset, arcount as usize, |offset| {
        // Check we have at least 8 bytes for TYPE, CLASS, TTL
        if offset.checked_add(8).is_none_or(|sum| sum > packet_len) {
            return Ok(()); // Skip malformed record
        }

        let rr_type = BigEndian::read_u16(&packet[offset..offset + 2]);
        if rr_type == DNS_TYPE_OPT {
            // The TTL field in OPT records contains:
            // Byte 0: Extended RCODE
            // Byte 1: EDNS Version
            // Bytes 2-3: Flags
            // The TTL is at offset + 4 (after TYPE and CLASS)
            let ttl_bytes = &packet[offset + 4..offset + 8];
            edns_version = Some(ttl_bytes[1]); // Byte 1 is the EDNS version
        }
        Ok(())
    })?;

    Ok(edns_version)
}

/// Validates that a DNS packet is a valid response
pub fn validate_dns_response(packet: &[u8]) -> DnsResult<()> {
    // First, validate that it's a valid DNS packet
    validate_dns_packet(packet)?;

    // Check that it's a response (QR bit set)
    if !is_response(packet) {
        return Err(DnsError::InvalidPacket("Not a response".to_string()));
    }

    // Check that we have at least one answer or an error code
    let qdcount = qdcount(packet);
    let rcode = rcode(packet);

    if qdcount != 1 && rcode == 0 {
        return Err(DnsError::InvalidPacket(
            "No question in successful response".to_string(),
        ));
    }

    Ok(())
}

/// Sets the transaction ID in a DNS packet
pub fn set_tid(packet: &mut [u8], tid: u16) -> DnsResult<()> {
    if packet.len() < 2 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    // DNS transaction ID is the first 2 bytes of the packet
    packet[0] = (tid >> 8) as u8;
    packet[1] = tid as u8;

    Ok(())
}

/// Returns the flags field from the DNS packet
///
/// The flags field contains various DNS header flags including:
/// - QR (Query/Response) bit
/// - Opcode (operation code)
/// - AA (Authoritative Answer) bit
/// - TC (Truncation) bit
/// - RD (Recursion Desired) bit
/// - RA (Recursion Available) bit
/// - Z (Reserved for future use)
/// - AD (Authentic Data) bit
/// - CD (Checking Disabled) bit
/// - RCODE (Response code)
///
/// # Arguments
///
/// * `packet` - The DNS packet data
///
/// # Returns
///
/// The 16-bit flags field value, or 0 for malformed packets
#[inline]
pub fn flags(packet: &[u8]) -> u16 {
    if packet.len() < 4 {
        return 0; // Return 0 for malformed packets
    }
    BigEndian::read_u16(&packet[2..4])
}

/// Sets the flags field in a DNS packet
pub fn set_flags(packet: &mut [u8], flags: u16) -> DnsResult<()> {
    if packet.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    // DNS flags are bytes 2-3 of the packet
    packet[2] = (flags >> 8) as u8;
    packet[3] = flags as u8;

    Ok(())
}

/// Sets the QR bit in a DNS packet (0 for query, 1 for response)
pub fn set_qr(packet: &mut [u8], is_response: bool) -> DnsResult<()> {
    if packet.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    let mut flags_val = flags(packet);
    if is_response {
        flags_val |= DNS_FLAGS_QR; // Set QR bit
    } else {
        flags_val &= !DNS_FLAGS_QR; // Clear QR bit
    }
    set_flags(packet, flags_val)
}

/// Sets the TC bit in a DNS packet (1 for truncated)
pub fn set_tc(packet: &mut [u8], is_truncated: bool) -> DnsResult<()> {
    if packet.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    let mut flags_val = flags(packet);
    if is_truncated {
        flags_val |= DNS_FLAGS_TC; // Set TC bit
    } else {
        flags_val &= !DNS_FLAGS_TC; // Clear TC bit
    }
    set_flags(packet, flags_val)
}

/// Sets the AA (Authoritative Answer) bit in a DNS packet
pub fn set_aa(packet: &mut [u8], is_authoritative: bool) -> DnsResult<()> {
    if packet.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    let mut flags_val = flags(packet);
    if is_authoritative {
        flags_val |= DNS_FLAGS_AA; // Set AA bit
    } else {
        flags_val &= !DNS_FLAGS_AA; // Clear AA bit
    }
    set_flags(packet, flags_val)
}

/// Sets the RA (Recursion Available) bit in a DNS packet
pub fn set_ra(packet: &mut [u8], recursion_available: bool) -> DnsResult<()> {
    if packet.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    let mut flags_val = flags(packet);
    if recursion_available {
        flags_val |= DNS_FLAGS_RA; // Set RA bit
    } else {
        flags_val &= !DNS_FLAGS_RA; // Clear RA bit
    }
    set_flags(packet, flags_val)
}

/// Sets or clears the AD flag in a DNS packet.
pub fn set_ad(packet: &mut [u8], authenticated_data: bool) -> DnsResult<()> {
    if packet.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    let mut current_flags = flags(packet);
    if authenticated_data {
        current_flags |= DNS_FLAGS_AD;
    } else {
        current_flags &= !DNS_FLAGS_AD;
    }
    set_flags(packet, current_flags)
}

/// Clears the RD, CD and AD flags of a query, since they don't change what an authoritative server answers.
pub fn clear_resolver_flags(query: &mut [u8]) -> DnsResult<()> {
    set_flags(
        query,
        flags(query) & !(DNS_FLAGS_RD | DNS_FLAGS_CD | DNS_FLAGS_AD),
    )
}

/// Copies the RD and CD flags of a query into its response, as RFC 1035 and RFC 4035 require.
pub fn copy_rd_cd(response: &mut [u8], query: &[u8]) -> DnsResult<()> {
    if response.len() < 4 || query.len() < 4 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    let copied = DNS_FLAGS_RD | DNS_FLAGS_CD;
    set_flags(
        response,
        (flags(response) & !copied) | (flags(query) & copied),
    )
}

/// Sets the answer count in a DNS packet
pub fn set_ancount(packet: &mut [u8], count: u16) -> DnsResult<()> {
    if packet.len() < 8 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    BigEndian::write_u16(&mut packet[6..8], count);
    Ok(())
}

/// Sets the authority count in a DNS packet
pub fn set_nscount(packet: &mut [u8], count: u16) -> DnsResult<()> {
    if packet.len() < 10 {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    BigEndian::write_u16(&mut packet[8..10], count);
    Ok(())
}

/// Sets the additional count in a DNS packet
pub fn set_arcount(packet: &mut [u8], count: u16) -> DnsResult<()> {
    if packet.len() < DNS_PACKET_LEN_MIN {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    BigEndian::write_u16(&mut packet[10..DNS_PACKET_LEN_MIN], count);
    Ok(())
}

/// Sets the RCODE in a DNS packet
pub fn set_rcode(packet: &mut [u8], rcode: u8) -> DnsResult<()> {
    if packet.len() < DNS_PACKET_LEN_MIN {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    // For standard RCODEs (0-15), set in the header
    if rcode <= 0x0F {
        // Clear the lower 4 bits and set the new RCODE
        packet[3] = (packet[3] & 0xF0) | (rcode & 0x0F);
        Ok(())
    } else {
        // For extended RCODEs (16-255), we need to handle them differently
        // Set lower 4 bits to 0 in header
        packet[3] &= 0xF0;

        // Extended RCODEs require an OPT record to hold the upper bits
        // This should be handled by the caller when creating extended RCODE responses
        Ok(())
    }
}

/// Extracts the EDNS0 maximum datagram size from a DNS packet
///
/// This function searches for an OPT record in the additional section of a DNS packet
/// and returns the maximum payload size if found.
///
/// # Arguments
///
/// * `packet` - The DNS packet to extract the EDNS0 maximum datagram size from
///
/// # Returns
///
/// * `Some(max_size)` - The maximum payload size if an OPT record is found
/// * `None` - If no OPT record is found or if the packet doesn't have additional records
pub fn extract_edns0_max_size(packet: &[u8]) -> DnsResult<Option<u16>> {
    let packet_len = packet.len();
    if packet_len < DNS_PACKET_LEN_MIN {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }
    if packet_len > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: packet_len,
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }

    // Check if there are any additional records
    let arcount_val = arcount(packet);
    if arcount_val == 0 {
        // No additional records, so no EDNS0
        return Ok(None);
    }

    // Check if there's at least one question
    let qdcount_val = qdcount(packet);
    if qdcount_val == 0 {
        return Err(DnsError::InvalidPacket("No question".to_string()));
    }

    // Try to skip the question section
    let mut offset = DNS_HEADER_SIZE;

    // Skip all questions
    for _ in 0..qdcount_val {
        match skip_name(packet, offset) {
            Ok(new_offset) => {
                offset = new_offset;
                // Skip QTYPE and QCLASS
                if packet_len - offset < 4 {
                    return Err(DnsError::PacketTooShort { offset: 0 });
                }
                offset += 4;
            }
            Err(_) => {
                // If we can't skip the question, assume there's no EDNS0
                return Ok(None);
            }
        }
    }

    // Skip answer and authority sections
    let (ancount_val, nscount_val) = (ancount(packet), nscount(packet));

    // Try to skip answer and authority sections
    match traverse_rrs(
        packet,
        offset,
        ancount_val as usize + nscount_val as usize,
        |_| Ok(()),
    ) {
        Ok(new_offset) => {
            offset = new_offset;
        }
        Err(_) => {
            // If we can't traverse the records, assume there's no EDNS0
            return Ok(None);
        }
    }

    // Check additional records for OPT
    let mut max_size: Option<u16> = None;

    // Try to traverse additional records
    match traverse_rrs(packet, offset, arcount_val as usize, |offset| {
        if packet_len - offset < 2 {
            return Ok(());
        }

        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype == DNS_TYPE_OPT {
            // OPT record found, extract the maximum payload size
            // The maximum payload size is in the CLASS field (bytes 2-3 of the OPT record)
            if packet_len - offset < 4 {
                return Ok(());
            }

            let size = BigEndian::read_u16(&packet[offset + 2..]);
            if max_size.is_none() {
                max_size = Some(size);
            }
        }
        Ok(())
    }) {
        Ok(_) => {}
        Err(_) => {
            // If we can't traverse the additional records, assume there's no EDNS0
            return Ok(None);
        }
    }

    Ok(max_size)
}

/// Creates or truncates a DNS message to fit within a maximum size
///
/// This function can:
/// 1. Convert a DNS query into a truncated DNS response
/// 2. Truncate a DNS response to fit within a maximum size
///
/// In both cases, it preserves the header and question section, but removes all answer,
/// authority, and additional records. It sets the TC bit to 1 (truncated) to indicate
/// that the response is truncated.
///
/// # Arguments
///
/// * `packet` - The DNS packet (query or response) to process
/// * `max_size` - Optional maximum size for the result. If None, the function will always truncate.
///   If Some(size), it will only truncate if the packet exceeds the size.
/// * `force_response` - If true, ensures the result is a response (sets QR bit to 1)
///
/// # Returns
///
/// A new Vec<u8> containing the truncated DNS message
pub fn truncate_dns_packet(
    packet: &[u8],
    max_size: Option<usize>,
    force_response: bool,
) -> DnsResult<Vec<u8>> {
    // First, check if the packet is valid
    if packet.len() < DNS_PACKET_LEN_MIN {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    // Check if the packet is already small enough (if max_size is provided)
    if let Some(size) = max_size
        && packet.len() <= size
    {
        return Ok(packet.to_vec());
    }

    // Create a new packet with the same header and question
    let mut truncated_data = packet.to_vec();

    // Skip the question section to find where to truncate
    let mut offset = DNS_HEADER_SIZE;
    let qdcount = qdcount(&truncated_data);

    if qdcount == 0 {
        return Err(DnsError::InvalidPacket("No question in packet".to_string()));
    }

    for _ in 0..qdcount {
        offset = skip_name(&truncated_data, offset)?;
        if truncated_data.len() - offset < 4 {
            return Err(DnsError::PacketTooShort { offset: 0 });
        }
        offset += 4; // Skip QTYPE and QCLASS
    }

    // Truncate the packet after the question section
    truncated_data.truncate(offset);

    // If force_response is true, set the QR bit to 1 (response)
    if force_response && !is_response(&truncated_data) {
        set_qr(&mut truncated_data, true)?;
    }

    // Set the TC bit to 1 (truncated)
    set_tc(&mut truncated_data, true)?;

    // Set answer, authority, and additional counts to 0
    set_ancount(&mut truncated_data, 0)?;
    set_nscount(&mut truncated_data, 0)?;
    set_arcount(&mut truncated_data, 0)?;

    Ok(truncated_data)
}

/// Creates a truncated DNS response from a DNS query
///
/// This function takes a DNS query and converts it into a truncated DNS response
/// by preserving the header and question section, but removing all answer, authority,
/// and additional records. It sets the QR bit to 1 (response) and the TC bit to 1 (truncated).
///
/// # Arguments
///
/// * `query` - The DNS query to convert to a truncated response
///
/// # Returns
///
/// A new Vec<u8> containing a truncated DNS response
#[allow(dead_code)]
pub fn create_truncated_response(query: &[u8]) -> DnsResult<Vec<u8>> {
    // Check that this is a query, not a response
    if is_response(query) {
        return Err(DnsError::InvalidPacket(
            "Expected a query, got a response".to_string(),
        ));
    }

    // Use the generic truncate_dns_packet function with force_response=true
    truncate_dns_packet(query, None, true)
}

/// Truncates a DNS response to fit within the maximum UDP packet size
///
/// This function takes a DNS response and truncates it to fit within the maximum UDP packet size
/// by preserving the header and question section, but removing answer, authority, and additional
/// records as needed. It sets the TC bit to 1 (truncated) to indicate that the response is truncated.
///
/// # Arguments
///
/// * `response` - The DNS response to truncate
/// * `max_size` - The maximum size of the truncated response
///
/// # Returns
///
/// A new Vec<u8> containing the truncated DNS response
#[allow(dead_code)]
pub fn truncate_response(response: &[u8], max_size: usize) -> DnsResult<Vec<u8>> {
    // Check that this is a response, not a query
    if !is_response(response) {
        return Err(DnsError::InvalidPacket(
            "Expected a response, got a query".to_string(),
        ));
    }

    // Use the generic truncate_dns_packet function with force_response=false
    truncate_dns_packet(response, Some(max_size), false)
}

/// Recovers a DNS query from a truncated DNS response
///
/// This function takes a truncated DNS response and converts it into a valid DNS query
/// by preserving the header and question section, but removing all answer, authority,
/// and additional records. It also sets the QR bit to 0 (query) and the TC bit to 0 (not truncated).
///
/// # Arguments
///
/// * `response` - The truncated DNS response
///
/// # Returns
///
/// A new Vec<u8> containing a valid DNS query
pub fn recover_question_from_response(response: &[u8]) -> DnsResult<Vec<u8>> {
    // First, check if the response is valid
    if response.len() < DNS_PACKET_LEN_MIN {
        return Err(DnsError::PacketTooShort { offset: 0 });
    }

    // Create a new query with the same header and question
    let mut query_data = response.to_vec();

    // Set the QR bit to 0 (query)
    set_qr(&mut query_data, false)?;

    // Set the TC bit to 0 (not truncated)
    set_tc(&mut query_data, false)?;

    // Keep only the header and question section
    let qdcount = qdcount(&query_data);
    if qdcount == 0 {
        return Err(DnsError::InvalidPacket(
            "No question in response".to_string(),
        ));
    }

    let mut offset = DNS_HEADER_SIZE;
    for _ in 0..qdcount {
        offset = skip_name(&query_data, offset)?;
        if query_data.len() - offset < 4 {
            return Err(DnsError::PacketTooShort { offset: 0 });
        }
        offset = offset.checked_add(4).ok_or_else(|| {
            DnsError::InvalidPacket("Integer overflow advancing past QTYPE/QCLASS".to_string())
        })?;
    }

    query_data.truncate(offset);

    // Set answer, authority, and additional counts to 0
    set_ancount(&mut query_data, 0)?;
    set_nscount(&mut query_data, 0)?;
    set_arcount(&mut query_data, 0)?;

    Ok(query_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a simple DNS query packet
    fn create_test_query() -> Vec<u8> {
        // Create DNS Header (DNS_PACKET_LEN_MIN bytes)
        let mut packet = vec![
            // Transaction ID (2 bytes)
            0x12, 0x34, // Flags (2 bytes) - Standard query with RD bit set
            0x01, 0x00, // QDCOUNT (2 bytes) - 1 question
            0x00, 0x01, // ANCOUNT (2 bytes) - 0 answers
            0x00, 0x00, // NSCOUNT (2 bytes) - 0 authority records
            0x00, 0x00, // ARCOUNT (2 bytes) - 0 additional records
            0x00, 0x00,
        ];

        // Question section - example.com A record
        // example
        packet.push(0x07); // Length of "example"
        for b in b"example" {
            packet.push(*b);
        }
        // com
        packet.push(0x03); // Length of "com"
        for b in b"com" {
            packet.push(*b);
        }
        // Root label
        packet.push(0x00);

        // QTYPE (2 bytes) - A record
        packet.push(0x00);
        packet.push(0x01);

        // QCLASS (2 bytes) - IN
        packet.push(0x00);
        packet.push(0x01);

        packet
    }

    // Helper function to create a DNS query with a specific opcode
    fn create_test_query_with_opcode(opcode: u8) -> Vec<u8> {
        let mut packet = create_test_query();

        // Set the opcode in the flags field (bits 11-14 of the flags field)
        // Opcode is stored in bits 3-6 of byte 2
        packet[2] = (packet[2] & 0x87) | ((opcode & 0x0F) << 3);

        packet
    }

    // Helper function to create a DNS query with EDNS0
    fn create_test_query_with_edns0(max_size: u16) -> Vec<u8> {
        let mut packet = create_test_query();

        // Add EDNS0 record
        // Increment ARCOUNT
        packet[11] = 0x01;

        // Root domain name
        packet.push(0x00);

        // TYPE = OPT (41)
        packet.push(0x00);
        packet.push(0x29);

        // CLASS field is the maximum UDP payload size
        packet.push((max_size >> 8) as u8);
        packet.push(max_size as u8);

        // TTL field (extended RCODE and flags)
        packet.push(0x00); // Extended RCODE
        packet.push(0x00); // Version
        packet.push(0x00); // High flags
        packet.push(0x00); // Low flags

        // RDLEN
        packet.push(0x00);
        packet.push(0x00);

        packet
    }

    #[test]
    fn test_extract_edns0_max_size() {
        // Test with no EDNS0 record
        let query = create_test_query();
        println!("Query length: {}", query.len());
        let result = match extract_edns0_max_size(&query) {
            Ok(r) => r,
            Err(e) => {
                println!("Error extracting EDNS0 max size from query: {:?}", e);
                panic!("Failed to extract EDNS0 max size from query");
            }
        };
        assert_eq!(result, None);

        // Test with EDNS0 record
        let query_with_edns0 = create_test_query_with_edns0(4096);
        println!("Query with EDNS0 length: {}", query_with_edns0.len());

        // Validate that the helper returns the EDNS0 max size
        let edns0_size = extract_edns0_max_size(&query_with_edns0).unwrap();
        assert_eq!(edns0_size, Some(4096));

        // Debug the packet
        println!("EDNS0 packet: {:?}", query_with_edns0);

        // Direct test for the specific test packet
        // This is a simplified test that directly checks the OPT record
        // without going through the full parsing logic
        assert_eq!(query_with_edns0[11], 1); // ARCOUNT = 1
        assert_eq!(query_with_edns0[29], 0); // Root domain name
        assert_eq!(query_with_edns0[30], 0); // TYPE = OPT (41) high byte
        assert_eq!(query_with_edns0[31], 41); // TYPE = OPT (41) low byte
        assert_eq!(query_with_edns0[32], 16); // CLASS = 4096 high byte
        assert_eq!(query_with_edns0[33], 0); // CLASS = 4096 low byte

        // The CLASS field in an OPT record is the maximum UDP payload size
        let max_size = (query_with_edns0[32] as u16) << 8 | query_with_edns0[33] as u16;
        assert_eq!(max_size, 4096);
    }

    #[test]
    fn test_change_ttl_preserves_opt_metadata() {
        let mut response = create_test_query();
        set_qr(&mut response, true).unwrap();
        set_ancount(&mut response, 1).unwrap();
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1,
        ]);
        add_edns_section(&mut response, 1232).unwrap();

        let opt_start = response.len() - 11;
        response[opt_start + 5..opt_start + 9].copy_from_slice(&[0x12, 0x00, 0x80, 0x00]);

        change_ttl(&mut response, 15).unwrap();

        let answer_ttl_offset = 29 + 2 + 4;
        assert_eq!(
            &response[answer_ttl_offset..answer_ttl_offset + 4],
            &[0, 0, 0, 15]
        );
        assert_eq!(
            &response[opt_start + 5..opt_start + 9],
            &[0x12, 0x00, 0x80, 0x00]
        );
    }

    #[test]
    fn test_decrement_ttl_preserves_individual_ttls_and_opt() {
        let mut response = create_test_query();
        set_qr(&mut response, true).unwrap();
        set_ancount(&mut response, 2).unwrap();
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 192, 0, 2, 1,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 2,
        ]);
        add_edns_section(&mut response, 1232).unwrap();
        let opt_start = response.len() - 11;
        response[opt_start + 5..opt_start + 9].copy_from_slice(&[0x12, 0x00, 0x80, 0x00]);

        decrement_ttl(&mut response, 10).unwrap();

        assert_eq!(BigEndian::read_u32(&response[35..39]), 290);
        assert_eq!(BigEndian::read_u32(&response[51..55]), 50);
        assert_eq!(
            &response[opt_start + 5..opt_start + 9],
            &[0x12, 0x00, 0x80, 0x00]
        );
    }

    #[test]
    fn test_question_matching() {
        let query = create_test_query();
        let mut response = query.clone();
        set_qr(&mut response, true).unwrap();
        assert!(questions_match(&query, &response).unwrap());

        let qtype_offset = response.len() - 4;
        response[qtype_offset..qtype_offset + 2].copy_from_slice(&[0, 28]);
        assert!(!questions_match(&query, &response).unwrap());

        response[13] = b'f';
        assert!(restore_qname_case(&mut response, &query).is_err());

        // Without a question, there is nothing to fix
        response[5] = 0;
        restore_qname_case(&mut response, &query).unwrap();
        assert_eq!(response[13], b'f');
    }

    #[test]
    fn test_dot_inside_label_is_rejected() {
        // The single label "example.com" instead of "example" and "com"
        let mut dotted = create_test_query();
        dotted[12] = 11;
        dotted[20] = b'.';

        assert!(validate_dns_packet(&dotted).is_err());
    }

    #[test]
    fn test_trailing_data_is_not_part_of_the_message() {
        let query = create_test_query();
        assert_eq!(validate_dns_packet(&query).unwrap(), query.len());

        // An OPT record at the end that the header doesn't count
        let mut with_trailing_opt = query.clone();
        add_edns_section(&mut with_trailing_opt, 1232).unwrap();
        set_arcount(&mut with_trailing_opt, 0).unwrap();
        assert_eq!(
            validate_dns_packet(&with_trailing_opt).unwrap(),
            query.len()
        );
    }

    #[test]
    fn test_invalid_opt_layout_is_rejected() {
        let mut duplicate = create_test_query();
        add_edns_section(&mut duplicate, 1232).unwrap();
        let opt = duplicate[duplicate.len() - 11..].to_vec();
        duplicate.extend_from_slice(&opt);
        set_arcount(&mut duplicate, 2).unwrap();
        assert!(validate_dns_packet(&duplicate).is_err());

        let mut named = create_test_query();
        add_edns_section(&mut named, 1232).unwrap();
        let opt_start = named.len() - 11;
        named.splice(opt_start..=opt_start, [1, b'x', 0]);
        assert!(validate_dns_packet(&named).is_err());
    }

    #[test]
    fn test_forward_compression_pointer_is_rejected() {
        let mut response = create_test_query();
        set_qr(&mut response, true).unwrap();
        set_ancount(&mut response, 1).unwrap();
        let answer_start = response.len();
        let pointer = answer_start + 2;
        response.extend_from_slice(&[
            0xc0 | ((pointer >> 8) as u8),
            pointer as u8,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x3c,
            0x00,
            0x04,
            192,
            0,
            2,
            1,
        ]);

        assert!(validate_dns_packet(&response).is_err());
    }

    #[test]
    fn test_wire_name_length_boundary() {
        fn query_with_labels(lengths: &[usize]) -> Vec<u8> {
            let mut query = vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            for &length in lengths {
                query.push(length as u8);
                query.extend(std::iter::repeat_n(b'a', length));
            }
            query.extend_from_slice(&[0, 0, 1, 0, 1]);
            query
        }

        assert!(validate_dns_packet(&query_with_labels(&[63, 63, 63, 61])).is_ok());
        assert!(validate_dns_packet(&query_with_labels(&[63, 63, 63, 62])).is_err());
    }

    #[test]
    fn test_ecs_is_replaced_and_can_be_removed() {
        let mut query = create_test_query();
        add_edns_section(&mut query, 1232).unwrap();
        // A cookie, which must survive the ECS removal
        add_cookie(&mut query, b"CLIENT01");
        add_edns_client_subnet(&mut query, "192.0.2.129", 24, 56, 1232).unwrap();
        add_edns_client_subnet(&mut query, "198.51.100.9", 24, 56, 1232).unwrap();

        let ecs = extract_edns_client_subnet(&query).unwrap().unwrap();
        assert_eq!(ecs.address, vec![198, 51, 100]);

        remove_edns_option(&mut query, EDNS_OPTION_CLIENT_SUBNET).unwrap();
        assert!(extract_edns_client_subnet(&query).unwrap().is_none());
        assert_eq!(arcount(&query), 1);

        let len = query.len();
        remove_edns_option(&mut query, EDNS_OPTION_COOKIE).unwrap();
        assert_eq!(query.len(), len - 12);
    }

    #[test]
    fn test_truncate_dns_packet() {
        // Test truncating a query into a response
        let query = create_test_query();
        let truncated_response = truncate_dns_packet(&query, None, true).unwrap();

        // Check that the response has the QR bit set
        assert!(is_response(&truncated_response));

        // Check that the response has the TC bit set
        assert!(is_truncated(&truncated_response));

        // Check that the response has the same transaction ID
        assert_eq!(tid(&truncated_response), 0x1234);

        // Check that the response has the same question count
        assert_eq!(qdcount(&truncated_response), 1);

        // Check that the response has no answer, authority, or additional records
        assert_eq!(ancount(&truncated_response), 0);
        assert_eq!(nscount(&truncated_response), 0);
        assert_eq!(arcount(&truncated_response), 0);

        // Test truncating a response with max_size
        // First, create a response
        let mut response = query.to_vec();
        set_qr(&mut response, true).unwrap();

        // Add some dummy data to make it larger
        response.extend_from_slice(&[0; 100]);

        // Truncate the response
        let max_size = 50;
        let truncated_response = truncate_dns_packet(&response, Some(max_size), false).unwrap();

        // Check that the response is smaller than max_size
        assert!(truncated_response.len() <= max_size);

        // Check that the response has the QR bit set
        assert!(is_response(&truncated_response));

        // Check that the response has the TC bit set
        assert!(is_truncated(&truncated_response));
    }

    #[test]
    fn test_recover_question_from_response() {
        // Create a truncated response
        let query = create_test_query();
        let truncated_response = truncate_dns_packet(&query, None, true).unwrap();

        // Recover the question from the truncated response
        let recovered_query = recover_question_from_response(&truncated_response).unwrap();

        // Check that the recovered query is not a response
        assert!(!is_response(&recovered_query));

        // Check that the recovered query is not truncated
        assert!(!is_truncated(&recovered_query));

        // Check that the recovered query has the same transaction ID
        assert_eq!(tid(&recovered_query), 0x1234);

        // Check that the recovered query has the same question count
        assert_eq!(qdcount(&recovered_query), 1);

        // Check that the recovered query has no answer, authority, or additional records
        assert_eq!(ancount(&recovered_query), 0);
        assert_eq!(nscount(&recovered_query), 0);
        assert_eq!(arcount(&recovered_query), 0);
    }

    #[test]
    fn test_recover_question_truncates_extra_data() {
        let query = create_test_query();
        let mut response = query.clone();
        set_qr(&mut response, true).unwrap();
        set_tc(&mut response, true).unwrap();
        response.extend_from_slice(&[0u8; 32]);

        let recovered_query = recover_question_from_response(&response).unwrap();
        assert_eq!(recovered_query.len(), query.len());
    }

    #[test]
    fn test_is_dnssec_requested_short_packet() {
        let result = is_dnssec_requested(&[0u8; 3]);
        assert!(matches!(result, Err(DnsError::PacketTooShort { .. })));
    }

    #[test]
    fn test_opcode_validation() {
        // Test standard query (opcode 0)
        let query = create_test_query();
        assert_eq!(opcode(&query), DNS_OPCODE_QUERY);
        assert!(is_standard_query(&query));
        let result = validate_dns_packet(&query);
        assert!(result.is_ok());

        // Test update query (opcode 5)
        let update_query = create_test_query_with_opcode(DNS_OPCODE_UPDATE);
        assert_eq!(opcode(&update_query), DNS_OPCODE_UPDATE);
        assert!(!is_standard_query(&update_query));
        let result = validate_dns_packet(&update_query);
        assert!(result.is_err());
        match result {
            Err(DnsError::UnsupportedOperation(msg)) => {
                assert!(msg.contains("Unsupported opcode: 5"));
            }
            _ => panic!("Expected UnsupportedOperation error"),
        }
    }

    #[test]
    fn test_domain_name_validation() {
        // Test valid domain names
        let valid_labels = [
            "example",
            "test123",
            "a-valid-label",
            "123valid",
            "valid123",
        ];

        for label in &valid_labels {
            // Check first character
            assert!(is_valid_domain_name_char(
                label.as_bytes()[0],
                0,
                label.len()
            ));

            // Check last character
            assert!(is_valid_domain_name_char(
                label.as_bytes()[label.len() - 1],
                label.len() - 1,
                label.len()
            ));

            // Check all characters in the label
            let label_bytes = label.as_bytes();
            let label_len = label_bytes.len();
            let mut is_valid = true;

            // Check if the label is empty
            if label_len == 0 {
                is_valid = false;
            }

            // Check if the label is too long
            if label_len > 63 {
                is_valid = false;
            }

            // Check each character in the label
            for (i, &c) in label_bytes.iter().enumerate() {
                if !is_valid_domain_name_char(c, i, label_len) {
                    is_valid = false;
                    break;
                }
            }

            assert!(is_valid, "Label '{}' should be valid", label);
        }

        // Test invalid domain names
        let invalid_labels = [
            "-invalid",      // Starts with hyphen
            "invalid-",      // Ends with hyphen
            "inva@lid",      // Contains invalid character
            "invalid label", // Contains space
            "",              // Empty label
        ];

        for label in &invalid_labels {
            if !label.is_empty() {
                if label.starts_with('-') {
                    assert!(!is_valid_domain_name_char(
                        label.as_bytes()[0],
                        0,
                        label.len()
                    ));
                }
                if label.ends_with('-') {
                    assert!(!is_valid_domain_name_char(
                        label.as_bytes()[label.len() - 1],
                        label.len() - 1,
                        label.len()
                    ));
                }
            }

            // Check all characters in the label
            let label_bytes = label.as_bytes();
            let label_len = label_bytes.len();
            let mut is_valid = true;

            // Check if the label is empty
            if label_len == 0 {
                is_valid = false;
            } else {
                // Check if the label is too long
                if label_len > 63 {
                    is_valid = false;
                }

                // Check each character in the label
                for (i, &c) in label_bytes.iter().enumerate() {
                    if !is_valid_domain_name_char(c, i, label_len) {
                        is_valid = false;
                        break;
                    }
                }
            }

            assert!(!is_valid, "Label '{}' should be invalid", label);
        }
    }

    #[test]
    fn test_extract_edns_version() {
        // Test query without OPT record
        let query = create_test_query();
        let version = extract_edns_version(&query).unwrap();
        assert_eq!(version, None);

        // Test query with EDNS version 0
        let mut query_with_edns = query.clone();
        add_edns_section(&mut query_with_edns, 1232).unwrap();
        let version = extract_edns_version(&query_with_edns).unwrap();
        assert_eq!(version, Some(0));

        // Test query with EDNS version 1
        // Create a custom OPT record with version 1
        let mut query_with_edns_v1 = create_test_query();

        // Manually add OPT record with version 1
        // OPT record structure:
        // - Name: 0 (root)
        // - Type: 41 (OPT)
        // - Class: UDP payload size
        // - TTL: Extended RCODE (byte 0), Version (byte 1), Flags (bytes 2-3)
        // - RDLEN: 0
        // - RDATA: empty
        let opt_record: Vec<u8> = vec![
            0, // Root domain name
            0, 41, // Type = OPT
            0x04, 0xd0, // Class = 1232 (UDP payload size)
            0,    // Extended RCODE
            1,    // EDNS Version = 1
            0, 0, // Flags
            0, 0, // RDLEN = 0
        ];

        // Update ARCOUNT
        let arcount_offset = 10;
        assert!(
            query_with_edns_v1.len() >= arcount_offset + 2,
            "Packet too short for ARCOUNT"
        );
        let arcount = BigEndian::read_u16(&query_with_edns_v1[arcount_offset..arcount_offset + 2]);
        BigEndian::write_u16(
            &mut query_with_edns_v1[arcount_offset..arcount_offset + 2],
            arcount + 1,
        );

        // Append OPT record
        query_with_edns_v1.extend_from_slice(&opt_record);

        let version = extract_edns_version(&query_with_edns_v1).unwrap();
        assert_eq!(version, Some(1));
    }

    #[test]
    fn test_validate_dns_packet_with_edns_version() {
        // Test that EDNS version 0 is accepted
        let mut query = create_test_query();
        add_edns_section(&mut query, 1232).unwrap();
        let result = validate_dns_packet(&query);
        assert!(result.is_ok());

        // Test that EDNS version 1 is rejected
        let mut query_with_edns_v1 = create_test_query();

        // Manually add OPT record with version 1
        let opt_record: Vec<u8> = vec![
            0, // Root domain name
            0, 41, // Type = OPT
            0x04, 0xd0, // Class = 1232 (UDP payload size)
            0,    // Extended RCODE
            1,    // EDNS Version = 1
            0, 0, // Flags
            0, 0, // RDLEN = 0
        ];

        // Update ARCOUNT
        let arcount_offset = 10;
        assert!(
            query_with_edns_v1.len() >= arcount_offset + 2,
            "Packet too short for ARCOUNT"
        );
        let arcount = BigEndian::read_u16(&query_with_edns_v1[arcount_offset..arcount_offset + 2]);
        BigEndian::write_u16(
            &mut query_with_edns_v1[arcount_offset..arcount_offset + 2],
            arcount + 1,
        );

        // Append OPT record
        query_with_edns_v1.extend_from_slice(&opt_record);

        let result = validate_dns_packet(&query_with_edns_v1);
        assert!(result.is_err());
        match result {
            Err(DnsError::UnsupportedEdnsVersion { version }) => {
                assert_eq!(version, 1);
            }
            _ => panic!("Expected UnsupportedEdnsVersion error"),
        }
    }
}

/// Structure to hold EDNS-client-subnet information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub struct EdnsClientSubnet {
    /// Address family (1 for IPv4, 2 for IPv6)
    pub family: u16,
    /// Source prefix length
    pub source_prefix_length: u8,
    /// Scope prefix length
    pub scope_prefix_length: u8,
    /// IP address (truncated to the prefix length)
    pub address: Vec<u8>,
}

/// Removes every instance of an EDNS option, and keeps the other ones.
pub fn remove_edns_option(packet: &mut Vec<u8>, option_code: u16) -> DnsResult<()> {
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    if packet.len().saturating_sub(offset) < 4 {
        return Err(DnsError::PacketTooShort { offset });
    }
    offset += 4;
    offset = traverse_rrs(
        packet,
        offset,
        ancount(packet) as usize + nscount(packet) as usize,
        |_| Ok(()),
    )?;

    for _ in 0..arcount(packet) {
        let rr_offset = skip_name(packet, offset)?;
        if packet.len().saturating_sub(rr_offset) < 10 {
            return Err(DnsError::PacketTooShort { offset: rr_offset });
        }
        let rr_type = BigEndian::read_u16(&packet[rr_offset..rr_offset + 2]);
        let mut rdlen = BigEndian::read_u16(&packet[rr_offset + 8..rr_offset + 10]) as usize;
        let rdata_offset = rr_offset + 10;
        if packet.len().saturating_sub(rdata_offset) < rdlen {
            return Err(DnsError::InvalidRecord(
                "OPT record data exceeds packet".to_string(),
            ));
        }

        if rr_type == DNS_TYPE_OPT {
            let mut option_offset = rdata_offset;
            while option_offset < rdata_offset + rdlen {
                if rdata_offset + rdlen - option_offset < 4 {
                    return Err(DnsError::InvalidEdns(
                        "Truncated EDNS option header".to_string(),
                    ));
                }
                let option_len =
                    BigEndian::read_u16(&packet[option_offset + 2..option_offset + 4]) as usize;
                let option_end = option_offset.checked_add(4 + option_len).ok_or_else(|| {
                    DnsError::InvalidEdns("EDNS option length overflow".to_string())
                })?;
                if option_end > rdata_offset + rdlen {
                    return Err(DnsError::InvalidEdns(
                        "EDNS option exceeds OPT record data".to_string(),
                    ));
                }
                if BigEndian::read_u16(&packet[option_offset..option_offset + 2]) == option_code {
                    packet.drain(option_offset..option_end);
                    rdlen -= option_end - option_offset;
                    continue;
                }
                option_offset = option_end;
            }
            BigEndian::write_u16(&mut packet[rr_offset + 8..rr_offset + 10], rdlen as u16);
        }

        offset = rdata_offset + rdlen;
    }

    Ok(())
}

/// Appends a cookie to a packet that ends with an OPT record without options.
#[cfg(test)]
pub(crate) fn add_cookie(packet: &mut Vec<u8>, cookie: &[u8]) {
    let rdlen = packet.len() - 2;
    packet[rdlen..].copy_from_slice(&(4 + cookie.len() as u16).to_be_bytes());
    packet.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());
    packet.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
    packet.extend_from_slice(cookie);
}

/// Removes the addresses that a referral has no business carrying.
///
/// Shared DNS hosting can add an address from one customer's zone to a referral made by
/// another customer's zone, and some resolvers use it.
///
/// We don't know which zone made the referral, but it always contains the parent of the
/// delegated name.
/// So in the additional section, we only keep the OPT record and the addresses under that
/// parent, along with their signatures.
///
/// Returns how many records were removed.
pub fn remove_out_of_bailiwick_glue(packet: &mut Vec<u8>) -> DnsResult<usize> {
    let arcount = arcount(packet);
    if flags(packet) & DNS_FLAGS_AA != 0
        || rcode(packet) != 0
        || qdcount(packet) != 1
        || ancount(packet) != 0
        || nscount(packet) == 0
        || arcount == 0
    {
        return Ok(0);
    }

    let qname = name_labels(packet, DNS_OFFSET_QUESTION)?;
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)? + 4;
    let mut delegation_depth = None;
    for _ in 0..nscount(packet) {
        let record = record_at(packet, offset)?;
        if record.rr_type == DNS_TYPE_NS {
            let owner = name_labels(packet, offset)?;
            if is_subdomain(&qname, &owner) {
                delegation_depth = delegation_depth.max(Some(owner.len()));
            }
        }
        offset = record.end;
    }
    let Some(depth) = delegation_depth else {
        return Ok(0);
    };
    let bailiwick = &qname[qname.len() - depth.saturating_sub(1)..];

    let additional_start = offset;
    let mut filtered = packet[..additional_start].to_vec();
    let mut removed = 0u16;
    for _ in 0..arcount {
        let record = record_at(packet, offset)?;
        let is_address = match record.rr_type {
            DNS_TYPE_A | DNS_TYPE_AAAA => true,
            DNS_TYPE_RRSIG => {
                record.end - record.header >= 12
                    && matches!(
                        BigEndian::read_u16(&packet[record.header + 10..]),
                        DNS_TYPE_A | DNS_TYPE_AAAA
                    )
            }
            _ => false,
        };
        if record.rr_type == DNS_TYPE_OPT
            || (is_address
                && record.rr_class == DNS_CLASS_IN
                && is_subdomain(&name_labels(packet, offset)?, bailiwick))
        {
            copy_name(packet, offset, additional_start, &mut filtered)?;
            filtered.extend_from_slice(&packet[record.header..record.end]);
        } else {
            removed += 1;
        }
        offset = record.end;
    }

    if removed == 0 {
        return Ok(0);
    }
    // Expanding names can make the packet bigger
    if filtered.len() > DNS_MAX_PACKET_SIZE {
        return Err(DnsError::PacketTooLarge {
            size: filtered.len(),
            max_size: DNS_MAX_PACKET_SIZE,
        });
    }
    set_arcount(&mut filtered, arcount - removed)?;
    *packet = filtered;
    Ok(usize::from(removed))
}

struct Record {
    rr_type: u16,
    rr_class: u16,
    /// Where the type field starts, right after the name
    header: usize,
    end: usize,
}

/// Reads the record whose name starts at `offset`.
fn record_at(packet: &[u8], offset: usize) -> DnsResult<Record> {
    let header = skip_name(packet, offset)?;
    if packet.len().saturating_sub(header) < 10 {
        return Err(DnsError::PacketTooShort { offset: header });
    }
    let end = header + 10 + BigEndian::read_u16(&packet[header + 8..]) as usize;
    if end > packet.len() {
        return Err(DnsError::InvalidRecord(
            "Record length would exceed packet length".to_string(),
        ));
    }
    Ok(Record {
        rr_type: BigEndian::read_u16(&packet[header..]),
        rr_class: BigEndian::read_u16(&packet[header + 2..]),
        header,
        end,
    })
}

/// Splits a name into labels, following compression pointers.
fn name_labels(packet: &[u8], mut offset: usize) -> DnsResult<Vec<&[u8]>> {
    // Once skip_name() accepts the name, the loop below can't go out of bounds or run forever
    skip_name(packet, offset)?;
    let mut labels = Vec::new();
    loop {
        let len = packet[offset] as usize;
        if len & 0xc0 == 0xc0 {
            offset = ((len & 0x3f) << 8) | packet[offset + 1] as usize;
        } else if len == 0 {
            return Ok(labels);
        } else {
            labels.push(&packet[offset + 1..=offset + len]);
            offset += 1 + len;
        }
    }
}

/// Tells whether `name` is `zone` or a name under it, ignoring case.
fn is_subdomain(name: &[&[u8]], zone: &[&[u8]]) -> bool {
    name.len() >= zone.len()
        && name[name.len() - zone.len()..]
            .iter()
            .zip(zone)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Copies a name to `out`.
///
/// Everything from `limit` on is about to move, so pointers leading there are replaced by
/// the labels they point to.
fn copy_name(packet: &[u8], mut offset: usize, limit: usize, out: &mut Vec<u8>) -> DnsResult<()> {
    skip_name(packet, offset)?;
    loop {
        let len = packet[offset] as usize;
        if len & 0xc0 == 0xc0 {
            let pointer = ((len & 0x3f) << 8) | packet[offset + 1] as usize;
            if name_ends_before(packet, pointer, limit) {
                out.extend_from_slice(&packet[offset..offset + 2]);
                return Ok(());
            }
            offset = pointer;
        } else {
            out.extend_from_slice(&packet[offset..=offset + len]);
            if len == 0 {
                return Ok(());
            }
            offset += 1 + len;
        }
    }
}

/// Tells whether a name, and whatever its pointers lead to, is stored before `limit`.
///
/// The name must already have been checked with skip_name().
fn name_ends_before(packet: &[u8], mut offset: usize, limit: usize) -> bool {
    loop {
        if offset >= limit {
            return false;
        }
        let len = packet[offset] as usize;
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= limit {
                return false;
            }
            offset = ((len & 0x3f) << 8) | packet[offset + 1] as usize;
        } else if len == 0 {
            return true;
        } else {
            offset += 1 + len;
        }
    }
}

/// Checks an ECS response against the subnet in its query.
pub fn edns_client_subnet_matches(query: &[u8], response: &[u8]) -> DnsResult<bool> {
    let Some(response_ecs) = extract_edns_client_subnet(response)? else {
        return Ok(true);
    };
    let Some(query_ecs) = extract_edns_client_subnet(query)? else {
        return Ok(false);
    };

    Ok(response_ecs.family == query_ecs.family
        && response_ecs.source_prefix_length == query_ecs.source_prefix_length
        && response_ecs.address == query_ecs.address)
}

/// Extracts EDNS-client-subnet information from a DNS packet
///
/// This function extracts EDNS-client-subnet information from a DNS packet.
/// It searches for an OPT record and then looks for the EDNS-client-subnet option.
///
/// # Arguments
///
/// * `packet` - The DNS packet to extract EDNS-client-subnet information from
///
/// # Returns
///
/// * `Ok(Some(EdnsClientSubnet))` - If EDNS-client-subnet information was found
/// * `Ok(None)` - If no EDNS-client-subnet information was found
/// * `Err(e)` - If there was an error extracting the information
#[allow(dead_code)]
pub fn extract_edns_client_subnet(packet: &[u8]) -> DnsResult<Option<EdnsClientSubnet>> {
    // Skip the question section
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    offset += 4; // Skip QTYPE and QCLASS

    // Skip answer and authority sections
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(packet, offset, ancount as usize + nscount as usize, |_| {
        Ok(())
    })?;

    // Check additional records for OPT
    let mut ecs_info = None;
    traverse_rrs(packet, offset, arcount as usize, |rr_offset| {
        let qtype = BigEndian::read_u16(&packet[rr_offset..]);
        if qtype == DNS_TYPE_OPT {
            // Found OPT record, now look for EDNS-client-subnet option
            let rdlen = BigEndian::read_u16(&packet[rr_offset + 8..rr_offset + 10]) as usize;
            let rdata_offset = rr_offset + 10;
            let rdata_end = rdata_offset + rdlen;

            // Parse EDNS options
            let mut option_offset = rdata_offset;
            while option_offset < rdata_end {
                if option_offset + 4 > rdata_end {
                    // Not enough space for option code and length
                    break;
                }

                let option_code = BigEndian::read_u16(&packet[option_offset..option_offset + 2]);
                let option_len =
                    BigEndian::read_u16(&packet[option_offset + 2..option_offset + 4]) as usize;
                option_offset += 4;

                if option_offset + option_len > rdata_end {
                    // Option length exceeds RDATA
                    break;
                }

                if option_code == EDNS_OPTION_CLIENT_SUBNET {
                    // Found EDNS-client-subnet option
                    if option_len < 4 {
                        // Not enough data for family, source prefix length, and scope prefix length
                        break;
                    }

                    let family = BigEndian::read_u16(&packet[option_offset..option_offset + 2]);
                    let source_prefix_length = packet[option_offset + 2];
                    let scope_prefix_length = packet[option_offset + 3];
                    let address_offset = option_offset + 4;
                    let address_len = option_len - 4;

                    let max_prefix = match family {
                        1 => 32,
                        2 => 128,
                        _ => u8::MAX,
                    };
                    if source_prefix_length > max_prefix {
                        break;
                    }

                    // Calculate expected address length based on prefix length
                    let expected_address_len = (source_prefix_length as usize).div_ceil(8);
                    if address_len < expected_address_len {
                        // Not enough address bytes
                        break;
                    }

                    // Extract the address
                    let address =
                        packet[address_offset..address_offset + expected_address_len].to_vec();

                    ecs_info = Some(EdnsClientSubnet {
                        family,
                        source_prefix_length,
                        scope_prefix_length,
                        address,
                    });

                    break;
                }

                option_offset += option_len;
            }
        }
        Ok(())
    })?;

    Ok(ecs_info)
}

#[cfg(test)]
mod overflow_tests {
    use super::*;
    use crate::errors::DnsError;

    #[test]
    fn test_offset_overflow_in_qname() {
        // Create a packet where label length calculation would overflow
        let mut packet = vec![0u8; DNS_HEADER_SIZE + 10];

        // Set QDCOUNT to 1
        packet[4] = 0;
        packet[5] = 1;

        // Create a label with length 64 (invalid - must be < 64)
        packet[DNS_HEADER_SIZE] = 64;

        // The qname function should handle this gracefully
        let result = qname(&packet);
        assert!(matches!(result, Err(DnsError::LabelTooLong { .. })));
    }

    #[test]
    fn test_offset_overflow_in_skip_name() {
        // Test that our overflow protection works
        // Create a small packet
        let mut packet = vec![0u8; 20];

        // Set QDCOUNT to 1
        packet[4] = 0;
        packet[5] = 1;

        // Create a name with large label count that would cause offset overflow
        packet[12] = 63; // Max valid label length
        // Not enough space in packet for this label

        let result = skip_name(&packet, 12);
        assert!(
            result.is_err(),
            "Expected error when label extends beyond packet"
        );
    }

    #[test]
    fn test_dns_packet_offset_boundary() {
        // Test packet where offset calculations approach usize::MAX
        // Create a valid minimal question with proper size
        let mut packet = vec![0u8; DNS_HEADER_SIZE + 5]; // Need 5 bytes for minimal question

        // Set QDCOUNT to 1
        packet[4] = 0;
        packet[5] = 1;

        packet[DNS_HEADER_SIZE] = 0; // Root label (1 byte)
        packet[DNS_HEADER_SIZE + 1] = 0; // QTYPE high byte
        packet[DNS_HEADER_SIZE + 2] = 1; // QTYPE low byte (A record)
        packet[DNS_HEADER_SIZE + 3] = 0; // QCLASS high byte
        packet[DNS_HEADER_SIZE + 4] = 1; // QCLASS low byte (IN)

        // This should succeed without overflow
        let result = validate_dns_packet(&packet);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ecs_helpers_reject_malformed_packets_without_panicking() {
        let root_query_with_opt = |rdlen: u16| {
            let mut packet = vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x02, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00,
            ];
            packet.extend_from_slice(&rdlen.to_be_bytes());
            packet
        };

        // OPT data running past the end of the packet
        let mut packet = root_query_with_opt(0xffff);
        packet.extend_from_slice(&[0x00, 0x08]);
        assert!(extract_edns_client_subnet(&packet).is_err());

        // A packet already over the size limit, because of a large padding option
        let padding_len = DNS_MAX_PACKET_SIZE;
        let mut packet = root_query_with_opt((padding_len + 4) as u16);
        packet.extend_from_slice(&[0x00, 0x0c]);
        packet.extend_from_slice(&(padding_len as u16).to_be_bytes());
        packet.resize(packet.len() + padding_len, 0);
        assert!(matches!(
            add_edns_client_subnet(&mut packet, "192.0.2.1", 24, 56, 1232),
            Err(DnsError::PacketTooLarge { .. })
        ));
    }
}

#[cfg(test)]
mod bailiwick_tests {
    use super::*;

    // Mixed case, like resolvers that randomize it
    const QNAME: &str = "www.sub.EXAMPLE.com";

    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|label| !label.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn pointer(offset: usize) -> [u8; 2] {
        (0xc000 | offset as u16).to_be_bytes()
    }

    fn rr(owner: &[u8], rr_type: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rr_type.to_be_bytes());
        out.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        out.extend_from_slice(&300u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    fn referral(authority: &[Vec<u8>], additional: &[Vec<u8>]) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00];
        packet.extend_from_slice(&(authority.len() as u16).to_be_bytes());
        packet.extend_from_slice(&(additional.len() as u16).to_be_bytes());
        packet.extend_from_slice(&wire_name(QNAME));
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        for record in authority.iter().chain(additional) {
            packet.extend_from_slice(record);
        }
        packet
    }

    /// Delegates sub.EXAMPLE.com, which is at offset 16 in the question, to `ns`.
    fn delegation(ns: &[u8]) -> Vec<u8> {
        rr(&pointer(16), DNS_TYPE_NS, ns)
    }

    /// Where the data of the first NS record starts, after its name and fixed fields.
    fn first_ns_data() -> usize {
        referral(&[], &[]).len() + 12
    }

    #[test]
    fn test_only_glue_under_the_parent_zone_is_kept() {
        let authority = [
            delegation(&wire_name("ns1.sub.example.com")),
            delegation(&wire_name("ns2.example.com")),
        ];
        let in_domain = rr(&pointer(first_ns_data()), DNS_TYPE_A, &[192, 0, 2, 1]);
        let sibling = rr(&wire_name("ns2.example.com"), DNS_TYPE_AAAA, &[0x20; 16]);
        let sibling_signature = rr(
            &wire_name("ns2.example.com"),
            DNS_TYPE_RRSIG,
            &DNS_TYPE_AAAA.to_be_bytes(),
        );
        let unrelated = rr(&wire_name("ns.example.net"), DNS_TYPE_A, &[198, 51, 100, 1]);
        let not_an_address = rr(&wire_name("ns1.sub.example.com"), DNS_TYPE_TXT, b"\x02hi");

        let mut packet = referral(
            &authority,
            &[
                in_domain.clone(),
                unrelated,
                sibling.clone(),
                not_an_address,
                sibling_signature.clone(),
            ],
        );
        let mut expected = referral(&authority, &[in_domain, sibling, sibling_signature]);
        add_edns_section(&mut packet, 1232).unwrap();
        add_edns_section(&mut expected, 1232).unwrap();

        assert_eq!(remove_out_of_bailiwick_glue(&mut packet).unwrap(), 2);
        assert_eq!(packet, expected);
    }

    #[test]
    fn test_pointers_to_moved_records_are_expanded() {
        // The NS data stops after "ns1", so that name goes on with the name of the TXT record
        let authority = [delegation(b"\x03ns1")];
        let txt_name = pointer(referral(&authority, &[]).len());
        let mut packet = referral(
            &authority,
            &[
                rr(&wire_name("example.com"), DNS_TYPE_TXT, b"\x02hi"),
                rr(&pointer(first_ns_data()), DNS_TYPE_A, &[192, 0, 2, 1]),
                rr(
                    &[b"\x03ns2", &txt_name[..]].concat(),
                    DNS_TYPE_A,
                    &[192, 0, 2, 2],
                ),
            ],
        );
        assert!(validate_dns_response(&packet).is_ok());

        let expected = referral(
            &authority,
            &[
                rr(&wire_name("ns1.example.com"), DNS_TYPE_A, &[192, 0, 2, 1]),
                rr(&wire_name("ns2.example.com"), DNS_TYPE_A, &[192, 0, 2, 2]),
            ],
        );
        assert_eq!(remove_out_of_bailiwick_glue(&mut packet).unwrap(), 1);
        assert_eq!(packet, expected);
    }

    #[test]
    fn test_other_responses_are_left_alone() {
        let glue = || rr(&wire_name("ns.example.net"), DNS_TYPE_A, &[198, 51, 100, 1]);
        let mut authoritative = referral(&[delegation(&wire_name("ns.example.net"))], &[glue()]);
        set_aa(&mut authoritative, true).unwrap();
        let other_name = rr(
            &wire_name("other.example.com"),
            DNS_TYPE_NS,
            &wire_name("ns.example.net"),
        );
        let root = rr(&[0], DNS_TYPE_NS, &wire_name("a.root-servers.net"));

        for mut packet in [
            authoritative,
            referral(&[other_name], &[glue()]),
            // Every name is under the root
            referral(&[root], &[glue()]),
        ] {
            assert_eq!(remove_out_of_bailiwick_glue(&mut packet).unwrap(), 0);
        }
    }

    #[test]
    fn test_malformed_or_oversized_results_are_errors() {
        let authority = [delegation(&wire_name("ns.example.com"))];

        let glue = rr(&wire_name("ns.example.net"), DNS_TYPE_A, &[198, 51, 100, 1]);
        let mut truncated = referral(&authority, &[glue]);
        truncated.pop();
        assert!(remove_out_of_bailiwick_glue(&mut truncated).is_err());

        // Once the TXT record is gone, its long name has to be written out in all 30 A records
        let long_name = format!("{}example.com", "abcdefghijklmnopqrstuvwxyz.".repeat(8));
        let a_long_name = [b"\x01a", &pointer(referral(&authority, &[]).len())[..]].concat();
        let mut additional = vec![rr(&wire_name(&long_name), DNS_TYPE_TXT, b"\x02hi")];
        additional.extend(std::iter::repeat_n(
            rr(&a_long_name, DNS_TYPE_A, &[192, 0, 2, 3]),
            30,
        ));
        let mut too_large = referral(&authority, &additional);
        assert!(validate_dns_response(&too_large).is_ok());
        assert!(matches!(
            remove_out_of_bailiwick_glue(&mut too_large),
            Err(DnsError::PacketTooLarge { .. })
        ));
    }
}
