//! Deterministic reverse-path Ethernet response packet generation.
//!
//! This module owns protocol parsing and checksums only. Scheduler ownership,
//! route selection, virtual delay, response-depth bounds, and checkpointing
//! remain host-side concerns above the device crate.

const ETHERNET_HEADER: usize = 14;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_HEADER: usize = 20;
const ICMP_HEADER: usize = 8;

/// Address and header fields selected by a typed response policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkResponseHeaders {
    /// Optional source MAC; absence uses the request destination MAC.
    pub source_mac: Option<[u8; 6]>,
    /// Optional IPv4 source; absence uses the request destination IPv4 address.
    pub source_ipv4: Option<[u8; 4]>,
    /// Optional IPv6 source; absence uses the request destination IPv6 address.
    pub source_ipv6: Option<[u8; 16]>,
    /// Positive IPv4 TTL or IPv6 hop limit.
    pub hop_limit: u8,
    /// Deterministic IPv4 identification used by generated IPv4 packets.
    pub ipv4_identification: u16,
}

/// Closed packet family generated for a modeled network rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkResponseKind {
    /// ICMPv4 Destination Unreachable, excluding Packet Too Big code 4.
    Icmpv4DestinationUnreachable {
        /// ICMP code in `0..=15`, other than 4.
        code: u8,
        /// Maximum request payload bytes quoted after its complete IPv4 header.
        quote_payload_bytes: u16,
    },
    /// ICMPv4 Packet Too Big (Destination Unreachable code 4).
    Icmpv4PacketTooBig {
        /// Maximum request payload bytes quoted after its complete IPv4 header.
        quote_payload_bytes: u16,
        /// Next-hop IPv4 MTU placed in the ICMP header.
        next_hop_mtu: u16,
    },
    /// ICMPv4 Time Exceeded.
    Icmpv4TimeExceeded {
        /// ICMP code, 0 for TTL or 1 for fragment reassembly.
        code: u8,
        /// Maximum request payload bytes quoted after its complete IPv4 header.
        quote_payload_bytes: u16,
    },
    /// ICMPv6 Destination Unreachable.
    Icmpv6DestinationUnreachable {
        /// ICMPv6 code in `0..=7`.
        code: u8,
        /// Maximum original IPv6 packet bytes quoted after the base header.
        quote_payload_bytes: u16,
    },
    /// ICMPv6 Packet Too Big.
    Icmpv6PacketTooBig {
        /// Maximum original IPv6 packet bytes quoted after the base header.
        quote_payload_bytes: u16,
        /// Next-hop IPv6 MTU placed in the ICMPv6 header.
        next_hop_mtu: u32,
    },
    /// TCP reset generated from an unfragmented IPv4 or IPv6 TCP segment.
    TcpReset,
    /// Exact complete Ethernet frame bytes.
    OpaqueEthernet {
        /// Bounded frame bytes supplied by the admitted policy.
        bytes: Vec<u8>,
    },
}

/// Complete protocol-level response generation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkResponseSpecification {
    /// Packet family and family-specific parameters.
    pub kind: NetworkResponseKind,
    /// Source-address and IP-header parameters.
    pub headers: NetworkResponseHeaders,
}

/// Result of protocol response generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkResponseOutcome {
    /// Protocol rules suppress a response to this request.
    Suppressed,
    /// Complete generated Ethernet frame.
    Frame(Vec<u8>),
}

/// Failure to parse a request or encode its configured response.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetworkResponseError {
    /// A positive TTL or hop limit is required.
    #[error("generated response TTL or hop limit must be positive")]
    ZeroHopLimit,
    /// The response kind contains an invalid protocol code or MTU.
    #[error("generated response parameters are invalid")]
    InvalidParameters,
    /// The request does not match the response packet family.
    #[error("request frame does not match the generated response packet family")]
    ProtocolMismatch,
    /// An Ethernet or IP length/header field is malformed.
    #[error("request frame contains a malformed Ethernet or IP packet")]
    MalformedRequest,
    /// A TCP header or segment length is malformed.
    #[error("request frame contains a malformed TCP segment")]
    MalformedTcp,
    /// The generated frame would exceed a protocol length field.
    #[error("generated response exceeds its protocol length field")]
    ResponseTooLarge,
    /// An opaque Ethernet response is empty or shorter than its header.
    #[error("opaque generated response is shorter than an Ethernet header")]
    InvalidOpaqueFrame,
}

/// Generates one exact reverse-path Ethernet response for `request`.
///
/// ICMP errors follow the standard suppression rules for multicast/broadcast
/// destinations, invalid sources, non-initial fragments, and ICMP errors in
/// response to ICMP errors. TCP resets are suppressed for incoming resets.
///
/// # Errors
///
/// Returns [`NetworkResponseError`] for invalid policy parameters, malformed
/// request headers, protocol-family mismatches, or unrepresentable lengths.
pub fn generate_network_response(
    request: &[u8],
    specification: &NetworkResponseSpecification,
) -> Result<NetworkResponseOutcome, NetworkResponseError> {
    match &specification.kind {
        NetworkResponseKind::Icmpv4DestinationUnreachable {
            code,
            quote_payload_bytes,
        } if *code <= 15 && *code != 4 => generate_icmpv4(
            request,
            specification.headers,
            3,
            *code,
            0,
            *quote_payload_bytes,
        ),
        NetworkResponseKind::Icmpv4PacketTooBig {
            quote_payload_bytes,
            next_hop_mtu,
        } if *next_hop_mtu > 0 => generate_icmpv4(
            request,
            specification.headers,
            3,
            4,
            u32::from(*next_hop_mtu),
            *quote_payload_bytes,
        ),
        NetworkResponseKind::Icmpv4TimeExceeded {
            code,
            quote_payload_bytes,
        } if *code <= 1 => generate_icmpv4(
            request,
            specification.headers,
            11,
            *code,
            0,
            *quote_payload_bytes,
        ),
        NetworkResponseKind::Icmpv6DestinationUnreachable {
            code,
            quote_payload_bytes,
        } if *code <= 7 => generate_icmpv6(
            request,
            specification.headers,
            1,
            *code,
            0,
            *quote_payload_bytes,
        ),
        NetworkResponseKind::Icmpv6PacketTooBig {
            quote_payload_bytes,
            next_hop_mtu,
        } if *next_hop_mtu >= 1_280 => generate_icmpv6(
            request,
            specification.headers,
            2,
            0,
            *next_hop_mtu,
            *quote_payload_bytes,
        ),
        NetworkResponseKind::TcpReset => generate_tcp_reset(request, specification.headers),
        NetworkResponseKind::OpaqueEthernet { bytes } if bytes.len() >= ETHERNET_HEADER => {
            Ok(NetworkResponseOutcome::Frame(bytes.clone()))
        }
        NetworkResponseKind::OpaqueEthernet { .. } => Err(NetworkResponseError::InvalidOpaqueFrame),
        _ => Err(NetworkResponseError::InvalidParameters),
    }
}

fn require_hop_limit(headers: NetworkResponseHeaders) -> Result<(), NetworkResponseError> {
    if headers.hop_limit == 0 {
        Err(NetworkResponseError::ZeroHopLimit)
    } else {
        Ok(())
    }
}

struct Ipv4Request<'a> {
    ethernet: &'a [u8],
    packet: &'a [u8],
    header_bytes: usize,
    protocol: u8,
    source: [u8; 4],
    destination: [u8; 4],
    flags_offset: u16,
}

fn parse_ipv4(request: &[u8]) -> Result<Ipv4Request<'_>, NetworkResponseError> {
    if request.get(12..14) != Some(&[0x08, 0x00]) {
        return Err(NetworkResponseError::ProtocolMismatch);
    }
    if request.len() < ETHERNET_HEADER + IPV4_HEADER {
        return Err(NetworkResponseError::MalformedRequest);
    }
    let version_ihl = request[ETHERNET_HEADER];
    let header_bytes = usize::from(version_ihl & 0x0f)
        .checked_mul(4)
        .ok_or(NetworkResponseError::MalformedRequest)?;
    if version_ihl >> 4 != 4 || header_bytes < IPV4_HEADER {
        return Err(NetworkResponseError::MalformedRequest);
    }
    let total_length = usize::from(u16::from_be_bytes([
        request[ETHERNET_HEADER + 2],
        request[ETHERNET_HEADER + 3],
    ]));
    let end = ETHERNET_HEADER
        .checked_add(total_length)
        .ok_or(NetworkResponseError::MalformedRequest)?;
    if total_length < header_bytes || end > request.len() {
        return Err(NetworkResponseError::MalformedRequest);
    }
    let source = request[ETHERNET_HEADER + 12..ETHERNET_HEADER + 16]
        .try_into()
        .map_err(|_error| NetworkResponseError::MalformedRequest)?;
    let destination = request[ETHERNET_HEADER + 16..ETHERNET_HEADER + 20]
        .try_into()
        .map_err(|_error| NetworkResponseError::MalformedRequest)?;
    Ok(Ipv4Request {
        ethernet: &request[..ETHERNET_HEADER],
        packet: &request[ETHERNET_HEADER..end],
        header_bytes,
        protocol: request[ETHERNET_HEADER + 9],
        source,
        destination,
        flags_offset: u16::from_be_bytes([
            request[ETHERNET_HEADER + 6],
            request[ETHERNET_HEADER + 7],
        ]),
    })
}

fn generate_icmpv4(
    request: &[u8],
    headers: NetworkResponseHeaders,
    icmp_type: u8,
    code: u8,
    rest_of_header: u32,
    quote_payload_bytes: u16,
) -> Result<NetworkResponseOutcome, NetworkResponseError> {
    require_hop_limit(headers)?;
    let request = parse_ipv4(request)?;
    if suppress_icmpv4(&request) {
        return Ok(NetworkResponseOutcome::Suppressed);
    }
    let quote_length = request
        .header_bytes
        .checked_add(
            request
                .packet
                .len()
                .saturating_sub(request.header_bytes)
                .min(usize::from(quote_payload_bytes)),
        )
        .ok_or(NetworkResponseError::ResponseTooLarge)?;
    let icmp_length = ICMP_HEADER
        .checked_add(quote_length)
        .ok_or(NetworkResponseError::ResponseTooLarge)?;
    let total_length = IPV4_HEADER
        .checked_add(icmp_length)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(NetworkResponseError::ResponseTooLarge)?;
    let mut response = reverse_ethernet(request.ethernet, headers.source_mac, 0x0800)?;
    response.resize(ETHERNET_HEADER + IPV4_HEADER, 0);
    response[14] = 0x45;
    response[16..18].copy_from_slice(&total_length.to_be_bytes());
    response[18..20].copy_from_slice(&headers.ipv4_identification.to_be_bytes());
    response[22] = headers.hop_limit;
    response[23] = 1;
    let source = headers.source_ipv4.unwrap_or(request.destination);
    response[26..30].copy_from_slice(&source);
    response[30..34].copy_from_slice(&request.source);
    let ip_checksum = internet_checksum(&response[14..34]);
    response[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    let icmp_start = response.len();
    response.resize(icmp_start + ICMP_HEADER, 0);
    response[icmp_start] = icmp_type;
    response[icmp_start + 1] = code;
    response[icmp_start + 4..icmp_start + 8].copy_from_slice(&rest_of_header.to_be_bytes());
    response.extend_from_slice(&request.packet[..quote_length]);
    let checksum = internet_checksum(&response[icmp_start..]);
    response[icmp_start + 2..icmp_start + 4].copy_from_slice(&checksum.to_be_bytes());
    Ok(NetworkResponseOutcome::Frame(response))
}

fn suppress_icmpv4(request: &Ipv4Request<'_>) -> bool {
    let destination_multicast = request.destination[0] & 0xf0 == 0xe0;
    let source_invalid =
        request.source == [0; 4] || request.source == [255; 4] || request.source[0] & 0xf0 == 0xe0;
    let ethernet_multicast = request.ethernet[0] & 1 != 0;
    let non_initial_fragment = request.flags_offset & 0x1fff != 0;
    let response_to_icmp_error = request.protocol == 1
        && request
            .packet
            .get(request.header_bytes)
            .is_some_and(|kind| matches!(kind, 3 | 4 | 5 | 11 | 12));
    destination_multicast
        || request.destination == [255; 4]
        || source_invalid
        || ethernet_multicast
        || non_initial_fragment
        || response_to_icmp_error
}

#[path = "response/ipv6.rs"]
mod ipv6;

use ipv6::*;

fn generate_tcp_reset(
    request: &[u8],
    headers: NetworkResponseHeaders,
) -> Result<NetworkResponseOutcome, NetworkResponseError> {
    require_hop_limit(headers)?;
    match request.get(12..14) {
        Some([0x08, 0x00]) => generate_tcp_reset_ipv4(request, headers),
        Some([0x86, 0xdd]) => generate_tcp_reset_ipv6(request, headers),
        _ => Err(NetworkResponseError::ProtocolMismatch),
    }
}

fn generate_tcp_reset_ipv4(
    request: &[u8],
    headers: NetworkResponseHeaders,
) -> Result<NetworkResponseOutcome, NetworkResponseError> {
    let request = parse_ipv4(request)?;
    if request.protocol != 6 || request.flags_offset & 0x3fff != 0 {
        return Err(NetworkResponseError::ProtocolMismatch);
    }
    let segment = &request.packet[request.header_bytes..];
    let reset = tcp_reset_segment(segment)?;
    let Some(reset) = reset else {
        return Ok(NetworkResponseOutcome::Suppressed);
    };
    let total_length = u16::try_from(IPV4_HEADER + reset.len())
        .map_err(|_error| NetworkResponseError::ResponseTooLarge)?;
    let mut response = reverse_ethernet(request.ethernet, headers.source_mac, 0x0800)?;
    response.resize(ETHERNET_HEADER + IPV4_HEADER, 0);
    response[14] = 0x45;
    response[16..18].copy_from_slice(&total_length.to_be_bytes());
    response[18..20].copy_from_slice(&headers.ipv4_identification.to_be_bytes());
    response[22] = headers.hop_limit;
    response[23] = 6;
    let source = headers.source_ipv4.unwrap_or(request.destination);
    response[26..30].copy_from_slice(&source);
    response[30..34].copy_from_slice(&request.source);
    let ip_checksum = internet_checksum(&response[14..34]);
    response[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    let tcp_start = response.len();
    response.extend_from_slice(&reset);
    let checksum = transport_checksum_ipv4(source, request.source, 6, &response[tcp_start..])?;
    response[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
    Ok(NetworkResponseOutcome::Frame(response))
}

fn generate_tcp_reset_ipv6(
    request: &[u8],
    headers: NetworkResponseHeaders,
) -> Result<NetworkResponseOutcome, NetworkResponseError> {
    let request = parse_ipv6(request)?;
    if request.upper_protocol != Some(6) || request.non_initial_fragment {
        return Err(NetworkResponseError::ProtocolMismatch);
    }
    let segment = &request.packet[request.upper_offset..];
    let reset = tcp_reset_segment(segment)?;
    let Some(reset) = reset else {
        return Ok(NetworkResponseOutcome::Suppressed);
    };
    let payload_length =
        u16::try_from(reset.len()).map_err(|_error| NetworkResponseError::ResponseTooLarge)?;
    let mut response = reverse_ethernet(request.ethernet, headers.source_mac, 0x86dd)?;
    response.resize(ETHERNET_HEADER + IPV6_HEADER, 0);
    response[14] = 0x60;
    response[18..20].copy_from_slice(&payload_length.to_be_bytes());
    response[20] = 6;
    response[21] = headers.hop_limit;
    let source = headers.source_ipv6.unwrap_or(request.destination);
    response[22..38].copy_from_slice(&source);
    response[38..54].copy_from_slice(&request.source);
    let tcp_start = response.len();
    response.extend_from_slice(&reset);
    let checksum = transport_checksum_ipv6(source, request.source, 6, &response[tcp_start..])?;
    response[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
    Ok(NetworkResponseOutcome::Frame(response))
}

fn tcp_reset_segment(segment: &[u8]) -> Result<Option<Vec<u8>>, NetworkResponseError> {
    if segment.len() < TCP_HEADER {
        return Err(NetworkResponseError::MalformedTcp);
    }
    let header_bytes = usize::from(segment[12] >> 4)
        .checked_mul(4)
        .ok_or(NetworkResponseError::MalformedTcp)?;
    if header_bytes < TCP_HEADER || header_bytes > segment.len() {
        return Err(NetworkResponseError::MalformedTcp);
    }
    let flags = segment[13];
    if flags & 0x04 != 0 {
        return Ok(None);
    }
    let sequence = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
    let acknowledgement = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
    let mut reset = vec![0_u8; TCP_HEADER];
    reset[0..2].copy_from_slice(&segment[2..4]);
    reset[2..4].copy_from_slice(&segment[0..2]);
    reset[12] = 5 << 4;
    if flags & 0x10 != 0 {
        reset[4..8].copy_from_slice(&acknowledgement.to_be_bytes());
        reset[13] = 0x04;
    } else {
        let payload_length = segment.len().saturating_sub(header_bytes);
        let control_length = u32::from(flags & 0x02 != 0) + u32::from(flags & 0x01 != 0);
        let consumed = u32::try_from(payload_length)
            .ok()
            .and_then(|length| length.checked_add(control_length))
            .ok_or(NetworkResponseError::MalformedTcp)?;
        let acknowledgement = sequence.wrapping_add(consumed);
        reset[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
        reset[13] = 0x14;
    }
    Ok(Some(reset))
}

fn reverse_ethernet(
    request: &[u8],
    source_override: Option<[u8; 6]>,
    ether_type: u16,
) -> Result<Vec<u8>, NetworkResponseError> {
    if request.len() < ETHERNET_HEADER {
        return Err(NetworkResponseError::MalformedRequest);
    }
    let mut response = Vec::with_capacity(ETHERNET_HEADER);
    response.extend_from_slice(&request[6..12]);
    response.extend_from_slice(&source_override.unwrap_or_else(|| {
        let mut address = [0_u8; 6];
        address.copy_from_slice(&request[..6]);
        address
    }));
    response.extend_from_slice(&ether_type.to_be_bytes());
    Ok(response)
}

fn transport_checksum_ipv4(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    segment: &[u8],
) -> Result<u16, NetworkResponseError> {
    let length =
        u16::try_from(segment.len()).map_err(|_error| NetworkResponseError::ResponseTooLarge)?;
    let mut material = Vec::with_capacity(12 + segment.len());
    material.extend_from_slice(&source);
    material.extend_from_slice(&destination);
    material.push(0);
    material.push(protocol);
    material.extend_from_slice(&length.to_be_bytes());
    material.extend_from_slice(segment);
    Ok(internet_checksum(&material))
}

fn transport_checksum_ipv6(
    source: [u8; 16],
    destination: [u8; 16],
    next_header: u8,
    segment: &[u8],
) -> Result<u16, NetworkResponseError> {
    let length =
        u32::try_from(segment.len()).map_err(|_error| NetworkResponseError::ResponseTooLarge)?;
    let mut material = Vec::with_capacity(40 + segment.len());
    material.extend_from_slice(&source);
    material.extend_from_slice(&destination);
    material.extend_from_slice(&length.to_be_bytes());
    material.extend_from_slice(&[0, 0, 0, next_header]);
    material.extend_from_slice(segment);
    Ok(internet_checksum(&material))
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(byte) = words.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
#[path = "response_test.rs"]
mod tests;
