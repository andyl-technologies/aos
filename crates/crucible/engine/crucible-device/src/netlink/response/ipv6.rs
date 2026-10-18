//! IPv6 request parsing and ICMPv6 response generation.

use super::*;

pub(super) struct Ipv6Request<'a> {
    pub(super) ethernet: &'a [u8],
    pub(super) packet: &'a [u8],
    pub(super) upper_protocol: Option<u8>,
    pub(super) upper_offset: usize,
    pub(super) non_initial_fragment: bool,
    pub(super) source: [u8; 16],
    pub(super) destination: [u8; 16],
}

pub(super) fn parse_ipv6(request: &[u8]) -> Result<Ipv6Request<'_>, NetworkResponseError> {
    if request.get(12..14) != Some(&[0x86, 0xdd]) {
        return Err(NetworkResponseError::ProtocolMismatch);
    }
    if request.len() < ETHERNET_HEADER + IPV6_HEADER {
        return Err(NetworkResponseError::MalformedRequest);
    }
    if request[ETHERNET_HEADER] >> 4 != 6 {
        return Err(NetworkResponseError::MalformedRequest);
    }
    let payload_length = usize::from(u16::from_be_bytes([
        request[ETHERNET_HEADER + 4],
        request[ETHERNET_HEADER + 5],
    ]));
    let packet_length = IPV6_HEADER
        .checked_add(payload_length)
        .ok_or(NetworkResponseError::MalformedRequest)?;
    let end = ETHERNET_HEADER
        .checked_add(packet_length)
        .ok_or(NetworkResponseError::MalformedRequest)?;
    if end > request.len() {
        return Err(NetworkResponseError::MalformedRequest);
    }
    let source = request[ETHERNET_HEADER + 8..ETHERNET_HEADER + 24]
        .try_into()
        .map_err(|_error| NetworkResponseError::MalformedRequest)?;
    let destination = request[ETHERNET_HEADER + 24..ETHERNET_HEADER + 40]
        .try_into()
        .map_err(|_error| NetworkResponseError::MalformedRequest)?;
    let (upper_protocol, upper_offset, non_initial_fragment) =
        parse_ipv6_extension_chain(&request[ETHERNET_HEADER..end])?;
    Ok(Ipv6Request {
        ethernet: &request[..ETHERNET_HEADER],
        packet: &request[ETHERNET_HEADER..end],
        upper_protocol,
        upper_offset,
        non_initial_fragment,
        source,
        destination,
    })
}

pub(super) fn parse_ipv6_extension_chain(
    packet: &[u8],
) -> Result<(Option<u8>, usize, bool), NetworkResponseError> {
    let mut next_header = packet[6];
    let mut offset = IPV6_HEADER;
    let mut non_initial_fragment = false;
    for _ in 0..16 {
        let extension_length = match next_header {
            0 | 43 | 60 => {
                let extension = packet
                    .get(offset..offset + 2)
                    .ok_or(NetworkResponseError::MalformedRequest)?;
                next_header = extension[0];
                (usize::from(extension[1]) + 1) * 8
            }
            44 => {
                let extension = packet
                    .get(offset..offset + 8)
                    .ok_or(NetworkResponseError::MalformedRequest)?;
                next_header = extension[0];
                let fragment = u16::from_be_bytes([extension[2], extension[3]]);
                non_initial_fragment |= fragment & 0xfff8 != 0;
                8
            }
            51 => {
                let extension = packet
                    .get(offset..offset + 2)
                    .ok_or(NetworkResponseError::MalformedRequest)?;
                next_header = extension[0];
                (usize::from(extension[1]) + 2) * 4
            }
            50 | 59 => return Ok((None, offset, non_initial_fragment)),
            protocol => return Ok((Some(protocol), offset, non_initial_fragment)),
        };
        offset = offset
            .checked_add(extension_length)
            .filter(|end| *end <= packet.len())
            .ok_or(NetworkResponseError::MalformedRequest)?;
    }
    Err(NetworkResponseError::MalformedRequest)
}

pub(super) fn generate_icmpv6(
    request: &[u8],
    headers: NetworkResponseHeaders,
    icmp_type: u8,
    code: u8,
    rest_of_header: u32,
    quote_payload_bytes: u16,
) -> Result<NetworkResponseOutcome, NetworkResponseError> {
    require_hop_limit(headers)?;
    let request = parse_ipv6(request)?;
    if suppress_icmpv6(&request, icmp_type) {
        return Ok(NetworkResponseOutcome::Suppressed);
    }
    let quote_length = IPV6_HEADER
        .checked_add(
            request
                .packet
                .len()
                .saturating_sub(IPV6_HEADER)
                .min(usize::from(quote_payload_bytes)),
        )
        .ok_or(NetworkResponseError::ResponseTooLarge)?;
    let icmp_length = ICMP_HEADER
        .checked_add(quote_length)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(NetworkResponseError::ResponseTooLarge)?;
    let mut response = reverse_ethernet(request.ethernet, headers.source_mac, 0x86dd)?;
    response.resize(ETHERNET_HEADER + IPV6_HEADER, 0);
    response[14] = 0x60;
    response[18..20].copy_from_slice(&icmp_length.to_be_bytes());
    response[20] = 58;
    response[21] = headers.hop_limit;
    let source = headers.source_ipv6.unwrap_or(request.destination);
    response[22..38].copy_from_slice(&source);
    response[38..54].copy_from_slice(&request.source);
    let icmp_start = response.len();
    response.resize(icmp_start + ICMP_HEADER, 0);
    response[icmp_start] = icmp_type;
    response[icmp_start + 1] = code;
    response[icmp_start + 4..icmp_start + 8].copy_from_slice(&rest_of_header.to_be_bytes());
    response.extend_from_slice(&request.packet[..quote_length]);
    let checksum = transport_checksum_ipv6(source, request.source, 58, &response[icmp_start..])?;
    response[icmp_start + 2..icmp_start + 4].copy_from_slice(&checksum.to_be_bytes());
    Ok(NetworkResponseOutcome::Frame(response))
}

pub(super) fn suppress_icmpv6(request: &Ipv6Request<'_>, response_type: u8) -> bool {
    let source_unspecified = request.source == [0; 16];
    let source_multicast = request.source[0] == 0xff;
    let destination_multicast = request.destination[0] == 0xff;
    let ethernet_multicast = request.ethernet[0] & 1 != 0;
    let response_to_icmp_error = request.upper_protocol == Some(58)
        && !request.non_initial_fragment
        && request
            .packet
            .get(request.upper_offset)
            .is_some_and(|kind| *kind < 128);
    source_unspecified
        || source_multicast
        || ((destination_multicast || ethernet_multicast) && response_type != 2)
        || response_to_icmp_error
}
