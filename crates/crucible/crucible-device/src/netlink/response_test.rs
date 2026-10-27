//! Typed network-response generation tests.

use super::*;

const REQUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const TARGET_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const V4_SOURCE: [u8; 4] = [192, 0, 2, 1];
const V4_DESTINATION: [u8; 4] = [198, 51, 100, 2];
const V6_SOURCE: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const V6_DESTINATION: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn headers() -> NetworkResponseHeaders {
    NetworkResponseHeaders {
        source_mac: None,
        source_ipv4: None,
        source_ipv6: None,
        hop_limit: 64,
        ipv4_identification: 0x1234,
    }
}

fn ethernet(ether_type: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&TARGET_MAC);
    frame.extend_from_slice(&REQUEST_MAC);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame
}

fn ipv4(protocol: u8, payload: &[u8], flags_offset: u16) -> Vec<u8> {
    let mut frame = ethernet(0x0800);
    frame.resize(ETHERNET_HEADER + IPV4_HEADER, 0);
    frame[14] = 0x45;
    let length = u16::try_from(IPV4_HEADER + payload.len())
        .unwrap_or_else(|error| panic!("test IPv4 payload must fit u16: {error}"));
    frame[16..18].copy_from_slice(&length.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
    frame[22] = 32;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&V4_SOURCE);
    frame[30..34].copy_from_slice(&V4_DESTINATION);
    let checksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = ethernet(0x86dd);
    frame.resize(ETHERNET_HEADER + IPV6_HEADER, 0);
    frame[14] = 0x60;
    let length = u16::try_from(payload.len())
        .unwrap_or_else(|error| panic!("test IPv6 payload must fit u16: {error}"));
    frame[18..20].copy_from_slice(&length.to_be_bytes());
    frame[20] = next_header;
    frame[21] = 32;
    frame[22..38].copy_from_slice(&V6_SOURCE);
    frame[38..54].copy_from_slice(&V6_DESTINATION);
    frame.extend_from_slice(payload);
    frame
}

fn tcp(flags: u8, sequence: u32, acknowledgement: u32, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0_u8; TCP_HEADER];
    segment[0..2].copy_from_slice(&1234_u16.to_be_bytes());
    segment[2..4].copy_from_slice(&443_u16.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = flags;
    segment.extend_from_slice(payload);
    segment
}

fn response(request: &[u8], kind: NetworkResponseKind) -> NetworkResponseOutcome {
    generate_network_response(
        request,
        &NetworkResponseSpecification {
            kind,
            headers: headers(),
        },
    )
    .unwrap_or_else(|error| panic!("test response must be valid: {error}"))
}

#[test]
fn icmpv4_packet_too_big_has_exact_headers_quote_and_checksums() {
    let request = ipv4(17, &[1, 2, 3, 4, 5, 6], 0);
    let NetworkResponseOutcome::Frame(frame) = response(
        &request,
        NetworkResponseKind::Icmpv4PacketTooBig {
            quote_payload_bytes: 4,
            next_hop_mtu: 1_400,
        },
    ) else {
        panic!("response was suppressed")
    };
    assert_eq!(&frame[..6], &REQUEST_MAC);
    assert_eq!(&frame[6..12], &TARGET_MAC);
    assert_eq!(&frame[26..30], &V4_DESTINATION);
    assert_eq!(&frame[30..34], &V4_SOURCE);
    assert_eq!(internet_checksum(&frame[14..34]), 0);
    assert_eq!(&frame[34..36], &[3, 4]);
    assert_eq!(&frame[38..42], &[0, 0, 0x05, 0x78]);
    assert_eq!(internet_checksum(&frame[34..]), 0);
    assert_eq!(&frame[42..], &request[14..38]);
}

#[test]
fn icmpv4_suppresses_noninitial_fragments_and_icmp_errors() {
    assert_eq!(
        response(
            &ipv4(17, &[0; 8], 1),
            NetworkResponseKind::Icmpv4TimeExceeded {
                code: 0,
                quote_payload_bytes: 8,
            }
        ),
        NetworkResponseOutcome::Suppressed
    );
    assert_eq!(
        response(
            &ipv4(1, &[3, 0, 0, 0, 0, 0, 0, 0], 0),
            NetworkResponseKind::Icmpv4DestinationUnreachable {
                code: 1,
                quote_payload_bytes: 8,
            }
        ),
        NetworkResponseOutcome::Suppressed
    );
}

#[test]
fn icmpv6_packet_too_big_has_exact_headers_quote_and_checksum() {
    let request = ipv6(17, &[1, 2, 3, 4]);
    let NetworkResponseOutcome::Frame(frame) = response(
        &request,
        NetworkResponseKind::Icmpv6PacketTooBig {
            quote_payload_bytes: 2,
            next_hop_mtu: 1_280,
        },
    ) else {
        panic!("response was suppressed")
    };
    assert_eq!(&frame[22..38], &V6_DESTINATION);
    assert_eq!(&frame[38..54], &V6_SOURCE);
    assert_eq!(&frame[54..56], &[2, 0]);
    assert_eq!(&frame[58..62], &1_280_u32.to_be_bytes());
    assert_eq!(&frame[62..], &request[14..56]);
    assert_eq!(
        transport_checksum_ipv6(V6_DESTINATION, V6_SOURCE, 58, &frame[54..])
            .unwrap_or_else(|error| panic!("test ICMPv6 checksum must be valid: {error}")),
        0
    );
}

#[test]
fn icmpv6_multicast_suppression_keeps_packet_too_big_exception() {
    let mut request = ipv6(17, &[1, 2, 3, 4]);
    request[0] |= 1;
    request[38] = 0xff;
    assert_eq!(
        response(
            &request,
            NetworkResponseKind::Icmpv6DestinationUnreachable {
                code: 0,
                quote_payload_bytes: 4,
            }
        ),
        NetworkResponseOutcome::Suppressed
    );
    assert!(matches!(
        response(
            &request,
            NetworkResponseKind::Icmpv6PacketTooBig {
                quote_payload_bytes: 4,
                next_hop_mtu: 1_280,
            }
        ),
        NetworkResponseOutcome::Frame(_)
    ));
}

#[test]
fn tcp_reset_ipv4_obeys_acknowledgement_rules() {
    let request = ipv4(6, &tcp(0x10, 10, 900, &[]), 0);
    let NetworkResponseOutcome::Frame(frame) = response(&request, NetworkResponseKind::TcpReset)
    else {
        panic!("response was suppressed")
    };
    assert_eq!(&frame[34..38], &[0x01, 0xbb, 0x04, 0xd2]);
    assert_eq!(&frame[38..42], &900_u32.to_be_bytes());
    assert_eq!(frame[47], 0x04);
    assert_eq!(
        transport_checksum_ipv4(V4_DESTINATION, V4_SOURCE, 6, &frame[34..])
            .unwrap_or_else(|error| panic!("test TCPv4 checksum must be valid: {error}")),
        0
    );

    let request = ipv4(6, &tcp(0x02, 10, 0, &[1, 2, 3]), 0);
    let NetworkResponseOutcome::Frame(frame) = response(&request, NetworkResponseKind::TcpReset)
    else {
        panic!("response was suppressed")
    };
    assert_eq!(&frame[42..46], &14_u32.to_be_bytes());
    assert_eq!(frame[47], 0x14);
}

#[test]
fn tcp_reset_ipv6_walks_extension_headers_and_suppresses_resets() {
    let mut extension_and_tcp = vec![6, 0, 0, 0, 0, 0, 0, 0];
    extension_and_tcp.extend_from_slice(&tcp(0x10, 1, 77, &[]));
    let request = ipv6(0, &extension_and_tcp);
    let NetworkResponseOutcome::Frame(frame) = response(&request, NetworkResponseKind::TcpReset)
    else {
        panic!("response was suppressed")
    };
    assert_eq!(&frame[58..62], &77_u32.to_be_bytes());
    assert_eq!(
        transport_checksum_ipv6(V6_DESTINATION, V6_SOURCE, 6, &frame[54..])
            .unwrap_or_else(|error| panic!("test TCPv6 checksum must be valid: {error}")),
        0
    );
    assert_eq!(
        response(
            &ipv6(6, &tcp(0x04, 1, 0, &[])),
            NetworkResponseKind::TcpReset
        ),
        NetworkResponseOutcome::Suppressed
    );
}

#[test]
fn opaque_response_is_exact_and_parameter_errors_are_closed() {
    let bytes = ethernet(0x88b5);
    assert_eq!(
        response(
            &[],
            NetworkResponseKind::OpaqueEthernet {
                bytes: bytes.clone()
            }
        ),
        NetworkResponseOutcome::Frame(bytes)
    );
    let error = generate_network_response(
        &[],
        &NetworkResponseSpecification {
            kind: NetworkResponseKind::OpaqueEthernet { bytes: vec![0; 13] },
            headers: headers(),
        },
    );
    assert_eq!(error, Err(NetworkResponseError::InvalidOpaqueFrame));
}

#[test]
fn family_mismatch_is_distinct_from_malformed_matching_packet() {
    let specification = NetworkResponseSpecification {
        kind: NetworkResponseKind::Icmpv4TimeExceeded {
            code: 0,
            quote_payload_bytes: 8,
        },
        headers: headers(),
    };
    assert_eq!(
        generate_network_response(&ipv6(17, &[0; 8]), &specification),
        Err(NetworkResponseError::ProtocolMismatch)
    );
    let mut truncated = ethernet(0x0800);
    truncated.push(0x45);
    assert_eq!(
        generate_network_response(&truncated, &specification),
        Err(NetworkResponseError::MalformedRequest)
    );
}
