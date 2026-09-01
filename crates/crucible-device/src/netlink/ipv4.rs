//! Deterministic Ethernet/IPv4 fragmentation and later-hop re-fragmentation.
//!
//! The parser accepts untagged Ethernet II frames carrying IPv4. The supplied
//! MTU bounds the complete Ethernet frame, including its 14-byte link header.

const ETHERNET_HEADER: usize = 14;
const IPV4_MINIMUM_HEADER: usize = 20;

/// Result of applying an IPv4 fragmentation policy to one oversized frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ipv4FragmentationOutcome {
    /// Drops the datagram because its IPv4 `DF` bit prohibits fragmentation.
    DontFragment,
    /// Replaces the parent with one or more ordered Ethernet frames.
    Frames(Vec<Vec<u8>>),
}

/// Failure to decode or exactly fragment an Ethernet/IPv4 frame.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Ipv4FragmentationError {
    /// The input is not an untagged Ethernet II IPv4 frame.
    #[error("fragmentation requires an untagged IPv4 Ethernet frame")]
    UnsupportedFrame,
    /// The IPv4 version or header-length field is invalid.
    #[error("fragmentation found an invalid IPv4 header")]
    InvalidHeader,
    /// The IPv4 total-length field does not fit the supplied frame.
    #[error("fragmentation found an invalid IPv4 total length")]
    InvalidTotalLength,
    /// An already fragmented datagram illegally retains the `DF` bit.
    #[error("fragmentation found DF on an already fragmented datagram")]
    DontFragmentOnFragment,
    /// A non-final input fragment has a payload not divisible by eight.
    #[error("non-final IPv4 fragment payload is not a multiple of eight bytes")]
    InvalidNonFinalLength,
    /// The MTU cannot carry the Ethernet header, IPv4 header, and one fragment unit.
    #[error("MTU cannot carry the Ethernet header, IPv4 header, and one fragment unit")]
    MtuTooSmall,
    /// A resulting 13-bit fragment offset cannot be represented.
    #[error("IPv4 fragment offset exceeds 13 bits")]
    OffsetOverflow,
    /// A resulting IPv4 total length cannot be represented.
    #[error("IPv4 fragment length exceeds 16 bits")]
    LengthOverflow,
}

/// Fragments one oversized untagged Ethernet/IPv4 frame at a complete-frame MTU.
///
/// Existing fragments may be fragmented again. Their base offset is added to
/// each child offset and an existing `MF` flag remains set on every child.
/// Ethernet padding past the IPv4 total length is removed.
///
/// # Errors
///
/// Returns [`Ipv4FragmentationError`] when the Ethernet/IPv4 encoding is
/// malformed, the MTU cannot carry a valid fragment, or a resulting length or
/// offset exceeds its protocol field.
pub fn fragment_ethernet_ipv4(
    frame: &[u8],
    mtu: usize,
) -> Result<Ipv4FragmentationOutcome, Ipv4FragmentationError> {
    if frame.len() < ETHERNET_HEADER + IPV4_MINIMUM_HEADER
        || frame.get(12..14) != Some(&[0x08, 0x00])
    {
        return Err(Ipv4FragmentationError::UnsupportedFrame);
    }
    let version_ihl = frame[ETHERNET_HEADER];
    let header_bytes = usize::from(version_ihl & 0x0f)
        .checked_mul(4)
        .ok_or(Ipv4FragmentationError::InvalidHeader)?;
    if version_ihl >> 4 != 4
        || header_bytes < IPV4_MINIMUM_HEADER
        || ETHERNET_HEADER
            .checked_add(header_bytes)
            .is_none_or(|end| end > frame.len())
    {
        return Err(Ipv4FragmentationError::InvalidHeader);
    }
    let total_length = usize::from(u16::from_be_bytes([
        frame[ETHERNET_HEADER + 2],
        frame[ETHERNET_HEADER + 3],
    ]));
    let ip_end = ETHERNET_HEADER
        .checked_add(total_length)
        .ok_or(Ipv4FragmentationError::InvalidTotalLength)?;
    if total_length < header_bytes || ip_end > frame.len() {
        return Err(Ipv4FragmentationError::InvalidTotalLength);
    }
    if ip_end <= mtu {
        return Ok(Ipv4FragmentationOutcome::Frames(vec![
            frame[..ip_end].to_vec(),
        ]));
    }
    let flags_offset = u16::from_be_bytes([frame[ETHERNET_HEADER + 6], frame[ETHERNET_HEADER + 7]]);
    let original_offset_units = flags_offset & 0x1fff;
    let original_more_fragments = flags_offset & 0x2000 != 0;
    let data = &frame[ETHERNET_HEADER + header_bytes..ip_end];
    if flags_offset & 0x4000 != 0 && (original_offset_units != 0 || original_more_fragments) {
        return Err(Ipv4FragmentationError::DontFragmentOnFragment);
    }
    if flags_offset & 0x4000 != 0 {
        return Ok(Ipv4FragmentationOutcome::DontFragment);
    }
    if original_more_fragments && !data.len().is_multiple_of(8) {
        return Err(Ipv4FragmentationError::InvalidNonFinalLength);
    }
    let maximum_ip_length = mtu
        .checked_sub(ETHERNET_HEADER)
        .filter(|length| *length >= header_bytes)
        .ok_or(Ipv4FragmentationError::MtuTooSmall)?;
    if data.is_empty() {
        return Ok(Ipv4FragmentationOutcome::Frames(vec![
            frame[..ip_end].to_vec(),
        ]));
    }
    let maximum_fragment_data = maximum_ip_length
        .checked_sub(header_bytes)
        .map(|bytes| bytes / 8 * 8)
        .filter(|bytes| *bytes > 0)
        .ok_or(Ipv4FragmentationError::MtuTooSmall)?;
    let mut fragments = Vec::new();
    for (ordinal, chunk) in data.chunks(maximum_fragment_data).enumerate() {
        let offset_bytes = ordinal
            .checked_mul(maximum_fragment_data)
            .ok_or(Ipv4FragmentationError::OffsetOverflow)?;
        let local_offset_units = u16::try_from(offset_bytes / 8)
            .map_err(|_error| Ipv4FragmentationError::OffsetOverflow)?;
        let offset_units = original_offset_units
            .checked_add(local_offset_units)
            .filter(|offset| *offset <= 0x1fff)
            .ok_or(Ipv4FragmentationError::OffsetOverflow)?;
        let fragment_ip_length = header_bytes
            .checked_add(chunk.len())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or(Ipv4FragmentationError::LengthOverflow)?;
        let mut fragment = Vec::with_capacity(ETHERNET_HEADER + usize::from(fragment_ip_length));
        fragment.extend_from_slice(&frame[..ETHERNET_HEADER + header_bytes]);
        fragment[ETHERNET_HEADER + 2..ETHERNET_HEADER + 4]
            .copy_from_slice(&fragment_ip_length.to_be_bytes());
        let more_fragments = original_more_fragments || offset_bytes + chunk.len() < data.len();
        let fragment_flags =
            (flags_offset & 0x8000) | (if more_fragments { 0x2000 } else { 0 }) | offset_units;
        fragment[ETHERNET_HEADER + 6..ETHERNET_HEADER + 8]
            .copy_from_slice(&fragment_flags.to_be_bytes());
        fragment[ETHERNET_HEADER + 10] = 0;
        fragment[ETHERNET_HEADER + 11] = 0;
        let checksum =
            ipv4_header_checksum(&fragment[ETHERNET_HEADER..ETHERNET_HEADER + header_bytes]);
        fragment[ETHERNET_HEADER + 10..ETHERNET_HEADER + 12]
            .copy_from_slice(&checksum.to_be_bytes());
        fragment.extend_from_slice(chunk);
        fragments.push(fragment);
    }
    Ok(Ipv4FragmentationOutcome::Frames(fragments))
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for word in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(data: &[u8], flags_offset: u16) -> Vec<u8> {
        let total_length = u16::try_from(IPV4_MINIMUM_HEADER + data.len())
            .unwrap_or_else(|error| panic!("test IPv4 length: {error}"));
        let mut frame = vec![0_u8; ETHERNET_HEADER + IPV4_MINIMUM_HEADER];
        frame[0..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame[6..12].copy_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&total_length.to_be_bytes());
        frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    fn frames(outcome: Ipv4FragmentationOutcome) -> Vec<Vec<u8>> {
        match outcome {
            Ipv4FragmentationOutcome::Frames(frames) => frames,
            Ipv4FragmentationOutcome::DontFragment => panic!("expected fragment frames"),
        }
    }

    #[test]
    fn fragmentation_preserves_data_offsets_and_checksums() {
        let data = (0_u8..40).collect::<Vec<_>>();
        let fragments = frames(
            fragment_ethernet_ipv4(&frame(&data, 0), 42)
                .unwrap_or_else(|error| panic!("fragmentation: {error}")),
        );
        assert_eq!(fragments.len(), 5);
        let mut reassembled = Vec::new();
        for (ordinal, fragment) in fragments.iter().enumerate() {
            assert!(fragment.len() <= 42);
            assert_eq!(ipv4_header_checksum(&fragment[14..34]), 0);
            let flags_offset = u16::from_be_bytes([fragment[20], fragment[21]]);
            assert_eq!(usize::from(flags_offset & 0x1fff), ordinal);
            assert_eq!(flags_offset & 0x2000 != 0, ordinal + 1 < fragments.len());
            reassembled.extend_from_slice(&fragment[34..]);
        }
        assert_eq!(reassembled, data);
        assert_eq!(
            fragment_ethernet_ipv4(&frame(&data, 0x4000), 42),
            Ok(Ipv4FragmentationOutcome::DontFragment)
        );
    }

    #[test]
    fn later_hop_can_refragment_an_existing_fragment() {
        let data = (0_u8..40).collect::<Vec<_>>();
        let first_hop = frames(
            fragment_ethernet_ipv4(&frame(&data, 0), 58)
                .unwrap_or_else(|error| panic!("first hop: {error}")),
        );
        assert_eq!(first_hop.len(), 2);
        let refragmented = frames(
            fragment_ethernet_ipv4(&first_hop[0], 42)
                .unwrap_or_else(|error| panic!("later hop: {error}")),
        );
        assert_eq!(refragmented.len(), 3);
        for (ordinal, fragment) in refragmented.iter().enumerate() {
            let flags_offset = u16::from_be_bytes([fragment[20], fragment[21]]);
            assert_eq!(usize::from(flags_offset & 0x1fff), ordinal);
            assert_ne!(flags_offset & 0x2000, 0);
        }
    }

    #[test]
    fn malformed_and_too_small_inputs_fail_loudly() {
        assert_eq!(
            fragment_ethernet_ipv4(&[0_u8; 64], 42),
            Err(Ipv4FragmentationError::UnsupportedFrame)
        );
        assert_eq!(
            fragment_ethernet_ipv4(&frame(&[0_u8; 40], 0), 41),
            Err(Ipv4FragmentationError::MtuTooSmall)
        );
    }
}
