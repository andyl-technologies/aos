//! Classic pcap and pcapng normalization.

use super::*;

pub(super) fn import_pcap_entries(
    bytes: &[u8],
    options: &TraceImportOptions,
) -> Result<Vec<TraceEntry>, TraceImportError> {
    if !options.event_channel
        || !matches!(options.shape.value_type, SignalValueType::Event(_))
        || bytes.len() < 24
    {
        return Err(TraceImportError::PacketCaptureContract);
    }
    let magic = bytes
        .get(0..4)
        .ok_or(TraceImportError::MalformedPacketCapture)?;
    let (little, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err(TraceImportError::MalformedPacketCapture),
    };
    let mut cursor = 24_usize;
    let mut sequence = 0_u64;
    let mut entries = Vec::new();
    while cursor < bytes.len() {
        let header = bytes
            .get(cursor..cursor.saturating_add(16))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let seconds = endian_u32(&header[0..4], little)?;
        let fraction = endian_u32(&header[4..8], little)?;
        let included = usize::try_from(endian_u32(&header[8..12], little)?)
            .map_err(|_| TraceImportError::MalformedPacketCapture)?;
        let original = endian_u32(&header[12..16], little)?;
        cursor = cursor
            .checked_add(16)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let packet = bytes
            .get(cursor..cursor.saturating_add(included))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        cursor = cursor
            .checked_add(included)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let fraction_nanos = if nanos {
            u64::from(fraction)
        } else {
            u64::from(fraction)
                .checked_mul(1_000)
                .ok_or(TraceImportError::MalformedPacketCapture)?
        };
        if fraction_nanos >= 1_000_000_000 {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        let source = u64::from(seconds)
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(fraction_nanos))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        entries.push(packet_entry(source, sequence, original, packet, options)?);
        sequence = sequence
            .checked_add(1)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
    }
    Ok(entries)
}

fn endian_u32(bytes: &[u8], little: bool) -> Result<u32, TraceImportError> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| TraceImportError::MalformedPacketCapture)?;
    Ok(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

pub(super) fn import_pcapng_entries(
    bytes: &[u8],
    options: &TraceImportOptions,
) -> Result<Vec<TraceEntry>, TraceImportError> {
    if !options.event_channel || !matches!(options.shape.value_type, SignalValueType::Event(_)) {
        return Err(TraceImportError::PacketCaptureContract);
    }
    let mut cursor = 0_usize;
    let mut little = true;
    let mut have_section = false;
    let mut timestamp_resolutions = Vec::new();
    let mut sequence = 0_u64;
    let mut entries = Vec::new();
    while cursor < bytes.len() {
        let prefix = bytes
            .get(cursor..cursor.saturating_add(12))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let raw_type: [u8; 4] = prefix[0..4]
            .try_into()
            .map_err(|_| TraceImportError::MalformedPacketCapture)?;
        if raw_type == [0x0a, 0x0d, 0x0d, 0x0a] {
            little = match &prefix[8..12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                _ => return Err(TraceImportError::MalformedPacketCapture),
            };
            have_section = true;
            timestamp_resolutions.clear();
        }
        if !have_section {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        let block_type = endian_u32(&prefix[0..4], little)?;
        let length = usize::try_from(endian_u32(&prefix[4..8], little)?)
            .map_err(|_| TraceImportError::MalformedPacketCapture)?;
        if length < 12 || length % 4 != 0 {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        let block = bytes
            .get(cursor..cursor.saturating_add(length))
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        if endian_u32(&block[length - 4..], little)?
            != u32::try_from(length).map_err(|_| TraceImportError::MalformedPacketCapture)?
        {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        if block_type == 1 {
            timestamp_resolutions.push(parse_pcapng_timestamp_resolution(block, little)?);
        } else if block_type == 6 {
            if length < 32 {
                return Err(TraceImportError::MalformedPacketCapture);
            }
            let interface = usize::try_from(endian_u32(&block[8..12], little)?)
                .map_err(|_| TraceImportError::MalformedPacketCapture)?;
            let resolution = timestamp_resolutions
                .get(interface)
                .copied()
                .ok_or(TraceImportError::MalformedPacketCapture)?;
            let high = endian_u32(&block[12..16], little)?;
            let low = endian_u32(&block[16..20], little)?;
            let timestamp = (u64::from(high) << 32) | u64::from(low);
            let source = resolution.to_nanoseconds(timestamp)?;
            let captured = usize::try_from(endian_u32(&block[20..24], little)?)
                .map_err(|_| TraceImportError::MalformedPacketCapture)?;
            let original = endian_u32(&block[24..28], little)?;
            let packet_end = 28_usize
                .checked_add(captured)
                .ok_or(TraceImportError::MalformedPacketCapture)?;
            let padded_end = packet_end
                .checked_add(3)
                .map(|end| end & !3)
                .ok_or(TraceImportError::MalformedPacketCapture)?;
            if padded_end > length.saturating_sub(4) {
                return Err(TraceImportError::MalformedPacketCapture);
            }
            let packet = block
                .get(28..packet_end)
                .ok_or(TraceImportError::MalformedPacketCapture)?;
            entries.push(packet_entry(source, sequence, original, packet, options)?);
            sequence = sequence
                .checked_add(1)
                .ok_or(TraceImportError::MalformedPacketCapture)?;
        }
        cursor = cursor
            .checked_add(length)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
    }
    Ok(entries)
}

#[derive(Clone, Copy)]
enum PcapNgTimestampResolution {
    Decimal(u8),
    Binary(u8),
}

impl PcapNgTimestampResolution {
    fn to_nanoseconds(self, timestamp: u64) -> Result<u64, TraceImportError> {
        let denominator = match self {
            Self::Decimal(exponent) => 10_u128
                .checked_pow(u32::from(exponent))
                .ok_or(TraceImportError::MalformedPacketCapture)?,
            Self::Binary(exponent) => 1_u128
                .checked_shl(u32::from(exponent))
                .ok_or(TraceImportError::MalformedPacketCapture)?,
        };
        let nanos = u128::from(timestamp)
            .checked_mul(1_000_000_000)
            .ok_or(TraceImportError::MalformedPacketCapture)?
            / denominator;
        u64::try_from(nanos).map_err(|_| TraceImportError::MalformedPacketCapture)
    }
}

fn parse_pcapng_timestamp_resolution(
    block: &[u8],
    little: bool,
) -> Result<PcapNgTimestampResolution, TraceImportError> {
    if block.len() < 20 {
        return Err(TraceImportError::MalformedPacketCapture);
    }
    let options_end = block.len() - 4;
    let mut cursor = 16_usize;
    let mut resolution = PcapNgTimestampResolution::Decimal(6);
    while cursor < options_end {
        if cursor.saturating_add(4) > options_end {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        let code = endian_u16(&block[cursor..cursor + 2], little)?;
        let length = usize::from(endian_u16(&block[cursor + 2..cursor + 4], little)?);
        cursor += 4;
        if code == 0 {
            if length != 0 {
                return Err(TraceImportError::MalformedPacketCapture);
            }
            break;
        }
        let value_end = cursor
            .checked_add(length)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        let padded_end = value_end
            .checked_add(3)
            .map(|end| end & !3)
            .ok_or(TraceImportError::MalformedPacketCapture)?;
        if padded_end > options_end {
            return Err(TraceImportError::MalformedPacketCapture);
        }
        if code == 9 {
            if length != 1 {
                return Err(TraceImportError::MalformedPacketCapture);
            }
            let encoded = block[cursor];
            resolution = if encoded & 0x80 == 0 {
                PcapNgTimestampResolution::Decimal(encoded)
            } else {
                PcapNgTimestampResolution::Binary(encoded & 0x7f)
            };
        }
        cursor = padded_end;
    }
    Ok(resolution)
}

fn endian_u16(bytes: &[u8], little: bool) -> Result<u16, TraceImportError> {
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| TraceImportError::MalformedPacketCapture)?;
    Ok(if little {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn packet_entry(
    source_nanos: u64,
    sequence: u64,
    original_length: u32,
    packet: &[u8],
    options: &TraceImportOptions,
) -> Result<TraceEntry, TraceImportError> {
    let coordinate = options
        .time_mapping
        .map(source_nanos)
        .map_err(TraceImportError::Trace)?;
    let digest = ContentHash::from_bytes(packet);
    let mut payload = Vec::with_capacity(44);
    payload.extend_from_slice(&original_length.to_be_bytes());
    payload.extend_from_slice(
        &u32::try_from(packet.len())
            .map_err(|_| TraceImportError::MalformedPacketCapture)?
            .to_be_bytes(),
    );
    payload.extend_from_slice(&digest.bytes);
    let schema = match &options.shape.value_type {
        SignalValueType::Event(schema) => schema.clone(),
        _ => return Err(TraceImportError::PacketCaptureContract),
    };
    Ok(TraceEntry {
        coordinate,
        event_sequence: Some(sequence),
        value: SignalValue::Event { schema, payload },
        validity: TraceValidity::Valid,
    })
}
