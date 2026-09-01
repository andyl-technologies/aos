//! Target-manifest validation, decoding, and identity hashing helpers.

use super::*;

pub(super) fn valid_identity(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= HARD_FAULT_TARGET_NAME_BYTES
        && bytes[0].is_ascii_lowercase()
        && (bytes[bytes.len() - 1].is_ascii_lowercase() || bytes[bytes.len() - 1].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
}

pub(super) fn valid_hardware_identity(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(valid_identity)
}

pub(super) fn valid_cpu_model(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= HARD_FAULT_TARGET_NAME_BYTES
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

pub(super) fn take_text(
    bytes: &[u8],
    offset: &mut usize,
    length: usize,
) -> Result<String, FaultAbiError> {
    let raw = take_bytes(bytes, offset, length)?;
    core::str::from_utf8(&raw)
        .map(str::to_owned)
        .map_err(|_| FaultAbiError::CapabilityInvariant)
}

pub(super) fn take_bytes(
    bytes: &[u8],
    offset: &mut usize,
    length: usize,
) -> Result<Vec<u8>, FaultAbiError> {
    let end = offset
        .checked_add(length)
        .ok_or(FaultAbiError::HeaderLength)?;
    let value = bytes.get(*offset..end).ok_or(FaultAbiError::HeaderLength)?;
    *offset = end;
    Ok(value.to_vec())
}

pub(super) fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, FaultAbiError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(FaultAbiError::HeaderLength)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

pub(super) fn bool_at(bytes: &[u8], offset: usize) -> Result<bool, FaultAbiError> {
    match bytes.get(offset).copied() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(FaultAbiError::CapabilityInvariant),
    }
}

pub(super) fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, FaultAbiError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(FaultAbiError::HeaderLength)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

pub(super) fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, FaultAbiError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(FaultAbiError::HeaderLength)?;
    Ok(u64::from_le_bytes(
        raw.try_into().map_err(|_| FaultAbiError::HeaderLength)?,
    ))
}

pub(super) struct FaultIdentityHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

impl FaultIdentityHasher {
    pub(super) const fn new() -> Self {
        Self {
            lanes: [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ],
            bytes_written: 0,
        }
    }

    pub(super) fn write_bytes(&mut self, bytes: &[u8]) {
        self.mix_word(bytes.len() as u64);
        self.bytes_written = self.bytes_written.wrapping_add(8);
        for chunk in bytes.chunks(8) {
            let mut word = [0_u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.mix_word(u64::from_le_bytes(word));
        }
        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
    }

    pub(super) fn mix_word(&mut self, word: u64) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            let rotation = 13 + (index as u32 * 7);
            let salt = (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            *lane ^= word.wrapping_add(salt);
            *lane = lane
                .rotate_left(rotation)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane ^= *lane >> 33;
        }
    }

    pub(super) fn finish(&self) -> [u8; 32] {
        let mut output = [0_u8; 32];
        for (index, lane) in self.lanes.iter().enumerate() {
            let salt = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let mut word = lane.wrapping_add(self.bytes_written).wrapping_add(salt);
            word ^= word >> 30;
            word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            word ^= word >> 27;
            word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
            word ^= word >> 31;
            output[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        output
    }
}
