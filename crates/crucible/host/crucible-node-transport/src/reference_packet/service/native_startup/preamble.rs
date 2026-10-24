//! Encodes the fixed private startup prefix without allocating parser owners.
//!
//! ```text
//! magic[8] pid[8] uid[8] launch_len[4] boot_max[4] flags[8]
//! birth[32] launch[32] source[32] registration[32] private_launch[32]
//! bootstrap_row[24] native_row[24] prepare_row[24] key[32] mac[32]
//! ```
//!
//! All integers use network byte order. The MAC covers the first 304 bytes.
//! These helpers compare process-protocol data only. The native private reader
//! separately authenticates its actual inherited socket and original parent;
//! no parsed prefix or successful MAC check alone grants construction rights.

use super::PacketNativeStartupAllocationRow;
use crate::ProviderError;
use crucible_node_format::U64;

/// Names the exact extent of the version-fourteen private startup prefix.
pub const ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES: usize = 336;

const MAGIC: &[u8; 8] = b"CNPNS14\0";
const KEY_RANGE: std::ops::Range<usize> = 272..304;
const MAC_RANGE: std::ops::Range<usize> = 304..336;
const MAC_DOMAIN: &str = "source-owned.packet-native-startup-preamble/14";

/// Holds fixed parsed startup data independently of live native authority.
///
/// The private key remains only in the caller's raw prefix bank. This fixed
/// value has no heap children, host clock coordinate or native constructor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PacketNativeStartupPreambleData {
    /// Identifies the actual original controller process.
    pub controller_pid: u64,
    /// Identifies the actual original controller user.
    pub controller_uid: u64,
    /// Bounds the one immutable canonical launch literal.
    pub launch_bytes: u32,
    /// Bounds the one immutable canonical private boot literal.
    pub maximum_boot_bytes: u32,
    /// Binds the existing private birth derivation.
    pub birth_id: [u8; 32],
    /// Binds the actual canonical immutable launch bytes.
    pub launch_digest: [u8; 32],
    /// Binds the actual canonical Source binding bytes.
    pub source_digest: [u8; 32],
    /// Binds the actual canonical host-registration bytes.
    pub registration_digest: [u8; 32],
    /// Binds the actual retained private-launch identifier bytes.
    pub private_launch_digest: [u8; 32],
    /// Carries the distinct original private-bootstrap phase data.
    pub private_bootstrap: PacketNativeStartupAllocationRow,
    /// Carries the distinct original native-birth phase data.
    pub native_birth: PacketNativeStartupAllocationRow,
    /// Carries the independently selected fixed Prepare phase data.
    pub restore_prepare: Option<PacketNativeStartupAllocationRow>,
}

impl PacketNativeStartupPreambleData {
    fn validate(&self) -> Result<(), ProviderError> {
        if self.controller_pid == 0
            || self.launch_bytes == 0
            || self.launch_bytes > 1024 * 1024
            || self.maximum_boot_bytes == 0
            || self.maximum_boot_bytes > 512 * 1024
        {
            return Err(invalid());
        }
        self.private_bootstrap.requested_peak_data()?;
        self.native_birth.requested_peak_data()?;
        if let Some(row) = self.restore_prepare {
            row.requested_peak_data()?;
        }
        Ok(())
    }
}

/// Encodes one closed prefix using its already retained original private key.
///
/// # Errors
/// Refuses invalid extents, missing phase terms or checked row overflow.
pub fn encode_original_native_startup_preamble_data(
    data: &PacketNativeStartupPreambleData,
    key: &[u8; 32],
) -> Result<[u8; ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES], ProviderError> {
    data.validate()?;
    let mut bytes = [0; ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..16].copy_from_slice(&data.controller_pid.to_be_bytes());
    bytes[16..24].copy_from_slice(&data.controller_uid.to_be_bytes());
    bytes[24..28].copy_from_slice(&data.launch_bytes.to_be_bytes());
    bytes[28..32].copy_from_slice(&data.maximum_boot_bytes.to_be_bytes());
    bytes[32..40].copy_from_slice(&u64::from(data.restore_prepare.is_some()).to_be_bytes());
    for (offset, digest) in [
        (40, &data.birth_id),
        (72, &data.launch_digest),
        (104, &data.source_digest),
        (136, &data.registration_digest),
        (168, &data.private_launch_digest),
    ] {
        bytes[offset..offset + 32].copy_from_slice(digest);
    }
    write_row(&mut bytes[200..224], data.private_bootstrap);
    write_row(&mut bytes[224..248], data.native_birth);
    if let Some(row) = data.restore_prepare {
        write_row(&mut bytes[248..272], row);
    }
    bytes[KEY_RANGE].copy_from_slice(key);
    let mac = mac(&bytes[..304], key);
    bytes[MAC_RANGE].copy_from_slice(mac.as_bytes());
    Ok(bytes)
}

/// Checks the complete prefix and its association with an expected private key.
///
/// The comparison uses fixed byte loops and neither allocates nor renews a cut.
///
/// # Errors
/// Refuses incorrect extents, revision, flags, rows, key or keyed digest.
pub fn authenticate_original_native_startup_preamble_data(
    bytes: &[u8],
    expected_key: &[u8],
) -> Result<(), ProviderError> {
    let key: &[u8; 32] = expected_key.try_into().map_err(|_| invalid())?;
    let _ = decode_original_native_startup_preamble_data(bytes)?;
    if !equal(&bytes[KEY_RANGE], key)
        || !equal(&bytes[MAC_RANGE], mac(&bytes[..304], key).as_bytes())
    {
        return Err(invalid());
    }
    Ok(())
}

/// Reads the closed primitive fields without authenticating live channel origin.
///
/// # Errors
/// Refuses another revision, invalid extents or flags, or incomplete phase rows.
pub fn decode_original_native_startup_preamble_data(
    bytes: &[u8],
) -> Result<PacketNativeStartupPreambleData, ProviderError> {
    if bytes.len() != ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid());
    }
    let flags = read_u64(&bytes[32..40])?;
    if flags > 1 || (flags == 0 && bytes[248..272].iter().any(|byte| *byte != 0)) {
        return Err(invalid());
    }
    let data = PacketNativeStartupPreambleData {
        controller_pid: read_u64(&bytes[8..16])?,
        controller_uid: read_u64(&bytes[16..24])?,
        launch_bytes: u32::from_be_bytes(bytes[24..28].try_into().map_err(|_| invalid())?),
        maximum_boot_bytes: u32::from_be_bytes(bytes[28..32].try_into().map_err(|_| invalid())?),
        birth_id: digest(&bytes[40..72])?,
        launch_digest: digest(&bytes[72..104])?,
        source_digest: digest(&bytes[104..136])?,
        registration_digest: digest(&bytes[136..168])?,
        private_launch_digest: digest(&bytes[168..200])?,
        private_bootstrap: read_row(&bytes[200..224])?,
        native_birth: read_row(&bytes[224..248])?,
        restore_prepare: if flags == 1 {
            Some(read_row(&bytes[248..272])?)
        } else {
            None
        },
    };
    data.validate()?;
    Ok(data)
}

fn mac(bytes: &[u8], key: &[u8; 32]) -> blake3::Hash {
    blake3::keyed_hash(&blake3::derive_key(MAC_DOMAIN, key), bytes)
}

fn equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], ProviderError> {
    bytes.try_into().map_err(|_| invalid())
}

fn read_u64(bytes: &[u8]) -> Result<u64, ProviderError> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| invalid())?))
}

fn read_row(bytes: &[u8]) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(read_u64(&bytes[..8])?),
        maximum_simultaneous_transient_bytes: U64::new(read_u64(&bytes[8..16])?),
        declared_counter_scratch_bytes: U64::new(read_u64(&bytes[16..24])?),
    })
}

fn write_row(bytes: &mut [u8], row: PacketNativeStartupAllocationRow) {
    // Every caller supplies the fixed 24-byte row from this edition's prefix.
    bytes[..8].copy_from_slice(&row.retained_requested_bytes.get().to_be_bytes());
    bytes[8..16].copy_from_slice(&row.maximum_simultaneous_transient_bytes.get().to_be_bytes());
    bytes[16..24].copy_from_slice(&row.declared_counter_scratch_bytes.get().to_be_bytes());
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("original native startup preamble data")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> (PacketNativeStartupPreambleData, [u8; 32]) {
        let key = [17; 32];
        let row = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(4096),
            maximum_simultaneous_transient_bytes: U64::new(8192),
            declared_counter_scratch_bytes: U64::new(256),
        };
        (
            PacketNativeStartupPreambleData {
                controller_pid: 42,
                controller_uid: 1000,
                launch_bytes: 1234,
                maximum_boot_bytes: 4096,
                birth_id: blake3::derive_key("source-owned.packet-canonical-ack-birth/5", &key),
                launch_digest: [1; 32],
                source_digest: [2; 32],
                registration_digest: [3; 32],
                private_launch_digest: [4; 32],
                private_bootstrap: row,
                native_birth: row,
                restore_prepare: Some(row),
            },
            key,
        )
    }

    #[test]
    fn fixed_prefix_roundtrip_authenticates_every_original_byte_and_expected_key() {
        let (original, key) = original();
        let bytes = encode_original_native_startup_preamble_data(&original, &key).unwrap();
        assert!(decode_original_native_startup_preamble_data(&bytes).unwrap() == original);
        authenticate_original_native_startup_preamble_data(&bytes, &key).unwrap();
        assert!(authenticate_original_native_startup_preamble_data(&bytes, &[18; 32]).is_err());

        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                authenticate_original_native_startup_preamble_data(&changed, &key).is_err(),
                "byte {index}"
            );
        }
        assert!(decode_original_native_startup_preamble_data(&bytes[..335]).is_err());
    }

    #[test]
    fn closed_flags_nullable_prepare_and_complete_rows_refuse_even_with_recomputed_mac() {
        let (mut data, key) = original();
        data.restore_prepare = None;
        let original = encode_original_native_startup_preamble_data(&data, &key).unwrap();
        authenticate_original_native_startup_preamble_data(&original, &key).unwrap();
        assert!(original[248..272].iter().all(|byte| *byte == 0));

        for (offset, value) in [(39, 2), (248, 1), (200, 0)] {
            let mut changed = original;
            if offset == 200 {
                changed[200..208].fill(0);
            } else {
                changed[offset] = value;
            }
            let digest = mac(&changed[..304], &key);
            changed[304..].copy_from_slice(digest.as_bytes());
            assert!(authenticate_original_native_startup_preamble_data(&changed, &key).is_err());
        }
        data.native_birth.retained_requested_bytes = U64::new(u64::MAX);
        assert!(encode_original_native_startup_preamble_data(&data, &key).is_err());
        data = original_data();
        data.launch_bytes = 1024 * 1024 + 1;
        assert!(encode_original_native_startup_preamble_data(&data, &key).is_err());
    }

    fn original_data() -> PacketNativeStartupPreambleData {
        original().0
    }
}
