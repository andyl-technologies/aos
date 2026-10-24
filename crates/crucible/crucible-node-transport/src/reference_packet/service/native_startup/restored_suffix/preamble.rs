//! Encodes a new private startup prefix with an independent suffix reservation.
//!
//! ```text
//! original fixed fields[272] suffix count[8] ingress row[24] actions row[24]
//! key[32] mac[32]
//! ```
//!
//! The first eight bytes are `CNPNS16\0`; the new MAC covers the first 360
//! bytes under a distinct domain. Legacy15 remains a different fixed format.
//! The full launch digest binds the new wrapper and complete selected schemas.
//! Decoding and MAC comparison are DATA checks, not inherited-channel authority.

use super::super::invocation_preamble::{
    PacketNativeInvocationPreambleData, decode_original_native_invocation_preamble_data,
    encode_original_native_invocation_preamble_data,
};
use super::*;

/// Names the complete fixed suffix-startup prefix extent.
pub const ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES: usize = 392;

const MAGIC: &[u8; 8] = b"CNPNS16\0";
const DOMAIN: &str = "source-owned.packet-native-restored-suffix-startup-preamble/1";
const KEY: std::ops::Range<usize> = 328..360;
const MAC: std::ops::Range<usize> = 360..392;

/// Carries the unchanged invocation fields and a distinct allocation window.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PacketNativeSuffixPreambleData {
    /// Binds the same genuine parent, private birth, full launch and old rows.
    pub invocation: PacketNativeInvocationPreambleData,
    /// Carries separately admitted ingress and action axes for the new owner.
    pub suffix_reservation: PacketRestoredSuffixReservationData,
}

/// Encodes the distinct fixed prefix under the actual retained private key.
///
/// # Errors
/// Refuses invalid original fields, absent reservation terms or checked overflow.
pub fn encode_original_native_suffix_preamble_data(
    data: &PacketNativeSuffixPreambleData,
    key: &[u8; 32],
) -> Result<[u8; ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES], ProviderError> {
    data.suffix_reservation.requested_bytes_data()?;
    let original = encode_original_native_invocation_preamble_data(&data.invocation, key)?;
    let mut bytes = [0; ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES];
    bytes[..272].copy_from_slice(&original[..272]);
    bytes[..8].copy_from_slice(MAGIC);
    bytes[272..280].copy_from_slice(
        &data
            .suffix_reservation
            .maximum_originals
            .get()
            .to_be_bytes(),
    );
    write_row(&mut bytes[280..304], data.suffix_reservation.ingress);
    write_row(&mut bytes[304..328], data.suffix_reservation.actions);
    bytes[KEY].copy_from_slice(key);
    let signature = signature(&bytes[..360], key);
    bytes[MAC].copy_from_slice(signature.as_bytes());
    Ok(bytes)
}

/// Decodes fixed DATA without authenticating a live parent or inherited socket.
///
/// # Errors
/// Refuses another revision, invalid original fields or malformed reservation.
pub fn decode_original_native_suffix_preamble_data(
    bytes: &[u8],
) -> Result<PacketNativeSuffixPreambleData, ProviderError> {
    if bytes.len() != ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid());
    }
    // Reuse the unchanged legacy field decoder, never its live constructor.
    // Its decoding helper deliberately does not authenticate a MAC; this
    // edition authenticates the complete original-plus-reservation bytes below.
    let mut original = [0; 336];
    original[..272].copy_from_slice(&bytes[..272]);
    original[..8].copy_from_slice(b"CNPNS15\0");
    original[272..304].copy_from_slice(&bytes[KEY]);
    let invocation = decode_original_native_invocation_preamble_data(&original)?;
    let suffix_reservation = PacketRestoredSuffixReservationData {
        maximum_originals: U64::new(read_u64(&bytes[272..280])?),
        ingress: read_row(&bytes[280..304])?,
        actions: read_row(&bytes[304..328])?,
    };
    suffix_reservation.requested_bytes_data()?;
    Ok(PacketNativeSuffixPreambleData {
        invocation,
        suffix_reservation,
    })
}

/// Authenticates every fixed field under the separate suffix-startup MAC.
///
/// # Errors
/// Refuses another extent/revision, invalid rows, a different key or changed MAC.
pub fn authenticate_original_native_suffix_preamble_data(
    bytes: &[u8],
    expected_key: &[u8],
) -> Result<(), ProviderError> {
    let key: &[u8; 32] = expected_key.try_into().map_err(|_| invalid())?;
    let _ = decode_original_native_suffix_preamble_data(bytes)?;
    if !equal(&bytes[KEY], key) || !equal(&bytes[MAC], signature(&bytes[..360], key).as_bytes()) {
        return Err(invalid());
    }
    Ok(())
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

fn signature(bytes: &[u8], key: &[u8; 32]) -> blake3::Hash {
    blake3::keyed_hash(&blake3::derive_key(DOMAIN, key), bytes)
}

fn equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0, |difference, (left, right)| difference | (left ^ right))
            == 0
}
