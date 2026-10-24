//! Streams the new closed wrapper around the same canonical launch5 bank.
//!
//! Static field order is UTF-16 lexicographic; all new scalar fields are exact
//! small integers or U64 decimal strings. The same canonical purpose writer
//! preserves its existing escaping and full-reference spelling. No DOM, sort,
//! replacement launch body or output bank is constructed by this helper.

use super::super::{
    PacketNativeInvocationPurposeData, write_original_native_invocation_purpose_data,
};
use super::*;
use serde::{Serializer, ser::SerializeStruct};
use std::io::Write;

// U64's ordinary serializer constructs a String. Precredit identity and
// projection use the same decimal spelling in a fixed stack bank instead.
struct Decimal(u64);

impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut digits = [0u8; 20];
        let mut first = digits.len();
        let mut value = self.0;
        loop {
            first -= 1;
            digits[first] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        let text = std::str::from_utf8(&digits[first..]).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(text)
    }
}

struct CanonicalRow<'a>(&'a PacketNativeStartupAllocationRow);

impl Serialize for CanonicalRow<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("SuffixPhase", 3)?;
        fields.serialize_field(
            "declared_counter_scratch_bytes",
            &Decimal(self.0.declared_counter_scratch_bytes.get()),
        )?;
        fields.serialize_field(
            "maximum_simultaneous_transient_bytes",
            &Decimal(self.0.maximum_simultaneous_transient_bytes.get()),
        )?;
        fields.serialize_field(
            "retained_requested_bytes",
            &Decimal(self.0.retained_requested_bytes.get()),
        )?;
        fields.end()
    }
}

pub(super) struct CanonicalReservation<'a>(pub(super) &'a PacketRestoredSuffixReservationData);

impl Serialize for CanonicalReservation<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("SuffixReservation", 3)?;
        fields.serialize_field("actions", &CanonicalRow(&self.0.actions))?;
        fields.serialize_field("ingress", &CanonicalRow(&self.0.ingress))?;
        fields.serialize_field(
            "maximum_originals",
            &Decimal(self.0.maximum_originals.get()),
        )?;
        fields.end()
    }
}

/// Retains the full streamed launch7 byte extent and raw BLAKE3 identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketNativeSuffixLaunchIdentityData {
    /// Counts the complete wrapper including the unchanged nested launch5 bank.
    pub encoded_bytes: usize,
    /// Hashes every byte of that exact wrapper.
    pub raw_digest: [u8; 32],
}

struct Identity {
    bytes: usize,
    hasher: blake3::Hasher,
}

impl Write for Identity {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Streams the distinct wrapper without re-encoding its authenticated raw child.
///
/// The caller retains the same actual canonical launch5 and partial output bank
/// through any refusal. These bytes are DATA, never a native startup claim.
///
/// # Errors
/// Refuses invalid reservation geometry or propagates the original writer error.
pub fn write_original_native_suffix_launch_data(
    purpose: &PacketNativeInvocationPurposeData,
    canonical_launch5: &[u8],
    suffix: &PacketRestoredSuffixReservationData,
    output: &mut impl Write,
) -> Result<(), ProviderError> {
    suffix.requested_bytes_data()?;
    if purpose.is_original_execution_data() {
        return Err(invalid());
    }
    output.write_all(b"{\"invocation\":")?;
    write_original_native_invocation_purpose_data(purpose, output)?;
    output.write_all(b",\"launch\":")?;
    output.write_all(canonical_launch5)?;
    output.write_all(b",\"schema_version\":7,\"suffix_reservation\":")?;
    serde_json::to_writer(&mut *output, &CanonicalReservation(suffix))
        .map_err(crucible_node_format::ContractError::from)?;
    output.write_all(b"}")?;
    Ok(())
}

/// Counts and hashes the new wrapper with no DOM or dynamic output bank.
///
/// # Errors
/// Refuses invalid rows, checked byte-count overflow or closed writer failure.
pub fn original_native_suffix_launch_identity_data(
    purpose: &PacketNativeInvocationPurposeData,
    canonical_launch5: &[u8],
    suffix: &PacketRestoredSuffixReservationData,
) -> Result<PacketNativeSuffixLaunchIdentityData, ProviderError> {
    let mut output = Identity {
        bytes: 0,
        hasher: blake3::Hasher::new(),
    };
    write_original_native_suffix_launch_data(purpose, canonical_launch5, suffix, &mut output)?;
    Ok(PacketNativeSuffixLaunchIdentityData {
        encoded_bytes: output.bytes,
        raw_digest: *output.hasher.finalize().as_bytes(),
    })
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<Identity>()
        + size_of::<Decimal>()
        + size_of::<[u8; 20]>()
        + size_of::<Result<&str, std::str::Utf8Error>>()
        + size_of::<CanonicalReservation<'static>>()
        + size_of::<CanonicalRow<'static>>() * 2
        + size_of::<PacketNativeSuffixLaunchIdentityData>()
        + size_of::<Result<PacketNativeSuffixLaunchIdentityData, ProviderError>>()
        + size_of::<std::io::Result<usize>>()
        + size_of::<std::io::Result<()>>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<&[u8]>()
        + size_of::<&PacketNativeInvocationPurposeData>()
        + size_of::<&PacketRestoredSuffixReservationData>()
        + size_of::<&PacketNativeStartupAllocationRow>() * 2
        + size_of::<&mut Identity>()
        + super::super::original_native_invocation_counter_scratch_data()
}
