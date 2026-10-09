//! Exact bounded binary encoding of the native Root journal sidecar.
//!
//! ```text
//! AOSMHC01 | version1 | flags0 | reserved[4] | original_scope[224] |
//! CAS_id[16] | lengths[4] | Root_assertion | settlement | verifier | suffix
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::bounded_codec::{BoundedReader, ReadError};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldOwnerV1, NativeHeldScopeV1,
    assertion::{
        NativeHeldDispositionV1, NativeHeldSettlementV1, RootNativeDispositionAssertionV1,
    },
    suffix::NativeHeldCompletionSuffixV1,
};

use super::{MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1, RootNativeTerminalVerifierV1};
use crate::mount_source_acquisition_state::{
    MountSourceAcquisitionStateError, Result, format::state_error,
};

const PREFIX: &[u8] = b"aos.mount.native-held-completion.v1\0";

/// Fixes the original Mount-attempt sidecar key width.
pub const ROOT_NATIVE_HELD_KEY_BYTES_V1: usize = 68;

const _: () = assert!(PREFIX.len() + 32 == ROOT_NATIVE_HELD_KEY_BYTES_V1);

/// Returns the exact native sidecar key for one nonzero original Mount attempt.
///
/// # Errors
///
/// Rejects a sentinel attempt; this creates no journal mutation scope.
pub fn native_root_sidecar_key_v1(attempt: [u8; 32]) -> Result<Vec<u8>> {
    if attempt == [0; 32] {
        return Err(state_error("native Root sidecar sentinel attempt"));
    }
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(&attempt);
    Ok(key)
}

pub(super) fn is_sidecar_key(key: &[u8]) -> bool {
    key.len() == ROOT_NATIVE_HELD_KEY_BYTES_V1 && key.starts_with(PREFIX)
}

/// Retains canonical native Root metadata without granting local FD acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeHeldSidecarV1 {
    pub(super) original_scope: NativeHeldScopeV1,
    pub(super) response_transaction: [u8; 16],
    pub(super) disposition: Option<RootNativeDispositionAssertionV1>,
    pub(super) settlement: Option<NativeHeldSettlementV1>,
    pub(super) terminal_verifier: Option<RootNativeTerminalVerifierV1>,
    pub(super) suffix: NativeHeldCompletionSuffixV1,
}

impl RootNativeHeldSidecarV1 {
    /// Collects bounded native journal claims after checking their phase shape.
    ///
    /// # Errors
    ///
    /// Rejects malformed scope, owner, CAS/phase or stable assertion presences.
    pub fn new(
        original_scope: NativeHeldScopeV1,
        response_transaction: [u8; 16],
        disposition: Option<RootNativeDispositionAssertionV1>,
        settlement: Option<NativeHeldSettlementV1>,
        terminal_verifier: Option<RootNativeTerminalVerifierV1>,
        suffix: NativeHeldCompletionSuffixV1,
    ) -> Result<Self> {
        let value = Self {
            original_scope,
            response_transaction,
            disposition,
            settlement,
            terminal_verifier,
            suffix,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the immutable five-known-field original Root scope.
    #[must_use]
    pub const fn original_scope(&self) -> &NativeHeldScopeV1 {
        &self.original_scope
    }

    /// Returns the retained response CAS identity, zero only before a CAS.
    #[must_use]
    pub const fn response_transaction(&self) -> [u8; 16] {
        self.response_transaction
    }

    /// Returns the stable owning-journal Root assertion, if committed.
    #[must_use]
    pub const fn disposition(&self) -> Option<&RootNativeDispositionAssertionV1> {
        self.disposition.as_ref()
    }

    /// Returns the stable terminal tuple, never a manager custody assertion.
    #[must_use]
    pub const fn settlement(&self) -> Option<&NativeHeldSettlementV1> {
        self.settlement.as_ref()
    }

    /// Returns the original current-provider terminal verification projection.
    #[must_use]
    pub const fn terminal_verifier(&self) -> Option<&RootNativeTerminalVerifierV1> {
        self.terminal_verifier.as_ref()
    }

    /// Returns the exact original archive/preparation data.
    #[must_use]
    pub const fn suffix(&self) -> &NativeHeldCompletionSuffixV1 {
        &self.suffix
    }

    /// Encodes the binary sidecar without changing any legacy canonical record.
    ///
    /// # Errors
    ///
    /// Rejects phase/identity mismatches or the fixed109902-byte ceiling.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let disposition = self
            .disposition
            .as_ref()
            .map(RootNativeDispositionAssertionV1::to_canonical_bytes)
            .transpose()
            .map_err(|_| state_error("native Root assertion"))?
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        let settlement = self
            .settlement
            .as_ref()
            .map(NativeHeldSettlementV1::to_canonical_bytes)
            .transpose()
            .map_err(|_| state_error("native Root settlement"))?
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        let verifier = self
            .terminal_verifier
            .as_ref()
            .map(RootNativeTerminalVerifierV1::to_canonical_bytes)
            .transpose()?
            .unwrap_or_default();
        let suffix = self
            .suffix
            .to_canonical_bytes()
            .map_err(|_| state_error("native Root suffix"))?;

        let mut bytes = b"AOSMHC01".to_vec();
        bytes.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&self.original_scope.to_canonical_bytes());
        bytes.extend_from_slice(&self.response_transaction);
        for field in [&disposition, &settlement, &verifier, &suffix] {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        }
        for field in [&disposition, &settlement, &verifier, &suffix] {
            bytes.extend_from_slice(field);
        }
        if bytes.len() > MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1 {
            return Err(state_error("native Root sidecar byte limit"));
        }
        Ok(bytes)
    }

    /// Decodes only the exact native binary version and matching original key.
    ///
    /// # Errors
    ///
    /// Rejects unknown framing, reserved bytes, lengths, phases or trailing data.
    pub fn from_canonical_bytes(key: &[u8], bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1 || !is_sidecar_key(key) {
            return Err(state_error("native Root sidecar key or byte limit"));
        }
        let mut reader = BoundedReader::new(bytes, native_root_read_error);
        read_header(&mut reader, b"AOSMHC01")?;
        let fields: [[u8; 32]; 7] = [
            reader.array()?,
            reader.array()?,
            reader.array()?,
            reader.array()?,
            reader.array()?,
            reader.array()?,
            reader.array()?,
        ];
        let original_scope = NativeHeldScopeV1 {
            flight: ObjectDigest::from_bytes(fields[0]),
            original_source_session: ObjectDigest::from_bytes(fields[1]),
            mount_attempt: ObjectDigest::from_bytes(fields[2]),
            provider_attempt: ObjectDigest::from_bytes(fields[3]),
            provider_acquisition: ObjectDigest::from_bytes(fields[4]),
            original_root_request: ObjectDigest::from_bytes(fields[5]),
            original_native_request: ObjectDigest::from_bytes(fields[6]),
        };
        let response_transaction = reader.array()?;
        let lengths = [
            reader.u32()? as usize,
            reader.u32()? as usize,
            reader.u32()? as usize,
            reader.u32()? as usize,
        ];
        let r = reader.bytes(lengths[0])?;
        let disposition = if r.is_empty() {
            None
        } else {
            Some(
                RootNativeDispositionAssertionV1::from_canonical_bytes(r)
                    .map_err(|_| state_error("native Root assertion bytes"))?,
            )
        };
        let s = reader.bytes(lengths[1])?;
        let settlement = if s.is_empty() {
            None
        } else {
            Some(
                NativeHeldSettlementV1::from_canonical_bytes(s)
                    .map_err(|_| state_error("native Root settlement bytes"))?,
            )
        };
        let evidence = reader.bytes(lengths[2])?;
        let terminal_verifier = if evidence.is_empty() {
            None
        } else {
            Some(RootNativeTerminalVerifierV1::from_canonical_bytes(
                evidence,
            )?)
        };
        let suffix = NativeHeldCompletionSuffixV1::from_canonical_bytes(reader.bytes(lengths[3])?)
            .map_err(|_| state_error("native Root suffix bytes"))?;
        reader.finish()?;
        let value = Self::new(
            original_scope,
            response_transaction,
            disposition,
            settlement,
            terminal_verifier,
            suffix,
        )?;
        if native_root_sidecar_key_v1(*value.original_scope.mount_attempt.as_bytes())? != key
            || value.to_canonical_bytes()? != bytes
        {
            return Err(state_error("native Root sidecar canonical/key mismatch"));
        }
        Ok(value)
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.original_scope
            .validate_root_only()
            .map_err(|_| state_error("native Root original scope"))?;
        if self.suffix.owner() != NativeHeldOwnerV1::Root
            || self.suffix.flight() != self.original_scope.flight
        {
            return Err(state_error("native Root suffix owner or flight"));
        }
        let phase = self.suffix.phase();
        let class = match phase {
            0..=3 => None,
            4..=7 => Some(NativeHeldDispositionV1::Accepted),
            10..=13 => Some(NativeHeldDispositionV1::Closed),
            _ => return Err(state_error("native Root durable phase")),
        };
        if self.disposition.as_ref().map(|r| r.disposition) != class
            || self.settlement.is_some() != matches!(phase, 6 | 7 | 12 | 13)
            || (phase <= 2 && self.response_transaction != [0; 16])
            || (matches!(phase, 3..=7) && self.response_transaction == [0; 16])
        {
            return Err(state_error("native Root phase/identity presence"));
        }
        if let Some(r) = &self.disposition {
            r.to_canonical_bytes()
                .map_err(|_| state_error("native Root assertion shape"))?;
            if r.scope.is_root_only() {
                if r.scope != self.original_scope {
                    return Err(state_error("native Root partial assertion scope"));
                }
            } else {
                r.scope
                    .require_root_prefix(&self.original_scope)
                    .map_err(|_| state_error("native Root assertion original prefix"))?;
            }
            if let Some(s) = &self.settlement {
                s.validate_for_kind(aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1::RootTerminalRecorded)
                    .map_err(|_| state_error("native Root terminal tuple"))?;
                if s.disposition != r.disposition
                    || s.root_disposition
                        != r.digest()
                            .map_err(|_| state_error("native Root stable ID"))?
                {
                    return Err(state_error("native Root terminal disposition ID"));
                }
            }
        }
        Ok(())
    }
}

pub(super) fn native_root_read_error(error: ReadError) -> MountSourceAcquisitionStateError {
    state_error(match error {
        ReadError::LengthOverflow => "native Root length overflow",
        ReadError::Truncated => "native Root truncated bytes",
        ReadError::NonzeroReserved => "native Root magic/version/reserved",
        ReadError::TrailingBytes => "native Root trailing bytes",
    })
}

// A rejected magic must precede reading or validating the version/reserved field.
pub(super) fn read_header(
    reader: &mut BoundedReader<'_, MountSourceAcquisitionStateError>,
    magic: &[u8; 8],
) -> Result<()> {
    if reader.bytes(8)? != magic || reader.bytes(8)? != [0, 1, 0, 0, 0, 0, 0, 0] {
        return Err(state_error("native Root magic/version/reserved"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_root_reader_preserves_borrows_failed_ranges_and_exact_errors() {
        let bytes = [1, 2, 3];
        let mut reader = BoundedReader::new(&bytes, native_root_read_error);
        let first = reader.bytes(1).unwrap();
        assert_eq!(first.as_ptr(), bytes.as_ptr());
        assert_eq!(
            reader.bytes(usize::MAX),
            Err(state_error("native Root length overflow"))
        );
        assert_eq!(
            reader.bytes(3),
            Err(state_error("native Root truncated bytes"))
        );
        assert_eq!(reader.remaining_bytes(), &bytes[1..]);
        assert_eq!(reader.array::<2>(), Ok([2, 3]));
        assert_eq!(reader.finish(), Ok(()));

        let reader = BoundedReader::new(&bytes, native_root_read_error);
        assert_eq!(
            reader.finish(),
            Err(state_error("native Root trailing bytes"))
        );

        // An exact-width slice always converts to its array; short slices fail before conversion.
        for length in 0..bytes.len() {
            let mut reader = BoundedReader::new(&bytes[..length], native_root_read_error);
            assert_eq!(
                reader.array::<3>(),
                Err(state_error("native Root truncated bytes"))
            );
            assert_eq!(reader.remaining(), length);
        }
    }

    #[test]
    fn native_root_header_preserves_short_circuit_and_reserved_byte_precedence() {
        let header = *b"AOSMHC01\0\x01\0\0\0\0\0\0";
        for length in 0..header.len() {
            let mut reader = BoundedReader::new(&header[..length], native_root_read_error);
            assert_eq!(
                read_header(&mut reader, b"AOSMHC01"),
                Err(state_error("native Root truncated bytes"))
            );
        }

        let mut wrong_magic = BoundedReader::new(b"AOSMHC02", native_root_read_error);
        assert_eq!(
            read_header(&mut wrong_magic, b"AOSMHC01"),
            Err(state_error("native Root magic/version/reserved"))
        );

        for index in 8..header.len() {
            let mut invalid = header;
            invalid[index] ^= 1;
            let mut reader = BoundedReader::new(&invalid, native_root_read_error);
            assert_eq!(
                read_header(&mut reader, b"AOSMHC01"),
                Err(state_error("native Root magic/version/reserved"))
            );
        }

        let mut reader = BoundedReader::new(&header, native_root_read_error);
        assert_eq!(read_header(&mut reader, b"AOSMHC01"), Ok(()));
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn native_root_lengths_preserve_big_endian_as_cast_values() {
        for length in [0, 1, u32::MAX] {
            let bytes = length.to_be_bytes();
            let mut reader = BoundedReader::new(&bytes, native_root_read_error);
            assert_eq!(reader.u32().unwrap() as usize, length as usize);
            assert_eq!(reader.finish(), Ok(()));
        }
    }
}
