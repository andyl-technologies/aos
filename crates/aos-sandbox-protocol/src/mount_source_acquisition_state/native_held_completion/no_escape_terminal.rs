//! Standalone local marker for a distinct pre-Requested Root terminal.
//!
//! This codec is not accepted by the existing AOSMHC02 sidecar or any Root
//! reducer. Encoding a marker cannot establish a protected terminal append.
//!
//! ```text
//! AOSMNT02 | version:u16be=2 | kind:u8=2 | reserved[5]=0 |
//! cleanup_tx[16] | Closed_R_digest[32] | settled_Attempt_ref[72] |
//! Faulted_Acquisition_ref[72] | retired_Root5_ID[32] |
//! retired_Root5_value_digest[32] | original_Source_floor_ID[32] |
//! original_Root1_digest[32] | signed_Source_archive_digest[32] |
//! accepted_Source_answer_digest[32]
//! ```

use aos_sandbox_core::ObjectDigest;

use crate::mount_source_acquisition_state::{RecordRefV2, Result, format::state_error};

/// Fixes the distinct pre-Requested terminal marker width.
pub const ROOT_NATIVE_NO_ESCAPE_TERMINAL_BYTES_V2: usize = 400;

const MAGIC: &[u8; 8] = b"AOSMNT02";
const HEADER: [u8; 8] = [0, 2, 2, 0, 0, 0, 0, 0];
const _: () = assert!(16 + 16 + 32 + 2 * 72 + 6 * 32 == ROOT_NATIVE_NO_ESCAPE_TERMINAL_BYTES_V2);

fn valid_reference(reference: RecordRefV2) -> bool {
    reference.id != [0; 32] && reference.revision != 0 && reference.record_digest != [0; 32]
}

fn array_at<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N]> {
    bytes
        .get(start..start + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| state_error("native no-escape marker truncated"))
}

fn reference_at(bytes: &[u8], start: usize) -> Result<RecordRefV2> {
    Ok(RecordRefV2 {
        id: array_at(bytes, start)?,
        revision: u64::from_be_bytes(array_at(bytes, start + 32)?),
        record_digest: array_at(bytes, start + 40)?,
    })
}

/// Retains exact Root terminal identities as nonauthorizing DATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeNoEscapeTerminalV2 {
    cleanup_transaction: [u8; 16],
    closed_disposition: ObjectDigest,
    settled_attempt: RecordRefV2,
    faulted_acquisition: RecordRefV2,
    retired_capacity_id: [u8; 32],
    retired_capacity_digest: [u8; 32],
    original_source_floor_id: [u8; 32],
    original_root_prepared: ObjectDigest,
    signed_source_archive: ObjectDigest,
    accepted_source_answer: ObjectDigest,
}

impl RootNativeNoEscapeTerminalV2 {
    /// Constructs only a bounded marker, not a Root journal or signer grant.
    ///
    /// # Errors
    /// Rejects zero identities/digests or unsupported settled revisions.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cleanup_transaction: [u8; 16],
        closed_disposition: ObjectDigest,
        settled_attempt: RecordRefV2,
        faulted_acquisition: RecordRefV2,
        retired_capacity: ([u8; 32], [u8; 32]),
        original_source_floor_id: [u8; 32],
        original_root_prepared: ObjectDigest,
        signed_source_archive: ObjectDigest,
        accepted_source_answer: ObjectDigest,
    ) -> Result<Self> {
        let marker = Self {
            cleanup_transaction,
            closed_disposition,
            settled_attempt,
            faulted_acquisition,
            retired_capacity_id: retired_capacity.0,
            retired_capacity_digest: retired_capacity.1,
            original_source_floor_id,
            original_root_prepared,
            signed_source_archive,
            accepted_source_answer,
        };
        marker.validate()?;
        Ok(marker)
    }

    /// Returns the actual terminal transaction identity as DATA.
    #[must_use]
    pub const fn cleanup_transaction(&self) -> [u8; 16] {
        self.cleanup_transaction
    }

    /// Returns the exact immutable Closed disposition assertion.
    #[must_use]
    pub const fn closed_disposition(&self) -> ObjectDigest {
        self.closed_disposition
    }

    /// Returns the final Mount Attempt and Faulted Acquisition references.
    #[must_use]
    pub const fn terminal_references(&self) -> (RecordRefV2, RecordRefV2) {
        (self.settled_attempt, self.faulted_acquisition)
    }

    /// Returns the retired original Root floor identity and value digest.
    #[must_use]
    pub const fn retired_capacity(&self) -> ([u8; 32], [u8; 32]) {
        (self.retired_capacity_id, self.retired_capacity_digest)
    }

    /// Returns the original Source floor and accepted Source closure commitments.
    #[must_use]
    pub const fn source_commitments(&self) -> ([u8; 32], ObjectDigest, ObjectDigest, ObjectDigest) {
        (
            self.original_source_floor_id,
            self.original_root_prepared,
            self.signed_source_archive,
            self.accepted_source_answer,
        )
    }

    /// Encodes exactly 400 bytes without implying a protected append.
    ///
    /// # Errors
    /// Rejects sentinel values or unsupported reference revisions.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(ROOT_NATIVE_NO_ESCAPE_TERMINAL_BYTES_V2);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&HEADER);
        bytes.extend_from_slice(&self.cleanup_transaction);
        bytes.extend_from_slice(self.closed_disposition.as_bytes());
        for record in [self.settled_attempt, self.faulted_acquisition] {
            bytes.extend_from_slice(&record.id);
            bytes.extend_from_slice(&record.revision.to_be_bytes());
            bytes.extend_from_slice(&record.record_digest);
        }
        for digest in [
            self.retired_capacity_id,
            self.retired_capacity_digest,
            self.original_source_floor_id,
            *self.original_root_prepared.as_bytes(),
            *self.signed_source_archive.as_bytes(),
            *self.accepted_source_answer.as_bytes(),
        ] {
            bytes.extend_from_slice(&digest);
        }
        Ok(bytes)
    }

    /// Decodes only the distinct canonical marker, not a current owner graph.
    ///
    /// # Errors
    /// Rejects changed magic, width, version, kind, reserved bytes, or sentinel.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ROOT_NATIVE_NO_ESCAPE_TERMINAL_BYTES_V2
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..16) != Some(HEADER.as_slice())
        {
            return Err(state_error("native no-escape marker header"));
        }
        let marker = Self::new(
            array_at(bytes, 16)?,
            ObjectDigest::from_bytes(array_at(bytes, 32)?),
            reference_at(bytes, 64)?,
            reference_at(bytes, 136)?,
            (array_at(bytes, 208)?, array_at(bytes, 240)?),
            array_at(bytes, 272)?,
            ObjectDigest::from_bytes(array_at(bytes, 304)?),
            ObjectDigest::from_bytes(array_at(bytes, 336)?),
            ObjectDigest::from_bytes(array_at(bytes, 368)?),
        )?;
        if marker.to_canonical_bytes()?.as_slice() != bytes {
            return Err(state_error("native no-escape marker canonical bytes"));
        }
        Ok(marker)
    }

    fn validate(&self) -> Result<()> {
        if self.cleanup_transaction == [0; 16]
            || self.closed_disposition.as_bytes() == &[0; 32]
            || !valid_reference(self.settled_attempt)
            || !matches!(self.settled_attempt.revision, 3 | 4)
            || !valid_reference(self.faulted_acquisition)
            || self.retired_capacity_id == [0; 32]
            || self.retired_capacity_digest == [0; 32]
            || self.original_source_floor_id == [0; 32]
            || self.original_root_prepared.as_bytes() == &[0; 32]
            || self.signed_source_archive.as_bytes() == &[0; 32]
            || self.accepted_source_answer.as_bytes() == &[0; 32]
        {
            return Err(state_error("native no-escape marker sentinel or revision"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount_source_acquisition_state::native_held_completion::RootNativeNoInterestTerminalV1;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn reference(id: u8, revision: u64, record: u8) -> RecordRefV2 {
        RecordRefV2 {
            id: [id; 32],
            revision,
            record_digest: [record; 32],
        }
    }

    fn marker() -> RootNativeNoEscapeTerminalV2 {
        RootNativeNoEscapeTerminalV2::new(
            [1; 16],
            digest(2),
            reference(3, 3, 4),
            reference(5, 2, 6),
            ([7; 32], [8; 32]),
            [9; 32],
            digest(10),
            digest(11),
            digest(12),
        )
        .unwrap()
    }

    #[test]
    fn marker_has_independently_assembled_400_byte_preimage() {
        let marker = marker();
        let bytes = marker.to_canonical_bytes().unwrap();

        let mut expected = b"AOSMNT02\0\x02\x02\0\0\0\0\0".to_vec();
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[2; 32]);
        for (id, revision, record) in [(3, 3_u64, 4), (5, 2, 6)] {
            expected.extend_from_slice(&[id; 32]);
            expected.extend_from_slice(&revision.to_be_bytes());
            expected.extend_from_slice(&[record; 32]);
        }
        for byte in 7..=12 {
            expected.extend_from_slice(&[byte; 32]);
        }

        assert_eq!(bytes.len(), ROOT_NATIVE_NO_ESCAPE_TERMINAL_BYTES_V2);
        assert_eq!(bytes, expected);
        assert_eq!(&bytes[96..104], &3_u64.to_be_bytes());
        assert_eq!(&bytes[168..176], &2_u64.to_be_bytes());
        assert_eq!(
            RootNativeNoEscapeTerminalV2::from_canonical_bytes(&bytes).unwrap(),
            marker
        );
        assert!(RootNativeNoInterestTerminalV1::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn marker_rejects_old_tag_reserved_bytes_sentinels_and_wrong_revision() {
        let bytes = marker().to_canonical_bytes().unwrap();
        for (offset, value) in [
            (0, b'X'),
            (8, 1),
            (9, 1),
            (10, 1),
            (11, 1),
            (103, 0),
            (175, 0),
        ] {
            let mut changed = bytes.clone();
            changed[offset] = value;
            assert!(RootNativeNoEscapeTerminalV2::from_canonical_bytes(&changed).is_err());
        }
        for start in [16, 32, 64, 104, 136, 176, 208, 240, 272, 304, 336, 368] {
            let mut changed = bytes.clone();
            let end = if start == 16 { 32 } else { start + 32 };
            changed[start..end].fill(0);
            assert!(RootNativeNoEscapeTerminalV2::from_canonical_bytes(&changed).is_err());
        }
        assert!(RootNativeNoEscapeTerminalV2::from_canonical_bytes(&bytes[..399]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(RootNativeNoEscapeTerminalV2::from_canonical_bytes(&trailing).is_err());
    }
}
