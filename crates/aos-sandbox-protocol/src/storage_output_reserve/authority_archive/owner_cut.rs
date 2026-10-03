//! Canonical six-owner historical Output cut data, without live provenance.
//!
//! ```text
//! AOSCOC01 | version:2 | kind:1 | count:1 | reserved:4 |
//! identity/time/assignment/key-generation prefix:192 |
//! six ordered entries:144 each | domain-sha256:32
//! ```

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};

use super::{ArchiveResult, HistoricalStorageOutputArchiveErrorV1, Reader, digest, nonzero};

const DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-owner-cut.v1\0";
const BYTES: usize = 1_104;

/// Retains canonical owner-cut comparison bytes, never six current owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalControllerOutputOwnerCutV1 {
    bytes: Vec<u8>,
    execution: ExecutionId,
    create_operation: OperationId,
    request_id: [u8; 16],
    boot_id: [u8; 16],
    deadline: u64,
    not_before: i64,
    not_after: i64,
    assignment: ObjectDigest,
    generations: [u64; 3],
    endpoint_generations: [u64; 3],
    digest: [u8; 32],
}

impl HistoricalControllerOutputOwnerCutV1 {
    /// Decodes the exact ordered Original46 owner-cut format as historical DATA.
    ///
    /// # Errors
    ///
    /// Rejects wrong size, version/kind, reserved bytes, owner order, zero rules,
    /// invalid validity intervals or a changed domain-separated digest.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoricalStorageOutputArchiveErrorV1> {
        if bytes.len() != BYTES {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != b"AOSCOC01" || reader.u16()? != 1 {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        if reader.u8()? != 1 {
            return Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedFutureKind);
        }
        if reader.u8()? != 6 {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        reader.zero(4)?;
        let execution = reader.array()?;
        let create_operation = reader.array()?;
        let request_id = reader.array()?;
        let boot_id = reader.array()?;
        for identity in [&execution, &create_operation, &request_id, &boot_id] {
            nonzero(identity)?;
        }
        let deadline = reader.u64()?;
        let not_before = reader.i64()?;
        let not_after = reader.i64()?;
        let assignment = reader.array()?;
        nonzero(&assignment)?;
        nonzero(reader.take(32)?)?;
        let generations = [reader.u64()?, reader.u64()?, reader.u64()?];
        reader.zero(16)?;
        if deadline == 0 || not_after <= not_before || generations.contains(&0) {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }

        let mut endpoint_generations = [0; 3];
        for code in 1..=6 {
            let entry_generations = validate_entry(&mut reader, code)?;
            if code == 5 {
                endpoint_generations = entry_generations;
            }
            if code == 6 && entry_generations != [generations[1], generations[2], generations[0]] {
                return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
            }
        }
        let recorded_digest = reader.array()?;
        reader.finish()?;
        if recorded_digest != digest(DOMAIN, &bytes[..BYTES - 32]) {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            execution: ExecutionId::from_bytes(execution),
            create_operation: OperationId::from_bytes(create_operation),
            request_id,
            boot_id,
            deadline,
            not_before,
            not_after,
            assignment: ObjectDigest::from_bytes(assignment),
            generations,
            endpoint_generations,
            digest: recorded_digest,
        })
    }

    /// Borrows the complete unchanged historical cut bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the historical execution identity, not an execution claim.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the historical Create operation identity.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the original request comparison identity.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the recorded host boot comparison identity.
    #[must_use]
    pub const fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }

    /// Returns the recorded boottime deadline, without reading a clock.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline
    }

    /// Returns the recorded wall-clock validity interval.
    #[must_use]
    pub const fn wall_interval(&self) -> (i64, i64) {
        (self.not_before, self.not_after)
    }

    /// Returns the exact historical assignment-manifest commitment.
    #[must_use]
    pub const fn assignment_manifest_digest(&self) -> ObjectDigest {
        self.assignment
    }

    /// Returns lease, plan-key and lease-key generation comparison values.
    #[must_use]
    pub const fn generations(&self) -> [u64; 3] {
        self.generations
    }

    pub(super) const fn endpoint_generations(&self) -> [u64; 3] {
        self.endpoint_generations
    }

    /// Returns the canonical historical cut checksum, not an authority proof.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn validate_entry(reader: &mut Reader<'_>, expected_code: u8) -> ArchiveResult<[u64; 3]> {
    if reader.u8()? != expected_code {
        return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
    }
    let flags = reader.u8()?;
    reader.zero(6)?;
    let sequence = reader.u64()?;
    let generations = [reader.u64()?, reader.u64()?, reader.u64()?];
    for _ in 0..3 {
        nonzero(reader.take(32)?)?;
    }
    let valid_until = reader.u64()?;
    let valid = match expected_code {
        1 => flags == 0 && sequence > 0 && generations == [0; 3] && valid_until == 0,
        2 => flags == 0 && sequence > 0 && generations[0] > 0
            && generations[1..] == [0; 2] && valid_until == 0,
        3 => flags == 0 && sequence > 0 && generations == [0; 3] && valid_until > 0,
        4 => sequence > 0 && generations[1..] == [0; 2] && valid_until == 0
            && ((flags == 0 && generations[0] > 0) || (flags == 1 && generations[0] == 0)),
        5 | 6 => flags == 0 && sequence == 0 && !generations.contains(&0) && valid_until == 0,
        _ => false,
    };
    if !valid {
        return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
    }
    Ok(generations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_rejects_truncation_future_kind_and_nonzero_reserved_bytes() {
        assert!(HistoricalControllerOutputOwnerCutV1::decode(&[0; BYTES - 1]).is_err());

        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(b"AOSCOC01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 2;
        assert!(matches!(HistoricalControllerOutputOwnerCutV1::decode(&bytes),
            Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedFutureKind)));

        bytes[10] = 1;
        bytes[11] = 6;
        bytes[12] = 1;
        assert!(HistoricalControllerOutputOwnerCutV1::decode(&bytes).is_err());
    }

    #[test]
    fn absence_flag_is_only_valid_on_original_session_entry() {
        let mut entry = [0; 144];
        entry[0] = 1;
        entry[1] = 1;
        entry[8..16].copy_from_slice(&1_u64.to_be_bytes());
        entry[40..136].fill(1);
        assert!(validate_entry(&mut Reader::new(&entry), 1).is_err());

        entry[0] = 4;
        assert!(validate_entry(&mut Reader::new(&entry), 4).is_ok());
        entry[16..24].copy_from_slice(&1_u64.to_be_bytes());
        assert!(validate_entry(&mut Reader::new(&entry), 4).is_err());
    }
}
