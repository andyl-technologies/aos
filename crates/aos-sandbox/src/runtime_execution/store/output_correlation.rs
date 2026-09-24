//! Protected Host correlation for a Controller-signed output reservation.
//!
//! The AOSEOR02 claim records accepted output bytes, while this record binds
//! the exact Host broker attempt that admitted those bytes. Both records must
//! be appended in one protected execution-journal transaction.
//!
//! ```text
//! AOSHOP01 || execution[16] || create-operation[16]
//!          || AOSCIP01-record-digest[32] || AOSEOR02-record-digest[32]
//!          || AOSCIR01-carrier-digest[32] || original-request-id[16]
//!          || assignment-digest[32] || host-boot-id[16]
//!          || signed-plan-digest[32] || semantic-request-digest[32]
//!          || deadline-boottime-nanoseconds:u64be
//!          || original-journal-sequence:u64be || SHA256(prefix)[32]
//! ```

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

pub(super) const KEY_PREFIX: u8 = b'p';
const MAGIC: &[u8; 8] = b"AOSHOP01";
const RECORD_BYTES: usize = 312;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HostOutputCorrelationV1 {
    pub(super) execution: ExecutionId,
    pub(super) create_operation: OperationId,
    pub(super) preissue_digest: ObjectDigest,
    pub(super) claim_digest: ObjectDigest,
    pub(super) carrier_digest: ObjectDigest,
    pub(super) original_request_id: [u8; 16],
    pub(super) assignment_digest: ObjectDigest,
    pub(super) host_boot_id: [u8; 16],
    pub(super) plan_digest: ObjectDigest,
    pub(super) semantic_request_digest: ObjectDigest,
    pub(super) deadline_boottime_nanoseconds: u64,
    pub(super) original_journal_sequence: u64,
}

impl HostOutputCorrelationV1 {
    pub(super) fn encode(self) -> Option<[u8; RECORD_BYTES]> {
        if !self.is_valid() {
            return None;
        }

        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(self.execution.as_bytes());
        bytes[24..40].copy_from_slice(self.create_operation.as_bytes());
        bytes[40..72].copy_from_slice(self.preissue_digest.as_bytes());
        bytes[72..104].copy_from_slice(self.claim_digest.as_bytes());
        bytes[104..136].copy_from_slice(self.carrier_digest.as_bytes());
        bytes[136..152].copy_from_slice(&self.original_request_id);
        bytes[152..184].copy_from_slice(self.assignment_digest.as_bytes());
        bytes[184..200].copy_from_slice(&self.host_boot_id);
        bytes[200..232].copy_from_slice(self.plan_digest.as_bytes());
        bytes[232..264].copy_from_slice(self.semantic_request_digest.as_bytes());
        bytes[264..272].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes[272..280].copy_from_slice(&self.original_journal_sequence.to_be_bytes());
        let checksum = Sha256::digest(&bytes[..280]);
        bytes[280..].copy_from_slice(&checksum);
        Some(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || Sha256::digest(&bytes[..280]).as_slice() != &bytes[280..]
        {
            return None;
        }

        let read_16 =
            |start: usize| -> Option<[u8; 16]> { bytes.get(start..start + 16)?.try_into().ok() };
        let read_32 = |start: usize| -> Option<ObjectDigest> {
            Some(ObjectDigest::from_bytes(
                bytes.get(start..start + 32)?.try_into().ok()?,
            ))
        };
        let record = Self {
            execution: ExecutionId::from_bytes(read_16(8)?),
            create_operation: OperationId::from_bytes(read_16(24)?),
            preissue_digest: read_32(40)?,
            claim_digest: read_32(72)?,
            carrier_digest: read_32(104)?,
            original_request_id: read_16(136)?,
            assignment_digest: read_32(152)?,
            host_boot_id: read_16(184)?,
            plan_digest: read_32(200)?,
            semantic_request_digest: read_32(232)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(
                bytes.get(264..272)?.try_into().ok()?,
            ),
            original_journal_sequence: u64::from_be_bytes(bytes.get(272..280)?.try_into().ok()?),
        };
        record.is_valid().then_some(record)
    }

    fn is_valid(self) -> bool {
        self.execution.as_bytes() != &[0; 16]
            && self.create_operation.as_bytes() != &[0; 16]
            && self.original_request_id != [0; 16]
            && self.host_boot_id != [0; 16]
            && self.deadline_boottime_nanoseconds != 0
            && self.original_journal_sequence != 0
            && [
                self.preissue_digest,
                self.claim_digest,
                self.carrier_digest,
                self.assignment_digest,
                self.plan_digest,
                self.semantic_request_digest,
            ]
            .iter()
            .all(|digest| digest.as_bytes() != &[0; 32])
    }
}

pub(super) fn host_output_key(execution: ExecutionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(KEY_PREFIX);
    key.extend_from_slice(execution.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_roundtrip_and_substitution_rejection() {
        let record = HostOutputCorrelationV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([2; 16]),
            preissue_digest: ObjectDigest::from_bytes([3; 32]),
            claim_digest: ObjectDigest::from_bytes([4; 32]),
            carrier_digest: ObjectDigest::from_bytes([5; 32]),
            original_request_id: [6; 16],
            assignment_digest: ObjectDigest::from_bytes([7; 32]),
            host_boot_id: [8; 16],
            plan_digest: ObjectDigest::from_bytes([9; 32]),
            semantic_request_digest: ObjectDigest::from_bytes([10; 32]),
            deadline_boottime_nanoseconds: 11,
            original_journal_sequence: 12,
        };
        let bytes = record.encode().unwrap();
        assert_eq!(HostOutputCorrelationV1::decode(&bytes), Some(record));
        let mut expected_key = vec![KEY_PREFIX];
        expected_key.extend_from_slice(&[1; 16]);
        assert_eq!(host_output_key(record.execution), expected_key);

        let mut substituted = bytes;
        substituted[136] ^= 1;
        assert_eq!(HostOutputCorrelationV1::decode(&substituted), None);
        assert_eq!(HostOutputCorrelationV1::decode(&bytes[..311]), None);
    }
}
