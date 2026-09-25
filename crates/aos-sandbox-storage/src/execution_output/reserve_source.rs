//! Durable original-request custody for a future Storage logical reserve.
//!
//! The original request marker and AOSEOR03 row enter one journal transaction.
//! The authority witness has no production constructor until Storage verifies
//! a Controller-signed source and a same-session, held Host readback. Query is
//! historical: it identifies the original commit, not a current Host permit.
//! Its Storage MAC is local integrity, not a Controller signature or a Host
//! outcome verification.
//!
//! ```text
//! AOSEOS01 | request[16] | execution[16] | create[16]
//!          | signed-source-digest[32] | Host-outcome-digest[32]
//!          | original-AOSEOR03-digest[32] | hmac[32]
//! ```

use aos_sandbox::{Journal, JournalRecord, JournalTransaction};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    ExecutionOutputLedgerErrorV1, ExecutionOutputLedgerKeyV1, ExecutionOutputLedgerV1, NAMESPACE,
    RetainedOutputRecord, STATE_RETAINED, decode_record, encode_record, reservation_key,
    transaction_id,
};

const MARKER_MAGIC: &[u8; 8] = b"AOSEOS01";
const MARKER_BYTES: usize = 184;
const MARKER_BODY_BYTES: usize = MARKER_BYTES - 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OriginalReserveMarker {
    request_id: [u8; 16],
    execution: [u8; 16],
    create: [u8; 16],
    signed_source_digest: ObjectDigest,
    host_outcome_digest: ObjectDigest,
    record_digest: ObjectDigest,
}

/// Holds values that the future Controller and Host verifier must establish.
///
/// There is deliberately no constructor in production code. A scalar source
/// digest or caller-supplied v2 claim cannot mint this witness.
struct VerifiedOriginalOutputReserveV1 {
    record: RetainedOutputRecord,
    request_id: [u8; 16],
    signed_source_digest: ObjectDigest,
    host_outcome_digest: ObjectDigest,
}

impl ExecutionOutputLedgerV1 {
    /// Commits the original source marker and the matching logical row atomically.
    ///
    /// The future verifier must retain the Controller and Host owner cut while
    /// invoking this method. It cannot be reached from the current service.
    fn reserve_verified_original(
        &mut self,
        verified: &VerifiedOriginalOutputReserveV1,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
        let record = &verified.record;
        if record.execution == [0; 16]
            || record.create == [0; 16]
            || record.assignment == [0; 32]
            || record.claim_digest == [0; 32]
            || record.state != STATE_RETAINED
            || record.delete_operation != [0; 16]
            || record
                .maximum_stdout_bytes
                .checked_add(record.maximum_stderr_bytes)
                != Some(record.bytes)
            || verified.request_id == [0; 16]
            || verified.signed_source_digest.as_bytes() == &[0; 32]
            || verified.host_outcome_digest.as_bytes() == &[0; 32]
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }

        self.journal.validate_held_protected_names()?;
        self.journal.ensure_healthy()?;
        let row_location = reservation_key(record.execution);
        let row_bytes = encode_record(record, &row_location, &self.key)?;
        let record_digest = ObjectDigest::from_bytes(Sha256::digest(row_bytes).into());
        let marker = OriginalReserveMarker {
            request_id: verified.request_id,
            execution: record.execution,
            create: record.create,
            signed_source_digest: verified.signed_source_digest,
            host_outcome_digest: verified.host_outcome_digest,
            record_digest,
        };
        let marker_location = marker_key(marker.request_id);
        let marker_bytes = encode_marker(marker, &marker_location, &self.key)?;

        if let Some(existing) = self.journal.get(NAMESPACE, &marker_location) {
            let existing = decode_marker(&marker_location, existing, &self.key)?;
            let result = if existing == marker
                && self.original_row_digest(&existing)? == marker.record_digest
            {
                Ok(marker.record_digest)
            } else {
                Err(ExecutionOutputLedgerErrorV1::Conflict)
            };
            self.journal.validate_held_protected_names()?;
            return result;
        }
        if self.journal.get(NAMESPACE, &row_location).is_some() {
            return Err(ExecutionOutputLedgerErrorV1::Conflict);
        }

        let next = self
            .retained_bytes
            .checked_add(record.bytes)
            .filter(|total| *total <= self.capacity_bytes)
            .ok_or(ExecutionOutputLedgerErrorV1::Capacity)?;
        let transaction = JournalTransaction::new(
            transaction_id(
                b"original-reserve",
                &marker_location,
                marker.signed_source_digest.as_bytes(),
            ),
            vec![
                JournalRecord::put(NAMESPACE, row_location, row_bytes.to_vec()),
                JournalRecord::put(NAMESPACE, marker_location, marker_bytes.to_vec()),
            ],
        )?;
        self.journal.commit(&transaction)?;
        self.retained_bytes = next;
        self.journal.validate_held_protected_names()?;
        Ok(record_digest)
    }

    /// Cold-queries only the original request and source after uncertain commit.
    ///
    /// An absent marker beside an occupied execution is a conflict. An unhealthy
    /// writer or unresolved journal tail never proves absence.
    fn query_original_reserve(
        &self,
        request_id: [u8; 16],
        execution: [u8; 16],
        create: [u8; 16],
        signed_source_digest: ObjectDigest,
    ) -> Result<Option<ObjectDigest>, ExecutionOutputLedgerErrorV1> {
        if request_id == [0; 16]
            || execution == [0; 16]
            || create == [0; 16]
            || signed_source_digest.as_bytes() == &[0; 32]
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        self.journal.validate_held_protected_names()?;
        self.journal.ensure_healthy()?;

        let location = marker_key(request_id);
        let result = match self.journal.get(NAMESPACE, &location) {
            Some(bytes) => {
                let marker = decode_marker(&location, bytes, &self.key)?;
                if marker.execution != execution
                    || marker.create != create
                    || marker.signed_source_digest != signed_source_digest
                    || self.original_row_digest(&marker)? != marker.record_digest
                {
                    return Err(ExecutionOutputLedgerErrorV1::Conflict);
                }
                Some(marker.record_digest)
            }
            None => {
                if self
                    .journal
                    .get(NAMESPACE, &reservation_key(execution))
                    .is_some()
                {
                    return Err(ExecutionOutputLedgerErrorV1::Conflict);
                }
                None
            }
        };
        self.journal.validate_held_protected_names()?;
        self.journal.ensure_healthy()?;
        Ok(result)
    }

    fn original_row_digest(
        &self,
        marker: &OriginalReserveMarker,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
        original_row_digest(&self.journal, marker, &self.key)
    }
}

pub(super) fn verify_replayed_original_reserve(
    journal: &Journal,
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<[u8; 16], ExecutionOutputLedgerErrorV1> {
    let marker = decode_marker(location, bytes, key)?;
    if original_row_digest(journal, &marker, key)? != marker.record_digest {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(marker.execution)
}

fn original_row_digest(
    journal: &Journal,
    marker: &OriginalReserveMarker,
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
    let location = reservation_key(marker.execution);
    let bytes = journal
        .get(NAMESPACE, &location)
        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
    let mut record = decode_record(&location, bytes, key)?;
    if record.create != marker.create {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    record.state = STATE_RETAINED;
    record.delete_operation = [0; 16];
    let original = encode_record(&record, &location, key)?;
    Ok(ObjectDigest::from_bytes(Sha256::digest(original).into()))
}

fn marker_key(request_id: [u8; 16]) -> Vec<u8> {
    let mut location = Vec::with_capacity(17);
    location.push(b'm');
    location.extend_from_slice(&request_id);
    location
}

fn encode_marker(
    marker: OriginalReserveMarker,
    location: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<[u8; MARKER_BYTES], ExecutionOutputLedgerErrorV1> {
    let mut bytes = [0; MARKER_BYTES];
    bytes[..8].copy_from_slice(MARKER_MAGIC);
    bytes[8..24].copy_from_slice(&marker.request_id);
    bytes[24..40].copy_from_slice(&marker.execution);
    bytes[40..56].copy_from_slice(&marker.create);
    bytes[56..88].copy_from_slice(marker.signed_source_digest.as_bytes());
    bytes[88..120].copy_from_slice(marker.host_outcome_digest.as_bytes());
    bytes[120..152].copy_from_slice(marker.record_digest.as_bytes());
    let mac = key.mac(location, &bytes[..MARKER_BODY_BYTES])?;
    bytes[MARKER_BODY_BYTES..].copy_from_slice(&mac);
    Ok(bytes)
}

fn decode_marker(
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<OriginalReserveMarker, ExecutionOutputLedgerErrorV1> {
    if location.len() != 17
        || location[0] != b'm'
        || bytes.len() != MARKER_BYTES
        || &bytes[..8] != MARKER_MAGIC
        || bytes[8..24] != location[1..]
        || bytes[8..24] == [0; 16]
        || bytes[24..40] == [0; 16]
        || bytes[40..56] == [0; 16]
        || bytes[56..88] == [0; 32]
        || bytes[88..120] == [0; 32]
        || bytes[120..152] == [0; 32]
        || !key.verify_mac(
            location,
            &bytes[..MARKER_BODY_BYTES],
            &bytes[MARKER_BODY_BYTES..],
        )?
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(OriginalReserveMarker {
        request_id: field_16(&bytes[8..24])?,
        execution: field_16(&bytes[24..40])?,
        create: field_16(&bytes[40..56])?,
        signed_source_digest: ObjectDigest::from_bytes(field_32(&bytes[56..88])?),
        host_outcome_digest: ObjectDigest::from_bytes(field_32(&bytes[88..120])?),
        record_digest: ObjectDigest::from_bytes(field_32(&bytes[120..152])?),
    })
}

fn field_16(bytes: &[u8]) -> Result<[u8; 16], ExecutionOutputLedgerErrorV1> {
    bytes
        .try_into()
        .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)
}

fn field_32(bytes: &[u8]) -> Result<[u8; 32], ExecutionOutputLedgerErrorV1> {
    bytes
        .try_into()
        .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox::{Journal, JournalLimits};
    use tempfile::TempDir;

    use super::*;

    fn open_ledger(directory: &TempDir) -> ExecutionOutputLedgerV1 {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        open_ledger_result(directory).unwrap()
    }

    fn verified(execution: u8, request: u8) -> VerifiedOriginalOutputReserveV1 {
        VerifiedOriginalOutputReserveV1 {
            record: RetainedOutputRecord {
                execution: [execution; 16],
                create: [3; 16],
                assignment: [4; 32],
                claim_digest: [5; 32],
                bytes: 9,
                maximum_stdout_bytes: 4,
                maximum_stderr_bytes: 5,
                state: STATE_RETAINED,
                delete_operation: [0; 16],
            },
            request_id: [request; 16],
            signed_source_digest: ObjectDigest::from_bytes([6; 32]),
            host_outcome_digest: ObjectDigest::from_bytes([7; 32]),
        }
    }

    #[test]
    fn original_reserve_reopens_with_exact_source_and_rejects_changed_replay() {
        let directory = TempDir::new().unwrap();
        let original = verified(1, 2);
        let mut ledger = open_ledger(&directory);

        let digest = ledger.reserve_verified_original(&original).unwrap();
        assert_eq!(ledger.reserve_verified_original(&original).unwrap(), digest);
        drop(ledger);

        let reopened = open_ledger(&directory);
        assert_eq!(
            reopened
                .query_original_reserve(
                    original.request_id,
                    original.record.execution,
                    original.record.create,
                    original.signed_source_digest,
                )
                .unwrap(),
            Some(digest)
        );
        assert!(
            reopened
                .query_original_reserve(
                    original.request_id,
                    original.record.execution,
                    original.record.create,
                    ObjectDigest::from_bytes([8; 32]),
                )
                .is_err()
        );
        assert!(
            reopened
                .query_original_reserve(
                    [9; 16],
                    original.record.execution,
                    original.record.create,
                    original.signed_source_digest,
                )
                .is_err()
        );
    }

    #[test]
    fn original_request_and_execution_cannot_be_reused() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open_ledger(&directory);
        ledger.reserve_verified_original(&verified(1, 2)).unwrap();

        assert!(ledger.reserve_verified_original(&verified(1, 3)).is_err());
        assert!(ledger.reserve_verified_original(&verified(4, 2)).is_err());
        assert_eq!(ledger.retained_bytes(), 9);
        assert_eq!(
            ledger
                .query_original_reserve(
                    [5; 16],
                    [6; 16],
                    [3; 16],
                    ObjectDigest::from_bytes([6; 32]),
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn cold_replay_rejects_second_original_marker_for_one_execution() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open_ledger(&directory);
        let original = verified(1, 2);
        let digest = ledger.reserve_verified_original(&original).unwrap();

        let conflicting = verified(1, 3);
        let marker = OriginalReserveMarker {
            request_id: conflicting.request_id,
            execution: conflicting.record.execution,
            create: conflicting.record.create,
            signed_source_digest: conflicting.signed_source_digest,
            host_outcome_digest: conflicting.host_outcome_digest,
            record_digest: digest,
        };
        let location = marker_key(marker.request_id);
        let bytes = encode_marker(marker, &location, &ledger.key).unwrap();
        ledger
            .journal
            .commit(
                &JournalTransaction::new(
                    [11; 16],
                    vec![JournalRecord::put(NAMESPACE, location, bytes.to_vec())],
                )
                .unwrap(),
            )
            .unwrap();
        drop(ledger);

        assert!(matches!(
            open_ledger_result(&directory),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }

    #[test]
    fn cold_replay_rejects_marker_under_another_request_name() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open_ledger(&directory);
        let original = verified(1, 2);
        let digest = ledger.reserve_verified_original(&original).unwrap();

        let marker = OriginalReserveMarker {
            request_id: [3; 16],
            execution: original.record.execution,
            create: original.record.create,
            signed_source_digest: original.signed_source_digest,
            host_outcome_digest: original.host_outcome_digest,
            record_digest: digest,
        };
        let location = marker_key([4; 16]);
        let bytes = encode_marker(marker, &location, &ledger.key).unwrap();
        ledger
            .journal
            .commit(
                &JournalTransaction::new(
                    [12; 16],
                    vec![JournalRecord::put(NAMESPACE, location, bytes.to_vec())],
                )
                .unwrap(),
            )
            .unwrap();
        drop(ledger);

        assert!(matches!(
            open_ledger_result(&directory),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }

    #[test]
    fn cold_replay_rejects_marker_without_its_aoseor03_row() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open_ledger(&directory);
        let original = verified(1, 2);
        ledger.reserve_verified_original(&original).unwrap();

        ledger
            .journal
            .commit(
                &JournalTransaction::new(
                    [13; 16],
                    vec![JournalRecord::delete(
                        NAMESPACE,
                        reservation_key(original.record.execution),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(ledger);

        assert!(matches!(
            open_ledger_result(&directory),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }

    fn open_ledger_result(
        directory: &TempDir,
    ) -> Result<ExecutionOutputLedgerV1, ExecutionOutputLedgerErrorV1> {
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "output.journal",
            JournalLimits::default(),
            uid,
        )?;
        ExecutionOutputLedgerV1::from_journal(
            journal,
            100,
            ExecutionOutputLedgerKeyV1::new([1; 16], [2; 32])?,
        )
    }
}
