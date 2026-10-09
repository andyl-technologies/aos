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
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerMethodResultV1, AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::host_storage_output_readback::{
    decode_captured_host_storage_output_readback_request_v1,
    decode_host_storage_output_readback_response_v1,
};
use aos_sandbox_protocol::storage_output_reserve::StorageOutputReserveRecordsV1;
use aos_sandbox_protocol::storage_output_reserve::continuation::original_plan_digest_v1;
use aos_proto::aos::sandbox::local::v1::{BrokerMethod, StorageOutputRegistrationResponseV1};
use buffa::Message as _;
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

/// Keeps the exact authenticated preimages after the sole canonical comparison.
///
/// This private DATA is not admission or currentness. Its caller retains the
/// original configured Storage and Host owners through the atomic write.
pub(crate) struct VerifiedOriginalOutputReserveV1 {
    record: RetainedOutputRecord,
    request_id: [u8; 16],
    signed_source_digest: ObjectDigest,
    host_outcome_digest: ObjectDigest,
}

impl ExecutionOutputLedgerV1 {
    /// Uses actual authenticated preimages only after configured Storage admission.
    /// The installed caller separately holds the genuine Host currentness loan.
    pub(crate) fn prepare_authenticated_original(
        &self,
        records: &StorageOutputReserveRecordsV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        host_terminal: &AuthenticatedBrokerMethodOutcomeV1,
        now_boottime_nanoseconds: u64,
    ) -> Result<VerifiedOriginalOutputReserveV1, ExecutionOutputLedgerErrorV1> {
        verified_original(
            records,
            request,
            host_terminal,
            now_boottime_nanoseconds,
        )
    }

    /// Uses the prepared preimages only under the caller's final live cut.
    pub(crate) fn reserve_authenticated_original(
        &mut self,
        verified: &VerifiedOriginalOutputReserveV1,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
        self.reserve_original_record_profile(verified, OriginalReserveProfile::Captured)
    }

    // Unit tests exercise row, capture, and deletion rules through the same
    // atomic marker transaction without manufacturing cross-owner authority.
    #[cfg(test)]
    pub(super) fn reserve_test_record(
        &mut self,
        record: RetainedOutputRecord,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
        let verified = VerifiedOriginalOutputReserveV1 {
            request_id: record.execution,
            signed_source_digest: ObjectDigest::from_bytes(record.claim_digest),
            host_outcome_digest: ObjectDigest::from_bytes(record.assignment),
            record,
        };
        self.reserve_original_record(&verified)
    }

    /// Commits the original source marker and the matching logical row atomically.
    ///
    /// The future verifier must retain the Controller and Host owner cut while
    /// invoking this method. It cannot be reached from the current service.
    fn reserve_verified_original(
        &mut self,
        verified: &VerifiedOriginalOutputReserveV1,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
        self.journal.validate_held_protected_names()?;
        let digest = self.reserve_original_record(verified)?;
        self.journal.validate_held_protected_names()?;
        Ok(digest)
    }

    fn reserve_original_record(
        &mut self,
        verified: &VerifiedOriginalOutputReserveV1,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
        self.reserve_original_record_profile(verified, OriginalReserveProfile::Legacy)
    }

    fn reserve_original_record_profile(
        &mut self,
        verified: &VerifiedOriginalOutputReserveV1,
        profile: OriginalReserveProfile,
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
            let current_bytes = self
                .journal
                .get(NAMESPACE, &row_location)
                .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
            let current = decode_record(&row_location, current_bytes, &self.key)?;
            let result = if existing == marker
                && current.state == STATE_RETAINED
                && ObjectDigest::from_bytes(Sha256::digest(current_bytes).into())
                    == marker.record_digest
            {
                Ok(marker.record_digest)
            } else {
                Err(ExecutionOutputLedgerErrorV1::Conflict)
            };
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
        ).map_err(aos_sandbox::JournalError::from)?;
        if matches!(profile, OriginalReserveProfile::Captured) {
            self.journal.preflight_transactions(std::slice::from_ref(&transaction))?;
        }
        self.journal.commit(&transaction)?;
        self.retained_bytes = next;
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

    /// Returns exact MAC-checked historical bytes, never a fresh Host permit.
    pub(crate) fn original_registration_response(
        &self,
        request_id: [u8; 16],
        records: &StorageOutputReserveRecordsV1,
        plan_digest: ObjectDigest,
    ) -> Result<Vec<u8>, ExecutionOutputLedgerErrorV1> {
        let locator = records.host_locator();
        self.query_original_reserve(
            request_id,
            *locator.execution().as_bytes(),
            *locator.create_operation().as_bytes(),
            plan_digest,
        )?
        .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let row_location = reservation_key(*locator.execution().as_bytes());
        let row = self.journal.get(NAMESPACE, &row_location)
            .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
        let original = self.journal.get(NAMESPACE, &marker_key(request_id))
            .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
        if row.len() != super::RECORD_BYTES || original.len() != MARKER_BYTES {
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        let response = StorageOutputRegistrationResponseV1 {
            canonical_reservation: row.to_vec(),
            canonical_original_marker: original.to_vec(),
            ..Default::default()
        };
        if response.encoded_len() > 1024 {
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        Ok(response.encode_to_vec())
    }
}

enum OriginalReserveProfile {
    Legacy,
    Captured,
}

fn verified_original(
    records: &StorageOutputReserveRecordsV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    terminal: &AuthenticatedBrokerMethodOutcomeV1,
    now: u64,
) -> Result<VerifiedOriginalOutputReserveV1, ExecutionOutputLedgerErrorV1> {
    let fail = || ExecutionOutputLedgerErrorV1::NotCurrent;
    if request.method() != BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
        || terminal.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
        || terminal.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
    {
        return Err(fail());
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = terminal.result() else {
        return Err(fail());
    };
    let host_request = terminal.request();
    let decoded = decode_captured_host_storage_output_readback_request_v1(
        host_request.exact_body(), host_request.peer(), host_request.peer_policy(), now,
    ).map_err(|_| fail())?;
    let plan_digest = original_plan_digest_v1(request).map_err(|_| fail())?;
    let observed = decode_host_storage_output_readback_response_v1(exact_body, &decoded)
        .map_err(|_| fail())?;
    if decoded.original_body() != request.exact_body()
        || decoded.records() != records
        || decoded.original_storage_request_id() != request.request_id()
        || decoded.original_storage_plan_digest() != plan_digest
        || decoded.original_storage_semantic_digest().as_bytes() != &request.semantic_commitment()
        || observed.current_assignment() != records.assignment()
    {
        return Err(fail());
    }
    let source = &records.attempt()[8..696];
    let number = |bytes: &[u8]| -> Result<u64, ExecutionOutputLedgerErrorV1> {
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| fail())?))
    };
    let locator = records.host_locator();
    Ok(VerifiedOriginalOutputReserveV1 {
        record: RetainedOutputRecord {
            execution: *locator.execution().as_bytes(),
            create: *locator.create_operation().as_bytes(),
            assignment: *records.assignment().digest().as_bytes(),
            claim_digest: *locator.claim_digest().as_bytes(),
            bytes: number(&source[424..432])?,
            maximum_stdout_bytes: number(&source[80..88])?,
            maximum_stderr_bytes: number(&source[88..96])?,
            state: STATE_RETAINED,
            delete_operation: [0; 16],
        },
        request_id: request.request_id(),
        signed_source_digest: plan_digest,
        host_outcome_digest: ObjectDigest::from_bytes(
            Sha256::digest(terminal.canonical_packet()).into(),
        ),
    })
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
    use crate::execution_output::{ExecutionOutputDeletionGrantV1, GRANT_BYTES, GRANT_MAGIC};

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
    fn deleted_original_remains_queryable_but_cannot_be_reserved_again() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open_ledger(&directory);
        let mut original = verified(1, 2);
        original.record.bytes = 0;
        original.record.maximum_stdout_bytes = 0;
        original.record.maximum_stderr_bytes = 0;
        let digest = ledger.reserve_verified_original(&original).unwrap();

        let location = reservation_key(original.record.execution);
        let mut bytes = [0; GRANT_BYTES];
        bytes[..8].copy_from_slice(GRANT_MAGIC);
        bytes[8..24].copy_from_slice(&original.record.execution);
        bytes[24..40].copy_from_slice(&original.record.create);
        bytes[40..72].copy_from_slice(&original.record.claim_digest);
        bytes[72..88].copy_from_slice(&[8; 16]);
        let mac = ledger.key.mac(&location, &bytes[..88]).unwrap();
        bytes[88..].copy_from_slice(&mac);
        let deletion = ExecutionOutputDeletionGrantV1::from_bytes(&bytes).unwrap();
        ledger.settle_zero_output_deletion(&deletion).unwrap();

        assert!(matches!(
            ledger.reserve_verified_original(&original),
            Err(ExecutionOutputLedgerErrorV1::Conflict)
        ));
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

    #[test]
    fn cold_replay_rejects_aoseor03_without_original_marker() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open_ledger(&directory);
        let original = verified(1, 2);
        let location = reservation_key(original.record.execution);
        let bytes = encode_record(&original.record, &location, &ledger.key).unwrap();
        ledger
            .journal
            .commit(
                &JournalTransaction::new(
                    [14; 16],
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
