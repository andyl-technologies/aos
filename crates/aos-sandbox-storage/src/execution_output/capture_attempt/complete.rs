//! Stores full historical Capture completion on the existing output ledger.
//!
//! This is a private DATA persistence engine. Its caller must retain the real
//! native worker, EOF/sync/readback, fresh ZFS/catalog, Host terminal and same-F
//! posts. Parsing or committing these bytes never constructs that native owner.
//! Replay uses the same original attempt, logical and physical-row comparison.
//!
//! ```text
//! key = 'c' | execution[16]
//! value = AOSCCD02 | canonical-AOSCRS02[676] | Storage-HMAC[32]
//! ```

use aos_sandbox::{Journal, JournalError, JournalRecord, JournalTransaction};
use aos_sandbox_core::{ObjectDigest, ResourceDimension, ResourceVector};
use aos_sandbox_protocol::storage_capture_result::{
    CaptureCompleteRecordDataV2, CAPTURE_COMPLETE_RECORD_BYTES_V2,
};
use sha2::{Digest as _, Sha256};

use super::{capture_attempt_key, decode_attempt};
use super::super::{
    decode_physical, decode_record, physical_key, reservation_key, transaction_id,
    ExecutionOutputLedgerErrorV1, ExecutionOutputLedgerKeyV1, ExecutionOutputLedgerV1,
    NAMESPACE, STATE_RETAINED,
};

const MAGIC: &[u8; 8] = b"AOSCCD02";
const CONTENT_BYTES: usize = 8 + CAPTURE_COMPLETE_RECORD_BYTES_V2;
const RECORD_BYTES: usize = CONTENT_BYTES + 32;

/// Retains every reached encoder, transaction and native append result.
///
/// Construction accepts DATA only. It cannot issue a physical permit, settle a
/// resident worker, authenticate EOF or construct a native terminal original.
#[derive(Default)]
pub(crate) struct CaptureCompletePersistenceOriginalV2 {
    encoded: Option<Result<[u8; RECORD_BYTES], ExecutionOutputLedgerErrorV1>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    commit: Option<Result<(), JournalError>>,
    returned: Option<Result<(), ExecutionOutputLedgerErrorV1>>,
}

impl CaptureCompletePersistenceOriginalV2 {
    /// Prices the actual compiled carrier and same held writer before encoding.
    pub(crate) fn receiving_demand_data_v2(
        ledger: &ExecutionOutputLedgerV1,
    ) -> Result<ResourceVector, aos_sandbox::journal::JournalAppendReceivingDemandErrorV1> {
        let append = ledger.journal.append_receiving_demand_v1(std::iter::once(
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: 17,
                value_bytes: Some(RECORD_BYTES),
            },
        ))?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CaptureCompleteRecordDataV2>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(append.checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))?)
    }

    /// Borrows an original error without cloning its native append cause.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.encoded.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.transaction.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.commit.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    pub(crate) fn completed_data_v2(&self) -> Option<CaptureCompleteRecordDataV2> {
        if !matches!(self.returned, Some(Ok(()))) { return None; }
        let encoded = self.encoded.as_ref()?.as_ref().ok()?;
        CaptureCompleteRecordDataV2::decode(&encoded[8..CONTENT_BYTES]).ok()
    }
}

#[derive(Clone, Copy)]
enum AnchorCheckV2 { NewCommit, Historical }

impl ExecutionOutputLedgerV1 {
    /// Persists historical DATA; the private native terminal caller owns authority.
    ///
    /// The same-F caller must prepay `receiving_demand_data_v2` and retain this
    /// original through its independent native posts. Reentry never overwrites
    /// an earlier result. An identical existing row is comparison-only success.
    pub(crate) fn commit_complete_record_data_v2(
        &mut self,
        original: &mut CaptureCompletePersistenceOriginalV2,
        record: &CaptureCompleteRecordDataV2,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        if original.returned.is_some() || original.encoded.is_some() || original.commit.is_some() {
            return Err(ExecutionOutputLedgerErrorV1::Conflict);
        }
        original.returned = Some((|| {
            self.journal.ensure_healthy()?;
            verify_anchors(&self.journal, record, &self.key, AnchorCheckV2::NewCommit)?;
            let location = complete_key(record.execution);
            original.encoded = Some(encode(&location, record, &self.key));
            let bytes = original.encoded.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
            if let Some(existing) = self.journal.get(NAMESPACE, &location) {
                if existing != bytes { return Err(ExecutionOutputLedgerErrorV1::Conflict); }
            } else {
                original.transaction = Some(JournalTransaction::new(
                    transaction_id(b"capture-complete-data-v2", &location, bytes),
                    vec![JournalRecord::put(NAMESPACE, location.to_vec(), bytes.to_vec())],
                ).map_err(JournalError::from));
                let transaction = original.transaction.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
                original.commit = Some(self.journal.commit(transaction).map(|_| ()));
                if !matches!(original.commit, Some(Ok(()))) {
                    return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
                }
            }
            self.journal.ensure_healthy()?;
            let actual = self.journal.get(NAMESPACE, &location)
                .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
            if actual != bytes || decode(&location, actual, &self.key)? != *record {
                return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
            }
            verify_anchors(&self.journal, record, &self.key, AnchorCheckV2::NewCommit)
        })());
        if matches!(original.returned, Some(Ok(()))) { Ok(()) }
        else { Err(ExecutionOutputLedgerErrorV1::NotCurrent) }
    }

    /// Reads complete DATA bound to the full signed Source944 and AOSCOA03.
    ///
    /// This preserves the attempt's distinct immutable acquisition and execution
    /// horizons. It cannot re-enter issuance or construct native completion.
    pub(crate) fn query_capture_complete_ongoing_data_v3(
        &self,
        source: &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
    ) -> Result<Option<CaptureCompleteRecordDataV2>, ExecutionOutputLedgerErrorV1> {
        self.journal.ensure_healthy()?;
        let original = source.original_source_v1();
        let execution = *original.settlement().execution().as_bytes();
        let location = complete_key(execution);
        let Some(bytes) = self.journal.get(NAMESPACE, &location) else { return Ok(None); };
        let record = decode(&location, bytes, &self.key)?;
        verify_anchors(&self.journal, &record, &self.key, AnchorCheckV2::Historical)?;
        // Reuse the sole attempt/source comparison. The versioned branch binds
        // both full-source digest and persisted acquisition/ongoing horizons.
        let attempt = self.query_capture_ongoing_source_v3(source)?
            .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
        record.verify_original_ongoing_v2(source, attempt.attempt, attempt.durable_attempt_digest)
            .map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;
        Ok(Some(record))
    }
}

pub(in crate::execution_output) fn verify_replayed_complete_v2(
    journal: &Journal,
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<(), ExecutionOutputLedgerErrorV1> {
    let record = decode(location, bytes, key)?;
    verify_anchors(journal, &record, key, AnchorCheckV2::Historical)
}

fn verify_anchors(
    journal: &Journal,
    complete: &CaptureCompleteRecordDataV2,
    key: &ExecutionOutputLedgerKeyV1,
    check: AnchorCheckV2,
) -> Result<(), ExecutionOutputLedgerErrorV1> {
    let invalid = || ExecutionOutputLedgerErrorV1::Corrupt;
    let location = capture_attempt_key(complete.execution);
    let bytes = journal.get(NAMESPACE, &location).ok_or_else(invalid)?;
    let attempt = decode_attempt(&location, bytes, key)?;
    if attempt.source.is_none_or(|source| source.digest != complete.source_digest)
        || attempt.attempt != complete.attempt || attempt.execution != complete.execution
        || attempt.create != complete.create_operation || attempt.record_digest != complete.output_record_digest
        || attempt.host_claim_digest != complete.claim_digest || attempt.assignment_digest != complete.assignment_digest
        || ObjectDigest::from_bytes(Sha256::digest(bytes).into()) != complete.durable_attempt_digest
    { return Err(invalid()); }
    let location = reservation_key(complete.execution);
    let bytes = journal.get(NAMESPACE, &location).ok_or_else(invalid)?;
    let logical = decode_record(&location, bytes, key)?;
    if logical.create != complete.create_operation || logical.claim_digest != *complete.claim_digest.as_bytes()
        || logical.assignment != *complete.assignment_digest.as_bytes()
        || logical.maximum_stdout_bytes != complete.stdout.maximum_bytes
        || logical.maximum_stderr_bytes != complete.stderr.maximum_bytes
        || (matches!(check, AnchorCheckV2::NewCommit) && logical.state != STATE_RETAINED)
        || (logical.state == STATE_RETAINED
            && ObjectDigest::from_bytes(Sha256::digest(bytes).into()) != complete.output_record_digest)
    { return Err(invalid()); }
    let location = physical_key(complete.execution);
    let bytes = journal.get(NAMESPACE, &location).ok_or_else(invalid)?;
    let physical = decode_physical(&location, bytes, key)?;
    if physical.binding != complete.dataset_binding || physical.claim_digest != logical.claim_digest
        || physical.bytes != logical.bytes || physical.creation_generation > complete.catalog_generation
        || ObjectDigest::from_bytes(Sha256::digest(bytes).into()) != complete.physical_row_digest
    { return Err(invalid()); }
    Ok(())
}

fn complete_key(execution: [u8; 16]) -> [u8; 17] {
    let mut location = [0; 17];
    location[0] = b'c';
    location[1..].copy_from_slice(&execution);
    location
}

fn encode(location: &[u8], record: &CaptureCompleteRecordDataV2,
    key: &ExecutionOutputLedgerKeyV1) -> Result<[u8; RECORD_BYTES], ExecutionOutputLedgerErrorV1>
{
    if location != complete_key(record.execution) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..CONTENT_BYTES].copy_from_slice(&record.encode()
        .map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?);
    let mac = key.mac(location, &bytes[..CONTENT_BYTES])?;
    bytes[CONTENT_BYTES..].copy_from_slice(&mac);
    Ok(bytes)
}

fn decode(location: &[u8], bytes: &[u8], key: &ExecutionOutputLedgerKeyV1)
    -> Result<CaptureCompleteRecordDataV2, ExecutionOutputLedgerErrorV1>
{
    if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC) || location.len() != 17
        || location[0] != b'c'
        || !key.verify_mac(location, &bytes[..CONTENT_BYTES], &bytes[CONTENT_BYTES..])?
    { return Err(ExecutionOutputLedgerErrorV1::Corrupt); }
    let record = CaptureCompleteRecordDataV2::decode(&bytes[8..CONTENT_BYTES])
        .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?;
    if location != complete_key(record.execution) { return Err(ExecutionOutputLedgerErrorV1::Corrupt); }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox::JournalLimits;
    use aos_sandbox_protocol::storage_capture_result::CaptureCompleteStreamDataV2;

    fn fixture() -> CaptureCompleteRecordDataV2 {
        let digest = |byte| ObjectDigest::from_bytes([byte; 32]);
        let stream = CaptureCompleteStreamDataV2 {
            maximum_bytes: 0,
            captured_bytes: 0,
            truncated: false,
            content_digest: ObjectDigest::from_bytes(Sha256::digest([]).into()),
        };
        CaptureCompleteRecordDataV2 {
            source_digest: digest(1), attempt: [2; 16], durable_attempt_digest: digest(3),
            execution: [4; 16], create_operation: [5; 16], output_record_digest: digest(6),
            claim_digest: digest(7), assignment_digest: digest(8), dataset_binding: digest(9),
            mount_id: 10, catalog_generation: 11, catalog_digest: digest(12),
            physical_row_digest: digest(13), before_observation_digest: digest(14),
            mounted_observation_digest: digest(15), after_observation_digest: digest(16),
            worker_request_digest: digest(17), worker_result_digest: digest(18),
            host_settlement_digest: digest(19), stdout: stream, stderr: stream,
        }
    }

    #[test]
    fn complete_mac_covers_both_streams_and_exact_execution_location() {
        let key = ExecutionOutputLedgerKeyV1::new([1; 16], [2; 32]).unwrap();
        let record = fixture();
        let location = complete_key(record.execution);
        let encoded = encode(&location, &record, &key).unwrap();
        assert_eq!(decode(&location, &encoded, &key).unwrap(), record);

        let mut changed = encoded;
        changed[8 + 604] ^= 1;
        assert!(decode(&location, &changed, &key).is_err());
        assert!(decode(&complete_key([20; 16]), &encoded, &key).is_err());
    }

    #[test]
    fn a_mac_and_complete_shape_without_original_native_rows_fail_replay() {
        let directory = tempfile::TempDir::new().unwrap();
        let (journal, _) = Journal::open(directory.path().join("output.journal"), JournalLimits::default()).unwrap();
        let key = ExecutionOutputLedgerKeyV1::new([1; 16], [2; 32]).unwrap();
        let record = fixture();
        let location = complete_key(record.execution);
        let encoded = encode(&location, &record, &key).unwrap();

        assert!(matches!(verify_replayed_complete_v2(&journal, &location, &encoded, &key),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)));
    }

    #[test]
    fn retained_refusal_cannot_be_replaced_by_another_complete_record() {
        let directory = tempfile::TempDir::new().unwrap();
        let (journal, _) = Journal::open(directory.path().join("output.journal"), JournalLimits::default()).unwrap();
        let key = ExecutionOutputLedgerKeyV1::new([1; 16], [2; 32]).unwrap();
        let mut ledger = ExecutionOutputLedgerV1::from_journal(journal, 200, key).unwrap();
        let mut original = CaptureCompletePersistenceOriginalV2::default();

        assert!(ledger.commit_complete_record_data_v2(&mut original, &fixture()).is_err());
        let first = original.failure().unwrap() as *const dyn std::error::Error;
        assert!(matches!(ledger.commit_complete_record_data_v2(&mut original, &fixture()),
            Err(ExecutionOutputLedgerErrorV1::Conflict)));
        assert!(std::ptr::eq(first, original.failure().unwrap()));
        assert!(original.completed_data_v2().is_none());
    }
}
