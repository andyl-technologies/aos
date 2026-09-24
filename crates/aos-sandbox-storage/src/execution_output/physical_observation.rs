//! Protected history of one exact, pinned physical capture readback.
//!
//! AOSPOV01 joins the original AOSCOA01 possible-effect fence, retained
//! AOSEOR03 claim, catalog GUID/binding, and a checkpoint-free three-probe ZFS
//! observation. It is historical evidence, not currentness, a create retry,
//! detached-mount permit, writer permit, signed response, or Host authority.
//!
//! ```text
//! AOSPOV01 | execution[16] | Create[16] | AOSEOR03-digest[32]
//!          | AOSCOA01-digest[32] | Controller-grant-digest[32]
//!          | Host-receipt-digest[32] | catalog-dataset-binding[32]
//!          | catalog-GUID:u64be | pinned-ZFS-observation-digest[32]
//!          | dataset-available:u64be | observed-headroom:u64be
//!          | Storage-dataset-policy-digest[32] | observation-boot[16]
//!          | observation-boottime:u64be | Storage-HMAC[32]
//! ```

use aos_sandbox::{JournalRecord, JournalTransaction};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::boot::KernelBootId;
use sha2::{Digest as _, Sha256};

use super::capture_attempt::{
    ProtectedCaptureCreateAttemptReceiptV1, VerifiedCaptureAttemptSourcesV1,
    verify_capture_observation_anchor,
};
use super::{
    ExecutionOutputLedgerErrorV1, ExecutionOutputLedgerKeyV1, ExecutionOutputLedgerV1, NAMESPACE,
    decode_physical, decode_record, physical_key, reservation_key, transaction_id,
};
use crate::ZfsHelperContract;
use crate::catalog_transition::VerifiedPhysicalCatalogSnapshotV1;
use crate::catalog_transition::execution_capture::readback::{
    CaptureZfsReadbackPlanV1, CaptureZfsReadbackV1,
};
use crate::catalog_transition::execution_capture::{
    CaptureDatasetRequirementV1, VerifiedCaptureDatasetV1,
};
use crate::execution_output::ProtectedRetainedCaptureV1;
use crate::pin_worker::boottime_now_nanoseconds;

const MAGIC: &[u8; 8] = b"AOSPOV01";
const RECORD_BYTES: usize = 344;
const CONTENT_BYTES: usize = RECORD_BYTES - 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhysicalObservationRecordV1 {
    execution: [u8; 16],
    create: [u8; 16],
    output_record_digest: ObjectDigest,
    durable_attempt_digest: ObjectDigest,
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    dataset_binding: ObjectDigest,
    catalog_guid: u64,
    zfs_observation_digest: ObjectDigest,
    dataset_available_bytes: u64,
    observed_headroom_bytes: u64,
    dataset_policy_digest: ObjectDigest,
    observation_boot_id: [u8; 16],
    observation_boottime_nanoseconds: u64,
}

impl PhysicalObservationRecordV1 {
    fn from_observed(
        attempt: &ProtectedCaptureCreateAttemptReceiptV1,
        verified: &VerifiedCaptureDatasetV1,
        observed: &CaptureZfsReadbackV1,
        boot_id: [u8; 16],
        now: u64,
    ) -> Self {
        Self {
            execution: attempt.execution,
            create: attempt.create,
            output_record_digest: attempt.record_digest,
            durable_attempt_digest: attempt.durable_attempt_digest,
            controller_grant_digest: attempt.controller_grant_digest,
            host_receipt_digest: attempt.host_receipt_digest,
            dataset_binding: verified.binding(),
            catalog_guid: verified.guid(),
            zfs_observation_digest: observed.observation_digest,
            dataset_available_bytes: observed.dataset_available_bytes,
            observed_headroom_bytes: observed.observed_headroom_bytes,
            dataset_policy_digest: attempt.dataset_policy_digest,
            observation_boot_id: boot_id,
            observation_boottime_nanoseconds: now,
        }
    }

    fn valid(&self) -> bool {
        self.execution != [0; 16]
            && self.create != [0; 16]
            && self.output_record_digest.as_bytes() != &[0; 32]
            && self.durable_attempt_digest.as_bytes() != &[0; 32]
            && self.controller_grant_digest.as_bytes() != &[0; 32]
            && self.host_receipt_digest.as_bytes() != &[0; 32]
            && self.dataset_binding.as_bytes() != &[0; 32]
            && self.catalog_guid != 0
            && self.zfs_observation_digest.as_bytes() != &[0; 32]
            && self.dataset_available_bytes != 0
            && self.observed_headroom_bytes != 0
            && self.dataset_policy_digest.as_bytes() != &[0; 32]
            && self.observation_boot_id != [0; 16]
            && self.observation_boottime_nanoseconds != 0
    }
}

/// Retains a MAC-protected historical observation, never a live effect permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProtectedCapturePhysicalObservationV1 {
    pub(super) execution: [u8; 16],
    pub(super) output_record_digest: ObjectDigest,
    pub(super) durable_attempt_digest: ObjectDigest,
    pub(super) dataset_binding: ObjectDigest,
    pub(super) catalog_guid: u64,
    pub(super) zfs_observation_digest: ObjectDigest,
    pub(super) dataset_available_bytes: u64,
    pub(super) observed_headroom_bytes: u64,
    pub(super) observation_boot_id: [u8; 16],
    pub(super) observation_boottime_nanoseconds: u64,
    pub(super) durable_observation_digest: ObjectDigest,
}

impl ExecutionOutputLedgerV1 {
    /// Runs fixed pinned ZFS probes and records their exact first observation.
    ///
    /// This method is not called by a production broker handler. It accepts
    /// only the private verified Controller/Host attempt source, then cold-
    /// reads protected Storage rows before invoking read-only ZFS commands.
    /// A later changed observation requires a separate renewal design; this
    /// first row is immutable and never asserts continuing currentness.
    pub(super) fn observe_capture_physical_readback(
        &mut self,
        sources: &VerifiedCaptureAttemptSourcesV1,
        requirement: &CaptureDatasetRequirementV1,
        catalog: &VerifiedPhysicalCatalogSnapshotV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
        zfs: &ZfsHelperContract,
    ) -> Result<ProtectedCapturePhysicalObservationV1, ExecutionOutputLedgerErrorV1> {
        let (attempt, retained, verified) = self.prepare_observation(
            sources,
            requirement,
            catalog,
            metadata_headroom_bytes,
            minimum_remaining_bytes,
        )?;
        let plan = CaptureZfsReadbackPlanV1::new(
            &verified,
            &retained,
            metadata_headroom_bytes,
            minimum_remaining_bytes,
        )
        .map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let observed = crate::process::observe_capture_zfs_for(zfs, &plan)
            .map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;

        self.commit_observation(&attempt, &verified, &observed)
    }

    #[cfg(test)]
    pub(super) fn record_capture_observation_for_test(
        &mut self,
        sources: &VerifiedCaptureAttemptSourcesV1,
        requirement: &CaptureDatasetRequirementV1,
        catalog: &VerifiedPhysicalCatalogSnapshotV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
        observed: &CaptureZfsReadbackV1,
    ) -> Result<ProtectedCapturePhysicalObservationV1, ExecutionOutputLedgerErrorV1> {
        let (attempt, _, verified) = self.prepare_observation(
            sources,
            requirement,
            catalog,
            metadata_headroom_bytes,
            minimum_remaining_bytes,
        )?;
        self.commit_observation(&attempt, &verified, observed)
    }

    fn prepare_observation(
        &self,
        sources: &VerifiedCaptureAttemptSourcesV1,
        requirement: &CaptureDatasetRequirementV1,
        catalog: &VerifiedPhysicalCatalogSnapshotV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> Result<
        (
            ProtectedCaptureCreateAttemptReceiptV1,
            ProtectedRetainedCaptureV1,
            VerifiedCaptureDatasetV1,
        ),
        ExecutionOutputLedgerErrorV1,
    > {
        let attempt = self
            .query_capture_create_attempt(sources)?
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        if attempt.dataset_policy_digest
            != requirement.attempt_policy_digest(metadata_headroom_bytes, minimum_remaining_bytes)
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        let retained = self.read_protected_retained_capture(
            attempt.execution,
            attempt.create,
            attempt.record_digest,
        )?;
        let verified = requirement
            .verify_present(catalog)
            .map_err(|_| ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)?;
        if !verified.matches_logical(
            attempt.execution,
            attempt.create,
            *retained.claim_digest.as_bytes(),
            retained.admitted_bytes(),
        ) {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }

        let location = physical_key(attempt.execution);
        let bytes = self
            .journal
            .get(NAMESPACE, &location)
            .ok_or(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)?;
        let bound = decode_physical(&location, bytes, &self.key)?;
        if bound.binding != verified.binding()
            || bound.guid != verified.guid()
            || bound.creation_generation != verified.catalog_generation()
            || bound.dataset_name != verified.dataset_name()
            || bound.claim_digest != *retained.claim_digest.as_bytes()
            || bound.bytes != retained.admitted_bytes()
        {
            return Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking);
        }
        Ok((attempt, retained, verified))
    }

    fn commit_observation(
        &mut self,
        attempt: &ProtectedCaptureCreateAttemptReceiptV1,
        verified: &VerifiedCaptureDatasetV1,
        observed: &CaptureZfsReadbackV1,
    ) -> Result<ProtectedCapturePhysicalObservationV1, ExecutionOutputLedgerErrorV1> {
        let location = observation_key(attempt.execution);
        if self.journal.get(NAMESPACE, &location).is_some() {
            return Err(ExecutionOutputLedgerErrorV1::Conflict);
        }
        if observed.record_digest != attempt.record_digest
            || observed.catalog_binding != verified.binding()
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        let boot_id = KernelBootId::current()
            .map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?
            .into_bytes();
        let now =
            boottime_now_nanoseconds().map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let record =
            PhysicalObservationRecordV1::from_observed(attempt, verified, observed, boot_id, now);
        if !record.valid() {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        let bytes = encode_observation(&location, record, &self.key)?;
        self.journal.commit(&JournalTransaction::new(
            transaction_id(b"capture-physical-observation", &location, &bytes),
            vec![JournalRecord::put(
                NAMESPACE,
                location.to_vec(),
                bytes.to_vec(),
            )],
        )?)?;
        let committed = self
            .journal
            .get(NAMESPACE, &location)
            .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
        let decoded = decode_observation(&location, committed, &self.key)?;
        if decoded != record {
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        Ok(receipt(record, committed))
    }

    /// Cold-queries the exact historical observation without a new ZFS probe.
    pub(super) fn query_capture_physical_observation(
        &self,
        sources: &VerifiedCaptureAttemptSourcesV1,
    ) -> Result<Option<ProtectedCapturePhysicalObservationV1>, ExecutionOutputLedgerErrorV1> {
        let attempt = self
            .query_capture_create_attempt(sources)?
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let location = observation_key(attempt.execution);
        let Some(bytes) = self.journal.get(NAMESPACE, &location) else {
            return Ok(None);
        };
        let record = decode_observation(&location, bytes, &self.key)?;
        if record.create != attempt.create
            || record.output_record_digest != attempt.record_digest
            || record.durable_attempt_digest != attempt.durable_attempt_digest
            || record.controller_grant_digest != attempt.controller_grant_digest
            || record.host_receipt_digest != attempt.host_receipt_digest
            || record.dataset_policy_digest != attempt.dataset_policy_digest
        {
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        Ok(Some(receipt(record, bytes)))
    }
}

pub(super) fn verify_replayed_capture_observation(
    journal: &aos_sandbox::Journal,
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<(), ExecutionOutputLedgerErrorV1> {
    let record = decode_observation(location, bytes, key)?;
    verify_capture_observation_anchor(
        journal,
        record.execution,
        record.create,
        record.output_record_digest,
        record.durable_attempt_digest,
        record.controller_grant_digest,
        record.host_receipt_digest,
        record.dataset_policy_digest,
        key,
    )?;

    let logical_location = reservation_key(record.execution);
    let logical_bytes = journal
        .get(NAMESPACE, &logical_location)
        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
    let logical = decode_record(&logical_location, logical_bytes, key)?;
    let physical_location = physical_key(record.execution);
    let physical_bytes = journal
        .get(NAMESPACE, &physical_location)
        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
    let physical = decode_physical(&physical_location, physical_bytes, key)?;
    if logical.create != record.create
        || physical.binding != record.dataset_binding
        || physical.guid != record.catalog_guid
        || physical.claim_digest != logical.claim_digest
        || physical.bytes != logical.bytes
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(())
}

fn observation_key(execution: [u8; 16]) -> [u8; 17] {
    let mut location = [0; 17];
    location[0] = b'o';
    location[1..].copy_from_slice(&execution);
    location
}

fn encode_observation(
    location: &[u8],
    record: PhysicalObservationRecordV1,
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<[u8; RECORD_BYTES], ExecutionOutputLedgerErrorV1> {
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&record.execution);
    bytes[24..40].copy_from_slice(&record.create);
    bytes[40..72].copy_from_slice(record.output_record_digest.as_bytes());
    bytes[72..104].copy_from_slice(record.durable_attempt_digest.as_bytes());
    bytes[104..136].copy_from_slice(record.controller_grant_digest.as_bytes());
    bytes[136..168].copy_from_slice(record.host_receipt_digest.as_bytes());
    bytes[168..200].copy_from_slice(record.dataset_binding.as_bytes());
    bytes[200..208].copy_from_slice(&record.catalog_guid.to_be_bytes());
    bytes[208..240].copy_from_slice(record.zfs_observation_digest.as_bytes());
    bytes[240..248].copy_from_slice(&record.dataset_available_bytes.to_be_bytes());
    bytes[248..256].copy_from_slice(&record.observed_headroom_bytes.to_be_bytes());
    bytes[256..288].copy_from_slice(record.dataset_policy_digest.as_bytes());
    bytes[288..304].copy_from_slice(&record.observation_boot_id);
    bytes[304..312].copy_from_slice(&record.observation_boottime_nanoseconds.to_be_bytes());
    let mac = key.mac(location, &bytes[..CONTENT_BYTES])?;
    bytes[CONTENT_BYTES..].copy_from_slice(&mac);
    Ok(bytes)
}

fn decode_observation(
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<PhysicalObservationRecordV1, ExecutionOutputLedgerErrorV1> {
    if location.len() != 17
        || location[0] != b'o'
        || bytes.len() != RECORD_BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || !key.verify_mac(location, &bytes[..CONTENT_BYTES], &bytes[CONTENT_BYTES..])?
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    let field_16 = |start: usize| -> [u8; 16] {
        let mut field = [0; 16];
        field.copy_from_slice(&bytes[start..start + 16]);
        field
    };
    let digest = |start: usize| -> ObjectDigest {
        let mut field = [0; 32];
        field.copy_from_slice(&bytes[start..start + 32]);
        ObjectDigest::from_bytes(field)
    };
    let number = |start: usize| -> u64 {
        let mut field = [0; 8];
        field.copy_from_slice(&bytes[start..start + 8]);
        u64::from_be_bytes(field)
    };
    let record = PhysicalObservationRecordV1 {
        execution: field_16(8),
        create: field_16(24),
        output_record_digest: digest(40),
        durable_attempt_digest: digest(72),
        controller_grant_digest: digest(104),
        host_receipt_digest: digest(136),
        dataset_binding: digest(168),
        catalog_guid: number(200),
        zfs_observation_digest: digest(208),
        dataset_available_bytes: number(240),
        observed_headroom_bytes: number(248),
        dataset_policy_digest: digest(256),
        observation_boot_id: field_16(288),
        observation_boottime_nanoseconds: number(304),
    };
    if record.execution.as_slice() != &location[1..] || !record.valid() {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(record)
}

fn receipt(
    record: PhysicalObservationRecordV1,
    bytes: &[u8],
) -> ProtectedCapturePhysicalObservationV1 {
    ProtectedCapturePhysicalObservationV1 {
        execution: record.execution,
        output_record_digest: record.output_record_digest,
        durable_attempt_digest: record.durable_attempt_digest,
        dataset_binding: record.dataset_binding,
        catalog_guid: record.catalog_guid,
        zfs_observation_digest: record.zfs_observation_digest,
        dataset_available_bytes: record.dataset_available_bytes,
        observed_headroom_bytes: record.observed_headroom_bytes,
        observation_boot_id: record.observation_boot_id,
        observation_boottime_nanoseconds: record.observation_boottime_nanoseconds,
        durable_observation_digest: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
    }
}
