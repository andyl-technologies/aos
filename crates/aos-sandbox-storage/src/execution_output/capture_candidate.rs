//! Read-only, nonauthorizing physical candidate for detached capture.
//!
//! This joins Storage's protected AOSEOR03 row to a distinct physical-catalog
//! head and a pinned, checkpoint-free ZFS preflight. The candidate is useful
//! only when a future method-41 handler authenticates its Controller peer and
//! signs the exact response under the Storage broker session. Reserve must
//! recheck both durable owners and ZFS, including pool GUID against a pinned
//! owner identity that this read-only source does not yet possess. This
//! observation grants no effect.

use aos_sandbox_core::{BrokerAssignment, ObjectDigest};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::storage_capture_grant::ControllerOutputSettlementPreimageV1;
use sha2::{Digest as _, Sha256};

use super::{ExecutionOutputLedgerErrorV1, ExecutionOutputLedgerV1};
use crate::ZfsHelperContract;
use crate::catalog_transition::VerifiedPhysicalCatalogSnapshotV1;
use crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1;
use crate::catalog_transition::execution_capture::readback::{
    CaptureZfsPreflightPlanV1, CaptureZfsPreflightV1, CaptureZfsReadbackErrorV1,
};
use crate::pin_worker::boottime_now_nanoseconds;
use crate::process::{ZfsWorkerError, observe_capture_zfs_preflight_for};

const CANDIDATE_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-candidate.v1\0";
const MAXIMUM_CANDIDATE_LIFETIME_NANOSECONDS: u64 = 5_000_000_000;

/// Rejects a stale owner, occupied dataset, changed claim, or failed probe.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureCandidateErrorV1 {
    #[error("capture candidate source is not current")]
    NotCurrent,
    #[error("capture candidate dataset is occupied or absent from its managed root")]
    Catalog,
    #[error(transparent)]
    Ledger(#[from] ExecutionOutputLedgerErrorV1),
    #[error(transparent)]
    Readback(#[from] CaptureZfsReadbackErrorV1),
    #[error(transparent)]
    Worker(#[from] ZfsWorkerError),
}

/// Holds method-41 session identities after a future pinned BSA verifier.
///
/// No production constructor exists. In particular, checksum-valid AOSCIS01
/// bytes and caller-supplied request IDs cannot construct this source.
pub(super) struct VerifiedCaptureCandidateQueryV1 {
    settlement: ControllerOutputSettlementPreimageV1,
    assignment: BrokerAssignment,
    output_claim_digest: ObjectDigest,
    request_id: [u8; 16],
    nonce: [u8; 16],
    host_boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
}

/// Holds one exact informational cut of both Storage owners and live ZFS.
///
/// The fields are intentionally private until a method-41 canonical response
/// is frozen and its issuer verifies the signed Controller session.
pub(super) struct ProtectedCaptureCandidateV1 {
    settlement: ControllerOutputSettlementPreimageV1,
    assignment: BrokerAssignment,
    output_claim_digest: ObjectDigest,
    output_record_digest: ObjectDigest,
    output_journal_sequence: u64,
    catalog_generation: u64,
    catalog_head_digest: ObjectDigest,
    request_id: [u8; 16],
    nonce: [u8; 16],
    kernel_boot_id: [u8; 16],
    expires_boottime_nanoseconds: u64,
    dataset_policy_digest: ObjectDigest,
    storage_create_operation: [u8; 16],
    admitted_bytes: u64,
    maximum_stdout_bytes: u64,
    maximum_stderr_bytes: u64,
    allocation_bytes: u64,
    metadata_headroom_bytes: u64,
    minimum_remaining_bytes: u64,
    pool_guid: u64,
    root_guid: u64,
    pool_available_bytes: u64,
    root_available_bytes: u64,
    preflight_digest: ObjectDigest,
    candidate_digest: ObjectDigest,
}

impl ExecutionOutputLedgerV1 {
    /// Observes one candidate without writing either Storage owner or ZFS.
    ///
    /// The catalog snapshot must be a fresh protected readback. This method
    /// does not establish a cross-owner atomic cut: reserve must repeat the
    /// AOSEOR03, catalog, and live-ZFS checks before any create attempt.
    pub(super) fn observe_capture_candidate(
        &self,
        query: &VerifiedCaptureCandidateQueryV1,
        requirement: &CaptureDatasetRequirementV1,
        catalog: &VerifiedPhysicalCatalogSnapshotV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
        zfs: &ZfsHelperContract,
    ) -> Result<ProtectedCaptureCandidateV1, CaptureCandidateErrorV1> {
        self.observe_capture_candidate_with(
            query,
            requirement,
            catalog,
            metadata_headroom_bytes,
            minimum_remaining_bytes,
            |plan| observe_capture_zfs_preflight_for(zfs, plan).map_err(Into::into),
        )
    }

    fn observe_capture_candidate_with(
        &self,
        query: &VerifiedCaptureCandidateQueryV1,
        requirement: &CaptureDatasetRequirementV1,
        catalog: &VerifiedPhysicalCatalogSnapshotV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
        observe: impl FnOnce(
            &CaptureZfsPreflightPlanV1,
        ) -> Result<CaptureZfsPreflightV1, CaptureCandidateErrorV1>,
    ) -> Result<ProtectedCaptureCandidateV1, CaptureCandidateErrorV1> {
        let boot = KernelBootId::current()
            .map_err(|_| CaptureCandidateErrorV1::NotCurrent)?
            .into_bytes();
        let now = boottime_now_nanoseconds()?;
        if query.request_id == [0; 16]
            || query.nonce == [0; 16]
            || query.host_boot_id != boot
            || query.deadline_boottime_nanoseconds <= now
            || requirement.execution() != query.settlement.execution()
            || requirement.create_operation() != query.settlement.create_operation()
            || requirement.claim_digest() != query.output_claim_digest
        {
            return Err(CaptureCandidateErrorV1::NotCurrent);
        }

        let (retained, output_journal_sequence) = self.read_current_capture_for_candidate(
            *requirement.execution().as_bytes(),
            *requirement.create_operation().as_bytes(),
            query.output_claim_digest,
            query.assignment.digest(),
        )?;
        if !catalog.roots().contains(requirement.root())
            || catalog
                .occupied_names()
                .iter()
                .any(|name| name == requirement.dataset_name())
        {
            return Err(CaptureCandidateErrorV1::Catalog);
        }

        let plan = CaptureZfsPreflightPlanV1::new(
            requirement,
            &retained,
            metadata_headroom_bytes,
            minimum_remaining_bytes,
        )?;
        let preflight = observe(&plan)?;
        if preflight.record_digest != retained.record_digest()
            || preflight.storage_create_operation != requirement.storage_create_operation()
            || preflight.dataset_name != requirement.dataset_name()
            || preflight.allocation_bytes != requirement.allocation_bytes()
            || preflight.root_guid != requirement.root().guid()
            || self.journal.snapshot_sequence() != output_journal_sequence
        {
            return Err(CaptureCandidateErrorV1::NotCurrent);
        }

        let expires_boottime_nanoseconds = now
            .checked_add(MAXIMUM_CANDIDATE_LIFETIME_NANOSECONDS)
            .ok_or(CaptureCandidateErrorV1::NotCurrent)?
            .min(query.deadline_boottime_nanoseconds);
        if boottime_now_nanoseconds()? >= expires_boottime_nanoseconds {
            return Err(CaptureCandidateErrorV1::NotCurrent);
        }
        let mut candidate = ProtectedCaptureCandidateV1 {
            settlement: query.settlement,
            assignment: query.assignment,
            output_claim_digest: query.output_claim_digest,
            output_record_digest: retained.record_digest(),
            output_journal_sequence,
            catalog_generation: catalog.binding().generation(),
            catalog_head_digest: catalog.binding().digest(),
            request_id: query.request_id,
            nonce: query.nonce,
            kernel_boot_id: boot,
            expires_boottime_nanoseconds,
            dataset_policy_digest: requirement
                .attempt_policy_digest(metadata_headroom_bytes, minimum_remaining_bytes),
            storage_create_operation: *requirement.storage_create_operation().as_bytes(),
            admitted_bytes: retained.admitted_bytes(),
            maximum_stdout_bytes: retained.maximum_stdout_bytes(),
            maximum_stderr_bytes: retained.maximum_stderr_bytes(),
            allocation_bytes: requirement.allocation_bytes(),
            metadata_headroom_bytes,
            minimum_remaining_bytes,
            pool_guid: preflight.pool_guid,
            root_guid: preflight.root_guid,
            pool_available_bytes: preflight.pool_available_bytes,
            root_available_bytes: preflight.root_available_bytes,
            preflight_digest: preflight.observation_digest,
            candidate_digest: ObjectDigest::from_bytes([0; 32]),
        };
        candidate.candidate_digest = candidate.digest();
        Ok(candidate)
    }
}

impl ProtectedCaptureCandidateV1 {
    fn digest(&self) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(CANDIDATE_DOMAIN);
        digest.update(self.settlement.canonical_bytes());
        digest.update(self.assignment.sandbox().as_bytes());
        digest.update(self.assignment.incarnation().as_bytes());
        digest.update(self.assignment.epoch().get().to_be_bytes());
        digest.update(self.assignment.desired_generation().get().to_be_bytes());
        digest.update(self.assignment.digest().as_bytes());
        digest.update(self.output_claim_digest.as_bytes());
        digest.update(self.output_record_digest.as_bytes());
        digest.update(self.output_journal_sequence.to_be_bytes());
        digest.update(self.catalog_generation.to_be_bytes());
        digest.update(self.catalog_head_digest.as_bytes());
        digest.update(self.request_id);
        digest.update(self.nonce);
        digest.update(self.kernel_boot_id);
        digest.update(self.expires_boottime_nanoseconds.to_be_bytes());
        digest.update(self.dataset_policy_digest.as_bytes());
        digest.update(self.storage_create_operation);
        for value in [
            self.admitted_bytes,
            self.maximum_stdout_bytes,
            self.maximum_stderr_bytes,
            self.allocation_bytes,
            self.metadata_headroom_bytes,
            self.minimum_remaining_bytes,
            self.pool_guid,
            self.root_guid,
            self.pool_available_bytes,
            self.root_available_bytes,
        ] {
            digest.update(value.to_be_bytes());
        }
        digest.update(self.preflight_digest.as_bytes());
        ObjectDigest::from_bytes(digest.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox::{Journal, JournalLimits};
    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};
    use tempfile::TempDir;

    use super::*;
    use crate::catalog_transition::execution_capture::tests::{
        occupied_precreate_fixture, precreate_fixture,
    };
    use crate::execution_output::{
        ExecutionOutputLedgerKeyV1, RetainedOutputRecord, STATE_RETAINED,
    };

    fn settlement() -> ControllerOutputSettlementPreimageV1 {
        let mut bytes = [0; 208];
        bytes[..8].copy_from_slice(b"AOSCIS01");
        bytes[8..24].copy_from_slice(&[1; 16]);
        bytes[24..40].copy_from_slice(&[2; 16]);
        bytes[40..72].copy_from_slice(&[5; 32]);
        bytes[72..104].copy_from_slice(&[6; 32]);
        bytes[104..112].copy_from_slice(&1_u64.to_be_bytes());
        bytes[112..144].copy_from_slice(&[7; 32]);
        bytes[144..176].copy_from_slice(&[8; 32]);
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.controller-output-settlement.v1\0");
        digest.update(&bytes[..176]);
        bytes[176..208].copy_from_slice(&digest.finalize());
        ControllerOutputSettlementPreimageV1::from_canonical_bytes(&bytes).unwrap()
    }

    fn query() -> VerifiedCaptureCandidateQueryV1 {
        VerifiedCaptureCandidateQueryV1 {
            settlement: settlement(),
            assignment: BrokerAssignment::new(
                SandboxId::from_bytes([11; 16]),
                IncarnationId::from_bytes([12; 16]),
                AssignmentEpoch::new(1),
                DesiredGeneration::new(2),
                ObjectDigest::from_bytes([13; 32]),
            )
            .unwrap(),
            output_claim_digest: ObjectDigest::from_bytes([3; 32]),
            request_id: [14; 16],
            nonce: [15; 16],
            host_boot_id: KernelBootId::current().unwrap().into_bytes(),
            deadline_boottime_nanoseconds: boottime_now_nanoseconds().unwrap() + 30_000_000_000,
        }
    }

    fn ledger(path: &std::path::Path) -> ExecutionOutputLedgerV1 {
        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        ExecutionOutputLedgerV1::from_journal(
            journal,
            200,
            ExecutionOutputLedgerKeyV1::new([7; 16], [9; 32]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn candidate_cold_joins_distinct_owner_heads_and_live_guid_capacity() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut owner = ledger(&path);
        owner
            .reserve_record(RetainedOutputRecord {
                execution: [1; 16],
                create: [2; 16],
                assignment: [13; 32],
                claim_digest: [3; 32],
                bytes: 100,
                maximum_stdout_bytes: 60,
                maximum_stderr_bytes: 40,
                state: STATE_RETAINED,
                delete_operation: [0; 16],
            })
            .unwrap();
        drop(owner);

        let owner = ledger(&path);
        let (requirement, catalog) = precreate_fixture();
        let lookup = query();
        let observe = |plan: &CaptureZfsPreflightPlanV1| {
            plan.evaluate([
                b"pool\t17\t-\t1000\tONLINE\n",
                b"pool/aos\tfilesystem\t11\t900\n",
            ])
            .map_err(Into::into)
        };
        let candidate = owner
            .observe_capture_candidate_with(&lookup, &requirement, &catalog, 20, 100, observe)
            .unwrap();
        assert_eq!(
            candidate.output_journal_sequence,
            owner.journal.snapshot_sequence()
        );
        assert_eq!(candidate.catalog_generation, catalog.binding().generation());
        assert_eq!(candidate.catalog_head_digest, catalog.binding().digest());
        assert_eq!(
            (
                candidate.maximum_stdout_bytes,
                candidate.maximum_stderr_bytes
            ),
            (60, 40)
        );
        assert_eq!((candidate.pool_guid, candidate.root_guid), (17, 11));
        assert_eq!(
            (
                candidate.pool_available_bytes,
                candidate.root_available_bytes
            ),
            (1000, 900)
        );
        assert_eq!(candidate.candidate_digest, candidate.digest());
        assert!(candidate.expires_boottime_nanoseconds <= lookup.deadline_boottime_nanoseconds);

        let mut substituted = query();
        substituted.assignment = BrokerAssignment::new(
            SandboxId::from_bytes([11; 16]),
            IncarnationId::from_bytes([12; 16]),
            AssignmentEpoch::new(1),
            DesiredGeneration::new(2),
            ObjectDigest::from_bytes([99; 32]),
        )
        .unwrap();
        assert!(
            owner
                .observe_capture_candidate_with(
                    &substituted,
                    &requirement,
                    &catalog,
                    20,
                    100,
                    observe
                )
                .is_err()
        );

        let (_, occupied) = occupied_precreate_fixture();
        assert!(matches!(
            owner.observe_capture_candidate_with(
                &lookup,
                &requirement,
                &occupied,
                20,
                100,
                observe
            ),
            Err(CaptureCandidateErrorV1::Catalog)
        ));

        let checkpoint = |plan: &CaptureZfsPreflightPlanV1| {
            plan.evaluate([
                b"pool\t17\t1\t1000\tONLINE\n",
                b"pool/aos\tfilesystem\t11\t900\n",
            ])
            .map_err(Into::into)
        };
        assert!(matches!(
            owner.observe_capture_candidate_with(
                &lookup,
                &requirement,
                &catalog,
                20,
                100,
                checkpoint
            ),
            Err(CaptureCandidateErrorV1::Readback(
                CaptureZfsReadbackErrorV1::PoolUnavailable
            ))
        ));
    }
}
