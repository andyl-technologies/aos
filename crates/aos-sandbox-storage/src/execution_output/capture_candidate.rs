//! Read-only, nonauthorizing physical candidate for detached capture.
//!
//! This joins Storage's protected AOSEOR03 row to a distinct physical-catalog
//! head and a pinned, checkpoint-free ZFS preflight. The candidate is useful
//! only when a future method-41 handler authenticates its Controller peer and
//! signs the exact response under the Storage broker session. Reserve must
//! recheck both durable owners and ZFS, including pool GUID against a pinned
//! owner identity that this read-only source does not yet possess. This
//! observation grants no effect.

use aos_sandbox_core::{BrokerAssignment, ObjectDigest, OperationId};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::storage_capture_candidate::STORAGE_CAPTURE_CANDIDATE_BYTES_V1;
use aos_sandbox_protocol::storage_capture_grant::ControllerOutputSettlementPreimageV1;
use sha2::{Digest as _, Sha256};

use super::{ExecutionOutputLedgerErrorV1, ExecutionOutputLedgerV1};
use crate::ZfsHelperContract;
use crate::broker::AuthenticatedCaptureCandidateCutV1;
use crate::catalog_transition::VerifiedPhysicalCatalogSnapshotV1;
use crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1;
use crate::catalog_transition::execution_capture::readback::{
    CaptureZfsPreflightPlanV1, CaptureZfsPreflightV1, CaptureZfsReadbackErrorV1,
};
use crate::execution_capture_policy::CaptureAllocationV1;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::process::{ZfsWorkerError, observe_capture_zfs_preflight_for};
use crate::resolver::policy::ProtectedStorageResolverPolicyV1;

const CANDIDATE_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-candidate.v1\0";
const POLICY_JOIN_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-candidate-policy-join.v1\0";
const CREATE_OPERATION_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-create-operation.v1\0";
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
/// bytes and caller-supplied request IDs cannot construct this source. The
/// eventual issuer must recompute the assignment from its canonical manifest
/// and compare the exact verified BSA transcript session binding.
pub(super) struct VerifiedCaptureCandidateQueryV1 {
    settlement: ControllerOutputSettlementPreimageV1,
    assignment: BrokerAssignment,
    output_claim_digest: ObjectDigest,
    request_id: [u8; 16],
    session_binding: [u8; 32],
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
    session_binding: [u8; 32],
    kernel_boot_id: [u8; 16],
    request_deadline_boottime_nanoseconds: u64,
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
    /// Resolves Storage-selected policy and emits only an informational readback.
    ///
    /// The admission cut is private to the signed-plan verifier. The caller
    /// must reauthenticate that cut and both policy publications after this
    /// ZFS observation before signing any broker outcome.
    pub(crate) fn observe_authenticated_capture_candidate(
        &self,
        cut: &AuthenticatedCaptureCandidateCutV1,
        resolver_policy: &ProtectedStorageResolverPolicyV1,
        allocation_policy: CaptureAllocationV1,
        zfs: &ZfsHelperContract,
    ) -> Result<[u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1], CaptureCandidateErrorV1> {
        let query = cut.query();
        if resolver_policy.assignment() != query.assignment() {
            return Err(CaptureCandidateErrorV1::NotCurrent);
        }
        let (retained, _) = self.read_current_capture_for_candidate(
            *query.settlement().execution().as_bytes(),
            *query.settlement().create_operation().as_bytes(),
            query.output_claim_digest(),
            query.assignment().digest(),
        )?;
        let allocation_bytes = allocation_policy
            .allocation_for(retained.admitted_bytes())
            .map_err(|_| CaptureCandidateErrorV1::NotCurrent)?;
        let storage_create_operation = capture_create_operation(
            query.settlement().execution(),
            query.settlement().create_operation(),
            query.output_claim_digest(),
        );
        let requirement = CaptureDatasetRequirementV1::new(
            query.settlement().execution(),
            query.settlement().create_operation(),
            query.output_claim_digest(),
            storage_create_operation,
            resolver_policy.root().clone(),
            resolver_policy.domains(),
            retained.admitted_bytes(),
            allocation_bytes,
        )
        .map_err(|_| CaptureCandidateErrorV1::NotCurrent)?;
        let verified = VerifiedCaptureCandidateQueryV1 {
            settlement: *query.settlement(),
            assignment: query.assignment(),
            output_claim_digest: query.output_claim_digest(),
            request_id: query.request_id(),
            session_binding: query.claimed_session_binding(),
            host_boot_id: query.host_boot_id(),
            deadline_boottime_nanoseconds: query.deadline_boottime_nanoseconds(),
        };
        let candidate = self.observe_capture_candidate(
            &verified,
            &requirement,
            cut.catalog(),
            allocation_policy.metadata_headroom_bytes(),
            allocation_policy.minimum_remaining_bytes(),
            allocation_policy.digest(),
            zfs,
        )?;
        if candidate.pool_guid != allocation_policy.expected_pool_guid() {
            return Err(CaptureCandidateErrorV1::NotCurrent);
        }
        Ok(candidate.canonical_bytes())
    }

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
        allocation_policy_digest: ObjectDigest,
        zfs: &ZfsHelperContract,
    ) -> Result<ProtectedCaptureCandidateV1, CaptureCandidateErrorV1> {
        self.observe_capture_candidate_with(
            query,
            requirement,
            catalog,
            metadata_headroom_bytes,
            minimum_remaining_bytes,
            allocation_policy_digest,
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
        allocation_policy_digest: ObjectDigest,
        observe: impl FnOnce(
            &CaptureZfsPreflightPlanV1,
        ) -> Result<CaptureZfsPreflightV1, CaptureCandidateErrorV1>,
    ) -> Result<ProtectedCaptureCandidateV1, CaptureCandidateErrorV1> {
        let boot = KernelBootId::current()
            .map_err(|_| CaptureCandidateErrorV1::NotCurrent)?
            .into_bytes();
        let now = boottime_now_nanoseconds()?;
        if query.request_id == [0; 16]
            || query.session_binding == [0; 32]
            || query.host_boot_id != boot
            || query.deadline_boottime_nanoseconds <= now
            || requirement.execution() != query.settlement.execution()
            || requirement.create_operation() != query.settlement.create_operation()
            || requirement.claim_digest() != query.output_claim_digest
            || allocation_policy_digest.as_bytes() == &[0; 32]
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
            session_binding: query.session_binding,
            kernel_boot_id: boot,
            request_deadline_boottime_nanoseconds: query.deadline_boottime_nanoseconds,
            expires_boottime_nanoseconds,
            dataset_policy_digest: joined_policy_digest(
                allocation_policy_digest,
                requirement.attempt_policy_digest(metadata_headroom_bytes, minimum_remaining_bytes),
            ),
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

fn capture_create_operation(
    execution: aos_sandbox_core::ExecutionId,
    create: OperationId,
    claim_digest: ObjectDigest,
) -> OperationId {
    let mut digest = Sha256::new();
    digest.update(CREATE_OPERATION_DOMAIN);
    digest.update(execution.as_bytes());
    digest.update(create.as_bytes());
    digest.update(claim_digest.as_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut operation = [0; 16];
    operation.copy_from_slice(&hash[..16]);
    OperationId::from_bytes(operation)
}

impl ProtectedCaptureCandidateV1 {
    fn digest(&self) -> ObjectDigest {
        let bytes = self.canonical_bytes();
        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes[672..704]);
        ObjectDigest::from_bytes(digest)
    }

    /// Encodes the fixed informational response after protected readback.
    ///
    /// The bytes are not signed until a future pinned Storage BSA outcome
    /// issuer commits them; no current handler exposes this method.
    fn canonical_bytes(&self) -> [u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1] {
        let mut bytes = [0; STORAGE_CAPTURE_CANDIDATE_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSSCB01");
        let query = &mut bytes[8..408];
        query[..8].copy_from_slice(b"AOSSCQ01");
        query[8..216].copy_from_slice(self.settlement.canonical_bytes());
        query[216..248].copy_from_slice(self.output_claim_digest.as_bytes());
        query[248..264].copy_from_slice(self.assignment.sandbox().as_bytes());
        query[264..280].copy_from_slice(self.assignment.incarnation().as_bytes());
        query[280..288].copy_from_slice(&self.assignment.epoch().get().to_be_bytes());
        query[288..296].copy_from_slice(&self.assignment.desired_generation().get().to_be_bytes());
        query[296..328].copy_from_slice(self.assignment.digest().as_bytes());
        query[328..344].copy_from_slice(&self.kernel_boot_id);
        query[344..376].copy_from_slice(&self.session_binding);
        query[376..392].copy_from_slice(&self.request_id);
        query[392..400].copy_from_slice(&self.request_deadline_boottime_nanoseconds.to_be_bytes());

        bytes[408..440].copy_from_slice(self.output_record_digest.as_bytes());
        bytes[440..448].copy_from_slice(&self.output_journal_sequence.to_be_bytes());
        bytes[448..456].copy_from_slice(&self.catalog_generation.to_be_bytes());
        bytes[456..488].copy_from_slice(self.catalog_head_digest.as_bytes());
        bytes[488..504].copy_from_slice(&self.kernel_boot_id);
        bytes[504..512].copy_from_slice(&self.expires_boottime_nanoseconds.to_be_bytes());
        bytes[512..544].copy_from_slice(self.dataset_policy_digest.as_bytes());
        bytes[544..560].copy_from_slice(&self.storage_create_operation);
        for (range, value) in [
            (560..568, self.admitted_bytes),
            (568..576, self.maximum_stdout_bytes),
            (576..584, self.maximum_stderr_bytes),
            (584..592, self.allocation_bytes),
            (592..600, self.metadata_headroom_bytes),
            (600..608, self.minimum_remaining_bytes),
            (608..616, self.pool_guid),
            (616..624, self.root_guid),
            (624..632, self.pool_available_bytes),
            (632..640, self.root_available_bytes),
        ] {
            bytes[range].copy_from_slice(&value.to_be_bytes());
        }
        bytes[640..672].copy_from_slice(self.preflight_digest.as_bytes());

        let mut digest = Sha256::new();
        digest.update(CANDIDATE_DOMAIN);
        digest.update(&bytes[..672]);
        bytes[672..704].copy_from_slice(&digest.finalize());
        bytes
    }
}

fn joined_policy_digest(
    allocation_policy_digest: ObjectDigest,
    attempt_policy_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(POLICY_JOIN_DOMAIN);
    digest.update(allocation_policy_digest.as_bytes());
    digest.update(attempt_policy_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        Audience, ReadStorageExecutionCaptureCandidateRequestV1, RequestHeader,
        StorageExecutionCaptureCandidateV1,
    };
    use aos_sandbox::{Journal, JournalLimits};
    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};
    use aos_sandbox_protocol::storage_capture_candidate::{
        StorageCaptureCandidateQueryV1, decode_storage_capture_candidate_request_v1,
        decode_storage_capture_candidate_response_v1,
    };
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
    use buffa::Message as _;
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
            session_binding: [15; 32],
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
        let record_digest = owner
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

        let mut owner = ledger(&path);
        assert!(matches!(
            owner.reserve_record(RetainedOutputRecord {
                execution: [1; 16],
                create: [99; 16],
                assignment: [13; 32],
                claim_digest: [3; 32],
                bytes: 100,
                maximum_stdout_bytes: 60,
                maximum_stderr_bytes: 40,
                state: STATE_RETAINED,
                delete_operation: [0; 16],
            }),
            Err(ExecutionOutputLedgerErrorV1::Conflict)
        ));
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
            .observe_capture_candidate_with(
                &lookup,
                &requirement,
                &catalog,
                20,
                100,
                ObjectDigest::from_bytes([23; 32]),
                observe,
            )
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

        let canonical = candidate.canonical_bytes();
        let wire_query =
            StorageCaptureCandidateQueryV1::from_canonical_bytes(&canonical[8..408]).unwrap();
        assert_eq!(wire_query.request_id(), lookup.request_id);
        assert_eq!(wire_query.claimed_session_binding(), lookup.session_binding);
        assert_eq!(
            wire_query.deadline_boottime_nanoseconds(),
            lookup.deadline_boottime_nanoseconds
        );
        let peer = PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(9),
        };
        let policy = PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };
        let request = ReadStorageExecutionCaptureCandidateRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: lookup.request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: lookup.deadline_boottime_nanoseconds,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            canonical_query: wire_query.canonical_bytes().to_vec(),
            ..Default::default()
        };
        let original = decode_storage_capture_candidate_request_v1(
            &request.encode_to_vec(),
            peer,
            policy,
            boottime_now_nanoseconds().unwrap(),
        )
        .unwrap();
        let response = StorageExecutionCaptureCandidateV1 {
            canonical_candidate: canonical.to_vec(),
            ..Default::default()
        };
        let validated = decode_storage_capture_candidate_response_v1(
            &response.encode_to_vec(),
            &original,
            boottime_now_nanoseconds().unwrap(),
        )
        .unwrap();
        assert_eq!(validated.candidate_digest(), candidate.candidate_digest);
        assert_eq!(validated.output_record_digest(), record_digest);
        assert_eq!(validated.admitted_bytes(), 100);
        assert_eq!(validated.maximum_stdout_bytes(), 60);
        assert_eq!(validated.maximum_stderr_bytes(), 40);

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
                    ObjectDigest::from_bytes([23; 32]),
                    observe
                )
                .is_err()
        );

        let mut wrong_claim = query();
        wrong_claim.output_claim_digest = ObjectDigest::from_bytes([99; 32]);
        assert!(matches!(
            owner.observe_capture_candidate_with(
                &wrong_claim,
                &requirement,
                &catalog,
                20,
                100,
                ObjectDigest::from_bytes([23; 32]),
                observe
            ),
            Err(CaptureCandidateErrorV1::NotCurrent)
        ));

        let (_, occupied) = occupied_precreate_fixture();
        assert!(matches!(
            owner.observe_capture_candidate_with(
                &lookup,
                &requirement,
                &occupied,
                20,
                100,
                ObjectDigest::from_bytes([23; 32]),
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
                ObjectDigest::from_bytes([23; 32]),
                checkpoint
            ),
            Err(CaptureCandidateErrorV1::Readback(
                CaptureZfsReadbackErrorV1::PoolUnavailable
            ))
        ));

        drop(owner);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let rotated = ExecutionOutputLedgerKeyV1::new([8; 16], [9; 32]).unwrap();
        assert!(matches!(
            ExecutionOutputLedgerV1::from_journal(journal, 200, rotated),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }
}
