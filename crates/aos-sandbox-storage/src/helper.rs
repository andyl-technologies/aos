//! Lock-coupled privileged ZFS observation and execution boundary.
//!
//! This module intentionally keeps executable argv crate-private. The fixed
//! backend contract receives only typed resolved semantics. The production
//! adapter sends those types to a systemd-contained one-shot worker, which
//! independently recompiles argv before invoking its fixed executable. ZFS
//! observations remain a separate backend and never trust child output.

mod snapshot_startup;
mod snapshot_read;
mod recovery_results;
mod recovery_observation;
pub(crate) use snapshot_startup::StorageSnapshotMetadataStartupV1;

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};

use crate::broker::FreshStorageEffectAuthority;
use crate::process::{
    HeldSnapshotPhysicalObservationV1, HeldSnapshotWorkerBindingV1, SystemdZfsExecutor,
    WorkerObservationOutcome, ZfsWorkerError,
};
use crate::runtime::original_held_measurement::{
    OriginalHeldMeasurementErrorV3, OriginalWorkerLoanV3,
};
use crate::{
    AncestorPolicyTransaction, DurableStoragePhase, PostconditionPolicyV1, ProjectAncestorPolicyV1,
    ResolvedCatalogCommitmentV1, StorageOperation, StorageRecoveryEntry, StorageStateError,
    StorageTransactionStore, ZfsHelperContract, ZfsPrecondition, ZfsTransaction,
    ZfsTransactionError,
};

const MAXIMUM_STDOUT_BYTES: usize = 64 * 1024;
const MAXIMUM_STDERR_BYTES: usize = 64 * 1024;
const PROCESS_TREE_TIMEOUT: Duration = Duration::from_secs(30);
const FIXED_SNAPSHOT_METADATA_DIRECTORY: &str = "/var/lib/aos/sandbox-storage/snapshot-metadata";
const SNAPSHOT_METADATA_RECORD_BYTES: usize = 384;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ZfsHelperError {
    #[error("storage transaction compilation failed: {0}")]
    Transaction(#[from] ZfsTransactionError),
    #[error("storage durable transition failed: {0}")]
    State(#[from] StorageStateError),
    #[error("ZFS precondition observation did not match")]
    PreconditionMismatch,
    #[error("ZFS postcondition observation did not match")]
    PostconditionMismatch,
    #[error("a prepared transaction already has its physical postcondition")]
    PreparedPostconditionConflict,
    #[error("fixed ZFS process backend failed: {0}")]
    Backend(#[from] ZfsWorkerError),
    #[error("fresh persisted storage authority was rejected")]
    Authority,
    #[error("fixed ZFS process output or timeout contract was violated")]
    ProcessContract,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ZfsHelperOutcome {
    Committed(crate::CommittedStorageResultV1),
    Aborted {
        mutation_digest: ObjectDigest,
    },
    ObservationRequired {
        phase: DurableStoragePhase,
        mutation_digest: ObjectDigest,
    },
}

pub(crate) struct ZfsProcessOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    success: bool,
    timed_out: bool,
}

/// Retains the exact observed group digest and each member's physical GUID.
pub(crate) struct ObservedAtomicSnapshotGroupV1 {
    digest: ObjectDigest,
    member_guids: Vec<u64>,
}

impl ObservedAtomicSnapshotGroupV1 {
    pub(crate) const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn member_guids(&self) -> &[u64] {
        &self.member_guids
    }
}

pub(crate) struct ZfsPostconditionObservation {
    observed: PostconditionPolicyV1,
    ancestor: Option<ProjectAncestorPolicyV1>,
    object_guid: Option<u64>,
    digest: ObjectDigest,
}

pub(crate) struct SealedZfsProgram<'a> {
    executable: &'a std::path::Path,
    operation: StorageOperation,
    catalog: &'a ResolvedCatalogCommitmentV1,
    environment_is_empty: bool,
    inherited_descriptor_count: u8,
    maximum_stdout_bytes: usize,
    maximum_stderr_bytes: usize,
    process_tree_timeout: Duration,
}

pub(crate) trait ZfsProcessBackend {
    // Closed actual Capture entry; only a genuine fresh424 Native original
    // reaches this borrowed port. Other fixed/test backends refuse it.
    fn begin_capture_created_ongoing_v3(
        &mut self,
        physical: &mut crate::process::CapturePhysicalPreparationOriginalV3,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), ZfsWorkerError> {
        let _ = (physical, request, journal, receiving);
        Err(ZfsWorkerError::Authority)
    }

    fn observe_capture_candidate_preflight_receiving_v1(
        &mut self,
        _contract: &ZfsHelperContract,
        _plan: &crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightPlanV1,
        _cutoff: u64,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightV1, ZfsHelperError> {
        let _ = stage;
        Err(ZfsHelperError::ProcessContract)
    }

    fn observe_preconditions_receiving_v1(
        &mut self,
        _program: &SealedZfsProgram<'_>,
        _expected: &[ZfsPrecondition],
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
        let _ = stage;
        Err(ZfsHelperError::ProcessContract)
    }

    fn execute_once_receiving_v1(
        &mut self,
        _program: &SealedZfsProgram<'_>,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        let _ = stage;
        Err(ZfsHelperError::ProcessContract)
    }

    fn atomic_snapshot_once_receiving_v1(
        &mut self,
        _contract: &ZfsHelperContract,
        _program: &crate::DormantAtomicDatasetSnapshotV1,
        _mutate: bool,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        let _ = stage;
        Err(ZfsHelperError::ProcessContract)
    }

    fn observe_postcondition_receiving_v1(
        &mut self,
        _program: &SealedZfsProgram<'_>,
        _expected: &PostconditionPolicyV1,
        _expected_ancestor: Option<&ProjectAncestorPolicyV1>,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
        let _ = stage;
        Err(ZfsHelperError::ProcessContract)
    }

    fn observe_original_held_snapshot(
        &mut self,
        _contract: &ZfsHelperContract,
        _snapshot: &crate::ResolvedSnapshot,
        _hold_id: crate::HoldId,
        _binding: HeldSnapshotWorkerBindingV1,
        _loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
        _progress: &mut crate::process::OriginalHeldWorkerProgressV3,
    ) -> Result<HeldSnapshotPhysicalObservationV1, OriginalHeldMeasurementErrorV3> {
        Err(OriginalHeldMeasurementErrorV3::Closed)
    }

    fn observe_held_snapshot(
        &mut self,
        _contract: &ZfsHelperContract,
        _snapshot: &crate::ResolvedSnapshot,
        _hold_id: crate::HoldId,
        _binding: HeldSnapshotWorkerBindingV1,
    ) -> Result<HeldSnapshotPhysicalObservationV1, ZfsHelperError> {
        Err(ZfsHelperError::ProcessContract)
    }

    fn observe_preconditions(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &[ZfsPrecondition],
    ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError>;

    fn execute_once(
        &mut self,
        program: &SealedZfsProgram<'_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError>;

    fn atomic_snapshot_once(
        &mut self,
        _contract: &ZfsHelperContract,
        _program: &crate::DormantAtomicDatasetSnapshotV1,
        _mutate: bool,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        Err(ZfsHelperError::ProcessContract)
    }

    fn observe_postcondition(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &PostconditionPolicyV1,
        expected_ancestor: Option<&ProjectAncestorPolicyV1>,
    ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError>;

    /// Reads protected whole-tree identity metadata for one Snapshot commit.
    fn snapshot_metadata_receiving_v1(
        &mut self,
        _operation_id: [u8; 16],
        _journal: &aos_sandbox::Journal,
        _receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<Option<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1>, ZfsHelperError> {
        Err(ZfsHelperError::ProcessContract)
    }

    fn snapshot_receiving_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn require_snapshot_reads_positive_v1(&self) -> Result<(), ZfsHelperError> {
        Err(ZfsHelperError::ProcessContract)
    }

    fn complete_snapshot_reads_disposal_v1(&mut self) {
        std::process::abort();
    }

    fn snapshot_metadata(
        &mut self,
        _operation_id: [u8; 16],
    ) -> Result<Option<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1>, ZfsHelperError>
    {
        Ok(None)
    }
}

impl<T: ZfsProcessBackend + ?Sized> ZfsProcessBackend for Box<T> {
    fn begin_capture_created_ongoing_v3(
        &mut self,
        physical: &mut crate::process::CapturePhysicalPreparationOriginalV3,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), ZfsWorkerError> {
        (**self).begin_capture_created_ongoing_v3(physical, request, journal, receiving)
    }

    fn observe_capture_candidate_preflight_receiving_v1(
        &mut self,
        contract: &ZfsHelperContract,
        plan: &crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightPlanV1,
        cutoff: u64,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightV1, ZfsHelperError> {
        (**self).observe_capture_candidate_preflight_receiving_v1(contract, plan, cutoff, stage)
    }

    fn observe_preconditions_receiving_v1(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &[ZfsPrecondition],
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
        (**self).observe_preconditions_receiving_v1(program, expected, stage)
    }

    fn execute_once_receiving_v1(
        &mut self,
        program: &SealedZfsProgram<'_>,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        (**self).execute_once_receiving_v1(program, stage)
    }

    fn atomic_snapshot_once_receiving_v1(
        &mut self,
        contract: &ZfsHelperContract,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        mutate: bool,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        (**self).atomic_snapshot_once_receiving_v1(contract, program, mutate, stage)
    }

    fn observe_postcondition_receiving_v1(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &PostconditionPolicyV1,
        expected_ancestor: Option<&ProjectAncestorPolicyV1>,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
        (**self).observe_postcondition_receiving_v1(program, expected, expected_ancestor, stage)
    }

    fn observe_original_held_snapshot(
        &mut self,
        contract: &ZfsHelperContract,
        snapshot: &crate::ResolvedSnapshot,
        hold_id: crate::HoldId,
        binding: HeldSnapshotWorkerBindingV1,
        loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
        progress: &mut crate::process::OriginalHeldWorkerProgressV3,
    ) -> Result<HeldSnapshotPhysicalObservationV1, OriginalHeldMeasurementErrorV3> {
        (**self).observe_original_held_snapshot(contract, snapshot, hold_id, binding, loan, progress)
    }

    fn observe_held_snapshot(
        &mut self,
        contract: &ZfsHelperContract,
        snapshot: &crate::ResolvedSnapshot,
        hold_id: crate::HoldId,
        binding: HeldSnapshotWorkerBindingV1,
    ) -> Result<HeldSnapshotPhysicalObservationV1, ZfsHelperError> {
        (**self).observe_held_snapshot(contract, snapshot, hold_id, binding)
    }

    fn observe_preconditions(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &[ZfsPrecondition],
    ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
        (**self).observe_preconditions(program, expected)
    }

    fn execute_once(
        &mut self,
        program: &SealedZfsProgram<'_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        (**self).execute_once(program)
    }

    fn atomic_snapshot_once(
        &mut self,
        contract: &ZfsHelperContract,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        mutate: bool,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        (**self).atomic_snapshot_once(contract, program, mutate)
    }

    fn observe_postcondition(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &PostconditionPolicyV1,
        expected_ancestor: Option<&ProjectAncestorPolicyV1>,
    ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
        (**self).observe_postcondition(program, expected, expected_ancestor)
    }

    fn snapshot_metadata_receiving_v1(
        &mut self,
        operation_id: [u8; 16],
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<Option<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1>, ZfsHelperError> {
        (**self).snapshot_metadata_receiving_v1(operation_id, journal, receiving)
    }

    fn snapshot_receiving_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        (**self).snapshot_receiving_failure_v1()
    }

    fn require_snapshot_reads_positive_v1(&self) -> Result<(), ZfsHelperError> {
        (**self).require_snapshot_reads_positive_v1()
    }

    fn complete_snapshot_reads_disposal_v1(&mut self) {
        (**self).complete_snapshot_reads_disposal_v1()
    }

    fn snapshot_metadata(
        &mut self,
        operation_id: [u8; 16],
    ) -> Result<Option<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1>, ZfsHelperError>
    {
        (**self).snapshot_metadata(operation_id)
    }
}

pub(crate) struct SystemdZfsProcessBackend {
    executor: SystemdZfsExecutor,
    snapshot_metadata: Option<ProtectedSnapshotMetadataDirectoryV1>,
    snapshot_reads: snapshot_read::SnapshotMetadataReadsV1,
}

impl SystemdZfsProcessBackend {
    pub(crate) fn new(executor: SystemdZfsExecutor) -> Self {
        Self {
            executor,
            snapshot_metadata: None,
            snapshot_reads: snapshot_read::SnapshotMetadataReadsV1::default(),
        }
    }

    /// Opens the fixed protected Snapshot metadata owner for dormant Apply.
    pub(crate) fn with_protected_snapshot_metadata(
        executor: SystemdZfsExecutor,
    ) -> Result<Self, ZfsHelperError> {
        Ok(Self {
            executor,
            snapshot_metadata: Some(ProtectedSnapshotMetadataDirectoryV1::open_fixed()?),
            snapshot_reads: snapshot_read::SnapshotMetadataReadsV1::default(),
        })
    }
}

impl ZfsProcessBackend for SystemdZfsProcessBackend {
    fn begin_capture_created_ongoing_v3(
        &mut self,
        physical: &mut crate::process::CapturePhysicalPreparationOriginalV3,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), ZfsWorkerError> {
        physical.begin_create_once_v3(&self.executor, request, journal, receiving)
    }

    fn observe_capture_candidate_preflight_receiving_v1(
        &mut self,
        contract: &ZfsHelperContract,
        plan: &crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightPlanV1,
        cutoff: u64,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightV1, ZfsHelperError> {
        self.executor.observe_capture_candidate_preflight_receiving_v1(contract, plan, cutoff, stage)
            .map_err(ZfsHelperError::from)
    }

    fn observe_preconditions_receiving_v1(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &[ZfsPrecondition],
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        preconditions_from_worker_v1(self.executor.observe_preconditions_receiving_v1(
            &contract, program.operation, program.catalog, stage,
        )?, expected)
    }

    fn execute_once_receiving_v1(
        &mut self,
        program: &SealedZfsProgram<'_>,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        let output = self.executor.execute_once_receiving_v1(
            &contract, program.operation, program.catalog, stage,
        )?;
        Ok(ZfsProcessOutput { stdout: output.stdout, stderr: output.stderr,
            success: output.success, timed_out: output.timed_out })
    }

    fn atomic_snapshot_once_receiving_v1(
        &mut self,
        contract: &ZfsHelperContract,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        mutate: bool,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        let output = self.executor.atomic_snapshot_once_receiving_v1(contract, program, mutate, stage)?;
        Ok(ZfsProcessOutput { stdout: output.stdout, stderr: output.stderr,
            success: output.success, timed_out: output.timed_out })
    }

    fn observe_postcondition_receiving_v1(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &PostconditionPolicyV1,
        expected_ancestor: Option<&ProjectAncestorPolicyV1>,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        postcondition_from_worker_v1(self.executor.observe_postcondition_receiving_v1(
            &contract, program.operation, program.catalog, stage,
        )?, expected, expected_ancestor)
    }

    fn observe_original_held_snapshot(
        &mut self,
        contract: &ZfsHelperContract,
        snapshot: &crate::ResolvedSnapshot,
        hold_id: crate::HoldId,
        binding: HeldSnapshotWorkerBindingV1,
        loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
        progress: &mut crate::process::OriginalHeldWorkerProgressV3,
    ) -> Result<HeldSnapshotPhysicalObservationV1, OriginalHeldMeasurementErrorV3> {
        self.executor
            .observe_original_held_snapshot(contract, snapshot, hold_id, binding, loan, progress)
    }

    fn observe_held_snapshot(
        &mut self,
        contract: &ZfsHelperContract,
        snapshot: &crate::ResolvedSnapshot,
        hold_id: crate::HoldId,
        binding: HeldSnapshotWorkerBindingV1,
    ) -> Result<HeldSnapshotPhysicalObservationV1, ZfsHelperError> {
        self.executor
            .observe_held_snapshot(contract, snapshot, hold_id, binding)
            .map_err(Into::into)
    }

    fn observe_preconditions(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &[ZfsPrecondition],
    ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        preconditions_from_worker_v1(
            self.executor.observe_preconditions(&contract, program.operation, program.catalog)?,
            expected,
        )
    }

    fn execute_once(
        &mut self,
        program: &SealedZfsProgram<'_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        let output = self
            .executor
            .execute_once(&contract, program.operation, program.catalog)?;
        Ok(ZfsProcessOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            success: output.success,
            timed_out: output.timed_out,
        })
    }

    fn atomic_snapshot_once(
        &mut self,
        contract: &ZfsHelperContract,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        mutate: bool,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        let output = self
            .executor
            .atomic_snapshot_once(contract, program, mutate)?;
        Ok(ZfsProcessOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            success: output.success,
            timed_out: output.timed_out,
        })
    }

    fn observe_postcondition(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &PostconditionPolicyV1,
        expected_ancestor: Option<&ProjectAncestorPolicyV1>,
    ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        postcondition_from_worker_v1(
            self.executor.observe_postcondition(&contract, program.operation, program.catalog)?,
            expected, expected_ancestor,
        )
    }

    fn snapshot_metadata_receiving_v1(
        &mut self,
        operation_id: [u8; 16],
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<Option<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1>, ZfsHelperError> {
        let Some(directory) = self.snapshot_metadata.as_ref() else {
            return Ok(None);
        };
        self.snapshot_reads.capture_receiving_v1(
            &directory.directory, operation_id, journal, receiving,
        ).map(Some)
    }

    fn snapshot_receiving_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.snapshot_reads.failure()
    }

    fn require_snapshot_reads_positive_v1(&self) -> Result<(), ZfsHelperError> {
        self.snapshot_reads.require_positive_after_posts_v1()
    }

    fn complete_snapshot_reads_disposal_v1(&mut self) {
        self.snapshot_reads.complete_positive_disposal_v1()
    }

    fn snapshot_metadata(
        &mut self,
        operation_id: [u8; 16],
    ) -> Result<Option<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1>, ZfsHelperError>
    {
        self.snapshot_metadata
            .as_ref()
            .map(|owner| owner.read(operation_id))
            .transpose()
    }
}

fn preconditions_from_worker_v1(
    outcome: WorkerObservationOutcome,
    expected: &[ZfsPrecondition],
) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
    match outcome {
        WorkerObservationOutcome::Matched { object_guid: None, .. } => Ok(expected.to_vec()),
        WorkerObservationOutcome::Matched { .. } => Err(ZfsHelperError::PreconditionMismatch),
        WorkerObservationOutcome::Incomplete | WorkerObservationOutcome::Mismatch => Ok(Vec::new()),
    }
}

fn postcondition_from_worker_v1(
    outcome: WorkerObservationOutcome,
    expected: &PostconditionPolicyV1,
    expected_ancestor: Option<&ProjectAncestorPolicyV1>,
) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
    match outcome {
        WorkerObservationOutcome::Matched { object_guid, observation_digest } => {
            let captures_guid = matches!(
                expected,
                PostconditionPolicyV1::CaptureDataset { .. }
                    | PostconditionPolicyV1::CaptureSnapshot { .. }
            );
            if captures_guid != object_guid.is_some() {
                return Err(ZfsHelperError::PostconditionMismatch);
            }
            Ok(Some(ZfsPostconditionObservation {
                observed: expected.clone(),
                ancestor: expected_ancestor.cloned(),
                object_guid,
                digest: observation_digest,
            }))
        }
        WorkerObservationOutcome::Incomplete => Ok(None),
        WorkerObservationOutcome::Mismatch => Err(ZfsHelperError::PostconditionMismatch),
    }
}

/// Retains the fixed root-owned directory containing exact AOSSMT01 records.
struct ProtectedSnapshotMetadataDirectoryV1 {
    directory: OwnedFd,
}

impl ProtectedSnapshotMetadataDirectoryV1 {
    fn open_fixed() -> Result<Self, ZfsHelperError> {
        snapshot_startup::open_ordinary_fixed()
    }

    fn read(
        &self,
        operation_id: [u8; 16],
    ) -> Result<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1, ZfsHelperError> {
        snapshot_read::read_ordinary(&self.directory, operation_id)
    }

}

fn snapshot_metadata_name(operation_id: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut name = String::with_capacity(41);
    for byte in operation_id {
        name.push(char::from(HEX[(byte >> 4) as usize]));
        name.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    name.push_str(".aossmt01");
    name
}

pub(crate) struct StorageMutationHelper<B> {
    contract: ZfsHelperContract,
    backend: B,
    recovery_results: recovery_results::RecoveryHelperResultsV1,
    recovery_observations: recovery_observation::RecoveryObservationsV1,
    recovery_failure: Option<RecoveryHelperFailureV1>,
}

#[derive(Clone, Copy)]
enum RecoveryHelperFailureV1 {
    ReturnedOutput,
    Observation,
}

/// Keeps every positive helper carrier resident through the last fallible check.
///
/// Only the actual helper can prepare this private disposition. The enclosing
/// Runtime completes its State/native posts before entry and performs actual
/// sibling-owner cleanup before this infallible final disposal.
#[must_use]
pub(crate) struct StorageRecoveryHelperDispositionV1<'helper, B: ZfsProcessBackend> {
    helper: &'helper mut StorageMutationHelper<B>,
}

impl<B: ZfsProcessBackend> StorageRecoveryHelperDispositionV1<'_, B> {
    pub(crate) fn complete_after_disposal_v1(self) {
        self.helper.complete_recovery_disposition_v1();
    }
}

/// Carries one pre-observed persisted transaction into its sole dispatch.
///
/// This capability is deliberately neither `Clone` nor `Copy`. Its fields are
/// reconstructed from authenticated store state rather than caller input.
pub(crate) struct PreobservedZfsMutation {
    context: PersistedZfsMutation,
}

struct PersistedZfsMutation {
    entry: StorageRecoveryEntry,
    catalog: ResolvedCatalogCommitmentV1,
    operation: StorageOperation,
}

impl PreobservedZfsMutation {
    pub(crate) const fn entry(&self) -> StorageRecoveryEntry {
        self.context.entry
    }

    pub(crate) const fn catalog(&self) -> &ResolvedCatalogCommitmentV1 {
        &self.context.catalog
    }

    pub(crate) const fn operation(&self) -> StorageOperation {
        self.context.operation
    }
}

impl<B: ZfsProcessBackend> StorageMutationHelper<B> {
    pub(crate) fn begin_capture_created_ongoing_v3(
        &mut self,
        physical: &mut crate::process::CapturePhysicalPreparationOriginalV3,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), ZfsWorkerError> {
        self.backend.begin_capture_created_ongoing_v3(physical, request, journal, receiving)
    }

    pub(crate) fn observe_capture_candidate_preflight_receiving_v1(
        &mut self,
        plan: &crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightPlanV1,
        cutoff: u64,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightV1, ZfsHelperError> {
        self.backend.observe_capture_candidate_preflight_receiving_v1(&self.contract, plan, cutoff, stage)
    }

    pub(crate) fn complete_recovery_disposition_v1(&mut self) {
        self.backend.complete_snapshot_reads_disposal_v1();
        self.recovery_results.complete_positive_disposal_v1();
        self.recovery_observations.complete_positive_disposal();
    }

    pub(crate) fn prepare_recovery_disposition_v1(
        &mut self,
    ) -> Result<StorageRecoveryHelperDispositionV1<'_, B>, ZfsHelperError> {
        self.recovery_results.require_positive_after_posts_v1()?;
        self.recovery_observations.require_positive(&self.backend)?;
        self.backend.require_snapshot_reads_positive_v1()?;
        Ok(StorageRecoveryHelperDispositionV1 { helper: self })
    }

    pub(crate) fn recovery_receiving_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        match self.recovery_failure? {
            RecoveryHelperFailureV1::ReturnedOutput => self.recovery_results.failure(),
            RecoveryHelperFailureV1::Observation => self.recovery_observations.failure(&self.backend),
        }
    }

    pub(crate) fn observe_original_held_snapshot(
        &mut self,
        snapshot: &crate::ResolvedSnapshot,
        hold_id: crate::HoldId,
        binding: HeldSnapshotWorkerBindingV1,
        loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
        progress: &mut crate::process::OriginalHeldWorkerProgressV3,
    ) -> Result<HeldSnapshotPhysicalObservationV1, OriginalHeldMeasurementErrorV3> {
        self.backend.observe_original_held_snapshot(
            &self.contract,
            snapshot,
            hold_id,
            binding,
            loan,
            progress,
        )
    }

    /// Dispatches only a nonmutating held-snapshot probe through the same worker custody.
    pub(crate) fn observe_held_snapshot(
        &mut self,
        snapshot: &crate::ResolvedSnapshot,
        hold_id: crate::HoldId,
        binding: HeldSnapshotWorkerBindingV1,
    ) -> Result<HeldSnapshotPhysicalObservationV1, ZfsHelperError> {
        self.backend
            .observe_held_snapshot(&self.contract, snapshot, hold_id, binding)
    }

    pub(crate) fn new(contract: ZfsHelperContract, backend: B) -> Self {
        Self {
            contract,
            backend,
            recovery_results: recovery_results::RecoveryHelperResultsV1::new(),
            recovery_observations: recovery_observation::RecoveryObservationsV1::default(),
            recovery_failure: None,
        }
    }

    pub(crate) fn into_boxed(self) -> StorageMutationHelper<Box<dyn ZfsProcessBackend + Send>>
    where
        B: Send + 'static,
    {
        StorageMutationHelper {
            contract: self.contract,
            backend: Box::new(self.backend),
            recovery_results: self.recovery_results,
            recovery_observations: self.recovery_observations,
            recovery_failure: self.recovery_failure,
        }
    }

    pub(crate) fn atomic_snapshot_once(
        &mut self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        mutate: bool,
    ) -> Result<ObservedAtomicSnapshotGroupV1, ZfsHelperError> {
        let output = self
            .backend
            .atomic_snapshot_once(&self.contract, program, mutate)?;
        parse_atomic_snapshot_output_v1(program, &output)
    }

    pub(crate) fn atomic_snapshot_once_receiving_v1(
        &mut self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        mutate: bool,
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<ObservedAtomicSnapshotGroupV1, ZfsHelperError> {
        if self.recovery_receiving_failure_v1().is_some() {
            return Err(StorageStateError::Receiving.into());
        }
        let result = self.atomic_snapshot_once_receiving_inner_v1(
            program, mutate, journal, receiving,
        );
        if result.is_err() {
            self.recovery_failure = Some(RecoveryHelperFailureV1::ReturnedOutput);
        }
        result
    }

    fn atomic_snapshot_once_receiving_inner_v1(
        &mut self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        mutate: bool,
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<ObservedAtomicSnapshotGroupV1, ZfsHelperError> {
        self.recovery_results.prepare_atomic_v1(
            receiving,
            program.member_count(),
            self.contract.executable().as_os_str().as_encoded_bytes().len(),
        )?;
        let output = {
            let mut physical = crate::process::receiving_stage::StoragePhysicalWorkerStageV1
                ::state(receiving, journal);
            self.backend.atomic_snapshot_once_receiving_v1(
                &self.contract, program, mutate, &mut physical,
            )
        };
        // The complete physical result is resident before semantic inspection.
        // Its real stdout/stderr remain independent of transport disposition.
        self.recovery_results.outputs.push(output);
        let Some(Ok(output)) = self.recovery_results.outputs.last() else {
            return Err(StorageStateError::Receiving.into());
        };
        let mut interpretation = recovery_results::AtomicInterpretationOriginalV1::new();
        let result = interpretation.run(program, output, true);
        self.recovery_results.interpretations.push(
            recovery_results::HelperOutputInterpretationV1::Atomic(interpretation),
        );
        result.map_err(|()| StorageStateError::Receiving.into())
    }

    /// Observes exact preconditions for the current persisted Prepared entry.
    pub(crate) fn preobserve(
        &mut self,
        store: &StorageTransactionStore,
        operation_id: [u8; 16],
    ) -> Result<PreobservedZfsMutation, ZfsHelperError> {
        self.preobserve_inner_v1(store, operation_id, None)
    }

    pub(crate) fn preobserve_receiving_v1(
        &mut self,
        store: &StorageTransactionStore,
        operation_id: [u8; 16],
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<PreobservedZfsMutation, ZfsHelperError> {
        receiving.require_models_current_v1(store.recovery_encoding_journal_v1())
            .map_err(|_| StorageStateError::Receiving)?;
        self.preobserve_inner_v1(store, operation_id, Some(receiving))
    }

    fn preobserve_inner_v1(
        &mut self,
        store: &StorageTransactionStore,
        operation_id: [u8; 16],
        receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<PreobservedZfsMutation, ZfsHelperError> {
        let context = persisted_context(store, operation_id)?;
        if context.entry.phase() != DurableStoragePhase::Prepared {
            return Err(StorageStateError::InvalidTransition.into());
        }
        let transaction = ZfsTransaction::from_catalog(context.operation, &context.catalog)?;
        let expected_preconditions = all_preconditions(&transaction);
        let program = sealed_program(&self.contract, &context);
        let observed = match receiving {
            Some(receiving) => {
                let mut physical = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::state(
                    receiving, store.recovery_encoding_journal_v1(),
                );
                self.backend.observe_preconditions_receiving_v1(&program, &expected_preconditions, &mut physical)
            }
            None => self.backend.observe_preconditions(&program, &expected_preconditions),
        }?;
        if observed != expected_preconditions {
            return Err(ZfsHelperError::PreconditionMismatch);
        }
        Ok(PreobservedZfsMutation { context })
    }

    /// Crosses Ambiguous, dispatches exactly once, then observes the result.
    pub(crate) fn execute_preobserved<F>(
        &mut self,
        store: &mut StorageTransactionStore,
        prepared: PreobservedZfsMutation,
        authority: FreshStorageEffectAuthority,
        check_after_ambiguous: F,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError>
    where
        F: FnMut() -> Result<(), ZfsHelperError>,
    {
        self.execute_preobserved_inner_v1(store, prepared, authority, check_after_ambiguous, None)
    }

    pub(crate) fn execute_preobserved_receiving_v1<F>(
        &mut self,
        store: &mut StorageTransactionStore,
        prepared: PreobservedZfsMutation,
        authority: FreshStorageEffectAuthority,
        check_after_ambiguous: F,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError>
    where
        F: FnMut() -> Result<(), ZfsHelperError>,
    {
        receiving.require_models_current_v1(store.recovery_encoding_journal_v1())
            .map_err(|_| StorageStateError::Receiving)?;
        self.execute_preobserved_inner_v1(store, prepared, authority, check_after_ambiguous, Some(receiving))
    }

    fn execute_preobserved_inner_v1<F>(
        &mut self,
        store: &mut StorageTransactionStore,
        prepared: PreobservedZfsMutation,
        authority: FreshStorageEffectAuthority,
        mut check_after_ambiguous: F,
        mut receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError>
    where
        F: FnMut() -> Result<(), ZfsHelperError>,
    {
        if authority.entry() != prepared.context.entry {
            return Err(StorageStateError::InvalidTransition.into());
        }
        let current = persisted_context(store, prepared.context.entry.operation_id())?;
        if current.entry != prepared.context.entry
            || current.catalog != prepared.context.catalog
            || current.operation != prepared.context.operation
        {
            return Err(StorageStateError::InvalidTransition.into());
        }
        store.validate_mutation_exact(
            current.entry.operation_id(),
            current.entry.request_digest(),
            current.entry.mutation_digest(),
            &current.catalog,
        )?;
        match receiving.as_deref_mut() {
            Some(receiving) => store.mark_mutation_ambiguous_exact_receiving_v1(
                current.entry.operation_id(), current.entry.request_digest(),
                current.entry.mutation_digest(), &current.catalog, receiving,
            ),
            None => store.mark_mutation_ambiguous_exact(
                current.entry.operation_id(), current.entry.request_digest(),
                current.entry.mutation_digest(), &current.catalog,
            ),
        }?;

        // The durable sync may outlive the first authority sample. Failure of
        // this second sample deliberately leaves Ambiguous for observation-only
        // recovery; dispatch must never resume from that phase.
        check_after_ambiguous()?;

        match receiving {
            Some(receiving) => {
                self.execute_process_receiving_v1(&current, store.recovery_encoding_journal_v1(), receiving)?;
                // The same held Store is still exclusive. Reusing its existing
                // observer/commit engine revalidates this Ambiguous context;
                // no fresh effect authority or second dispatch is created.
                self.observe_only_receiving_v1(store, current.entry.operation_id(), receiving)
            }
            None => {
                let program = sealed_program(&self.contract, &current);
                validate_process_output(self.backend.execute_once(&program)?)?;
                self.observe_postcondition(store, &current, DurableStoragePhase::Ambiguous)
            }
        }
    }

    fn execute_process_receiving_v1(
        &mut self,
        context: &PersistedZfsMutation,
        journal: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), ZfsHelperError> {
        // Borrow the executable only inside this helper. The caller retains
        // the same persisted context; backend/result fields remain disjoint.
        let program = sealed_program(&self.contract, context);
        let result = (|| {
            self.recovery_results.prepare_mutation_v1(receiving,
                self.contract.executable().as_os_str().as_encoded_bytes().len())?;
            let output = {
                let mut physical = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::state(receiving, journal);
                self.backend.execute_once_receiving_v1(&program, &mut physical)
            };
            self.recovery_results.outputs.push(output);
            let Some(Ok(output)) = self.recovery_results.outputs.last() else {
                return Err(StorageStateError::Receiving.into());
            };
            let validation = validate_process_output_ref_v1(output);
            let positive = validation.is_ok();
            self.recovery_results.interpretations.push(
                recovery_results::HelperOutputInterpretationV1::Mutation(validation),
            );
            if positive { Ok(()) } else { Err(StorageStateError::Receiving.into()) }
        })();
        if result.is_err() {
            self.recovery_failure = Some(RecoveryHelperFailureV1::ReturnedOutput);
        }
        result
    }

    /// Re-observes current Prepared or Ambiguous state without dispatching.
    pub(crate) fn observe_only(
        &mut self,
        store: &mut StorageTransactionStore,
        operation_id: [u8; 16],
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        let mut original = recovery_observation::ObservationOriginalV1::new();
        original.run(&mut self.backend, &self.contract, store, operation_id, None);
        original.take_ordinary_result()
    }

    pub(crate) fn observe_only_receiving_v1(
        &mut self,
        store: &mut StorageTransactionStore,
        operation_id: [u8; 16],
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        if self.recovery_receiving_failure_v1().is_some() {
            return Err(StorageStateError::Receiving.into());
        }
        let result = self.recovery_observations.capture(
            &mut self.backend, &self.contract, store, operation_id, receiving,
        );
        if result.is_err() {
            self.recovery_failure = Some(RecoveryHelperFailureV1::Observation);
        }
        result
    }

    fn observe_postcondition(
        &mut self,
        store: &mut StorageTransactionStore,
        context: &PersistedZfsMutation,
        phase: DurableStoragePhase,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        let mut original = recovery_observation::PostOriginalV1::new();
        match original.run(&mut self.backend, &self.contract, store, context, phase, None) {
            Ok(outcome) => Ok(outcome),
            Err(()) => Err(original.take_failure()),
        }
    }
}

fn parse_atomic_snapshot_output_v1(
    program: &crate::DormantAtomicDatasetSnapshotV1,
    output: &ZfsProcessOutput,
) -> Result<ObservedAtomicSnapshotGroupV1, ZfsHelperError> {
    let mut interpretation = recovery_results::AtomicInterpretationOriginalV1::new();
    match interpretation.run(program, output, false) {
        Ok(observed) => Ok(observed),
        Err(()) => Err(interpretation.take_failure()),
    }
}

fn persisted_context(
    store: &StorageTransactionStore,
    operation_id: [u8; 16],
) -> Result<PersistedZfsMutation, ZfsHelperError> {
    recovery_observation::context_ordinary(store, operation_id)
}

fn sealed_program<'a>(
    contract: &'a ZfsHelperContract,
    context: &'a PersistedZfsMutation,
) -> SealedZfsProgram<'a> {
    SealedZfsProgram {
        executable: contract.executable(),
        operation: context.operation,
        catalog: &context.catalog,
        environment_is_empty: true,
        inherited_descriptor_count: 0,
        maximum_stdout_bytes: MAXIMUM_STDOUT_BYTES,
        maximum_stderr_bytes: MAXIMUM_STDERR_BYTES,
        process_tree_timeout: PROCESS_TREE_TIMEOUT,
    }
}

fn all_preconditions(transaction: &ZfsTransaction) -> Vec<ZfsPrecondition> {
    let mut values = transaction.preconditions().to_vec();
    if let Some(ancestor) = transaction.ancestor_transaction() {
        values.push(ancestor.precondition().clone());
    }
    values
}

fn validate_process_output(output: ZfsProcessOutput) -> Result<(), ZfsHelperError> {
    validate_process_output_ref_v1(&output)
}

fn validate_process_output_ref_v1(output: &ZfsProcessOutput) -> Result<(), ZfsHelperError> {
    if output.timed_out
        || !output.success
        || output.stdout.len() > MAXIMUM_STDOUT_BYTES
        || output.stderr.len() > MAXIMUM_STDERR_BYTES
    {
        Err(ZfsHelperError::ProcessContract)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tempfile::TempDir;

    use super::*;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageDomainsV1, StorageStateKey,
        WorkspaceSpacePolicyV1,
    };

    pub(super) struct FakeBackend {
        preconditions_match: bool,
        precondition_observation_count: usize,
        execute_count: usize,
        fail_execution: bool,
        oversized_output: bool,
        observation: Option<ZfsPostconditionObservation>,
    }

    impl ZfsProcessBackend for FakeBackend {
        fn observe_preconditions(
            &mut self,
            _program: &SealedZfsProgram<'_>,
            expected: &[ZfsPrecondition],
        ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
            self.precondition_observation_count += 1;
            if self.preconditions_match {
                Ok(expected.to_vec())
            } else {
                Ok(Vec::new())
            }
        }

        fn execute_once(
            &mut self,
            program: &SealedZfsProgram<'_>,
        ) -> Result<ZfsProcessOutput, ZfsHelperError> {
            assert!(program.executable.is_absolute());
            let transaction =
                ZfsTransaction::from_catalog(program.operation, program.catalog).unwrap();
            assert!(!transaction.mutation_arguments().is_empty());
            assert!(transaction.ancestor_transaction().is_some());
            assert!(program.environment_is_empty);
            assert_eq!(program.inherited_descriptor_count, 0);
            assert_eq!(program.maximum_stdout_bytes, MAXIMUM_STDOUT_BYTES);
            assert_eq!(program.maximum_stderr_bytes, MAXIMUM_STDERR_BYTES);
            assert_eq!(program.process_tree_timeout, PROCESS_TREE_TIMEOUT);
            self.execute_count += 1;
            if self.fail_execution {
                return Err(ZfsHelperError::ProcessContract);
            }
            Ok(ZfsProcessOutput {
                stdout: vec![
                    0;
                    if self.oversized_output {
                        MAXIMUM_STDOUT_BYTES + 1
                    } else {
                        0
                    }
                ],
                stderr: Vec::new(),
                success: true,
                timed_out: false,
            })
        }

        fn observe_postcondition(
            &mut self,
            _program: &SealedZfsProgram<'_>,
            _expected: &PostconditionPolicyV1,
            _expected_ancestor: Option<&ProjectAncestorPolicyV1>,
        ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
            Ok(self.observation.take())
        }
    }

    pub(super) fn fixture() -> (ResolvedCatalogCommitmentV1, StorageOperation) {
        fixture_named("tank/aos/project/work")
    }

    fn fixture_named(name: &str) -> (ResolvedCatalogCommitmentV1, StorageOperation) {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains)
                .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let destination = PlannedDataset::from_catalog(root, name, domains).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
        (
            ResolvedCatalogCommitmentV1::new_for_test(
                7,
                domains,
                CatalogPlanV1::CreateWorkspace {
                    destination,
                    space,
                    ancestor,
                },
            )
            .unwrap(),
            StorageOperation::CreateWorkspace { quota_bytes: 4096 },
        )
    }

    pub(super) fn open_store(directory: &TempDir) -> StorageTransactionStore {
        StorageTransactionStore::open_for_test(
            directory.path(),
            StorageStateKey::new([1; 16], [2; 32]).unwrap(),
            0,
        )
        .unwrap()
    }

    pub(super) fn backend(catalog: &ResolvedCatalogCommitmentV1) -> FakeBackend {
        FakeBackend {
            preconditions_match: true,
            precondition_observation_count: 0,
            execute_count: 0,
            fail_execution: false,
            oversized_output: false,
            observation: Some(ZfsPostconditionObservation {
                observed: catalog.plan().postcondition(),
                ancestor: match catalog.plan() {
                    CatalogPlanV1::CreateWorkspace { ancestor, .. } => Some(ancestor.clone()),
                    _ => None,
                },
                object_guid: Some(91),
                digest: ObjectDigest::from_bytes([9; 32]),
            }),
        }
    }

    pub(super) fn prepare(
        store: &mut StorageTransactionStore,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> ObjectDigest {
        store
            .initialize_catalog_from_protected_snapshot(
                catalog.generation() - 1,
                std::slice::from_ref(catalog),
            )
            .unwrap();
        let crate::BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin([3; 16], ObjectDigest::from_bytes([4; 32]), catalog)
            .unwrap()
        else {
            panic!("fixture did not prepare")
        };
        mutation_digest
    }

    #[test]
    fn prepared_runs_once_and_commits_full_observation() {
        let directory = TempDir::new().unwrap();
        let (catalog, _) = fixture();
        let mut store = open_store(&directory);
        let mutation = prepare(&mut store, &catalog);
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            backend(&catalog),
        );
        let prepared = helper.preobserve(&store, [3; 16]).unwrap();
        assert_eq!(prepared.entry().mutation_digest(), mutation);
        let authority = FreshStorageEffectAuthority::new_for_test(prepared.entry());
        assert!(matches!(
            helper
                .execute_preobserved(&mut store, prepared, authority, || Ok(()))
                .unwrap(),
            ZfsHelperOutcome::Committed(_)
        ));
        assert_eq!(helper.backend.execute_count, 1);
        assert_eq!(
            store.phase([3; 16]).unwrap(),
            Some(DurableStoragePhase::Committed)
        );
    }

    #[test]
    fn crash_after_ambiguous_never_reexecutes_during_recovery() {
        let directory = TempDir::new().unwrap();
        let (catalog, _) = fixture();
        let mut store = open_store(&directory);
        let mutation = prepare(&mut store, &catalog);
        let mut failed = backend(&catalog);
        failed.fail_execution = true;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            failed,
        );
        let prepared = helper.preobserve(&store, [3; 16]).unwrap();
        let authority = FreshStorageEffectAuthority::new_for_test(prepared.entry());
        assert!(
            helper
                .execute_preobserved(&mut store, prepared, authority, || Ok(()))
                .is_err()
        );
        assert_eq!(
            store.phase([3; 16]).unwrap(),
            Some(DurableStoragePhase::Ambiguous)
        );
        drop(store);

        let mut recovered = open_store(&directory);
        let mut observer = backend(&catalog);
        observer.observation = None;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            observer,
        );
        assert_eq!(
            helper.observe_only(&mut recovered, [3; 16]).unwrap(),
            ZfsHelperOutcome::ObservationRequired {
                phase: DurableStoragePhase::Ambiguous,
                mutation_digest: mutation
            }
        );
        assert_eq!(helper.backend.execute_count, 0);
        assert_eq!(helper.backend.precondition_observation_count, 0);
    }

    #[test]
    fn persisted_context_mismatch_and_oversized_output_fail_closed() {
        let directory = TempDir::new().unwrap();
        let (catalog, _) = fixture();
        let mut store = open_store(&directory);
        prepare(&mut store, &catalog);

        let mut wrong = backend(&catalog);
        wrong.preconditions_match = false;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            wrong,
        );
        assert!(matches!(
            helper.preobserve(&store, [3; 16]),
            Err(ZfsHelperError::PreconditionMismatch)
        ));
        assert_eq!(
            store.phase([3; 16]).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );

        let mut oversized = backend(&catalog);
        oversized.oversized_output = true;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            oversized,
        );
        let prepared = helper.preobserve(&store, [3; 16]).unwrap();
        let authority = FreshStorageEffectAuthority::new_for_test(prepared.entry());
        assert!(matches!(
            helper.execute_preobserved(&mut store, prepared, authority, || Ok(())),
            Err(ZfsHelperError::ProcessContract)
        ));
        assert_eq!(
            store.phase([3; 16]).unwrap(),
            Some(DurableStoragePhase::Ambiguous)
        );
    }
}
