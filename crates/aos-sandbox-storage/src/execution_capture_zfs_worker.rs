//! Closed, two-phase ZFS create effect for retained execution output.
//!
//! A fresh Controller-signed admission, actual Host45 readback, protected
//! AOSEOR03 row and newly committed AOSCOA03 mint the private native owner.
//! The authenticated fixed worker alone reconstructs the closed create/writer
//! recipes; parsed Source or historical attempt DATA cannot enter them. The effect phase observes checkpoint-free headroom and invokes
//! one fixed create command; even a zero exit yields only an ambiguous effect
//! record. A separate cold catalog readback must prove the exact GUID and
//! create operation before any detached mount or writer can be admitted.

use std::ffi::OsString;
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::mount::{DetachedMount, FileSystemContext, MountAttributes};
use aos_sandbox_linux::process::{FixedProcessOutcome, FixedProcessRequest, run_fixed_process};
use sha2::{Digest as _, Sha256};

use crate::ZfsHelperContract;
use crate::catalog_transition::execution_capture::readback::{
    CaptureZfsCreateCommandV1, CaptureZfsPreflightPlanV1, CaptureZfsReadbackErrorV1,
    CaptureZfsReadbackPlanV1, CaptureZfsToolV1, MAXIMUM_MACHINE_OUTPUT_BYTES,
};
use crate::catalog_transition::execution_capture::{
    CaptureDatasetRequirementV1, VerifiedCaptureDatasetV1,
};
use crate::execution_capture_files::{
    CaptureFileCustodyErrorV1, CaptureWriterDirectoryGuardV1, PinnedCaptureDirectoryV1,
};
use crate::execution_capture_writer::{
    CaptureStreamV1, CaptureWriteErrorV1, DetachedCaptureWriterV1, UnboundCaptureWriteResultV1,
};
use crate::execution_output::ProtectedRetainedCaptureV1;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::process::{PinnedCaptureZfsTools, ZfsWorkerError, process_timeout};

mod clock;
pub(crate) use clock::CaptureWorkerClockOriginalV3;

mod create_execution;
pub(crate) use create_execution::CaptureCreateExecutionOriginalV3;

mod preparation;
mod completion;
pub(crate) use completion::CaptureWriterCompletionOriginalV3;
mod issuance;
pub(crate) use issuance::NativeCaptureCreateOriginalV3;
pub(crate) use preparation::CaptureWriterPreparationFailureV2;

const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-create-attempt.v1\0";
const WRITE_RESULT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-detached-write.v1\0";

/// Rejects a stale protected join or a failed pre-effect readback.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureCreateWorkerErrorV1 {
    #[error("capture worker source differs from the authenticated parent: {0}")]
    Source(crate::execution_output::ExecutionOutputLedgerErrorV1),
    #[error("capture create authority is not current")]
    InvalidAttempt,
    #[error("capture create preflight or command is invalid: {0}")]
    Readback(#[from] CaptureZfsReadbackErrorV1),
    #[error("capture create preflight could not be observed: {0}")]
    Observation(#[from] ZfsWorkerError),
}

/// Holds the closed worker recipe under the actual fresh native admission.
///
/// Only the authenticated inherited worker reconstructs it after the genuine
/// parent joins the signed Controller grant, Host45, protected logical output,
/// selected allocation and newly committed attempt on the same Storage F.
pub(crate) struct AuthorizedCaptureCreateAttemptV1 {
    attempt: [u8; 16],
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    durable_attempt_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    retained: ProtectedRetainedCaptureV1,
    requirement: CaptureDatasetRequirementV1,
    preflight: CaptureZfsPreflightPlanV1,
    expected_pool_guid: u64,
}

impl AuthorizedCaptureCreateAttemptV1 {
    pub(crate) fn deadline_data_v3(&self) -> u64 { self.deadline_boottime_nanoseconds }

    fn check_live(&self) -> Result<(), CaptureCreateWorkerErrorV1> {
        let boot_id =
            KernelBootId::current().map_err(|_| CaptureCreateWorkerErrorV1::InvalidAttempt)?;
        let now =
            boottime_now_nanoseconds().map_err(|_| CaptureCreateWorkerErrorV1::InvalidAttempt)?;
        if self.attempt == [0; 16]
            || self.controller_grant_digest.as_bytes() == &[0; 32]
            || self.host_receipt_digest.as_bytes() == &[0; 32]
            || self.durable_attempt_digest.as_bytes() == &[0; 32]
            || self.kernel_boot_id != boot_id.into_bytes()
            || now >= self.deadline_boottime_nanoseconds
        {
            return Err(CaptureCreateWorkerErrorV1::InvalidAttempt);
        }
        Ok(())
    }

    /// Runs preflight and exactly one effect call, never returning create success.
    ///
    /// The backend's effect error is retained alongside the ambiguous
    /// disposition. Once `create` is entered, recovery may only observe; it
    /// cannot infer that no dataset was made from a timeout or nonzero exit.
    #[cfg(test)]
    pub(crate) fn execute_with<B: CaptureCreateBackendV1>(
        self,
        backend: &mut B,
    ) -> Result<CaptureCreateAttemptedV1, CaptureCreateWorkerErrorV1> {
        let mut original = create_execution::CaptureCreateExecutionOriginalV3::new(self);
        original.run_once_v3(backend);
        original.into_ordinary_result_v3()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        retained: ProtectedRetainedCaptureV1,
        requirement: CaptureDatasetRequirementV1,
        preflight: CaptureZfsPreflightPlanV1,
    ) -> Self {
        let now = boottime_now_nanoseconds().unwrap();
        Self {
            attempt: [6; 16],
            controller_grant_digest: ObjectDigest::from_bytes([7; 32]),
            host_receipt_digest: ObjectDigest::from_bytes([8; 32]),
            durable_attempt_digest: ObjectDigest::from_bytes([9; 32]),
            kernel_boot_id: KernelBootId::current().unwrap().into_bytes(),
            deadline_boottime_nanoseconds: now + 30_000_000_000,
            retained,
            requirement,
            preflight,
            expected_pool_guid: 17,
        }
    }
}

/// Supplies only fixed, bounded OpenZFS observations and one create attempt.
pub(crate) trait CaptureCreateBackendV1 {
    fn observe_preflight(
        &mut self,
        authorized: &AuthorizedCaptureCreateAttemptV1,
        plan: &CaptureZfsPreflightPlanV1,
    ) -> Result<[Vec<u8>; 2], ZfsWorkerError>;

    fn create(
        &mut self,
        authorized: &AuthorizedCaptureCreateAttemptV1,
        command: &CaptureZfsCreateCommandV1,
    ) -> Result<bool, ZfsWorkerError>;
}

/// Records only that the ZFS create command may have changed physical state.
///
/// Neither this value nor a reported zero exit authorizes a mount, retained
/// output result, or Host dispatch. The Storage catalog must cold-observe the
/// exact create operation and GUID, then the worker must perform current ZFS
/// quota, reservation, checkpoint, and headroom readback again.
pub(crate) struct CaptureCreateAttemptedV1 {
    pub(crate) attempt: [u8; 16],
    pub(crate) record_digest: ObjectDigest,
    pub(crate) storage_create_operation: aos_sandbox_core::OperationId,
    pub(crate) controller_grant_digest: ObjectDigest,
    pub(crate) host_receipt_digest: ObjectDigest,
    pub(crate) durable_attempt_digest: ObjectDigest,
    pub(crate) kernel_boot_id: [u8; 16],
    pub(crate) deadline_boottime_nanoseconds: u64,
    pub(crate) preflight_digest: ObjectDigest,
    pub(crate) command_digest: ObjectDigest,
    pub(crate) reported_zero_exit: bool,
    effect_result: Result<bool, ZfsWorkerError>,
    pub(crate) attempt_digest: ObjectDigest,
}

impl CaptureCreateAttemptedV1 {
    /// Borrows the actual failed effect call without asserting no effect.
    pub(crate) fn effect_failure_v2(&self) -> Option<&ZfsWorkerError> {
        self.effect_result.as_ref().err()
    }
}

/// Rejects an unqualified detached mount, writer failure, or stale ZFS state.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureWriterWorkerErrorV1 {
    #[error("capture protected source changed: {0}")]
    Source(#[from] crate::execution_output::ExecutionOutputLedgerErrorV1),
    #[error("capture catalog association changed: {0}")]
    Dataset(#[from] crate::catalog_transition::execution_capture::ExecutionCaptureDatasetErrorV1),
    #[error("capture writer attempt is not current")]
    InvalidAttempt,
    #[error("capture writer ZFS readback is invalid: {0}")]
    Readback(#[from] CaptureZfsReadbackErrorV1),
    #[error("capture writer fixed ZFS observation failed: {0}")]
    Zfs(#[from] ZfsWorkerError),
    #[error("capture writer detached mount failed: {0}")]
    Mount(#[from] aos_sandbox_linux::Error),
    #[error("capture writer root descriptor failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("capture writer file namespace failed: {0}")]
    Files(#[from] CaptureFileCustodyErrorV1),
    #[error("capture writer bounded stream failed: {0}")]
    Writer(#[from] CaptureWriteErrorV1),
}

/// Retains the exact catalog and AOSEOR03 join for a detached writer phase.
///
/// Its private constructor requires the actual authenticated child context
/// and same-parent catalog handoff. The parent retains the fresh admission,
/// whole catalog replay and exact Output physical-row commit/readback.
pub(crate) struct AuthorizedCaptureWriterAttemptV1 {
    attempt: [u8; 16],
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    durable_attempt_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    retained: ProtectedRetainedCaptureV1,
    verified: VerifiedCaptureDatasetV1,
    ongoing_source: Option<ObjectDigest>,
    metadata_headroom_bytes: u64,
    minimum_remaining_bytes: u64,
}

impl AuthorizedCaptureWriterAttemptV1 {
    pub(crate) fn from_authenticated_catalog_v3(
        context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
        catalog: &crate::process::capture_worker::CaptureWorkerCatalogOriginalV3,
    ) -> Result<Self, CaptureWriterWorkerErrorV1> {
        let verified = CaptureDatasetRequirementV1::from_authenticated_worker_catalog_v3(context, catalog)?;
        let (retained, attempt, controller, host, durable, boot, deadline) =
            crate::execution_output::capture_worker_inputs_v3(context)?;
        Ok(Self { attempt, controller_grant_digest: controller, host_receipt_digest: host,
            durable_attempt_digest: durable, kernel_boot_id: boot,
            deadline_boottime_nanoseconds: deadline, retained, verified,
            ongoing_source: Some(context.source_v3().source_digest_v2()),
            metadata_headroom_bytes: context.metadata_headroom_v3(),
            minimum_remaining_bytes: context.remaining_floor_v3() })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        retained: ProtectedRetainedCaptureV1,
        verified: VerifiedCaptureDatasetV1,
    ) -> Self {
        Self {
            attempt: [6; 16],
            controller_grant_digest: ObjectDigest::from_bytes([7; 32]),
            host_receipt_digest: ObjectDigest::from_bytes([8; 32]),
            durable_attempt_digest: ObjectDigest::from_bytes([9; 32]),
            kernel_boot_id: KernelBootId::current().unwrap().into_bytes(),
            deadline_boottime_nanoseconds: boottime_now_nanoseconds().unwrap() + 30_000_000_000,
            retained,
            verified,
            ongoing_source: None,
            metadata_headroom_bytes: 20,
            minimum_remaining_bytes: 100,
        }
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.deadline_boottime_nanoseconds = 1;
    }

    fn check_live(&self) -> Result<(), CaptureWriterWorkerErrorV1> {
        let boot_id =
            KernelBootId::current().map_err(|_| CaptureWriterWorkerErrorV1::InvalidAttempt)?;
        let now =
            boottime_now_nanoseconds().map_err(|_| CaptureWriterWorkerErrorV1::InvalidAttempt)?;
        if self.attempt == [0; 16]
            || self.controller_grant_digest.as_bytes() == &[0; 32]
            || self.host_receipt_digest.as_bytes() == &[0; 32]
            || self.durable_attempt_digest.as_bytes() == &[0; 32]
            || self.kernel_boot_id != boot_id.into_bytes()
            || now >= self.deadline_boottime_nanoseconds
        {
            return Err(CaptureWriterWorkerErrorV1::InvalidAttempt);
        }
        Ok(())
    }

    /// Exposes only the already-authenticated tuple to the file-custody owner.
    pub(crate) fn file_custody_binding(
        &self,
    ) -> (
        [u8; 16],
        ObjectDigest,
        ObjectDigest,
        ObjectDigest,
        ObjectDigest,
    ) {
        (
            self.attempt,
            self.controller_grant_digest,
            self.host_receipt_digest,
            self.retained.record_digest(),
            self.verified.binding(),
        )
    }

    pub(crate) fn prepare_detached_in_scope_v3(
        self,
        zfs: &ZfsHelperContract,
        execution: &mut crate::process::worker_aggregate::WorkerExecutionScopeV1<'_>,
        context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
    ) -> Result<PreparedDetachedCaptureWriterV1, CaptureWriterPreparationFailureV2> {
        preparation::prepare_in_scope_v3(self, zfs, execution, context)
    }

    /// Probes current ZFS state and opens an unpublished, secure ZFS mount.
    ///
    /// An already occupied claim, changed mount identity, unexpected root
    /// owner, or unavailable reservation leaves no success-shaped writer.
    #[cfg(test)]
    pub(crate) fn prepare_detached(
        self,
        zfs: &ZfsHelperContract,
    ) -> Result<PreparedDetachedCaptureWriterV1, CaptureWriterWorkerErrorV1> {
        preparation::prepare_ordinary_v3(self, zfs)
    }

    /// Runs the same detached preparation while parking every reached native owner.
    #[cfg(test)]
    pub(crate) fn prepare_detached_retaining_v2(
        self,
        zfs: &ZfsHelperContract,
    ) -> Result<PreparedDetachedCaptureWriterV1, CaptureWriterPreparationFailureV2> {
        preparation::prepare_retaining_v2(self, zfs)
    }
}

/// Keeps the unpublished mount and exclusive namespace pinned through EOF.
pub(crate) struct PreparedDetachedCaptureWriterV1 {
    authority: AuthorizedCaptureWriterAttemptV1,
    detached: DetachedMount,
    writer: DetachedCaptureWriterV1,
    guard: CaptureWriterDirectoryGuardV1,
    before_observation_digest: ObjectDigest,
    mounted_observation_digest: ObjectDigest,
}

pub(crate) struct CaptureMountedWriterDataV3 {
    pub(crate) source: ObjectDigest,
    pub(crate) durable: ObjectDigest,
    pub(crate) dataset_binding: ObjectDigest,
    pub(crate) mount_id: u64,
    pub(crate) before: ObjectDigest,
    pub(crate) mounted: ObjectDigest,
}

impl PreparedDetachedCaptureWriterV1 {
    pub(crate) fn native_io_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.writer.native_io_failure_v3()
    }

    pub(crate) fn mounted_data_v3(
        &self,
        context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
    ) -> Result<CaptureMountedWriterDataV3, CaptureWriterWorkerErrorV1> {
        let (_, _, _, _, durable, _, cutoff) = crate::execution_output::capture_worker_inputs_v3(context)?;
        if self.authority.ongoing_source != Some(context.source_v3().source_digest_v2())
            || self.authority.durable_attempt_digest != durable
            || self.authority.deadline_boottime_nanoseconds != cutoff
        { return Err(CaptureWriterWorkerErrorV1::InvalidAttempt); }
        Ok(CaptureMountedWriterDataV3 {
            source: context.source_v3().source_digest_v2(), durable,
            dataset_binding: self.authority.verified.binding(), mount_id: self.detached.mount_id().get(),
            before: self.before_observation_digest, mounted: self.mounted_observation_digest,
        })
    }

    pub(crate) fn consume_native_drain_read_v3(
        &mut self,
        read: crate::process::capture_worker::CaptureDrainReadBorrowV3<'_>,
    ) -> Result<(), CaptureWriterWorkerErrorV1> {
        if self.authority.ongoing_source != Some(read.source_v3())
            || self.authority.durable_attempt_digest != read.durable_v3()
            || self.authority.deadline_boottime_nanoseconds != read.cutoff_v3()
        { return Err(CaptureWriterWorkerErrorV1::InvalidAttempt); }
        if read.chunk_v3().is_empty() {
            self.writer.finish_stream(read.stream_v3())?;
        } else {
            self.writer.write_chunk(read.stream_v3(), read.chunk_v3())?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn write_chunk(
        &mut self,
        stream: CaptureStreamV1,
        chunk: &[u8],
    ) -> Result<(), CaptureWriterWorkerErrorV1> {
        self.authority.check_live()?;
        self.writer.write_chunk(stream, chunk)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn finish_stream(
        &mut self,
        stream: CaptureStreamV1,
    ) -> Result<(), CaptureWriterWorkerErrorV1> {
        self.authority.check_live()?;
        self.writer.finish_stream(stream)?;
        Ok(())
    }

    /// Runs the sole completion engine for the established local fixtures.
    #[cfg(test)]
    pub(crate) fn finish(
        self,
        zfs: &ZfsHelperContract,
    ) -> Result<UnboundCaptureWorkerResultV1, CaptureWriterWorkerErrorV1> {
        let mut original = completion::CaptureWriterCompletionOriginalV3::from_prepared_v3(self);
        original.run_once_v3(zfs, None);
        original.into_ordinary_result_v3()
    }

}

/// Contains physical observations and bytes without signed broker provenance.
pub(crate) struct UnboundCaptureWorkerResultV1 {
    pub(crate) attempt: [u8; 16],
    pub(crate) record_digest: ObjectDigest,
    pub(crate) dataset_binding: ObjectDigest,
    pub(crate) mount_id: u64,
    pub(crate) before_observation_digest: ObjectDigest,
    pub(crate) mounted_observation_digest: ObjectDigest,
    pub(crate) after_observation_digest: ObjectDigest,
    pub(crate) written: UnboundCaptureWriteResultV1,
    pub(crate) result_digest: ObjectDigest,
}


pub(crate) struct CaptureWorkerResultIdentityDataV3 {
    pub(crate) attempt: [u8; 16],
    pub(crate) controller: ObjectDigest,
    pub(crate) host: ObjectDigest,
    pub(crate) durable: ObjectDigest,
}

impl UnboundCaptureWorkerResultV1 {
    pub(crate) fn result_digest_data_v3(&self, identity: &CaptureWorkerResultIdentityDataV3) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(WRITE_RESULT_DOMAIN);
        digest.update(identity.attempt);
        digest.update(identity.controller.as_bytes());
        digest.update(identity.host.as_bytes());
        digest.update(identity.durable.as_bytes());
        digest.update(self.dataset_binding.as_bytes());
        digest.update(self.before_observation_digest.as_bytes());
        digest.update(self.mounted_observation_digest.as_bytes());
        digest.update(self.mount_id.to_be_bytes());
        digest.update(self.written.result_digest.as_bytes());
        digest.update(self.after_observation_digest.as_bytes());
        ObjectDigest::from_bytes(digest.finalize().into())
    }
}
