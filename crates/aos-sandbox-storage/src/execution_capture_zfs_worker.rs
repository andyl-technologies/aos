//! Closed, two-phase ZFS create effect for retained execution output.
//!
//! An independently authenticated Controller Storage grant, Host output
//! receipt, current AOSEOR03 record, and durably prepared Storage attempt must
//! eventually mint [`AuthorizedCaptureCreateAttemptV1`]. No production issuer
//! exists yet. The effect phase observes checkpoint-free headroom and invokes
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
use crate::process::{PinnedExecutable, ZfsWorkerError, process_timeout};

const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-create-attempt.v1\0";
const WRITE_RESULT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-detached-write.v1\0";

/// Rejects a stale protected join or a failed pre-effect readback.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureCreateWorkerErrorV1 {
    #[error("capture create authority is not current")]
    InvalidAttempt,
    #[error("capture create preflight or command is invalid: {0}")]
    Readback(#[from] CaptureZfsReadbackErrorV1),
    #[error("capture create preflight could not be observed: {0}")]
    Observation(#[from] ZfsWorkerError),
}

/// Holds a future signed-grant and receipt join under a durable attempt.
///
/// All fields are private, and there is no production constructor. The future
/// issuer must validate the exact Controller grant, Host receipt, protected
/// AOSEOR03 readback, selected ZFS root and allocation, boot/deadline, and
/// durable effect-scheduled record before constructing this type.
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
}

impl AuthorizedCaptureCreateAttemptV1 {
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
    /// The backend's effect error is deliberately folded into an ambiguous
    /// disposition. Once `create` is entered, recovery may only observe; it
    /// cannot infer that no dataset was made from a timeout or nonzero exit.
    pub(crate) fn execute_with<B: CaptureCreateBackendV1>(
        self,
        backend: &mut B,
    ) -> Result<CaptureCreateAttemptedV1, CaptureCreateWorkerErrorV1> {
        self.check_live()?;
        let outputs = backend.observe_preflight(&self, &self.preflight)?;
        let observed = self.preflight.evaluate([&outputs[0], &outputs[1]])?;
        let command = CaptureZfsCreateCommandV1::new(&self.requirement, &self.retained, &observed)?;
        self.check_live()?;

        let reported_zero_exit = backend.create(&self, &command).unwrap_or(false);
        let mut digest = Sha256::new();
        digest.update(ATTEMPT_DOMAIN);
        digest.update(self.attempt);
        digest.update(self.controller_grant_digest.as_bytes());
        digest.update(self.host_receipt_digest.as_bytes());
        digest.update(self.durable_attempt_digest.as_bytes());
        digest.update(self.kernel_boot_id);
        digest.update(self.deadline_boottime_nanoseconds.to_be_bytes());
        digest.update(command.record_digest.as_bytes());
        digest.update(command.storage_create_operation.as_bytes());
        digest.update(command.preflight_digest.as_bytes());
        digest.update(command.command_digest.as_bytes());
        digest.update([u8::from(reported_zero_exit)]);

        Ok(CaptureCreateAttemptedV1 {
            attempt: self.attempt,
            record_digest: command.record_digest,
            storage_create_operation: command.storage_create_operation,
            controller_grant_digest: self.controller_grant_digest,
            host_receipt_digest: self.host_receipt_digest,
            durable_attempt_digest: self.durable_attempt_digest,
            kernel_boot_id: self.kernel_boot_id,
            deadline_boottime_nanoseconds: self.deadline_boottime_nanoseconds,
            preflight_digest: command.preflight_digest,
            command_digest: command.command_digest,
            reported_zero_exit,
            attempt_digest: ObjectDigest::from_bytes(digest.finalize().into()),
        })
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
    pub(crate) attempt_digest: ObjectDigest,
}

/// Runs pinned AOS-store commands only after a dedicated worker receives a permit.
///
/// The installed Storage broker does not invoke this entry point and has no
/// CAP_SYS_ADMIN. A future dedicated process must independently authenticate
/// its own cgroup/peer provenance and the durable permit issuer.
pub(crate) fn run_capture_create_for(
    authorized: AuthorizedCaptureCreateAttemptV1,
    zfs: &ZfsHelperContract,
) -> Result<CaptureCreateAttemptedV1, CaptureCreateWorkerErrorV1> {
    authorized.check_live()?;
    let mut backend = FixedCaptureCreateBackendV1::new(zfs)?;
    authorized.execute_with(&mut backend)
}

struct FixedCaptureCreateBackendV1<'a> {
    zfs: &'a ZfsHelperContract,
    zpool: ZfsHelperContract,
    zfs_pin: PinnedExecutable,
    zpool_pin: PinnedExecutable,
}

impl<'a> FixedCaptureCreateBackendV1<'a> {
    fn new(zfs: &'a ZfsHelperContract) -> Result<Self, ZfsWorkerError> {
        if zfs
            .executable()
            .file_name()
            .is_none_or(|name| name != "zfs")
        {
            return Err(ZfsWorkerError::Executable(
                "capture create requires the fixed AOS zfs executable".to_owned(),
            ));
        }
        let zpool = ZfsHelperContract::new(zfs.executable().with_file_name("zpool"))?;
        let zfs_pin = PinnedExecutable::open(zfs)?;
        let zpool_pin = PinnedExecutable::open(&zpool)?;
        Ok(Self {
            zfs,
            zpool,
            zfs_pin,
            zpool_pin,
        })
    }

    fn remaining(
        authorized: &AuthorizedCaptureCreateAttemptV1,
    ) -> Result<Duration, ZfsWorkerError> {
        let now = boottime_now_nanoseconds()?;
        let nanoseconds = authorized
            .deadline_boottime_nanoseconds
            .checked_sub(now)
            .filter(|remaining| *remaining != 0)
            .ok_or(ZfsWorkerError::Authority)?;
        Ok(Duration::from_nanos(nanoseconds).min(process_timeout()))
    }
}

impl CaptureCreateBackendV1 for FixedCaptureCreateBackendV1<'_> {
    fn observe_preflight(
        &mut self,
        authorized: &AuthorizedCaptureCreateAttemptV1,
        plan: &CaptureZfsPreflightPlanV1,
    ) -> Result<[Vec<u8>; 2], ZfsWorkerError> {
        let mut outputs = Vec::with_capacity(2);
        for command in plan.commands() {
            let (contract, pin) = match command.tool {
                CaptureZfsToolV1::Zpool => (&self.zpool, &self.zpool_pin),
                CaptureZfsToolV1::Zfs => (self.zfs, &self.zfs_pin),
            };
            pin.validate_current(contract)?;
            let arguments: Vec<OsString> = command.arguments.iter().map(OsString::from).collect();
            let output = run_fixed_process(FixedProcessRequest {
                executable: contract.executable(),
                arguments: &arguments,
                timeout: Self::remaining(authorized)?,
                maximum_stdout_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
                maximum_stderr_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
            })?;
            match output {
                FixedProcessOutcome::Completed(output)
                    if output.exit_code == Some(0)
                        && output.signal.is_none()
                        && output.stderr.is_empty() =>
                {
                    outputs.push(output.stdout);
                }
                _ => return Err(ZfsWorkerError::Protocol("capture preflight command failed")),
            }
        }
        self.zfs_pin.validate_current(self.zfs)?;
        self.zpool_pin.validate_current(&self.zpool)?;
        outputs
            .try_into()
            .map_err(|_| ZfsWorkerError::Protocol("capture preflight is incomplete"))
    }

    fn create(
        &mut self,
        authorized: &AuthorizedCaptureCreateAttemptV1,
        command: &CaptureZfsCreateCommandV1,
    ) -> Result<bool, ZfsWorkerError> {
        self.zfs_pin.validate_current(self.zfs)?;
        self.zpool_pin.validate_current(&self.zpool)?;
        let arguments: Vec<OsString> = command.arguments.iter().map(OsString::from).collect();
        let output = run_fixed_process(FixedProcessRequest {
            executable: self.zfs.executable(),
            arguments: &arguments,
            timeout: Self::remaining(authorized)?,
            maximum_stdout_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
            maximum_stderr_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
        })?;
        self.zfs_pin.validate_current(self.zfs)?;
        self.zpool_pin.validate_current(&self.zpool)?;
        Ok(matches!(
            output,
            FixedProcessOutcome::Completed(output)
                if output.exit_code == Some(0)
                    && output.signal.is_none()
                    && output.stdout.is_empty()
                    && output.stderr.is_empty()
        ))
    }
}

/// Rejects an unqualified detached mount, writer failure, or stale ZFS state.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureWriterWorkerErrorV1 {
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
/// No production constructor exists. The future issuer must cold-read the
/// committed physical binding, independently authenticate the signed
/// Controller Storage grant and Host receipt, and prove a durable one-shot
/// writer attempt before constructing this token.
pub(crate) struct AuthorizedCaptureWriterAttemptV1 {
    attempt: [u8; 16],
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    durable_attempt_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    retained: ProtectedRetainedCaptureV1,
    verified: VerifiedCaptureDatasetV1,
    metadata_headroom_bytes: u64,
    minimum_remaining_bytes: u64,
}

impl AuthorizedCaptureWriterAttemptV1 {
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

    /// Probes current ZFS state and opens an unpublished, secure ZFS mount.
    ///
    /// An already occupied claim, changed mount identity, unexpected root
    /// owner, or unavailable reservation leaves no success-shaped writer.
    pub(crate) fn prepare_detached(
        self,
        zfs: &ZfsHelperContract,
    ) -> Result<PreparedDetachedCaptureWriterV1, CaptureWriterWorkerErrorV1> {
        self.check_live()?;
        let readback_plan = CaptureZfsReadbackPlanV1::new(
            &self.verified,
            &self.retained,
            self.metadata_headroom_bytes,
            self.minimum_remaining_bytes,
        )?;
        let before = crate::process::observe_capture_zfs_for(zfs, &readback_plan)?;
        self.check_live()?;

        let mut filesystem = FileSystemContext::open("zfs")?;
        filesystem.set_string("source", self.verified.dataset_name())?;
        let detached = filesystem.create()?.mount()?;
        detached.set_attributes(
            false,
            MountAttributes::secure_writable().with_no_exec(true),
            None,
        )?;
        let directory = rustix::fs::openat(
            detached.as_fd(),
            ".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let original = rustix::fs::fstat(&directory)?;
        if rustix::fs::FileType::from_raw_mode(original.st_mode) != rustix::fs::FileType::Directory
            || original.st_uid != 0
            || original.st_dev == 0
            || original.st_ino == 0
        {
            return Err(CaptureWriterWorkerErrorV1::InvalidAttempt);
        }
        rustix::fs::fchmod(&directory, rustix::fs::Mode::from_raw_mode(0o700))?;
        rustix::fs::fsync(&directory)?;
        let after = rustix::fs::fstat(&directory)?;
        if after.st_dev != original.st_dev
            || after.st_ino != original.st_ino
            || after.st_uid != 0
            || after.st_mode & 0o7777 != 0o700
        {
            return Err(CaptureWriterWorkerErrorV1::InvalidAttempt);
        }

        // A same-name replacement between the first probe and fsopen must
        // not become this execution's backing. A platform that reports a
        // detached mount as mounted remains closed pending qualification.
        let mounted_readback = crate::process::observe_capture_zfs_for(zfs, &readback_plan)?;
        self.check_live()?;

        let pin =
            PinnedCaptureDirectoryV1::from_authorized_detached_root(&self, &detached, directory)?;
        let files = pin.claim_files()?;
        let (writer, guard) = files.into_writer(&self.retained)?;
        self.check_live()?;
        Ok(PreparedDetachedCaptureWriterV1 {
            authority: self,
            detached,
            writer,
            guard,
            before_observation_digest: before.observation_digest,
            mounted_observation_digest: mounted_readback.observation_digest,
        })
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

impl PreparedDetachedCaptureWriterV1 {
    pub(crate) fn write_chunk(
        &mut self,
        stream: CaptureStreamV1,
        chunk: &[u8],
    ) -> Result<(), CaptureWriterWorkerErrorV1> {
        self.authority.check_live()?;
        self.writer.write_chunk(stream, chunk)?;
        Ok(())
    }

    pub(crate) fn finish_stream(
        &mut self,
        stream: CaptureStreamV1,
    ) -> Result<(), CaptureWriterWorkerErrorV1> {
        self.authority.check_live()?;
        self.writer.finish_stream(stream)?;
        Ok(())
    }

    /// Returns only an unbound result after EOF, sync, and current ZFS readback.
    pub(crate) fn finish(
        self,
        zfs: &ZfsHelperContract,
    ) -> Result<UnboundCaptureWorkerResultV1, CaptureWriterWorkerErrorV1> {
        self.authority.check_live()?;
        let written = self.writer.finish()?;
        self.guard.sync_after_write()?;
        let mount_id = self.detached.mount_id().get();
        drop(self.guard);
        drop(self.detached);

        let after_plan = CaptureZfsReadbackPlanV1::after_write(
            &self.authority.verified,
            &self.authority.retained,
            &written,
            self.authority.metadata_headroom_bytes,
            self.authority.minimum_remaining_bytes,
        )?;
        let after = crate::process::observe_capture_zfs_for(zfs, &after_plan)?;
        self.authority.check_live()?;

        let mut digest = Sha256::new();
        digest.update(WRITE_RESULT_DOMAIN);
        digest.update(self.authority.attempt);
        digest.update(self.authority.controller_grant_digest.as_bytes());
        digest.update(self.authority.host_receipt_digest.as_bytes());
        digest.update(self.authority.durable_attempt_digest.as_bytes());
        digest.update(self.authority.verified.binding().as_bytes());
        digest.update(self.before_observation_digest.as_bytes());
        digest.update(self.mounted_observation_digest.as_bytes());
        digest.update(mount_id.to_be_bytes());
        digest.update(written.result_digest.as_bytes());
        digest.update(after.observation_digest.as_bytes());

        Ok(UnboundCaptureWorkerResultV1 {
            attempt: self.authority.attempt,
            record_digest: self.authority.retained.record_digest(),
            dataset_binding: self.authority.verified.binding(),
            mount_id,
            before_observation_digest: self.before_observation_digest,
            mounted_observation_digest: self.mounted_observation_digest,
            after_observation_digest: after.observation_digest,
            written,
            result_digest: ObjectDigest::from_bytes(digest.finalize().into()),
        })
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
