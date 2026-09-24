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
use aos_sandbox_linux::process::{FixedProcessOutcome, FixedProcessRequest, run_fixed_process};
use sha2::{Digest as _, Sha256};

use crate::ZfsHelperContract;
use crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1;
use crate::catalog_transition::execution_capture::readback::{
    CaptureZfsCreateCommandV1, CaptureZfsPreflightPlanV1, CaptureZfsReadbackErrorV1,
    CaptureZfsToolV1, MAXIMUM_MACHINE_OUTPUT_BYTES,
};
use crate::execution_output::ProtectedRetainedCaptureV1;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::process::{PinnedExecutable, ZfsWorkerError, process_timeout};

const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-create-attempt.v1\0";

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
