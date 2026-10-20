//! Supplies the single fixed Capture command backend under the real worker scope.
//!
//! Ordinary and selected calls share the exact argv/executable/timeout/native
//! engine. The selected branch keeps actual tool names/pins and rejected
//! outcomes beside the actual worker's retained fork/process originals; it
//! constructs no financial owner or Capture authorization.

use super::*;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::execution_capture_zfs_worker::{AuthorizedCaptureCreateAttemptV1, CaptureCreateBackendV1};
use crate::catalog_transition::execution_capture::readback::{CaptureZfsPreflightPlanV1, CaptureZfsCreateCommandV1};

pub(crate) struct FixedCaptureCreateBackendV1<'a, 'scope, 'aggregate> {
    tools: PinnedCaptureZfsTools<'a>,
    scope: Option<&'scope mut worker_aggregate::WorkerExecutionScopeV1<'aggregate>>,
    original: Option<&'scope mut capture_observation::CaptureZfsObservationOriginalV3>,
}

impl<'a, 'scope, 'aggregate> FixedCaptureCreateBackendV1<'a, 'scope, 'aggregate> {
    pub(crate) fn new(zfs: &'a ZfsHelperContract) -> Result<Self, ZfsWorkerError> {
        let tools = PinnedCaptureZfsTools::new(
            zfs,
            "capture create requires the fixed AOS zfs executable",
        )?;
        Ok(Self { tools, scope: None, original: None })
    }

    pub(crate) fn new_retaining_in_scope_v3(
        zfs: &'a ZfsHelperContract,
        scope: &'scope mut worker_aggregate::WorkerExecutionScopeV1<'aggregate>,
        original: &'scope mut capture_observation::CaptureZfsObservationOriginalV3,
    ) -> Result<Self, ZfsWorkerError> {
        scope.require_capture_context_v3()?;
        let tools = PinnedCaptureZfsTools::new_retaining_v3(zfs,
            "capture create requires the fixed AOS zfs executable", &mut original.opening)?;
        Ok(Self { tools, scope: Some(scope), original: Some(original) })
    }

    // Move the SAME actual tool pins to the surrounding worker reservoir before
    // exposing any error. The scope then aborts/parks with those owners alive.
    pub(crate) fn park_tools_once_v3(self) {
        if let Some(original) = self.original {
            original.opening.zpool = Some(self.tools.zpool);
            original.opening.zfs_pin = Some(self.tools.zfs_pin);
            original.opening.zpool_pin = Some(self.tools.zpool_pin);
        }
    }

    fn remaining(
        authorized: &AuthorizedCaptureCreateAttemptV1,
    ) -> Result<Duration, ZfsWorkerError> {
        let now = boottime_now_nanoseconds()?;
        let nanoseconds = authorized
            .deadline_data_v3()
            .checked_sub(now)
            .filter(|remaining| *remaining != 0)
            .ok_or(ZfsWorkerError::Authority)?;
        Ok(Duration::from_nanos(nanoseconds).min(process_timeout()))
    }
}

impl CaptureCreateBackendV1 for FixedCaptureCreateBackendV1<'_, '_, '_> {
    fn observe_preflight(
        &mut self,
        authorized: &AuthorizedCaptureCreateAttemptV1,
        plan: &CaptureZfsPreflightPlanV1,
    ) -> Result<[Vec<u8>; 2], ZfsWorkerError> {
        let mut outputs = Vec::with_capacity(2);
        let result = (|| {
        for command in plan.commands() {
            let (contract, pin) = self.tools.for_tool(command.tool);
            if let Some(original) = self.original.as_deref_mut() {
                let mut metadata = None;
                let result = pin.validate_current_into_v3(contract, Some(&mut metadata));
                original.tool_checks.push(metadata);
                result?;
            } else { pin.validate_current(contract)?; }
            let arguments: Vec<OsString> = command.arguments.iter().map(OsString::from).collect();
            let output = run_worker_fixed_process_v1(FixedProcessRequest {
                executable: contract.executable(),
                arguments: &arguments,
                timeout: Self::remaining(authorized)?,
                maximum_stdout_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
                maximum_stderr_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
            }, self.scope.as_deref_mut())?;
            match output {
                FixedProcessOutcome::Completed(output)
                    if output.exit_code == Some(0)
                        && output.signal.is_none()
                        && output.stderr.is_empty() =>
                {
                    outputs.push(output.stdout);
                }
                rejected => {
                    if let Some(original) = self.original.as_deref_mut() {
                        original.rejected_output = Some(rejected);
                    }
                    return Err(ZfsWorkerError::Protocol("capture preflight command failed"));
                }
            }
        }
        match self.original.as_deref_mut() {
            Some(original) => self.tools.validate_current_retaining_v3(&mut original.tool_checks)?,
            None => self.tools.validate_current()?,
        }
        Ok(())
        })();
        if let Err(cause) = result {
            if let Some(original) = self.original.as_deref_mut() { original.outputs = outputs; }
            return Err(cause);
        }
        match outputs.try_into() {
            Ok(outputs) => Ok(outputs),
            Err(outputs) => {
                if let Some(original) = self.original.as_deref_mut() { original.outputs = outputs; }
                Err(ZfsWorkerError::Protocol("capture preflight is incomplete"))
            }
        }
    }

    fn create(
        &mut self,
        authorized: &AuthorizedCaptureCreateAttemptV1,
        command: &CaptureZfsCreateCommandV1,
    ) -> Result<bool, ZfsWorkerError> {
        match self.original.as_deref_mut() {
            Some(original) => self.tools.validate_current_retaining_v3(&mut original.tool_checks)?,
            None => self.tools.validate_current()?,
        }
        let (zfs, _) = self.tools.for_tool(CaptureZfsToolV1::Zfs);
        let arguments: Vec<OsString> = command.arguments.iter().map(OsString::from).collect();
        let output = run_worker_fixed_process_v1(FixedProcessRequest {
            executable: zfs.executable(),
            arguments: &arguments,
            timeout: Self::remaining(authorized)?,
            maximum_stdout_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
            maximum_stderr_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
        }, self.scope.as_deref_mut())?;
        let completed = matches!(&output,
            FixedProcessOutcome::Completed(output)
                if output.exit_code == Some(0) && output.signal.is_none()
                    && output.stdout.is_empty() && output.stderr.is_empty());
        if let Some(original) = self.original.as_deref_mut() {
            // Even a completed/nonzero/limited effect remains the actual native
            // outcome; its coarse bool cannot replace the rejected prefix.
            original.rejected_output = Some(output);
            self.tools.validate_current_retaining_v3(&mut original.tool_checks)?;
        } else {
            self.tools.validate_current()?;
        }
        Ok(completed)
    }
}

