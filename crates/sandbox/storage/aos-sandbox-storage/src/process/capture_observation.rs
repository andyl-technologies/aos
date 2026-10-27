//! Retains the actual fixed Capture ZFS command and process prefixes.
//!
//! The shared observer below owns one parser/command sequence. Selected
//! failures keep pinned tools, already reached outputs and the Linux process
//! attempt. Empty construction is custody only, never Capture authority.

use super::*;
use aos_sandbox_linux::process::FixedProcessRunOriginalV3;

pub(super) struct CaptureToolEvidenceV3 {
    pub(super) named: Option<std::fs::Metadata>,
    pub(super) opened: Option<std::fs::Metadata>,
}

pub(crate) struct CaptureToolOpeningV3 {
    pub(super) zfs_evidence: CaptureToolEvidenceV3,
    pub(super) zpool_evidence: CaptureToolEvidenceV3,
    pub(super) zpool_pin: Option<PinnedExecutable>,
    pub(super) zfs_pin: Option<PinnedExecutable>,
    pub(super) zpool: Option<ZfsHelperContract>,
}

impl CaptureToolOpeningV3 {
    pub(super) fn new() -> Self {
        Self {
            zfs_evidence: CaptureToolEvidenceV3 { named: None, opened: None },
            zpool_evidence: CaptureToolEvidenceV3 { named: None, opened: None },
            zpool_pin: None, zfs_pin: None, zpool: None,
        }
    }
}

pub(crate) struct CaptureZfsObservationOriginalV3 {
    pub(super) opening: CaptureToolOpeningV3,
    pub(super) runs: Vec<FixedProcessRunOriginalV3>,
    pub(super) tool_checks: Vec<Option<std::fs::Metadata>>,
    pub(super) outputs: Vec<Vec<u8>>,
    pub(super) arguments: Vec<OsString>,
    pub(super) rejected_output: Option<FixedProcessOutcome>,
    failure: Option<ZfsWorkerError>,
    entered: bool,
}

impl CaptureZfsObservationOriginalV3 {
    pub(crate) fn new() -> Self {
        Self {
            opening: CaptureToolOpeningV3::new(), runs: Vec::new(), tool_checks: Vec::new(), outputs: Vec::new(),
            arguments: Vec::new(), rejected_output: None, failure: None, entered: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // The process error precedes its coarse Storage classification.
        self.runs.iter().find_map(|run| run.failure().map(|error| error as _))
            .or_else(|| self.failure.as_ref().map(|error| error as _))
    }

    #[cfg(test)]
    pub(crate) fn take_ordinary_error_v3(&mut self) -> ZfsWorkerError {
        self.failure.take().unwrap_or(ZfsWorkerError::Protocol("capture ZFS readback mismatch"))
    }

    /// Prices the actual three fixed command carriers and declared outputs.
    /// Native task-directory allocator/containment costs remain the enclosing
    /// worker provider's obligation; this is not a whole worker fit supplier.
    pub(crate) fn representation_bytes_v3(zfs: &ZfsHelperContract, plan: &CaptureZfsReadbackPlanV1) -> Option<usize> {
        Self::representation_commands_bytes_v1(zfs, plan.commands())
    }

    pub(super) fn representation_commands_bytes_v1(zfs: &ZfsHelperContract,
        commands: &[CaptureZfsReadbackCommandV1],
    ) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(5usize.checked_mul(std::mem::size_of::<Option<std::fs::Metadata>>())?)?;
        use std::os::unix::ffi::OsStrExt as _;
        let zfs_bytes = zfs.executable().as_os_str().as_bytes().len();
        // The sole owned zpool PathBuf may grow while replacing zfs's basename.
        bytes = bytes.checked_add(zfs_bytes.checked_add(2)?.checked_mul(2)?)?
            .checked_add(commands.len().checked_mul(std::mem::size_of::<Vec<u8>>())?)?;
        for command in commands {
            let executable_bytes = match command.tool {
                CaptureZfsToolV1::Zfs => zfs_bytes,
                // The fixed validated basename changes zfs (3) to zpool (5).
                CaptureZfsToolV1::Zpool => zfs_bytes.checked_add(2)?,
            };
            let argument_bytes = command.arguments.iter().try_fold(0usize, |sum, argument| {
                sum.checked_add(argument.len().checked_add(1)?)
            })?;
            bytes = bytes.checked_add(FixedProcessRunOriginalV3::representation_from_lengths_v3(
                executable_bytes, command.arguments.len(), argument_bytes,
                MAXIMUM_MACHINE_OUTPUT_BYTES, MAXIMUM_STDERR_BYTES,
            )?)?
                .checked_add(MAXIMUM_MACHINE_OUTPUT_BYTES)?
                .checked_add(argument_bytes)?
                .checked_add(command.arguments.len().checked_mul(std::mem::size_of::<OsString>())?)?;
        }
        Some(bytes)
    }

    pub(super) fn retire_positive(&mut self) -> Result<(), ZfsWorkerError> {
        for run in &mut self.runs {
            run.dispose_after_completed_posts_v3()
                .map_err(|_| ZfsWorkerError::Protocol("capture process disposition is incomplete"))?;
        }
        self.opening = CaptureToolOpeningV3::new();
        self.tool_checks.clear();
        self.outputs.clear();
        self.arguments.clear();
        Ok(())
    }
}

enum CaptureReadbackDataV3 {
    Catalogued(CaptureZfsReadbackV1),
    Created(crate::catalog_transition::execution_capture::readback::CaptureCreatedDatasetReadbackV3),
}

pub(crate) fn observe_capture_zfs_retaining_v3(
    zfs: &ZfsHelperContract,
    plan: &CaptureZfsReadbackPlanV1,
    original: &mut CaptureZfsObservationOriginalV3,
) -> Result<CaptureZfsReadbackV1, ()> {
    match observe_recipe_v3(zfs, plan, original, None, false)? {
        CaptureReadbackDataV3::Catalogued(readback) => Ok(readback),
        CaptureReadbackDataV3::Created(_) => std::process::abort(),
    }
}

pub(crate) fn observe_capture_zfs_in_scope_v3(
    zfs: &ZfsHelperContract,
    plan: &CaptureZfsReadbackPlanV1,
    original: &mut CaptureZfsObservationOriginalV3,
    execution: &mut worker_aggregate::WorkerExecutionScopeV1<'_>,
    cutoff: u64,
) -> Result<CaptureZfsReadbackV1, ()> {
    match observe_recipe_v3(zfs, plan, original, Some((execution, cutoff)), false)? {
        CaptureReadbackDataV3::Catalogued(readback) => Ok(readback),
        CaptureReadbackDataV3::Created(_) => std::process::abort(),
    }
}

pub(super) fn observe_created_capture_zfs_in_scope_v3(
    zfs: &ZfsHelperContract,
    plan: &CaptureZfsReadbackPlanV1,
    original: &mut CaptureZfsObservationOriginalV3,
    execution: &mut worker_aggregate::WorkerExecutionScopeV1<'_>,
    context: &capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
    cutoff: u64,
) -> Result<crate::catalog_transition::execution_capture::readback::CaptureCreatedDatasetReadbackV3, ()> {
    if cutoff == 0 || cutoff > context.source_v3().effective_execution_deadline_v2() { return Err(()); }
    match observe_recipe_v3(zfs, plan, original, Some((execution, cutoff)), true)? {
        CaptureReadbackDataV3::Created(readback) => Ok(readback),
        CaptureReadbackDataV3::Catalogued(_) => std::process::abort(),
    }
}

fn observe_recipe_v3(
    zfs: &ZfsHelperContract,
    plan: &CaptureZfsReadbackPlanV1,
    original: &mut CaptureZfsObservationOriginalV3,
    execution: Option<(&mut worker_aggregate::WorkerExecutionScopeV1<'_>, u64)>,
    created: bool,
) -> Result<CaptureReadbackDataV3, ()> {
    if original.entered { return Err(()); }
    original.entered = true;
    if execution.is_none() { original.runs = Vec::with_capacity(plan.commands().len()); }
    original.tool_checks = Vec::with_capacity(plan.commands().len().checked_add(2).ok_or(())?);
    let result = (|| {
        let [pool, root, dataset] = run_capture_zfs_observation_commands_with_scope_v3(
            zfs, plan.commands(), Some(original), execution,
        )?;
        original.outputs = vec![pool, root, dataset];
        let outputs = [&original.outputs[0][..], &original.outputs[1][..], &original.outputs[2][..]];
        let observed = if created {
            plan.evaluate_created_v3(outputs).map(CaptureReadbackDataV3::Created)
        } else {
            plan.evaluate(outputs).map(CaptureReadbackDataV3::Catalogued)
        }.map_err(|_| ZfsWorkerError::Protocol("capture ZFS readback mismatch"))?;
        // This three-command phase, parser and every entered worker post are
        // complete. The next phase needs only the returned observation DATA.
        original.retire_positive()?;
        Ok(observed)
    })();
    match result {
        Ok(observed) => Ok(observed),
        Err(cause) => { original.failure = Some(cause); Err(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_tool_type_keeps_the_actual_named_metadata_before_file_open() {
        let mut evidence = CaptureToolEvidenceV3 { named: None, opened: None };
        let mut pin = None;

        let error = PinnedExecutable::capture_open_path_into_v3(
            Path::new("/proc"), &mut pin, Some(&mut evidence),
        ).unwrap_err();

        assert!(matches!(error, ZfsWorkerError::Executable(_)));
        assert!(evidence.named.as_ref().unwrap().file_type().is_dir());
        assert!(evidence.opened.is_none());
        assert!(pin.is_none());
    }
}
