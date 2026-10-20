//! Drives one actual supervised occurrence at a time on the existing actor poll.
//!
//! Original jobs remain in member slots while active. A Source loan only streams
//! its request or consumes a physically complete result. Shutdown drains every
//! member before receivers, namespace ownership or world credit can be released.

use super::*;
use crucible_engine::node_adapters::cnp::source_birth_derivation::request_wire::{
    ExportWorkspace, export_fixed_bytes,
};
use crucible_host_resources::LinuxPureWorkerAttempt;

impl PreparedCompleteRestoration {
    /// Advances the isolated operational step without claiming preparation success.
    ///
    /// The actor calls this from its existing poll. A real failed job stops new
    /// starts but retains its original input/error/cleanup owners. Cleanup visits
    /// all members even if an earlier member refuses. This is not a native Ready,
    /// Initial, Recipe or legacy BirthWorker route.
    ///
    /// # Errors
    /// Refuses unavailable original ownership, actual export/start/result error
    /// or a failed cleanup poll. Every pending owner stays in this Prepared.
    pub(crate) fn poll_funded_derivation_data(
        &mut self,
        stopping: bool,
    ) -> Result<bool, RuntimeError> {
        let result = self.poll_funded_derivation_inner(stopping);
        match result {
            Ok(complete) => Ok(complete),
            Err(error) => {
                if self.import18_templates.derivation_failure.is_none() {
                    self.import18_templates.derivation_failure = Some(error);
                }
                self.import18_templates.failed = true;
                Err(RuntimeError::OwnerUnavailable)
            }
        }
    }

    fn poll_funded_derivation_inner(&mut self, stopping: bool) -> Result<bool, RuntimeError> {
        if self.import18_templates.deployment.is_none() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if stopping || self.import18_templates.failed {
            return self.drain_funded_derivation_data();
        }
        if !self.import18_templates.funded_complete {
            return Ok(true);
        }
        self.observe_import18_templates_data([0; 3])?;
        for selected in 0..3 {
            match self.import18_templates.members[selected].stage {
                Stage::FundedTemplate => {
                    if let Err(error) = self.start_funded_derivation_member(selected) {
                        self.import18_templates.members[selected].stage = Stage::DerivationFailed;
                        self.import18_templates.failed = true;
                        return Err(error);
                    }
                    return Ok(false);
                }
                Stage::DerivationRunning => {
                    let polled = self.import18_templates.members[selected]
                        .job
                        .as_mut()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .poll();
                    match polled {
                        Ok(false) => return Ok(false),
                        Err(error) => {
                            self.import18_templates.members[selected].stage =
                                Stage::DerivationFailed;
                            self.import18_templates.failed = true;
                            return Err(error);
                        }
                        Ok(true) => {}
                    }
                    let result = {
                        let member = &mut self.import18_templates.members[selected];
                        member
                            .output
                            .completed_unique_data()?
                            .retain_native_import18_derivation_result_into(&mut member.job)
                    };
                    // The result, including a consumed failed completion, remains
                    // installed while the complete original holder is observed.
                    let observed = self.observe_import18_templates_data([0; 3]);
                    if let Err(error) = result.and(observed) {
                        self.import18_templates.members[selected].stage = Stage::DerivationFailed;
                        self.import18_templates.failed = true;
                        return Err(error);
                    }
                    self.import18_templates.members[selected].stage = Stage::DerivedBanks;
                }
                Stage::DerivedBanks => {}
                _ => return Err(RuntimeError::OutstandingObligations),
            }
        }
        Ok(true)
    }

    fn start_funded_derivation_member(&mut self, selected: usize) -> Result<(), RuntimeError> {
        let deployment = self
            .import18_templates
            .deployment
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .clone();
        deployment.authenticate()?;
        let mechanism = deployment.mechanism()?.clone();
        let requested = ExportWorkspace::requested_bytes(mechanism.workspace_slots())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let fixed = export_fixed_bytes::<LinuxPureWorkerAttempt>()
            .into_iter()
            .try_fold(0usize, |sum, bytes| {
                sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
            })?;
        // This disclosed operational workspace budget is admitted before its
        // allocation and before a Source loan. It is not input-depth demand.
        self.observe_import18_templates_data([requested[0], requested[1], fixed])?;
        self.import18_templates.members[selected].stage = Stage::DerivationExporting;
        SourceBirthDerivationJob::reserve_into(
            mechanism,
            &mut self.import18_templates.members[selected].job,
        )?;
        self.observe_import18_templates_data([0; 3])?;
        let workspace = {
            let job = self.import18_templates.members[selected]
                .job
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            job.prepare_input()?;
            job.reserve_workspace()?
        };
        // No whole-Prepared observation is possible while this borrowed bank or
        // the synchronous Source/export loan holds original references.
        let result = {
            let member = &mut self.import18_templates.members[selected];
            let source = member.output.completed_unique_data()?;
            let job = member.job.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
            member.registration.retain_source_derivation_into(
                source,
                &self.launches[selected],
                job,
                workspace,
            )
        };
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;
        self.import18_templates.members[selected]
            .job
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .start()?;
        self.import18_templates.members[selected].stage = Stage::DerivationRunning;
        self.observe_import18_templates_data([0; 3])
    }

    fn drain_funded_derivation_data(&mut self) -> Result<bool, RuntimeError> {
        let mut pending = false;
        let mut first = None;
        for member in &mut self.import18_templates.members {
            if let Some(job) = &mut member.job {
                job.cancel();
                match job.poll_cleanup() {
                    Ok(complete) => pending |= !complete,
                    Err(error) => {
                        pending = true;
                        if first.is_none() {
                            first = Some(error);
                        }
                    }
                }
            }
            // Only these private stages can have entered the Source export.
            // Failed earlier template constructors have never owned a job.
            if matches!(
                member.stage,
                Stage::DerivationExporting
                    | Stage::DerivationRunning
                    | Stage::DerivedBanks
                    | Stage::DerivationFailed
            ) {
                let cancelled = member
                    .output
                    .completed_unique_data()
                    .and_then(PacketCompleteSemanticSource::cancel_native_import18_derivation);
                if let Err(error) = cancelled {
                    pending = true;
                    if first.is_none() {
                        first = Some(error);
                    }
                }
            }
        }
        if let Some(error) = first {
            return Err(error);
        }
        Ok(!pending)
    }
}
