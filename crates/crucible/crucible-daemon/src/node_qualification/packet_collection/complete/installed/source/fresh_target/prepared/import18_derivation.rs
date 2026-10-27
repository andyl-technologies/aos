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
    #[cfg(feature = "test-support")]
    pub(crate) fn funded_private_births_retained_data(&self) -> bool {
        let retained = !self.import18_templates.failed
            && self.import18_templates.funded_complete
            && self.import18_templates.members.iter().all(|member| {
                member.stage == Stage::PrivateBirth
                    && member.initial_projection.is_some()
                    && member.launch_identity.is_some()
                    && member.mapping_nonce.is_some()
                    && member
                        .declaration_encoding
                        .as_ref()
                        .is_some_and(|bank| !bank.is_empty())
            });
        retained
            && self
                .authenticate_funded_initial_source_census_data()
                .is_ok()
            && self.authenticate_funded_mapping_nonces_data().is_ok()
    }

    /// Checks repeatable, distinct challenges from the three real private Births.
    #[cfg(feature = "test-support")]
    fn authenticate_funded_mapping_nonces_data(&self) -> Result<(), RuntimeError> {
        let [retained, transient, scratch] =
            PacketCompleteSemanticSource::native_import18_original_mapping_nonce_counter_data();
        let scratch = scratch
            .checked_add(size_of::<[[u8; 32]; 3]>())
            .and_then(|bytes| bytes.checked_add(size_of::<&Self>()))
            .and_then(|bytes| bytes.checked_add(size_of::<usize>() * 2))
            .and_then(|bytes| bytes.checked_add(size_of::<[u8; 32]>() * 2))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<(), RuntimeError>>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        self.observe_import18_templates_data([retained, transient, scratch])?;

        let mut nonces = [[0; 32]; 3];
        for selected in 0..3 {
            let member = &self.import18_templates.members[selected];
            let nonce = member
                .output
                .completed_data()?
                .native_import18_original_mapping_nonce_data()?;
            if member.mapping_nonce != Some(nonce) || nonce == [0; 32] {
                return Err(RuntimeError::InvalidReceipt);
            }
            nonces[selected] = nonce;
        }
        if nonces[0] == nonces[1] || nonces[0] == nonces[2] || nonces[1] == nonces[2] {
            return Err(RuntimeError::InvalidReceipt);
        }

        self.observe_import18_templates_data([0; 3])
    }

    /// Checks actual Source components only after funding their complete visitor.
    ///
    /// This qualification observation creates no Source/native completion. Each
    /// read uses the original deployment and exercises its exact component bound
    /// after a refused one-byte-short walk, without changing any owning bank.
    #[cfg(feature = "test-support")]
    fn authenticate_funded_initial_source_census_data(&self) -> Result<(), RuntimeError> {
        use crucible_engine::node_adapters::cnp::source_birth_derivation::deployment::SourceDeploymentStorageRead;
        use crucible_host_resources::DeploymentResourceReadContext;
        use std::mem::{size_of, size_of_val};

        let controls = [
            size_of::<&Self>() * 3,
            size_of::<bool>() * 5,
            size_of::<&Rc<crate::node_control::deployment::InstalledDeployment>>(),
            size_of::<Option<&Rc<crate::node_control::deployment::InstalledDeployment>>>(),
            size_of::<
                Result<&Rc<crate::node_control::deployment::InstalledDeployment>, RuntimeError>,
            >(),
            size_of::<DeploymentResourceReadContext<'static>>(),
            size_of::<Result<DeploymentResourceReadContext<'static>, RuntimeError>>(),
            size_of::<&DeploymentResourceReadContext<'static>>() * 2,
            size_of::<std::slice::Iter<'static, Member>>(),
            size_of::<&Member>(),
            size_of::<&Rc<PacketCompleteSemanticSource>>(),
            size_of::<Result<&Rc<PacketCompleteSemanticSource>, RuntimeError>>(),
            size_of::<SourceDeploymentStorageRead<'static>>() * 3,
            size_of::<&SourceDeploymentStorageRead<'static>>() * 3,
            size_of::<Result<SourceDeploymentStorageRead<'static>, RuntimeError>>() * 3,
            size_of::<Result<(), RuntimeError>>() * 5,
            size_of::<Result<usize, std::num::TryFromIntError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Option<usize>>(),
            size_of::<[usize; 3]>() * 2,
            size_of::<usize>() * 5,
        ];
        let scratch = controls
            .into_iter()
            .try_fold(
                PacketCompleteSemanticSource::initial_lifecycle_deployment_counter_scratch_data(),
                |sum, field| sum.checked_add(field).ok_or(RuntimeError::ResourceLimit),
            )?
            .checked_add(size_of_val(&controls))
            .and_then(|sum| sum.checked_add(size_of_val(&controls.into_iter())))
            .ok_or(RuntimeError::ResourceLimit)?;
        self.observe_funded_templates_data([0, 0, scratch])?;

        let outcome = (|| {
            let context = self
                .import18_templates
                .deployment
                .as_ref()
                .ok_or(RuntimeError::ForeignAuthority)?
                .context()?;
            let maximum = usize::try_from(self.selected.resources.memory_bytes.get())
                .map_err(|_| RuntimeError::ResourceLimit)?;
            for member in &self.import18_templates.members {
                let source = member.output.completed_data()?;
                let read =
                    source.original_initial_lifecycle_deployment_storage_data(&context, maximum)?;
                read.authenticate_original(&context)?;
                let actual = read.known_requested_bytes_data();
                let short = actual.checked_sub(1).ok_or(RuntimeError::ResourceLimit)?;
                if !matches!(
                    source.original_initial_lifecycle_deployment_storage_data(&context, short),
                    Err(RuntimeError::ResourceLimit)
                ) {
                    return Err(RuntimeError::OwnerUnavailable);
                }
                let exact =
                    source.original_initial_lifecycle_deployment_storage_data(&context, actual)?;
                exact.authenticate_original(&context)?;
                if exact.known_requested_bytes_data() != actual {
                    return Err(RuntimeError::OwnerUnavailable);
                }
            }
            Ok(())
        })();
        // Every Source and deployment-read view ends before the whole holder is
        // observed again, including when a read or bound control has refused.
        let terminal = self.observe_funded_templates_data([0; 3]);
        outcome?;
        terminal
    }

    /// Advances the isolated operational step without claiming preparation success.
    ///
    /// The actor calls this from its existing poll. A real failed job stops new
    /// starts but retains its original input/error/cleanup owners. Cleanup visits
    /// all members even if an earlier member refuses. This is not a native Ready,
    /// Initial, Recipe or legacy BirthWorker route. Private Birth assembly keeps
    /// native startup closed until its independent finalization is available.
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
                    self.note_funded_operation_stage("starting original isolated derivation");
                    if let Err(error) = self.start_funded_derivation_member(selected) {
                        self.import18_templates.members[selected].stage = Stage::DerivationFailed;
                        self.import18_templates.failed = true;
                        return Err(error);
                    }
                    return Ok(false);
                }
                Stage::DerivationRunning => {
                    self.note_funded_operation_stage("polling original isolated derivation");
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
                    self.note_funded_operation_stage("retaining original worker result");
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
                    self.prepare_funded_initial_banks(selected)?;
                    self.prepare_funded_private_seed(selected)?;
                }
                Stage::DerivedBanks => {
                    self.prepare_funded_initial_banks(selected)?;
                    self.prepare_funded_private_seed(selected)?;
                }
                Stage::InitialBanks => self.prepare_funded_private_seed(selected)?,
                Stage::PrivateSeed => self.prepare_funded_private_birth(selected)?,
                Stage::PrivateBirth => {}
                _ => return Err(RuntimeError::OutstandingObligations),
            }
        }
        Ok(true)
    }

    /// Reserves actual initial-lifecycle banks before constructing private Birth.
    ///
    /// The isolated worker's accepted banks stay in their original completion.
    /// These separate Capture reservations use the same Source's own quote and
    /// are admitted beside every existing holder before allocation. No native
    /// startup, model, Initial, Recipe or phase permission follows.
    ///
    /// # Errors
    /// Refuses a foreign member or phase, missing installed policy, unavailable
    /// Source custody, a failed original quote, insufficient funding or actual
    /// reservation failure. Every started policy/bank prefix remains retained.
    fn prepare_funded_initial_banks(&mut self, selected: usize) -> Result<(), RuntimeError> {
        if selected >= self.import18_templates.members.len()
            || self.import18_templates.members[selected].stage != Stage::DerivedBanks
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.observe_import18_templates_data([
            0,
            0,
            Self::funded_initial_banks_counter_scratch_data(),
        ])?;
        let maximum_records = self
            .selected
            .maximum_coordinator_records
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let maximum = usize::try_from(self.selected.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;

        self.note_funded_operation_stage("binding isolated Source initial-lifecycle policy");
        let result = self.import18_templates.members[selected]
            .output
            .completed_unique_data()?
            .bind_original_restored_settled_coordinator_policy18(maximum_records);
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;

        self.note_funded_operation_stage("quoting isolated Source Capture banks");
        let row = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .original_import18_capture_bank_construction_data(
                self.selected.maximum_native_rows,
                maximum,
            )?;
        let (retained, transient, scratch) = row.requested_storage_data();
        self.import18_templates.members[selected].bank_row = Some(row);
        self.observe_import18_templates_data([retained, transient, scratch])?;

        self.note_funded_operation_stage("reserving isolated Source Capture banks");
        let result = self.import18_templates.members[selected]
            .output
            .completed_unique_data()?
            .reserve_original_import18_capture_banks_data(&row);
        // End the mutable Source loan before counting either a complete bank
        // transfer or every failed constructor prefix in its original owner.
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;
        self.import18_templates.members[selected].stage = Stage::InitialBanks;
        Ok(())
    }

    /// Names both defining constructors and the actor's fixed handoff controls.
    pub(super) fn funded_initial_banks_counter_scratch_data() -> usize {
        use std::mem::{size_of, size_of_val};

        let controls = [
            size_of::<&mut Self>(),
            size_of::<&Self>() * 3,
            size_of::<&str>() * 3,
            size_of::<usize>() * 10,
            size_of::<bool>() * 5,
            size_of::<Stage>() * 2,
            size_of::<Option<usize>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Result<usize, std::num::TryFromIntError>>(),
            size_of::<&Rc<PacketCompleteSemanticSource>>() * 2,
            size_of::<Result<&Rc<PacketCompleteSemanticSource>, RuntimeError>>() * 2,
            size_of::<&mut PacketCompleteSemanticSource>() * 2,
            size_of::<Result<&mut PacketCompleteSemanticSource, RuntimeError>>() * 2,
            size_of::<OriginalImport18CaptureBankConstructionData>() * 3,
            size_of::<Option<OriginalImport18CaptureBankConstructionData>>(),
            size_of::<Result<OriginalImport18CaptureBankConstructionData, RuntimeError>>(),
            size_of::<&OriginalImport18CaptureBankConstructionData>() * 2,
            size_of::<(usize, usize, usize)>() * 2,
            size_of::<[usize; 3]>() * 5,
            size_of::<Result<(), RuntimeError>>() * 10,
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<std::iter::Copied<std::slice::Iter<'static, usize>>>(),
        ];
        PacketCompleteSemanticSource::original_import18_capture_bank_counter_scratch_data()
            .saturating_add(
                PacketCompleteSemanticSource::original_restored_settled_coordinator_policy18_counter_scratch_data(),
            )
            .saturating_add(controls.iter().copied().fold(0usize, usize::saturating_add))
            .saturating_add(size_of_val(&controls))
            .saturating_add(size_of_val(&controls.into_iter()))
    }

    fn prepare_funded_private_seed(&mut self, selected: usize) -> Result<(), RuntimeError> {
        self.note_funded_operation_stage("constructing private Birth seed");
        self.observe_import18_templates_data([
            0,
            0,
            PacketCompleteSemanticSource::native_import18_private_seed_counter_scratch_data(),
        ])?;
        // This exact reference was independently pinned and authenticated against
        // /proc/self/exe before launch creation; the peer is a different artifact.
        let requested = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_private_seed_construction_data(
                &self.measurements[selected].host,
                usize::MAX,
            )?;
        self.observe_import18_templates_data(requested)?;
        let result = self.import18_templates.members[selected]
            .output
            .completed_unique_data()?
            .prepare_native_import18_private_seed_into(&self.measurements[selected].host);
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;
        self.import18_templates.members[selected].stage = Stage::PrivateSeed;
        Ok(())
    }

    fn prepare_funded_private_birth(&mut self, selected: usize) -> Result<(), RuntimeError> {
        self.note_funded_operation_stage("constructing private Birth");
        self.observe_import18_templates_data([
            0,
            0,
            PacketCompleteSemanticSource::native_import18_private_birth_counter_scratch_data(),
        ])?;
        let requested = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_private_birth_construction_data(usize::MAX)?;
        self.observe_import18_templates_data(requested)?;
        let result = self.import18_templates.members[selected]
            .output
            .completed_unique_data()?
            .prepare_native_import18_private_birth_into();
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;
        self.note_funded_operation_stage("quoting original Source declaration encoding");
        self.observe_import18_templates_data(
            PacketCompleteSemanticSource::native_import18_declaration_encoding_quote_construction_data(),
        )?;
        let row = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_declaration_encoding_construction_data(usize::MAX)?;
        self.import18_templates.members[selected].declaration_encoding_row = Some(row);
        self.observe_import18_templates_data(row)?;
        self.note_funded_operation_stage("encoding original pre-report Source declaration");
        let encoded = {
            let member = &mut self.import18_templates.members[selected];
            member
                .output
                .completed_data()?
                .encode_native_import18_source_declaration_into_data(
                    usize::MAX,
                    &mut member.declaration_encoding,
                )
        };
        // All original declaration/Birth loans end before this whole-Prepared
        // census, including after a partial canonical write or guard refusal.
        let observed = self.observe_import18_templates_data([0; 3]);
        encoded.and(observed)?;
        self.note_funded_operation_stage("projecting original initial demand");
        self.observe_import18_templates_data(
            PacketCompleteSemanticSource::native_import18_initial_projection_counter_data(),
        )?;
        let prewalk = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_initial_projection_prewalk_data()?;
        self.observe_import18_templates_data(prewalk)?;
        let projected = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_initial_projection_data(usize::MAX);
        // Release every original Source/Birth/launch loan before the complete
        // Prepared census, including a failed formatter or projection outcome.
        let result = projected.map(|projection| {
            self.import18_templates.members[selected].initial_projection = Some(projection);
        });
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;
        self.note_funded_operation_stage("quoting original Initial producer formatters");
        self.observe_import18_templates_data(
            PacketCompleteSemanticSource::native_import18_original_initial_funding_counter_data(),
        )?;
        let prewalk = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_original_initial_funding_prewalk_data();
        // End the genuine Source/Birth loan before either whole-owner census.
        let observed = self.observe_import18_templates_data([0; 3]);
        let prewalk = prewalk.and_then(|row| observed.map(|()| row))?;
        self.observe_import18_templates_data(prewalk)?;
        self.prepare_funded_launch_identity(selected)?;
        self.prepare_funded_mapping_nonce(selected)?;
        self.import18_templates.members[selected].stage = Stage::PrivateBirth;
        Ok(())
    }

    fn prepare_funded_mapping_nonce(&mut self, selected: usize) -> Result<(), RuntimeError> {
        self.note_funded_operation_stage("deriving original mapping nonce");
        self.observe_import18_templates_data(
            PacketCompleteSemanticSource::native_import18_original_mapping_nonce_counter_data(),
        )?;
        let derived = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_original_mapping_nonce_data();
        let result = derived.map(|nonce| {
            self.import18_templates.members[selected].mapping_nonce = Some(nonce);
        });
        // Release the original Source/Birth loan before either census outcome.
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)
    }

    fn prepare_funded_launch_identity(&mut self, selected: usize) -> Result<(), RuntimeError> {
        self.note_funded_operation_stage("deriving original launch commitments");
        self.observe_import18_templates_data(
            PacketCompleteSemanticSource::native_import18_original_launch_identity_counter_data(),
        )?;
        let prewalk = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_original_launch_identity_prewalk_data()?;
        self.observe_import18_templates_data(prewalk)?;
        let row = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_original_launch_identity_construction_data(usize::MAX)?;
        self.observe_import18_templates_data(row)?;
        let derived = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .derive_native_import18_original_launch_identity_data(usize::MAX);
        let result = derived.map(|identity| {
            self.import18_templates.members[selected].launch_identity = Some(identity);
        });
        // The whole Prepared census follows release of every original loan,
        // including failed canonical construction or terminal authentication.
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)
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
            })?
            .checked_add(SourceBirthDerivationJob::fresh_export_counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        // This disclosed operational workspace budget is admitted before its
        // allocation and before a Source loan. It is not input-depth demand.
        // Fund the real metadata walk before obtaining a new owning handle.
        self.observe_import18_templates_data([0, 0, fixed])?;
        let original_views = self
            .launches
            .retained_requested_storage_data()?
            .checked_mul(2)
            .ok_or(RuntimeError::ResourceLimit)?;
        let retained = requested[0]
            .checked_add(original_views)
            .ok_or(RuntimeError::ResourceLimit)?;
        // Job and Source association each conservatively report this same
        // actual tuple view. Admit both census increments before either clone.
        self.observe_import18_templates_data([retained, requested[1], fixed])?;
        self.import18_templates.members[selected].stage = Stage::DerivationExporting;
        let original = self.launches.selected(selected)?;
        SourceBirthDerivationJob::reserve_fresh_into(
            mechanism,
            original,
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
            member.registration.retain_fresh_source_derivation_into(
                source,
                &self.launches.selected(selected)?,
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
                #[cfg(feature = "test-support")]
                let outcome_already_retained = job.failed_outcome_data().is_some();

                let cleanup = job.poll_cleanup();
                #[cfg(feature = "test-support")]
                if !outcome_already_retained {
                    observe_terminal_worker_outcome(job);
                }

                match cleanup {
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
                    | Stage::InitialBanks
                    | Stage::PrivateSeed
                    | Stage::PrivateBirth
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

#[cfg(feature = "test-support")]
fn observe_terminal_worker_outcome(job: &SourceBirthDerivationJob) {
    let Some(outcome) = job.failed_outcome_data() else {
        return;
    };

    // Observe this original terminal transfer once. Stdout contains candidate
    // banks and is never rendered; stderr retains the worker's original bound.
    use std::io::Write;
    let mut diagnostic = std::io::stderr().lock();
    let _ = writeln!(
        diagnostic,
        "funded worker terminal outcome: failure={:?}, status={:?}, oom_kills={:?}, stdout_bytes={}, stderr_bytes={}",
        outcome.failure,
        outcome.status,
        outcome.memory_oom_kills,
        outcome.stdout.len(),
        outcome.stderr.len(),
    );
    let _ = diagnostic.write_all(&outcome.stderr);
}
