//! Owns the paid successor assignment proposal before a fresh Ownership Advance.
//!
//! The same accepted Start enters a distinct real C/Source native interval.
//! Every reached Source and C post runs after a failed body. Only their complete
//! positive disposition publishes the typed proposal to the next Start stage.

use super::*;
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use aos_sandbox_model::{CanonicalAssignmentManifestV1, RawPairedClockSample};
use aos_sandbox_model::source_tree_model::SandboxTreeRecordV1;
use crate::lifecycle::LifecycleHistoricalReadOriginalV1;
use crate::policy_compiler::{StartAssignmentCompilationDataV2, StartAssignmentCompilationResultV2};
use crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1;
use super::super::super::CreateStorageCompletedIntakeOriginalV1;
use crate::JournalError;

#[derive(Clone, Copy)]
enum First {
    Next,
    Native,
    Before,
    Geometry,
    Funding,
    Current,
    Replay,
    Signed,
    Tree,
    CompilerGeometry,
    CompilerFunding,
    Compile,
    SourceAfter,
    ControllerAfter,
    After,
    Disposal,
    Resident,
    Reentry,
}

pub(super) struct StartAssignmentOriginalV2 {
    entered: bool,
    next: Option<Result<(), ResourceReservationErrorV1>>,
    native: Option<Result<SourceProvisioningCurrentnessOriginalV1, ResourceReservationErrorV1>>,
    before_clock: PairOriginal,
    after_clock: PairOriginal,
    before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_time: Option<Result<(), ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    read: LifecycleHistoricalReadOriginalV1,
    current: Option<Result<(), ResourceReservationErrorV1>>,
    replay: Option<Result<(), JournalError>>,
    signed: Option<Result<RootSignedProjectSourcesV1, Box<dyn Error + Send + Sync>>>,
    tree: Option<Result<(SandboxTreeRecordV1, aos_sandbox_model::ObjectDigest,
        aos_sandbox_model::ObjectDigest), Box<dyn Error + Send + Sync>>>,
    compiler_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    compiler_funding: Option<Result<(), ResourceReservationErrorV1>>,
    compiled: Option<StartAssignmentCompilationResultV2>,
    source_after: Option<Result<(), JournalError>>,
    controller_after: Option<Result<(), ResourceReservationErrorV1>>,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_time: Option<Result<(), ResourceReservationErrorV1>>,
    disposal: Option<Result<(), ResourceReservationErrorV1>>,
    resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    base: Option<ResourceVector>,
    first: Option<First>,
}

impl StartAssignmentOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            next: None,
            native: None,
            before_clock: Default::default(),
            after_clock: Default::default(),
            before: None,
            before_time: None,
            geometry: None,
            funding: None,
            read: LifecycleHistoricalReadOriginalV1::new(),
            current: None,
            replay: None,
            signed: None,
            tree: None,
            compiler_geometry: None,
            compiler_funding: None,
            compiled: None,
            source_after: None,
            controller_after: None,
            after: None,
            after_time: None,
            disposal: None,
            resident: None,
            base: None,
            first: None,
        }
    }

    pub(super) fn completed_v2(&self) -> bool {
        self.first.is_none()
            && matches!(self.disposal, Some(Ok(())))
            && matches!(self.resident, Some(Ok(_)))
    }

    pub(super) fn manifest_v2(&self) -> Result<&CanonicalAssignmentManifestV1, ResourceReservationErrorV1> {
        if !self.completed_v2() {
            return Err(CLOSED);
        }
        self.compiled.as_ref().and_then(|result| result.as_ref().ok())
            .map(StartAssignmentCompilationDataV2::manifest_v2).ok_or(CLOSED)
    }

    fn fixed_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let memory = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(PairOriginal::dominant_requested_bytes_v1()?.checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
        let files = PairOriginal::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)
            .and_then(|files| u64::try_from(files).ok()).ok_or(CLOSED)?;
        let names = PairOriginal::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(2))
            .and_then(|names| u64::try_from(names).ok()).ok_or(CLOSED)?;
        ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, files).with(D::MetadataEntries, names)
            .checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)
            .map_err(Into::into)
    }

    fn require_sample_v2(
        origin: aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1,
        sample: RawPairedClockSample,
    ) -> Result<(), ResourceReservationErrorV1> {
        origin.first_native_clock_v1().validate_later_sample(sample).map_err(|_| CLOSED)?;
        if sample.boottime_nanoseconds() >= origin.cutoff_v1()
            || origin.accepted_v1().cutoff_for_sample_data_v1(sample).is_none()
        {
            return Err(CLOSED);
        }
        Ok(())
    }

    fn debit_v2(
        state: &mut StartNativeStateV1,
        controller: &Journal,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let native = state.native.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
        state.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_create_provisioning_complete_v1(
                native.original_mut_v1(), controller, state.profile.as_ref(), complete,
            )
    }
}

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;

impl StartAssignmentOriginalV2 {
    pub(super) fn prepare_once_v2(
        &mut self,
        state: &mut StartNativeStateV1,
        plan: &Arc<crate::OperationPlan>,
        origin: aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1,
        completed: &CreateStorageCompletedIntakeOriginalV1<'_>,
        current_inputs: &crate::normal_root::RootStartAssignmentInputsClientOriginalV2,
        controller: &mut Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.entered = true;
        self.next = Some((|| {
            let complete = state.history_resident.ok_or(CLOSED)?.checked_add(Self::fixed_demand_v2()?)?;
            self.base = Some(complete);
            state.begin_next_start_native_v1(controller, complete)
        })());
        if !matches!(self.next, Some(Ok(()))) {
            self.first = Some(First::Next);
        }
        if self.first.is_none() {
            self.native = Some((|| {
                let native = state.native.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .begin_provisioning_source_native_v1(
                        native.original_mut_v1(), controller, source.journal(),
                        state.profile.as_ref(), self.base.ok_or(CLOSED)?,
                    )
            })());
            if self.native.as_ref().and_then(|result| result.as_ref().ok())
                .is_none_or(|native| native.failure().is_some())
            {
                self.first = Some(First::Native);
            }
        }
        if self.first.is_none() {
            self.before = Some(self.before_clock.observe_once(Some(origin.first_native_clock_v1())));
            self.before_time = Some(self.before.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(CLOSED).and_then(|sample| Self::require_sample_v2(origin, sample)));
            if !matches!(self.before_time, Some(Ok(()))) {
                self.first = Some(First::Before);
            }
        }
        if self.first.is_none() {
            self.geometry = Some((|| {
                let source = source.journal_ref_v1();
                let lifecycle = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(
                    source.all_records(),
                ).ok_or(CLOSED)?;
                let carriers = LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1()
                    .and_then(|bytes| bytes.checked_add(aos_sandbox_policy::signed_inputs::fixed_root_startup_decoding_bytes_v1()?))
                    .and_then(|bytes| bytes.checked_add(crate::policy_compiler::assignment_manifest_construction_receiving_bytes_v2()?))
                    .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
                self.base.ok_or(CLOSED)?.checked_add(lifecycle)?
                    .checked_add(crate::hierarchy::protected_journal::start_assignment_tree_receiving_demand_v2(source)?)?
                    .checked_add(plan.start_source_context_receiving_demand_v1(controller).ok_or(CLOSED)?)?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carriers))
                    .map_err(Into::into)
            })());
            if !matches!(self.geometry, Some(Ok(_))) {
                self.first = Some(First::Geometry);
            }
        }
        if self.first.is_none() {
            self.funding = Some(self.geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(CLOSED).and_then(|complete| Self::debit_v2(state, controller, complete)));
            if !matches!(self.funding, Some(Ok(()))) {
                self.first = Some(First::Funding);
            }
        }
        if self.first.is_none() {
            self.current = Some((|| {
                let source_native = self.native.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
                let native = state.native.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_provisioning_source_readonly_current_v1(
                        source_native, native.original_v1(), controller,
                        source.journal_ref_v1(), state.profile.as_ref(),
                    )
            })());
            if !matches!(self.current, Some(Ok(()))) {
                self.first = Some(First::Current);
            }
        }
        if self.first.is_none() {
            self.replay = Some(self.read.observe_once_v1(source.journal_ref_v1(), plan.operation_id()));
            if !matches!(self.replay, Some(Ok(()))) {
                self.first = Some(First::Replay);
            }
        }
        if self.first.is_none() {
            self.signed = Some((|| {
                let (_, ((deployment_generation, deployment_pin), (project_generation, project_pin))) =
                    completed.start_assignment_policy_inputs_v2()?;
                let reply = current_inputs.borrow_completed_inputs_v2()?;
                let deployment = aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::SignedDeploymentInputsDataV2::decode_v2(reply.deployment)?;
                let project = aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::SignedProjectInputsDataV2::decode_v2(reply.project)?;
                let inputs = aos_sandbox_policy::signed_inputs::PolicyDeploymentInputsV1 {
                    node: deployment.node,
                    site: deployment.site,
                    backend: deployment.backend,
                    catalogs: deployment.catalogs,
                };
                let now = self.before.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?.wall_seconds();
                let signed = crate::policy_compiler::root_signed_sources::verify_signed_project_input_data_v2(
                    deployment.signed_packet, &inputs, project.signed_packet, project.input,
                    deployment_pin, project_pin, now,
                )?;
                if signed.0.head().deployment_signer_generation() != deployment_generation
                    || signed.0.head().project_signer_generation() != project_generation
                {
                    return Err(CLOSED.into());
                }
                Ok(signed)
            })());
            if !matches!(self.signed, Some(Ok(_))) {
                self.first = Some(First::Signed);
            }
        }
        if self.first.is_none() {
            self.tree = Some((|| {
                let previous = completed.publication_material_v1()?.0.manifest();
                crate::hierarchy::protected_journal::start_assignment_source_tree_data_v2(
                    source.journal_ref_v1(), previous.project(), previous.sandbox(),
                ).map_err(Into::into)
            })());
            if !matches!(self.tree, Some(Ok(_))) {
                self.first = Some(First::Tree);
            }
        }
        if self.first.is_none() {
            self.compiler_geometry = Some((|| {
                let signed = self.signed.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
                let reply = current_inputs.borrow_completed_inputs_v2().map_err(|_| CLOSED)?;
                let mut width = u64::try_from(reply.encoded_bytes_v2().map_err(|_| CLOSED)?)
                    .map_err(|_| CLOSED)?;
                for (_, key, value) in controller.all_records() {
                    let row = key.len().checked_add(value.len())
                        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
                    width = width.checked_add(row).ok_or(CLOSED)?;
                }
                let compiler = controller.start_assignment_compiler_receiving_demand_v2(width, signed)?;
                self.geometry.as_ref().and_then(|result| result.as_ref().ok()).copied()
                    .ok_or(CLOSED)?.checked_add(compiler).map_err(Into::into)
            })());
            if !matches!(self.compiler_geometry, Some(Ok(_))) {
                self.first = Some(First::CompilerGeometry);
            }
        }
        if self.first.is_none() {
            self.compiler_funding = Some(self.compiler_geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(CLOSED).and_then(|complete| Self::debit_v2(state, controller, complete)));
            if !matches!(self.compiler_funding, Some(Ok(()))) {
                self.first = Some(First::CompilerFunding);
            }
        }
        if self.first.is_none() {
            self.compiled = Some((|| {
                let previous = completed.publication_material_v1()?.0;
                let (record, tree_head, _) = self.tree.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
                if record.parent().is_some() || record.project() != previous.manifest().project()
                    || record.incarnation() != Some(previous.manifest().incarnation())
                    || record.desired_generation() != previous.manifest().desired_generation()
                {
                    return Err(CLOSED.into());
                }
                crate::policy_compiler::compile_accepted_start_assignment_v2(
                    controller, plan, &self.read, previous, completed.original_specification_v2()?,
                    self.signed.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?,
                    *tree_head, *self.before.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?,
                )
            })());
            if !matches!(self.compiled, Some(Ok(_))) {
                self.first = Some(First::Compile);
            }
        }

        self.finish_all_once_v2(state, origin, controller, source);
        if self.first.is_none() {
            self.resident = Some(self.compiler_geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .map(aos_sandbox_model::component_receiving::without_operation_traffic_v1)
                .ok_or(CLOSED));
            if let Some(Ok(complete)) = self.resident.as_ref() {
                // All retained models and native destinations were part of this
                // exact turn's complete bound before they grew. No wire is
                // carried as new traffic into the next native Start interval.
                state.history_resident = Some(*complete);
            } else {
                self.first = Some(First::Resident);
            }
        }
        if self.completed_v2() { Ok(()) } else { Err(CLOSED) }
    }
}

impl StartAssignmentOriginalV2 {
    fn finish_all_once_v2(
        &mut self,
        state: &mut StartNativeStateV1,
        origin: aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1,
        controller: &mut Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) {
        if let Some(Ok(native)) = self.native.as_mut() {
            self.source_after = Some(source.journal_ref_v1().finish_source_provisioning_native_v1(native));
            if !matches!(self.source_after, Some(Ok(()))) {
                self.first.get_or_insert(First::SourceAfter);
            }
        }
        if state.after.is_none() {
            self.controller_after = Some(state.finish_native_once_v1(controller));
            if !matches!(self.controller_after, Some(Ok(()))) {
                self.first.get_or_insert(First::ControllerAfter);
            }
        }
        if self.native.as_ref().is_some_and(Result::is_ok) {
            self.after = Some(self.after_clock.observe_once(Some(origin.first_native_clock_v1())));
            self.after_time = Some((|| {
                let sample = *self.after.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
                Self::require_sample_v2(origin, sample)?;
                let before = *self.before.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
                before.validate_later_sample(sample).map_err(|_| CLOSED)
            })());
            if !matches!(self.after_time, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
        }
        if self.first.is_none() {
            self.disposal = Some((|| {
                let source_native = self.native.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
                let native = state.native.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .dispose_provisioning_source_native_v1(
                        source_native, native.original_v1(), controller,
                        source.journal(), state.profile.as_ref(),
                    )
            })());
            if !matches!(self.disposal, Some(Ok(()))) {
                self.first = Some(First::Disposal);
            }
        }
    }

    pub(super) fn original_failure_is_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::Next | First::Funding | First::CompilerFunding | First::ControllerAfter))
    }

    pub(super) fn failure<'held>(
        &'held self,
        original: Option<&'held (dyn Error + 'static)>,
    ) -> Option<&'held (dyn Error + 'static)> {
        match self.first? {
            First::Next => original.or_else(|| error_v2(&self.next)),
            First::Native => self.native.as_ref().and_then(|result| match result {
                Ok(native) => native.failure(),
                Err(cause) => Some(cause as &(dyn Error + 'static)),
            }),
            First::Before => self.before_clock.failure()
                .or_else(|| error_v2(&self.before)).or_else(|| error_v2(&self.before_time)),
            First::Geometry => error_v2(&self.geometry),
            First::Funding => original.or_else(|| error_v2(&self.funding)),
            First::Current => self.native.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|native| native.failure()).or_else(|| error_v2(&self.current)),
            First::Replay => self.read.failure().or_else(|| error_v2(&self.replay)),
            First::Signed => self.signed.as_ref()?.as_ref().err()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            First::Tree => self.tree.as_ref()?.as_ref().err()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            First::CompilerGeometry => error_v2(&self.compiler_geometry),
            First::CompilerFunding => original.or_else(|| error_v2(&self.compiler_funding)),
            First::Compile => self.compiled.as_ref()?.as_ref().err()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            First::SourceAfter => self.native.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|native| native.failure()).or_else(|| error_v2(&self.source_after)),
            First::ControllerAfter => original.or_else(|| error_v2(&self.controller_after)),
            First::After => self.after_clock.failure()
                .or_else(|| error_v2(&self.after)).or_else(|| error_v2(&self.after_time)),
            First::Disposal => error_v2(&self.disposal),
            First::Resident => error_v2(&self.resident),
            First::Reentry => Some(&CLOSED as &(dyn Error + 'static)),
        }.or(Some(&CLOSED))
    }
}

fn error_v2<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

// This owner crosses into the Controller worker together with the retained
// Start entry. Keep actual dynamic causes thread-safe at their capture sites.
const _: fn() = || {
    fn require_send<T: Send>() {}
    require_send::<StartAssignmentOriginalV2>();
};
