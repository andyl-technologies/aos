//! Retains the fresh paid Start read of the actual Source/Create predecessor.
//!
//! Mechanical custody is insufficient to authorize Start. This stage rejoins
//! the new C native original and same held Source, pays the complete schema
//! graph before decoding, and always observes the independent Source after.
//! No Source transaction is selected and ordinary mutation stays fenced.

use super::*;
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::lifecycle::LifecycleHistoricalReadOriginalV1;
use super::super::source::SourceAdmissionErrorV1;

#[derive(Clone, Copy)]
enum First { Native, Geometry, Funding, Relation, After, Disposal, Reentry }

pub(super) struct StartHistoryOriginalV1 {
    native: Option<Result<SourceProvisioningCurrentnessOriginalV1, ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    relation: Option<Result<(), SourceAdmissionErrorV1>>,
    after: Option<Result<(), crate::JournalError>>,
    disposal: Option<Result<(), ResourceReservationErrorV1>>,
    read: LifecycleHistoricalReadOriginalV1,
    first: Option<First>,
    entered: bool,
}

impl StartHistoryOriginalV1 {
    pub(super) fn new() -> Self {
        Self { native: None, geometry: None, funding: None, relation: None,
            after: None, disposal: None, read: LifecycleHistoricalReadOriginalV1::new(),
            first: None, entered: false }
    }

    pub(super) fn observe_once_v1(&mut self, state: &mut StartNativeStateV1,
        predecessor: &CreateStoppedTerminalCustodyV1<'_>, controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { self.first.get_or_insert(First::Reentry); return Err(CLOSED); }
        self.entered = true;
        state.require_current_v1(controller)?;
        let complete = *state.geometry.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
        self.native = Some((|| {
            let native = state.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
            state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                .begin_provisioning_source_native_v1(native.original_mut_v1(), controller,
                    source.journal(), state.profile.as_ref(), complete)
        })());
        if self.native.as_ref().and_then(|value|value.as_ref().ok())
            .is_none_or(|native|native.failure().is_some()) { self.first = Some(First::Native); }
        if self.first.is_none() {
            self.geometry = Some((|| {
                let lifecycle = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(
                    source.journal_ref_v1().all_records()).ok_or(CLOSED)?;
                let historical = crate::lifecycle::protected_journal::LifecycleReplayReceivingV1::
                    additional_selection_receiving_v1(source.journal_ref_v1().all_records()).ok_or(CLOSED)?;
                let controller_models = crate::cold_launch_publication::completion::
                    create_stopped_controller_receiving_demand_v1(
                        controller.historical_read_view_v1().materialized_state_v1()).ok_or(CLOSED)?;
                let bytes = LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1().ok_or(CLOSED)?;
                let fixed = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_|CLOSED)?);
                Ok(complete.checked_add(lifecycle)?.checked_add(historical)?.checked_add(controller_models)?.checked_add(fixed)?
                    .checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)?)
            })());
            if !matches!(self.geometry,Some(Ok(_))) { self.first = Some(First::Geometry); }
        }
        if let Some(Ok(complete)) = self.geometry.as_ref() {
            self.funding = Some((|| {
                let native = state.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_create_provisioning_complete_v1(native.original_mut_v1(),controller,
                        state.profile.as_ref(),*complete)
            })());
            if !matches!(self.funding,Some(Ok(()))) { self.first.get_or_insert(First::Funding); }
            else { state.history_resident = Some(*complete); }
        }
        if self.first.is_none() {
            self.relation = Some((|| {
                let source_native=self.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
                let native=state.native.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_provisioning_source_readonly_current_v1(source_native,native.original_v1(),
                        controller,source.journal_ref_v1(),state.profile.as_ref())?;
                if predecessor.parent_operation_v1()? != state.create_parent { return Err(CLOSED.into()); }
                self.read.observe_once_v1(source.journal_ref_v1(),state.create_parent)?;
                predecessor.require_start_history_v1(state.create_parent,controller,&mut self.read)
            })());
            if !matches!(self.relation,Some(Ok(()))) { self.first.get_or_insert(First::Relation); }
        }
        // No body, model, geometry or funding refusal suppresses this post.
        if let Some(Ok(native))=self.native.as_mut() {
            self.after=Some(source.journal_ref_v1().finish_source_provisioning_native_v1(native));
            if !matches!(self.after,Some(Ok(()))) { self.first.get_or_insert(First::After); }
        }
        self.require_before_authorization_v1()
    }

    pub(super) fn require_before_authorization_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some() || !matches!(self.relation,Some(Ok(())))
            || !matches!(self.after,Some(Ok(()))) || self.disposal.is_some() { return Err(CLOSED); }
        Ok(())
    }

    pub(super) fn dispose_after_controller_once_v1(&mut self, state:&StartNativeStateV1,
        controller:&Journal,source:&mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(),ResourceReservationErrorV1> {
        if self.disposal.is_some() {self.first.get_or_insert(First::Reentry);return Err(CLOSED);}
        self.require_before_authorization_v1()?;
        self.disposal=Some((|| {
            let source_native=self.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
            let native=state.native.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
            state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                .dispose_provisioning_source_native_v1(source_native,native.original_v1(),controller,
                    source.journal(),state.profile.as_ref())
        })());
        if matches!(self.disposal,Some(Ok(()))) {Ok(())}
        else {self.first.get_or_insert(First::Disposal);Err(CLOSED)}
    }

    // The original Start read already qualified the whole completed Create
    // Source relation. Its stable logical assignment identity is preserved;
    // the new current manifest supplies epoch2 separately.
    pub(super) fn completed_assignment_resource_v2(&self, create: OperationId,
        sandbox: aos_sandbox_core::SandboxId,
    ) -> Result<aos_sandbox_core::ResourceId, ResourceReservationErrorV1> {
        if self.first.is_some() || !matches!(self.relation, Some(Ok(())))
            || !matches!(self.after, Some(Ok(()))) || !matches!(self.disposal, Some(Ok(())))
        { return Err(CLOSED); }
        let operation = self.read.operation_v1()?.0;
        if operation.operation_id() != create || operation.phase() != crate::lifecycle::LifecyclePhaseV1::Terminal
            || operation.terminal_result() != Some(crate::lifecycle::LifecycleTerminalResultV1::Succeeded)
        { return Err(CLOSED); }
        let commit = operation.method_semantic_commit().ok_or(CLOSED)?;
        let crate::lifecycle::LifecycleSemanticCommitFactV1::DesiredState { assignments, .. } = commit.facts()
            else { return Err(CLOSED); };
        let [assignment] = assignments.as_slice() else { return Err(CLOSED); };
        if assignment.sandbox() != sandbox { return Err(CLOSED); }
        Ok(assignment.assignment())
    }

    pub(super) fn native_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::Funding))
    }

    pub(super) fn failure<'a>(&'a self,native:Option<&'a(dyn Error+'static)>)->Option<&'a(dyn Error+'static)> {
        match self.first? {
            First::Native=>self.native.as_ref()?.as_ref().err().map(|cause|cause as _)
                .or_else(||self.native.as_ref()?.as_ref().ok()?.failure()),
            First::Geometry=>self.geometry.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Funding=>native.or_else(||self.funding.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Relation=>self.read.failure().or_else(||self.relation.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::After=>self.native.as_ref().and_then(|value|value.as_ref().ok()).and_then(|native|native.failure())
                .or_else(||self.after.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Disposal=>self.disposal.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Reentry=>Some(&CLOSED),
        }
    }
}
const CLOSED:ResourceReservationErrorV1=ResourceReservationErrorV1::Conflict;
