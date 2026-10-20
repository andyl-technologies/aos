//! Retains genuine Root Environment and Source publication on the original C18.
//!
//! The selected Controller never opens Root's UID0 evidence directory. The real
//! Root owner commits evidence and holds its policy/artifact interval while this
//! same-C client publishes every Source phase and the exact execution lease.
//! Framing, EOF and returned rows alone are never adoption or readiness grants.

use std::error::Error;
use std::mem::size_of;
use std::sync::Arc;
use aos_sandbox_core::{ExecutionId, OperationId, ResourceDimension as D, ResourceVector};
use crate::controller_resource_reservation::{ControllerExecutionSourceScopeV1, ControllerResourceBankOpeningV1};
use crate::controller_execution_operation::ControllerExecutionClockOriginalV1;
use crate::normal_root::{ProductionControllerNormalRootProfileV1, RootEnvironmentClientOriginalV1};
use super::*;
use super::super::authority_clock::{LiveAuthorityClockErrorV1,
    retained_live_clock_demand_v1, retaining_live_authority_clock_v1};
use super::super::deployment::EnvironmentSourcePublicationOriginalV1;

#[derive(Clone, Copy)]
enum First { ClientOpen, Publication, ClientFinish, Clock, Evidence }

pub(crate) struct EnvironmentExecutionEvidenceOriginalV1 {
    client: RootEnvironmentClientOriginalV1,
    publication: EnvironmentSourcePublicationOriginalV1,
    clock: Option<FixedLiveAuthorityClockV1>,
    before: Option<Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1>>,
    pinned: Vec<u8>,
    completion: Option<Result<(), EnvironmentProtectedEvidenceErrorV1>>,
    owner: Option<EnvironmentProtectedEvidenceOwnerV1>,
    entered: bool,
    first: Option<First>,
}

impl EnvironmentExecutionEvidenceOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { client: RootEnvironmentClientOriginalV1::new(), publication: EnvironmentSourcePublicationOriginalV1::new(),
            clock: None, before: None, pinned: Vec::new(), completion: None, owner: None, entered: false, first: None }
    }

    pub(crate) fn fixed_demand_v1() -> Option<ResourceVector> {
        let memory = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<EnvironmentProtectedEvidenceOwnerV1>().checked_mul(3)?)?;
        retained_live_clock_demand_v1()?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)).ok()
    }

    /// Runs the genuine funded Root interval and canonical Source publisher.
    ///
    /// Every fallible step precedes moves into the completed evidence owner.
    /// Failed peer/IO/model/native prefixes stay resident in this same capsule;
    /// its independently paid Root native after is always attempted before the
    /// enclosing Source/C completion runs, even if Source planning refused.
    pub(crate) fn prepare_once_v1(&mut self,
        source: &mut ControllerExecutionSourceScopeV1<'_, '_>, complete: &mut ResourceVector,
        bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &Arc<ProductionControllerNormalRootProfileV1>, operation: OperationId, execution: ExecutionId,
        parent: &crate::execution_parent_resource::ExecutionParentResourceSourceV1,
        assignment: &crate::runtime_scope::CurrentAssignmentTarget, clock: &mut ControllerExecutionClockOriginalV1,
    ) -> Result<(), EnvironmentProtectedEvidenceErrorV1> {
        if self.entered { return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence); }
        self.entered = true;
        self.completion = Some(self.prepare_inner_v1(source, complete, bank, controller,
            profile, operation, execution, parent, assignment, clock));
        self.client.finish_native_after_once_v1();
        if self.completion.as_ref().is_some_and(Result::is_ok) && self.owner.is_some() {
            Ok(())
        } else { Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence) }
    }

    fn prepare_inner_v1(&mut self,
        source: &mut ControllerExecutionSourceScopeV1<'_, '_>, complete: &mut ResourceVector,
        bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &Arc<ProductionControllerNormalRootProfileV1>, operation: OperationId, execution: ExecutionId,
        parent: &crate::execution_parent_resource::ExecutionParentResourceSourceV1,
        assignment: &crate::runtime_scope::CurrentAssignmentTarget, clock: &mut ControllerExecutionClockOriginalV1,
    ) -> Result<(), EnvironmentProtectedEvidenceErrorV1> {
        self.first = Some(First::ClientOpen);
        self.client.open_once_v1(source, complete, bank, controller, profile,
            operation, execution, parent, assignment, clock)?;
        self.first = Some(First::Publication);
        bank.publish_execution_environment_once_v1(source, controller, profile,
            &mut self.client, &mut self.publication, clock, complete)
            .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
        self.first = Some(First::ClientFinish);
        self.client.finish_once_v1(&self.publication, clock)?;
        self.first = Some(First::Clock);
        self.clock = Some(retaining_live_authority_clock_v1());
        let before = self.clock.as_mut().ok_or(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?.sample()
            .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
        self.before = Some(Ok(before));
        self.first = Some(First::Evidence);
        let record = self.client.completed_evidence_v1()?;
        self.pinned.try_reserve_exact(record.len()).map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
        self.pinned.extend_from_slice(record);
        let evidence = decode_evidence(&self.pinned)?;
        let after = self.clock.as_mut().ok_or(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?.sample()
            .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
        let last_sample = validate_bracketed_samples_v1(before, after)
            .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
        validate_currentness(&evidence, last_sample)?;
        self.client.require_completed_current_data_v1(last_sample.boot(), last_sample.boottime_nanoseconds())?;
        // The only positive backend constructor consumes the WHOLE genuine
        // completed client, never a byte slice, File tuple or response DTO.
        let root = Box::new(std::mem::replace(&mut self.client, RootEnvironmentClientOriginalV1::new()));
        let clock = self.clock.take().ok_or(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
        let pinned_record = std::mem::take(&mut self.pinned);
        self.owner = Some(EnvironmentProtectedEvidenceOwnerV1 { journal: None, root: Some(root),
            pinned_record, clock, last_sample, selected: true, selected_failure: None });
        Ok(())
    }

    pub(crate) fn owner_mut_v1(&mut self) -> Option<&mut EnvironmentProtectedEvidenceOwnerV1> {
        if !self.completion.as_ref().is_some_and(Result::is_ok) { return None; }
        self.owner.as_mut().filter(|owner| owner.selected_failure.is_none())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // An independently owed native after must never replace an earlier
        // Source planner or publication refusal selected by the actual body.
        let first = match self.first {
            Some(First::ClientOpen | First::ClientFinish) => self.client.failure(),
            Some(First::Publication) => self.publication.failure(),
            Some(First::Clock | First::Evidence) => self.clock.as_ref()
                .and_then(FixedLiveAuthorityClockV1::native_failure)
                .or_else(|| self.before.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)),
            None => None,
        };
        first.or_else(|| self.completion.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.client.failure()).or_else(|| self.publication.failure())
            .or_else(|| self.owner.as_ref().and_then(|owner| owner.clock.native_failure()
                .or_else(|| owner.root.as_ref().and_then(|root| root.failure()))
                .or_else(|| owner.selected_failure.as_ref().map(|cause| cause as _))))
    }
}
