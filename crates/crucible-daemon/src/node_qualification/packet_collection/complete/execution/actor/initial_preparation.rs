//! Observes real initial preparations after their runtime moves into this actor.

use super::*;
use crucible::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_admission::{CompleteOriginalFreshRestoreHostWindow, InstalledConformancePlan},
    node_contract::RuntimeError,
};

impl PacketCompleteExecutionActor {
    /// Inspects the same inactive node while this actor actually owns its runtime.
    ///
    /// # Errors
    /// Refuses changed plan/phase, active grants, missing runtime or foreign owners.
    pub(in crate::node_qualification::packet_collection::complete) fn inspect_original_initial_preparation_data(
        &self,
        ticket: &CompleteOriginalFreshRestoreHostWindow,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
    ) -> Result<bool, RuntimeError> {
        self.original_creator()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // The holder and installed scene retain the same outer Plan allocation.
        if !std::ptr::eq(plan, self.scene.plan.as_ref()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.phase == Phase::Reserved && !self.attachment_attempted && self.runtime.is_none() {
            return Ok(false);
        }
        if self.phase != Phase::Attached
            || !self.attachment_attempted
            || self.next != 0
            || self.grants.iter().any(|grant| grant.token.is_some())
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .inspect_original_initial_preparation_data(ticket, source, plan)?;
        Ok(true)
    }

    /// Inspects the same inactive node while this actor actually owns its runtime.
    ///
    /// # Errors
    /// Refuses changed plan/phase, active grants, missing runtime, foreign owners
    /// or any host Query attempt.
    pub(in crate::node_qualification::packet_collection::complete) fn inspect_original_admitted_preparation_data(
        &self,
        destination: &crucible_node_contract::Id,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
    ) -> Result<bool, RuntimeError> {
        self.original_creator()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // The holder and installed scene retain the same outer Plan allocation.
        if !std::ptr::eq(plan, self.scene.plan.as_ref()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.phase == Phase::Reserved && !self.attachment_attempted && self.runtime.is_none() {
            return Ok(false);
        }
        if self.phase != Phase::Attached
            || !self.attachment_attempted
            || self.next != 0
            || self.grants.iter().any(|grant| grant.token.is_some())
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .inspect_original_admitted_preparation_data(destination, source, plan)?;
        Ok(true)
    }

    /// Counts the actual inactive actor using its nodes' initial Source census.
    ///
    /// # Errors
    /// Preserves every phase, owner, metadata and requested-storage refusal.
    pub(in crate::node_qualification::packet_collection::complete) fn retained_original_initial_requested_storage_precredit_data(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.inactive_storage_selected_precredit_data(maximum, Some(sources))
    }

    /// Names actual actor/runtime and initial Source loan controls.
    pub(in crate::node_qualification::packet_collection::complete) fn original_initial_preparation_counter_scratch_data()
    -> usize {
        use std::mem::size_of;
        size_of::<&crucible_node_contract::Id>()
            + size_of::<&Self>()
            + size_of::<&CompleteOriginalFreshRestoreHostWindow>()
            + size_of::<&InstalledConformancePlan>()
            + size_of::<&Rc<PacketCompleteSemanticSource>>()
            + size_of::<&[Rc<PacketCompleteSemanticSource>; 3]>()
            + size_of::<Option<&[Rc<PacketCompleteSemanticSource>; 3]>>()
            + size_of::<&ConformanceRuntime>()
            + size_of::<Option<&ConformanceRuntime>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
