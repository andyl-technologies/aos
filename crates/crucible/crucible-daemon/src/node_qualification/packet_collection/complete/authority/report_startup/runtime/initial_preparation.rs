//! Authenticates the actual destination of a moved original scene preparation.

use super::super::preparation::PreparationOwners;
use super::*;
use crucible_engine::node_adapters::cnp::{
    CnpSemanticPreparation, CnpSemanticSource, PacketCompleteSemanticSource,
};
use crucible_engine::node_admission::CompleteOriginalFreshRestoreHostWindow;
use std::mem::size_of;

impl PacketCompleteReportStartupHolder {
    // The initial-lifecycle observer also counts the fully moved inactive
    // holder after construction. Empty precreation peers are not destinations.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_collecting_graph_started_data(
        &self,
    ) -> bool {
        self.runtime_members[index(OriginalRuntimeConstructionPhase::CollectingGraph)]
            .get()
            .is_some()
    }

    /// Finds exactly one actual destination of the same moved initial preparation.
    ///
    /// # Errors
    /// Refuses missing/duplicate destinations, failed owners or changed originals.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn authenticate_original_scene_preparation_destination_data(
        &self,
        selected: usize,
        ticket: &CompleteOriginalFreshRestoreHostWindow,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        if !matches!(&self.purpose, StartupHolderPurpose::OriginalScene)
            || self.runtime_members[index(OriginalRuntimeConstructionPhase::CollectingGraph)]
                .get()
                .is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let source = self
            .authority
            .roster
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let owners = self
            .runtime_owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if owners.provider_failure.is_some()
            || owners.preparation_failure.is_some()
            || owners.attachment_failure.is_some()
            || owners.node_failures.iter().any(Option::is_some)
            || owners.unwinds.iter().any(Option::is_some)
            || !owners.native.is_empty()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut found = false;
        if let Some(node) = owners.nodes.get(selected).and_then(Option::as_ref) {
            node.inspect_original_initial_preparation_data(ticket, source, &self.plan)?;
            record_destination(&mut found)?;
        }
        for node in &owners.node_vector {
            if node.original_conformance_route_data().node == source.installation().descriptor.id {
                node.inspect_original_initial_preparation_data(ticket, source, &self.plan)?;
                record_destination(&mut found)?;
            }
        }
        if let Some(provider) = &owners.provider
            && provider.inspect_original_initial_preparation_data(ticket, source, &self.plan)?
        {
            record_destination(&mut found)?;
        }
        if let Some(runtime) = &owners.runtime {
            runtime.inspect_original_initial_preparation_data(ticket, source, &self.plan)?;
            record_destination(&mut found)?;
        }
        if let Some(actor) = &owners.actor
            && actor.inspect_original_initial_preparation_data(ticket, source, &self.plan)?
        {
            record_destination(&mut found)?;
        }
        if !found {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.authenticate_native_origin_data()
    }

    /// Finds the unique moved completed-Admit destination without a host Query.
    ///
    /// # Errors
    /// Refuses missing/duplicate destinations, failed owners or changed originals.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn authenticate_original_scene_admitted_destination_data(
        &self,
        selected: usize,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        if !matches!(&self.purpose, StartupHolderPurpose::OriginalScene)
            || self.runtime_members[index(OriginalRuntimeConstructionPhase::CollectingGraph)]
                .get()
                .is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let source = self
            .authority
            .roster
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let owners = self
            .runtime_owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if owners.provider_failure.is_some()
            || owners.preparation_failure.is_some()
            || owners.attachment_failure.is_some()
            || owners.node_failures.iter().any(Option::is_some)
            || owners.unwinds.iter().any(Option::is_some)
            || !owners.native.is_empty()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut found = false;
        if let Some(node) = owners.nodes.get(selected).and_then(Option::as_ref) {
            node.inspect_original_admitted_preparation_data(source, &self.plan)?;
            record_destination(&mut found)?;
        }
        for node in &owners.node_vector {
            if node.original_conformance_route_data().node == source.installation().descriptor.id {
                node.inspect_original_admitted_preparation_data(source, &self.plan)?;
                record_destination(&mut found)?;
            }
        }
        if let Some(provider) = &owners.provider
            && provider.inspect_original_admitted_preparation_data(
                &source.installation().descriptor.id,
                source,
                &self.plan,
            )?
        {
            record_destination(&mut found)?;
        }
        if let Some(runtime) = &owners.runtime {
            runtime.inspect_original_admitted_preparation_data(
                &source.installation().descriptor.id,
                source,
                &self.plan,
            )?;
            record_destination(&mut found)?;
        }
        if let Some(actor) = &owners.actor
            && actor.inspect_original_admitted_preparation_data(
                &source.installation().descriptor.id,
                source,
                &self.plan,
            )?
        {
            record_destination(&mut found)?;
        }
        if !found {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.authenticate_native_origin_data()
    }
}

fn record_destination(found: &mut bool) -> Result<(), RuntimeError> {
    if std::mem::replace(found, true) {
        Err(RuntimeError::ForeignAuthority)
    } else {
        Ok(())
    }
}

/// Names the complete additional initial destination and owning-census controls.
///
/// # Errors
/// Refuses checked layout overflow before the actual owning-data traversal.
pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn counter_scratch_data()
-> Result<usize, RuntimeError> {
    let terms = [
        size_of::<&PacketCompleteReportStartupHolder>(),
        PreparationOwners::original_admitted_peer_counter_scratch_data(),
        size_of::<bool>(), // Actual CollectingGraph predicate result.
        size_of::<&CompleteOriginalFreshRestoreHostWindow>(),
        size_of::<std::cell::Ref<'static, OriginalRuntimeOwners>>(),
        size_of::<std::cell::Ref<'static, CompleteOriginalFreshRestoreHostWindow>>(),
        size_of::<
            Result<
                std::cell::Ref<'static, CompleteOriginalFreshRestoreHostWindow>,
                std::cell::BorrowError,
            >,
        >(),
        size_of::<std::slice::Iter<'static, CnpSemanticConformanceNode>>(),
        size_of::<Option<&CnpSemanticConformanceNode>>(),
        size_of::<&Rc<PacketCompleteSemanticSource>>(),
        size_of::<&mut bool>(),
        size_of::<bool>() * 2,
        size_of::<Result<std::cell::Ref<'static, OriginalRuntimeOwners>, std::cell::BorrowError>>(),
        size_of::<Option<&ConformanceRuntime>>(),
        size_of::<Option<&CnpSemanticExactConformanceWorldProvider>>(),
        size_of::<Option<&Box<PacketCompleteExecutionActor>>>(),
        size_of::<&CnpSemanticConformanceNode>(),
        size_of::<&crucible_node_format::Id>(),
        size_of::<usize>() * 2,
        size_of::<Result<usize, RuntimeError>>(),
        size_of::<Result<bool, RuntimeError>>(),
        size_of::<Result<(), RuntimeError>>(),
        CnpSemanticPreparation::original_initial_node_retained_counter_scratch_data()?,
        ConformanceRuntime::original_initial_preparation_counter_scratch_data(),
        CnpSemanticExactConformanceWorldProvider::original_initial_preparation_counter_scratch_data(
        ),
        PacketCompleteExecutionActor::original_initial_preparation_counter_scratch_data(),
    ];
    let local = std::mem::size_of_val(&terms)
        .checked_add(size_of::<std::slice::Iter<'static, usize>>())
        .ok_or(RuntimeError::ResourceLimit)?;
    terms
        .iter()
        .try_fold(local, |total, next| add(total, *next, usize::MAX))
}

#[cfg(test)]
impl PacketCompleteReportStartupHolder {
    /// Counts the complete real inactive test holder.
    ///
    /// # Errors
    /// Preserves actual origin, owner, phase and bound refusals.
    pub(in crate::node_qualification::packet_collection::complete) fn original_inactive_holder_storage_for_test(
        original: &Rc<RefCell<Self>>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        Self::original_initial_holder_storage_data(original, &held, maximum)
    }

    /// Checks a real completed-Admit Source against an actual inactive member.
    ///
    /// # Errors
    /// Preserves actual origin, owner, phase and bound refusals.
    pub(in crate::node_qualification::packet_collection::complete) fn original_inactive_destination_for_test(
        original: &Rc<RefCell<Self>>,
        ticket_member: usize,
        destination_member: usize,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        let preparations = held
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let queried = preparations.original_initial_query_attempted_for_test(ticket_member)?;
        if !queried {
            preparations.authenticate_original_admitted_peer_data(ticket_member)?;
        }
        let source = held
            .authority
            .roster
            .sources
            .get(ticket_member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let destination = held
            .authority
            .roster
            .sources
            .get(destination_member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let owners = held
            .runtime_owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let actor = owners
            .actor
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let present = if queried {
            let ticket = preparations.original_initial_ticket_data(ticket_member)?;
            actor.inspect_original_initial_preparation_data(&ticket, destination, &held.plan)?
        } else {
            actor.inspect_original_admitted_preparation_data(
                &destination.installation().descriptor.id,
                source,
                &held.plan,
            )?
        };
        if present {
            Ok(())
        } else {
            Err(RuntimeError::OwnerUnavailable)
        }
    }

    /// Retains the real actor locally while checking its absent holder slot.
    ///
    /// # Errors
    /// Preserves actual origin, owner, phase and bound refusals.
    pub(in crate::node_qualification::packet_collection::complete) fn original_inactive_missing_destination_for_test(
        original: &Rc<RefCell<Self>>,
        member: usize,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let preparations = held
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let queried = preparations.original_initial_query_attempted_for_test(member)?;
        if !queried {
            preparations.authenticate_original_admitted_peer_data(member)?;
        }
        let actor = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .actor
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        // Retain the same real actor locally while testing the absent holder
        // destination. Restore it before propagating the observation result.
        let observed = if queried {
            // Retain the moved actor while observing either authentic phase.
            // Borrow failure is included in the result so restoration below
            // precedes every observation error return.
            preparations
                .original_initial_ticket_data(member)
                .and_then(|ticket| {
                    held.authenticate_original_scene_preparation_destination_data(member, &ticket)
                })
        } else {
            held.authenticate_original_scene_admitted_destination_data(member)
        };
        held.runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .actor = Some(actor);
        observed
    }
}
