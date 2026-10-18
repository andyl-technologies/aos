//! Observes actual moved initial preparations inside an inactive collecting runtime.
//!
//! These read-only checks follow the real erased node. They neither recreate a
//! preparation nor renew the old host Query, Source read or runtime admission.

use super::*;
use crate::node_adapters::cnp::{CnpSemanticSource, PacketCompleteSemanticSource};
use crate::node_admission::{CompleteOriginalFreshRestoreHostWindow, InstalledConformancePlan};
use std::mem::size_of;

impl NodeRuntime {
    /// Checks the actual erased initial node against its retained original ticket.
    ///
    /// # Errors
    /// Refuses noninitial/dormant custody, a missing node or changed original owners.
    pub(crate) fn inspect_original_initial_preparation_data(
        &self,
        ticket: &CompleteOriginalFreshRestoreHostWindow,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_initial_members_data(plan)?;
        let node = self
            .nodes
            .get(&source.installation().descriptor.id)
            .ok_or(RuntimeError::UnknownNode)?;
        node.inspect_original_initial_preparation_data(ticket, source, plan)?;
        self.authenticate_original_initial_members_data(plan)
    }

    /// Counts the same inactive runtime with its exact initial Source roster.
    ///
    /// # Errors
    /// Refuses duplicate/missing Sources, unknown owners or the ordinary bound.
    pub(crate) fn retained_original_initial_requested_storage_precredit_data(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        plan: &InstalledConformancePlan,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_initial_members_data(plan)?;
        for (index, source) in sources.iter().enumerate() {
            let id = &source.installation().descriptor.id;
            if !self.nodes.contains_key(id)
                || sources[..index]
                    .iter()
                    .any(|previous| previous.installation().descriptor.id == *id)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        self.original_initial_requested_storage_precredit_scratch_data(sources)?;
        let bytes = self.retained_requested_storage_inner(maximum, true, Some(sources))?;
        self.authenticate_original_initial_members_data(plan)?;
        Ok(bytes)
    }

    fn original_initial_requested_storage_precredit_scratch_data(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
    ) -> Result<usize, RuntimeError> {
        let mut child = 0usize;
        for (key, node) in &self.nodes {
            let initial = sources
                .iter()
                .any(|source| source.installation().descriptor.id == *key);
            let scratch = if initial {
                node.retained_original_initial_requested_storage_precredit_scratch_data()?
            } else {
                node.retained_requested_storage_precredit_scratch_data()?
            };
            child = child.max(scratch.ok_or(RuntimeError::UnsupportedFacet)?);
        }
        if let Some(slot) = &self.custody_slot {
            child = child.max(
                slot.retained_requested_storage_precredit_scratch_data()?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            );
        }
        child = child.max(super::opaque_owner_counter_scratch_data());
        child = child.max(super::coordinator_commitment::counter_scratch_data());
        size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>()
            .checked_add(child)
            .and_then(|bytes| {
                bytes.checked_add(Self::original_initial_preparation_counter_scratch_data())
            })
            .ok_or(RuntimeError::ResourceLimit)
    }

    fn authenticate_original_initial_members_data(
        &self,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        if self.activated
            || self.nodes.len() != 4
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
            || !self
                .collecting
                .as_ref()
                .is_some_and(|graph| graph.plan().same_original(plan))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .authenticate_retained(&self.authority, &self.barrier.record().world_binding_hash)
    }

    /// Names actual roster, erased-node and checked-counter loan controls.
    pub(crate) fn original_initial_preparation_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&CompleteOriginalFreshRestoreHostWindow>()
            + size_of::<&InstalledConformancePlan>()
            + size_of::<&Rc<PacketCompleteSemanticSource>>()
            + size_of::<&[Rc<PacketCompleteSemanticSource>; 3]>()
            + size_of::<Option<&[Rc<PacketCompleteSemanticSource>; 3]>>()
            + size_of::<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>()
            + size_of::<
                std::iter::Enumerate<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>,
            >()
            + size_of::<Option<&Rc<PacketCompleteSemanticSource>>>()
            + size_of::<&Box<dyn SimulationNode>>()
            + size_of::<Option<&Box<dyn SimulationNode>>>()
            + size_of::<std::collections::btree_map::Iter<'static, Id, Box<dyn SimulationNode>>>()
            + size_of::<(&Id, &Box<dyn SimulationNode>)>()
            + size_of::<(usize, &Rc<PacketCompleteSemanticSource>)>()
            + size_of::<&Id>()
            + size_of::<usize>() * 3
            + size_of::<bool>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
