//! Moves complete original cleanup custody before invoking native callbacks.
//!
//! Borrowed upper owners remain alive on refusal and callback unwind. Native
//! quarantine/getter callbacks run only after the original enters the queue.

use super::*;
use crate::node_contract::PreparedRealization;

pub(crate) fn prepared(
    nodes: &mut Vec<Box<dyn SimulationNode>>,
    activation: &ActivationRecord,
    limits: RuntimeLimits,
    slot: &mut Option<Box<dyn RuntimeCustodySlot>>,
) -> Result<(), RuntimeError> {
    let Some(prior) = slot.as_mut() else {
        return Err(RuntimeError::OutstandingObligations);
    };
    if prior.original_transferred() {
        return Ok(());
    }
    let mut original = Some(WholeRuntimeCustody {
        authority: Rc::new(()),
        nodes: BTreeMap::new(),
        rejected_nodes: Vec::new(),
        rejected_reclamation: Default::default(),
        snapshots: BTreeMap::new(),
        owners: BTreeMap::new(),
        operations: BTreeMap::new(),
        input_batches: BTreeMap::new(),
        scheduler: None,
        terminal: None,
        condition_stop: None,
        prepared: None,
        activation: activation.clone(),
        publication: None,
        node_preparations: Rc::from([]),
        world_preparation: None,
        limits,
        reclamation_cursor: None,
        pending_retirement: true,
        borrowed_retirement: true,
    });
    if let Some(custody) = original.as_mut() {
        custody.rejected_nodes = std::mem::take(nodes);
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prior.retain_borrowed(&mut original)
    }));
    if let Some(mut custody) = original {
        *nodes = std::mem::take(&mut custody.rejected_nodes);
    }
    result.unwrap_or(Err(RuntimeError::OutstandingObligations))
}

impl NodeRuntime {
    pub(in super::super::super) fn retire_collecting_original(
        &mut self,
    ) -> Result<(), RuntimeError> {
        if self.collecting.is_none() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let Some(prior) = self.custody_slot.as_mut() else {
            return Err(RuntimeError::OutstandingObligations);
        };
        if prior.original_transferred() {
            return Ok(());
        }
        // All copies below are fixed retained barrier data, never native callbacks.
        let activation = self.barrier.record().clone();
        let node_preparations = self.barrier.retained_nodes();
        let world_preparation = self.barrier.retained_preparation();
        let mut original = Some(WholeRuntimeCustody {
            authority: Rc::clone(&self.authority),
            nodes: std::mem::take(&mut self.nodes),
            rejected_nodes: Vec::new(),
            rejected_reclamation: Default::default(),
            snapshots: std::mem::take(&mut self.snapshots),
            owners: std::mem::take(&mut self.owners),
            operations: std::mem::take(&mut self.operations),
            input_batches: std::mem::take(&mut self.input_batches),
            scheduler: self.scheduler.take(),
            terminal: self.terminal.take(),
            condition_stop: self.condition_stop.take(),
            prepared: None,
            activation,
            publication: self.barrier.publication_status_or_not_attempted(),
            node_preparations,
            world_preparation,
            limits: self.limits,
            reclamation_cursor: None,
            pending_retirement: true,
            borrowed_retirement: true,
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prior.retain_borrowed(&mut original)
        }));
        if let Some(mut custody) = original {
            self.nodes = std::mem::take(&mut custody.nodes);
            self.snapshots = std::mem::take(&mut custody.snapshots);
            self.owners = std::mem::take(&mut custody.owners);
            self.operations = std::mem::take(&mut custody.operations);
            self.input_batches = std::mem::take(&mut custody.input_batches);
            self.scheduler = custody.scheduler.take();
            self.terminal = custody.terminal.take();
            self.condition_stop = custody.condition_stop.take();
        }
        result.unwrap_or(Err(RuntimeError::OutstandingObligations))
    }
}

impl PreparedRealization {
    /// Transfers original inactive owners while retaining this preparation metadata.
    ///
    /// # Errors
    /// Refuses unsupported supervision; original nodes remain held on refusal.
    pub fn retire_original(&mut self) -> Result<(), RuntimeError> {
        prepared(
            &mut self.nodes,
            &self.activation,
            self.limits,
            &mut self.custody_slot,
        )
    }
}

impl RuntimePreparationFailure {
    /// Transfers failed original native custody without consuming its diagnostic.
    ///
    /// # Errors
    /// Refuses unsupported supervision and preserves the same supplied owners.
    pub fn retire_original(&mut self) -> Result<(), RuntimeError> {
        prepared(
            &mut self.nodes,
            &self.original_activation,
            self.limits,
            &mut self.custody_slot,
        )
    }
}

#[cfg(test)]
#[path = "borrowed_retirement_tests.rs"]
mod tests;
