//! Replays the host scope's original-to-fresh mapping and ACK construction.
//!
//! Original requests, references and once knowledge are never read from a
//! current ACK to manufacture its expected value. Each completed or partial
//! vector stays in the historical owner until final actual census admission.

use super::*;
use crate::node_contract::{ActivationRecord, SavedRuntimeResult};

impl HistoricalInitial15Scope17 {
    /// Replays the original host field constructor into retained partial banks.
    ///
    /// # Errors
    /// Refuses reuse, missing/ambiguous owner mappings or rosters, reserve failures
    /// and changed archive origin. This does not qualify the completed loan.
    pub(super) fn construct_data(
        &mut self,
        parent: &ParentArchive17ReadScope<'_, '_>,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        operands: &proof::ScopeOperands17<'_>,
    ) -> Result<(), StateError> {
        if self.completed.is_some()
            || self.owners.capacity() != 0
            || self.first_scopes.capacity() != 0
            || self.journals.capacity() != 0
            || self.acknowledgements.capacity() != 0
        {
            return Err(refused(
                "historical scope field construction is already spent",
            ));
        }
        let record = operands.original_runtime_data()?;
        let target = &scope.runtime.source_activation;
        let index = parent.manifest_data()?;
        self.owners
            .try_reserve_exact(record.owners.len())
            .map_err(crate::node_state::schema)?;
        for saved in &record.owners {
            let mut targets = target
                .owners
                .iter()
                .filter(|fresh| fresh.owner == saved.identity.owner);
            let fresh = targets
                .next()
                .ok_or_else(|| refused("historical scope fresh owner absent"))?;
            if targets.next().is_some()
                || fresh.generation <= saved.identity.generation
                || fresh.incarnation == saved.identity.incarnation
            {
                return Err(refused(
                    "historical scope owner mapping is not fresh or unique",
                ));
            }
            self.owners.push(OriginalLineageOwnerMapping {
                source: saved.identity.clone(),
                target: fresh.clone(),
            });
        }
        let first_count = record
            .inputs
            .iter()
            .filter(|input| input.lineage.is_some())
            .count();
        self.first_scopes
            .try_reserve_exact(first_count)
            .map_err(crate::node_state::schema)?;
        for input in &record.inputs {
            if let Some(lineage) = &input.lineage {
                self.first_scopes.push(lineage.source.clone());
            }
        }

        // The defining constructor emits all four participants in node order,
        // independently of the caller's three native continuation slot order.
        self.journals
            .try_reserve_exact(4)
            .map_err(crate::node_state::schema)?;
        for _ in 0..4 {
            let previous = self.journals.last().map(|last| &last.node);
            let mut next: Option<&Id> = None;
            for owner in &index.owners {
                let [node] = owner.participant_ids.as_slice() else {
                    return Err(refused("historical scope participant is not singleton"));
                };
                if previous.is_none_or(|previous| previous < node)
                    && next.is_none_or(|current| node < current)
                {
                    next = Some(node);
                }
            }
            let node = next.ok_or_else(|| refused("historical scope node roster is not unique"))?;
            self.journals.push(OriginalLineageJournal {
                node: node.clone(),
                operations: Vec::new(),
                pending_operations: Vec::new(),
                acknowledged_operations: Vec::new(),
                input_stages: Vec::new(),
            });
            let journal = self
                .journals
                .last_mut()
                .ok_or_else(|| refused("historical scope node journal absent"))?;
            let operations = record
                .operations
                .iter()
                .filter(|entry| entry.route.node == journal.node);
            let pending = operations
                .clone()
                .filter(|entry| matches!(entry.result, SavedRuntimeResult::Pending))
                .count();
            let acknowledged = operations
                .clone()
                .filter(|entry| matches!(entry.result, SavedRuntimeResult::Acknowledged(_)))
                .count();
            let count = operations.count();
            journal
                .operations
                .try_reserve_exact(count)
                .map_err(crate::node_state::schema)?;
            journal
                .pending_operations
                .try_reserve_exact(pending)
                .map_err(crate::node_state::schema)?;
            journal
                .acknowledged_operations
                .try_reserve_exact(acknowledged)
                .map_err(crate::node_state::schema)?;
            for entry in &record.operations {
                if entry.route.node != journal.node {
                    continue;
                }
                journal.operations.push(entry.operation.clone());
                match entry.result {
                    SavedRuntimeResult::Pending => {
                        journal.pending_operations.push(entry.operation.clone())
                    }
                    SavedRuntimeResult::Acknowledged(_) => journal
                        .acknowledged_operations
                        .push(entry.operation.clone()),
                    SavedRuntimeResult::Complete(_) | SavedRuntimeResult::Failed(_) => {}
                }
            }
            let count = record
                .inputs
                .iter()
                .filter(|input| input.node == journal.node)
                .count();
            journal
                .input_stages
                .try_reserve_exact(count)
                .map_err(crate::node_state::schema)?;
            for input in &record.inputs {
                if input.node == journal.node {
                    journal.input_stages.push(input.stage_operation.clone());
                }
            }
        }

        let count = record
            .inputs
            .iter()
            .filter(|input| input.acknowledgement.is_some())
            .count();
        self.acknowledgements
            .try_reserve_exact(count)
            .map_err(crate::node_state::schema)?;
        for input in &record.inputs {
            let Some(original) = &input.acknowledgement else {
                continue;
            };
            self.acknowledgements.push(NativeInputAcknowledgement {
                stage_operation: original.stage_operation.clone(),
                batch: original.batch.clone(),
                node: original.node.clone(),
                owners: Vec::new(),
                cutoff: original.cutoff,
                inventory: original.inventory.clone(),
                proof_ref: operands.reference.clone(),
            });
            let acknowledgement = self
                .acknowledgements
                .last_mut()
                .ok_or_else(|| refused("historical scope ACK owner absent"))?;
            acknowledgement
                .owners
                .try_reserve_exact(input.owners.len())
                .map_err(crate::node_state::schema)?;
            for old in &input.owners {
                let mut mappings = self.owners.iter().filter(|mapping| &mapping.source == old);
                let mapped = mappings
                    .next()
                    .ok_or_else(|| refused("historical scope ACK source mapping absent"))?;
                if mappings.next().is_some() {
                    return Err(refused("historical scope ACK mapping is ambiguous"));
                }
                acknowledgement.owners.push(mapped.target.clone());
            }
        }

        // These are public activation DATA fields; no WorldActivation or
        // runtime authority is reconstructed. Moves retain all partial banks.
        let target = ActivationRecord {
            generation: target.generation,
            activation_id: target.activation_id.clone(),
            world_binding_hash: target.world_binding_hash.clone(),
            owners: target.owners.clone(),
            boundary: target.boundary,
        };
        self.completed = Some(OriginalLineageNativeScope {
            coordinator_schema: 7,
            source_record: operands
                .original
                .journal_data()
                .map_err(original_failure_data)?
                .runtime
                .clone(),
            source_capture: record.source_activation.clone(),
            target,
            owners: std::mem::take(&mut self.owners),
            first_scopes: std::mem::take(&mut self.first_scopes),
            journals: std::mem::take(&mut self.journals),
            input_acknowledgements: std::mem::take(&mut self.acknowledgements),
            proof: operands.reference.clone(),
        });
        parent.manifest_data().map(|_| ())
    }
}
