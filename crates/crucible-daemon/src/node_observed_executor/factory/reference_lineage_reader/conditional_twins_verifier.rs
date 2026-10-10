//! Checks owned source pins against the actual source factory and fresh models.
//!
//! This fixture verifier never opens the old package or archive namespace. Its
//! returned scope remains inert until the owning runtime independently validates
//! every producer, consumer, pending permission and newly scoped input receipt.

#![cfg(test)]

use std::rc::Rc;

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, NativeRuntimeContinuationEvidence, NativeRuntimeContinuationVerifier,
        OriginalLineageJournal, OriginalLineageNativeScope, OriginalLineageOwnerMapping,
        OriginalLineageRuntimeRecord, RuntimeError, RuntimeLimits, SavedRuntimeActivation,
        SavedRuntimeResult,
    },
    node_scheduling::{InputPayload, SchedulingSnapshot},
    node_state::PinnedOriginalLineageSource,
};
use crucible_node_contract::{ContentRef, Id, Validate, canonical};
use serde::Serialize;

use super::{
    conditional_capture_factory::ConditionalCaptureFactory, conditional_profile::ConditionalProfile,
};

pub(super) struct ModelEvidence {
    pub(super) node: Id,
    pub(super) native: NativeRuntimeContinuationEvidence,
}

pub(super) struct TwinsVerifier<'a> {
    pub(super) source_graph: &'a AdmittedGraph,
    pub(super) source_profile: &'a ConditionalProfile,
    pub(super) factory: &'a ConditionalCaptureFactory,
    pub(super) pins: &'a [Rc<PinnedOriginalLineageSource>],
    pub(super) target_profile: &'a ConditionalProfile,
    pub(super) target_graph: &'a AdmittedGraph,
    pub(super) evidence: &'a [ModelEvidence],
    pub(super) proof_custody: &'a mut Vec<InputPayload>,
}

impl NativeRuntimeContinuationVerifier for TwinsVerifier<'_> {
    fn verify_runtime_continuation(
        &mut self,
        _: &crucible::node_contract::RuntimeSnapshot,
        _: &SchedulingSnapshot,
        _: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
        // Legacy projections cannot authenticate the complete selected Runtime7.
        Err(RuntimeError::InvalidReceipt)
    }

    fn verify_original_lineage_scope(
        &mut self,
        source_record: &ContentRef,
        record: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
        _: RuntimeLimits,
    ) -> Result<OriginalLineageNativeScope, RuntimeError> {
        // Exact signed owners and the accepted source cut are checked before
        // copying any journal metadata into the verifier's inert response.
        let first = self.pins.first().ok_or(RuntimeError::InvalidReceipt)?;
        if self.pins.len() != 3
            || self.evidence.len() != 3
            || record.owners.len() != 3
            || source_record != first.runtime_reference()
            || record != first.runtime()
            || scheduling != first.scheduling()
            || record.source_activation
                != SavedRuntimeActivation::from(&self.source_profile.activation)
            || target != &self.target_profile.activation
            || target.world_binding_hash != record.source_activation.world_binding_hash
            || self.source_graph.world_binding_hash() != &target.world_binding_hash
            || self.target_graph.world_binding_hash() != &target.world_binding_hash
            || target.boundary != record.capture_cut
            || target.generation.get()
                != record
                    .source_activation
                    .generation
                    .get()
                    .checked_add(1)
                    .ok_or(RuntimeError::InvalidReceipt)?
            || record.operations.len() > 9
            || record.inputs.len() > 9
            || self.proof_custody.len() >= 3
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for pin in self.pins {
            if pin.source_artifact() != first.source_artifact()
                || pin.runtime_reference() != source_record
                || pin.runtime() != record
                || pin.scheduling() != scheduling
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            self.factory
                .verify_pinned_source(self.source_graph, pin)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }

        let mut owners = reserve(3)?;
        for saved in &record.owners {
            if self
                .pins
                .iter()
                .filter(|pin| pin.source().owner().owner == saved.identity.owner)
                .count()
                != 1
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            let fresh = target
                .owners
                .iter()
                .find(|owner| owner.owner == saved.identity.owner)
                .ok_or(RuntimeError::ForeignAuthority)?;
            if fresh.incarnation == saved.identity.incarnation
                || fresh.generation.get()
                    != saved
                        .identity
                        .generation
                        .get()
                        .checked_add(1)
                        .ok_or(RuntimeError::InvalidReceipt)?
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            owners.push(OriginalLineageOwnerMapping {
                source: saved.identity.clone(),
                target: fresh.clone(),
            });
        }

        let mut journals = reserve(3)?;
        let mut acknowledgements = reserve(9)?;
        for node in self.target_graph.node_ids() {
            let mut selected = self.evidence.iter().filter(|entry| &entry.node == node);
            let evidence = selected.next().ok_or(RuntimeError::InvalidReceipt)?;
            if selected.next().is_some() {
                return Err(RuntimeError::InvalidReceipt);
            }
            evidence
                .native
                .proof
                .validate()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let binding = self
                .target_graph
                .binding(node)
                .ok_or(RuntimeError::UnknownNode)?;
            let expected = record.inputs.iter().filter(|input| &input.node == node);
            if expected.clone().count() != 3 || evidence.native.input_acknowledgements.len() != 3 {
                return Err(RuntimeError::InvalidReceipt);
            }
            for fresh in &evidence.native.input_acknowledgements {
                let saved = expected
                    .clone()
                    .find(|input| input.stage_operation == fresh.stage_operation)
                    .ok_or(RuntimeError::InvalidReceipt)?;
                let original = saved
                    .acknowledgement
                    .as_ref()
                    .ok_or(RuntimeError::InvalidReceipt)?;
                let [owner] = fresh.owners.as_slice() else {
                    return Err(RuntimeError::InvalidReceipt);
                };
                if fresh.node != original.node
                    || fresh.batch != original.batch
                    || fresh.inventory != original.inventory
                    || fresh.cutoff != original.cutoff
                    || owner.owner != binding.compatibility.execution_owner.id
                    || !target.owners.contains(owner)
                    || fresh.proof_ref == original.proof_ref
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                acknowledgements.push(fresh.clone());
            }
            let saved_operations = record
                .operations
                .iter()
                .filter(|operation| &operation.route.node == node);
            if saved_operations.clone().count() != 3
                || saved_operations
                    .clone()
                    .filter(|operation| matches!(operation.result, SavedRuntimeResult::Pending))
                    .count()
                    != 1
                || saved_operations
                    .clone()
                    .filter(|operation| {
                        matches!(operation.result, SavedRuntimeResult::Acknowledged(_))
                    })
                    .count()
                    != 2
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            let mut operations = reserve(3)?;
            let mut pending_operations = reserve(1)?;
            let mut acknowledged_operations = reserve(2)?;
            let mut input_stages = reserve(3)?;
            for saved in saved_operations {
                operations.push(saved.operation.clone());
                match &saved.result {
                    SavedRuntimeResult::Pending => pending_operations.push(saved.operation.clone()),
                    SavedRuntimeResult::Acknowledged(_) => {
                        acknowledged_operations.push(saved.operation.clone())
                    }
                    SavedRuntimeResult::Complete(_) | SavedRuntimeResult::Failed(_) => {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                }
            }
            input_stages.extend(expected.map(|input| input.stage_operation.clone()));
            if operations.len() != 3
                || pending_operations.len() != 1
                || acknowledged_operations.len() != 2
                || input_stages.len() != 3
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            operations.sort();
            input_stages.sort();
            acknowledged_operations.sort();
            journals.push(OriginalLineageJournal {
                node: node.clone(),
                operations,
                pending_operations,
                acknowledged_operations,
                input_stages,
            });
        }
        journals.sort_by(|left, right| left.node.cmp(&right.node));
        acknowledgements.sort_by(|left, right| left.stage_operation.cmp(&right.stage_operation));
        if acknowledgements
            .windows(2)
            .any(|pair| pair[0].stage_operation == pair[1].stage_operation)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        if record
            .inputs
            .iter()
            .filter(|input| input.lineage.is_some())
            .count()
            != 4
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let mut first_scopes = reserve(4)?;
        first_scopes.extend(
            record
                .inputs
                .iter()
                .filter_map(|input| input.lineage.as_ref().map(|lineage| lineage.source.clone())),
        );

        #[derive(Serialize)]
        struct Witness<'a> {
            format: &'static str,
            source_artifact: &'a ContentRef,
            source_record: &'a ContentRef,
            target: SavedRuntimeActivation,
            model_proofs: Vec<(&'a Id, &'a ContentRef)>,
        }
        let mut model_proofs = reserve(3)?;
        model_proofs.extend(
            self.evidence
                .iter()
                .map(|entry| (&entry.node, &entry.native.proof)),
        );
        model_proofs.sort_by(|left, right| left.0.cmp(right.0));
        let witness = Witness {
            format: "crucible.reader-tape2.owned-twins-verifier.v1",
            source_artifact: first.source_artifact(),
            source_record,
            target: SavedRuntimeActivation::from(target),
            model_proofs,
        };
        metadata_credit(&witness)?;
        self.proof_custody
            .try_reserve(1)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let value = serde_json::to_value(witness).map_err(|_| RuntimeError::InvalidReceipt)?;
        let bytes = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
        if bytes.len() > 65_536 {
            return Err(RuntimeError::InvalidReceipt);
        }
        let proof = canonical::content_ref(&bytes, "application/json")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.proof_custody.push(InputPayload {
            reference: proof.clone(),
            bytes,
        });
        Ok(OriginalLineageNativeScope {
            coordinator_schema: 7,
            source_record: source_record.clone(),
            source_capture: record.source_activation.clone(),
            target: target.clone(),
            owners,
            first_scopes,
            journals,
            input_acknowledgements: acknowledgements,
            proof,
        })
    }
}

fn reserve<T>(count: usize) -> Result<Vec<T>, RuntimeError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(values)
}

fn metadata_credit(value: &impl Serialize) -> Result<(), RuntimeError> {
    struct Credit(usize);

    impl std::io::Write for Credit {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|total| *total <= 65_536)
                .ok_or_else(|| std::io::Error::other("twins witness metadata credit exhausted"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    serde_json::to_writer(Credit(0), value).map_err(|_| RuntimeError::InvalidReceipt)
}
