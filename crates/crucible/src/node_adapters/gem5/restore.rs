//! Fresh native lineage and original-cache attachment beneath restored authority.

use std::{collections::BTreeSet, rc::Rc};

use crucible_node_contract::canonical;

use crate::{node_contract::*, node_scheduling::RuntimeInputBatch};

use super::{
    Gem5NodePreparation, QualifiedGem5Node, continuation::Gem5AuthenticatedContinuation,
    ledger::OperationLedger, node::native_refusal, refusal,
};

pub(super) fn validate_fresh_continuation(
    preparation: &Gem5NodePreparation,
    restored: &Gem5AuthenticatedContinuation,
) -> Result<(), OperationFailure> {
    let wire = &restored.record.wire;
    let native = &preparation.native;
    let old = wire
        .owners
        .first()
        .ok_or_else(|| refusal("gem5 original owner missing"))?;
    let fresh = preparation
        .route
        .owners
        .first()
        .ok_or_else(|| refusal("gem5 fresh owner missing"))?;
    if preparation.route.node != wire.node
        || preparation.world_binding_hash != wire.source_activation.world_binding_hash
        || old.owner != fresh.owner
        || old.incarnation == fresh.incarnation
        || old.generation >= fresh.generation
        || native.boundary() != &wire.native_boundary
        || native.launch().guest_isa != wire.guest_isa
        || native
            .pending_completion()
            .map(|receipt| &receipt.operation)
            != wire.native_pending.as_ref()
        || native.last_acknowledged() != wire.native_acknowledged.as_ref()
        || native.completed_prefixes().len() != restored.record.prefixes.len()
    {
        return Err(refusal(
            "gem5 fresh native peer differs from authenticated original cut or custody",
        ));
    }

    for prefix in native.completed_prefixes() {
        if restored.record.prefixes.get(&prefix.operation) != Some(prefix) {
            return Err(refusal(
                "gem5 actual restored original native prefix differs",
            ));
        }
        native.validate_completion(prefix).map_err(native_refusal)?;
    }
    Ok(())
}

impl QualifiedGem5Node {
    /// Authenticates genuine fresh native reattachment without executing original work.
    ///
    /// Installed whole-world capsules use this evidence in their trusted native
    /// continuation verifier before publication. Original permissions remain
    /// inert until the runtime supplies fresh opaque operation handles.
    ///
    /// # Errors
    /// Refuses changed source runtime/cut, stale target owners, foreign world
    /// identities, missing original custody or a substituted fresh native peer.
    pub fn restored_continuation_evidence(
        &self,
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, OperationFailure> {
        let restored = self
            .restored
            .as_ref()
            .ok_or_else(|| refusal("gem5 has no authenticated original continuation"))?;
        if source != &restored.source
            || target.boundary != source.capture_cut
            || target.world_binding_hash != self.preparation.world_binding_hash
            || !self
                .preparation
                .route
                .owners
                .iter()
                .all(|owner| target.owners.contains(owner))
            || target.generation <= source.source_activation.generation
            || target.activation_id == source.source_activation.activation_id
        {
            return Err(refusal(
                "gem5 unchanged native continuation differs from fresh complete world",
            ));
        }
        validate_fresh_continuation(&self.preparation, restored)?;
        self.preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(native_refusal)?;
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.gem5.fresh-continuation.v1",
            "source":source,"target":{"generation":target.generation,"activation_id":target.activation_id,"world_binding_hash":target.world_binding_hash,"owners":target.owners,"boundary":target.boundary},
            "node":self.preparation.route.node,"native":self.preparation.native.boundary(),"live_closure":self.authority.evidence().0,
        })).map_err(|error| refusal(&error.to_string()))?;
        Ok(NativeRuntimeContinuationEvidence {
            proof: canonical::content_ref(&bytes, "application/json")
                .map_err(|error| refusal(&error.to_string()))?,
            input_acknowledgements: Vec::new(),
        })
    }

    pub(super) fn install_original_custody(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        operations: &[OperationAdmission],
        inputs: &[Rc<RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.restored_continuation_evidence(source, activation.record())?;
        if !inputs.is_empty()
            || !self.same_world(activation)
            || self.quarantined
            || self.active.is_some()
            || self.ledger.operations().len() != 0
        {
            return Err(refusal(
                "gem5 restored original custody is repeated or input-bearing",
            ));
        }
        let restored = self
            .restored
            .as_ref()
            .ok_or_else(|| refusal("gem5 original continuation absent"))?;
        if operations.len() != restored.record.wire.operations.len() {
            return Err(refusal(
                "gem5 restored original opaque handle roster is incomplete",
            ));
        }

        let mut ledger = OperationLedger::new(
            self.resources.maximum_operations,
            self.resources.maximum_prefixes,
            self.resources.maximum_retained_bytes,
        )?;
        super::observations::retain_historical_observations(&mut ledger, &restored.record)?;
        let mut unique = BTreeSet::new();
        let mut active = None;
        for saved in &restored.record.wire.operations {
            let original = operations
                .iter()
                .find(|operation| operation.token().operation() == &saved.original.operation)
                .ok_or_else(|| refusal("gem5 original opaque restored handle missing"))?;
            if !unique.insert(original.token().operation())
                || original.token().route() != &self.preparation.route
                || original.request() != &saved.original.request
                || original.inputs().is_some()
                || !Rc::ptr_eq(&original.activation.authority, &activation.authority)
            {
                return Err(refusal(
                    "gem5 fresh opaque original handle changed route or permission",
                ));
            }
            ledger.reserve(original)?;
            for (index, reference) in saved.prefixes.iter().enumerate() {
                let object = restored
                    .record
                    .evidence
                    .get(reference)
                    .ok_or_else(|| refusal("gem5 preserved receipt body missing"))?;
                let receipt: crucible_node_provider::gem5::Gem5Completion = serde_json::from_value(
                    canonical::parse_json(&object.bytes, 16 * 1024 * 1024)
                        .map_err(|error| refusal(&error.to_string()))?,
                )
                .map_err(|error| refusal(&error.to_string()))?;
                if ledger.retain_prefix(original.token(), receipt)? != *reference {
                    return Err(refusal("gem5 original preserved receipt bytes changed"));
                }
                ledger.original_mut(original.token())?.prefix_scopes[index] =
                    saved.prefix_scopes[index].clone();
            }
            match &saved.original.result {
                SavedRuntimeResult::Failed(_) => {
                    return Err(refusal(
                        "gem5 failed native continuation requires unresolved-effect custody",
                    ));
                }
                SavedRuntimeResult::Pending => {
                    if active.replace(saved.original.operation.clone()).is_some() {
                        return Err(refusal(
                            "gem5 multiple native original operations remain active",
                        ));
                    }
                }
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => {
                    let mut outcome = outcome.clone();
                    outcome.owners = self.preparation.route.owners.clone();
                    if let Some(observation) = &mut outcome.scheduling {
                        observation.owners = outcome.owners.clone();
                    }
                    let mut objects = Vec::new();
                    if let Some(observation) = &outcome.scheduling {
                        for publication in &observation.publications {
                            let object = restored
                                .record
                                .evidence
                                .get(&publication.payload)
                                .ok_or_else(|| {
                                    refusal("gem5 preserved publication body missing")
                                })?;
                            if object.bytes != publication.payload_bytes {
                                return Err(refusal("gem5 preserved publication bytes changed"));
                            }
                            objects.push(object.clone());
                        }
                    }
                    ledger.retain_objects(original.token(), objects)?;
                    let retained = ledger.original_mut(original.token())?;
                    retained.outcome = Some(outcome);
                    retained.acknowledged =
                        matches!(saved.original.result, SavedRuntimeResult::Acknowledged(_));
                    if !retained.acknowledged
                        && active.replace(saved.original.operation.clone()).is_some()
                    {
                        return Err(refusal("gem5 multiple held original native ACKs remain"));
                    }
                }
            }
        }
        // Installing caches performs no native command, event, staging or ACK.
        // The complete replacement is built first; failures leave original
        // native custody in the owning inactive capsule and common supervisor.
        self.ledger = ledger;
        self.active = active;
        self.activation_authority = Some(Rc::clone(&activation.authority));
        Ok(())
    }
}
