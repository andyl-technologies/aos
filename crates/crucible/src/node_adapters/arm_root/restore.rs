//! Reattaches exact original Root custody beneath genuinely fresh native authority.
//!
//! Imported history remains inert until the complete world publishes and the
//! runtime supplies fresh opaque operation handles. Cache installation performs
//! no native Run, ACK, capture or input staging.

use std::{collections::BTreeSet, rc::Rc};

use crucible_node_contract::{ContentRef, Id, canonical};
use crucible_node_provider::gem5::{ArmRootExactAuthority, ArmRootRunOutcome};
use serde::Serialize;

use crate::{node_contract::*, node_scheduling::RuntimeInputBatch};

use super::{
    ArmRootNodePreparation, ArmRootNodeResources, AuthenticatedArmRootContinuation,
    QualifiedArmRootNode, encoding, ledger::RootLedger, refusal,
};

pub(super) fn validate_fresh(
    preparation: &ArmRootNodePreparation,
    authority: &ArmRootExactAuthority,
    resources: ArmRootNodeResources,
    source: &AuthenticatedArmRootContinuation,
) -> Result<(), OperationFailure> {
    let native = &preparation.native;
    let old = source
        .wire
        .owners
        .first()
        .ok_or_else(|| refusal("ARM signed original owner is absent"))?;
    let fresh = preparation
        .route
        .owners
        .first()
        .ok_or_else(|| refusal("ARM actual fresh owner is absent"))?;
    let launch = native
        .launch()
        .map_err(|error| refusal(&error.to_string()))?;
    if source.wire.node != preparation.route.node
        || preparation.world_binding_hash != source.wire.source_activation.world_binding_hash
        || preparation.route.owners.len() != 1
        || source.wire.owners.len() != 1
        || old.owner != fresh.owner
        || old.incarnation == fresh.incarnation
        || old.generation >= fresh.generation
        || native.boundary() != &source.wire.native_boundary
        || native.pending_operation() != source.pending()
        || native.last_acknowledged_operation() != source.last_acknowledged()
        || native.outcomes().len() != source.wire.native_outcomes.len()
        || resources.maximum_events_per_poll != source.maximum_events_per_poll()
        || authority.maximum_microsteps() != source.wire.maximum_microsteps
        || launch.profile() != &source.wire.source.profile
        || !launch.bindings().eq(source
            .wire
            .source
            .bindings
            .iter()
            .map(|(role, reference)| (role.as_str(), reference)))
    {
        return Err(refusal(
            "ARM actual fresh peer differs from the complete signed original custody",
        ));
    }
    native
        .restored_prepared_session(authority, source.capture())
        .map_err(|error| refusal(&error.to_string()))?;
    native
        .next_publication_bound(authority)
        .map_err(|error| refusal(&error.to_string()))?;

    let history = native
        .control_history()
        .map_err(|error| refusal(&error.to_string()))?;
    if history.schema != source.control.schema
        || !history.packets.starts_with(&source.control.packets)
        || !history.sessions.starts_with(&source.control.sessions)
    {
        return Err(refusal(
            "ARM fresh reconstruction lost original ordered control or preparation bodies",
        ));
    }
    // The native cache is keyed by operation ID; the signed roster follows
    // original transport order. Authenticate exact bodies without treating
    // lexicographic cache order as a second chronological transcript.
    let mut seen = BTreeSet::new();
    for reference in &source.wire.native_outcomes {
        let body = source.object(reference)?;
        if !seen.insert(reference)
            || !native
                .outcomes()
                .any(|(_, actual)| actual.bytes() == body.bytes)
        {
            return Err(refusal(
                "ARM restored original native response bytes changed or repeat",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_target(
    preparation: &ArmRootNodePreparation,
    authority: &ArmRootExactAuthority,
    source: &AuthenticatedArmRootContinuation,
    target: &ActivationRecord,
) -> Result<(), OperationFailure> {
    if target.world_binding_hash != preparation.world_binding_hash
        || target.boundary != source.common_cut()
        || target.activation_id == source.runtime.source_activation.activation_id
        || target.generation <= source.runtime.source_activation.generation
        || !preparation
            .route
            .owners
            .iter()
            .all(|owner| target.owners.contains(owner))
        || preparation.native.boundary() != source.native_boundary()
    {
        return Err(refusal(
            "ARM fresh complete-world activation differs from signed source lineage",
        ));
    }
    preparation
        .native
        .restored_prepared_session(authority, source.capture())
        .map_err(|error| refusal(&error.to_string()))?;
    preparation
        .native
        .next_publication_bound(authority)
        .map_err(|error| refusal(&error.to_string()))?;
    Ok(())
}

#[derive(Serialize)]
struct ContinuationProof<'a> {
    schema: &'static str,
    source: &'a ContentRef,
    target: SavedRuntimeActivation,
    node: &'a Id,
    native: &'a crucible_node_provider::gem5::Gem5Boundary,
    current_closure: &'a ContentRef,
}

impl QualifiedArmRootNode {
    /// Authenticates actual unchanged native custody beneath a fresh complete world.
    ///
    /// This proof is consumed by an installed continuation verifier. Historical
    /// permission bodies alone never establish current execution authority.
    ///
    /// # Errors
    /// Refuses changed runtime, foreign target, missing original native history,
    /// changed resource policy or an unavailable current native certificate.
    pub fn restored_continuation_evidence(
        &self,
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, OperationFailure> {
        let original = self
            .restored
            .as_ref()
            .ok_or_else(|| refusal("ARM signed original continuation is absent"))?;
        if source != original.runtime() || self.quarantined {
            return Err(refusal(
                "ARM restored runtime differs from authenticated original history",
            ));
        }
        validate_fresh(&self.preparation, &self.authority, self.resources, original)?;
        validate_target(&self.preparation, &self.authority, original, target)?;
        let bytes = encoding::record(
            &ContinuationProof {
                schema: "crucible.gem5.arm-root-fresh-continuation.v1",
                source: original.source_record().0,
                target: SavedRuntimeActivation::from(target),
                node: &self.preparation.route.node,
                native: self.preparation.native.boundary(),
                current_closure: self.authority.evidence().0,
            },
            16 * 1024 * 1024,
        )?;
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
        if !self.same_world(activation)
            || !inputs.is_empty()
            || self.active.is_some()
            || !self.ledger.operations.is_empty()
        {
            return Err(refusal(
                "ARM original cache installation is repeated or input-bearing",
            ));
        }
        let restored = self
            .restored
            .as_ref()
            .ok_or_else(|| refusal("ARM signed source history disappeared"))?;
        if operations.len() != restored.wire.operations.len() {
            return Err(refusal(
                "ARM restored original opaque handle roster is incomplete",
            ));
        }
        let mut ledger = RootLedger::new(
            self.resources.maximum_operations,
            self.resources.maximum_prefixes,
            self.resources.maximum_retained_bytes,
        )?;
        // Preserve source receipts and newly armed target readiness in the same
        // finite owner ledger before replacing any live common cache.
        for body in restored
            .evidence
            .values()
            .chain(self.ledger.standalone.iter())
        {
            ledger.retain_standalone(&[(&body.reference, &body.bytes)])?;
        }
        ledger.retain_standalone(&[(restored.source_record().0, restored.source_record().1)])?;
        let mut seen = BTreeSet::new();
        let mut active = None;
        for saved in &restored.wire.operations {
            let admission = operations
                .iter()
                .find(|admission| admission.token().operation() == &saved.original.operation)
                .ok_or_else(|| refusal("ARM original fresh opaque operation handle is absent"))?;
            if !seen.insert(admission.token().operation())
                || admission.token().route() != &self.preparation.route
                || admission.request() != &saved.original.request
                || admission.inputs().is_some()
                || !Rc::ptr_eq(&admission.activation.authority, &activation.authority)
            {
                return Err(refusal(
                    "ARM fresh original handle changed its immutable permission or custody",
                ));
            }
            ledger.reserve(admission)?;
            for (index, prefix) in saved.prefixes.iter().enumerate() {
                let body = restored.object(&prefix.body)?;
                let actual = self
                    .preparation
                    .native
                    .outcomes()
                    .find_map(|(_, native)| (native.bytes() == body.bytes).then_some(native))
                    .ok_or_else(|| {
                        refusal("ARM restored peer lacks an original native response")
                    })?;
                ledger.prepare_prefix(admission.token())?;
                if ledger.retain_prefix(admission.token(), actual.clone())? != prefix.body {
                    return Err(refusal(
                        "ARM original native response content identity changed",
                    ));
                }
                let retained = &mut ledger.original_mut(admission.token())?.prefixes[index];
                retained.activation = prefix.activation.clone();
                retained.route = prefix.route.clone();
            }
            match &saved.original.result {
                SavedRuntimeResult::Pending => {
                    if active.replace(saved.original.operation.clone()).is_some() {
                        return Err(refusal(
                            "ARM source retains multiple active original operations",
                        ));
                    }
                }
                SavedRuntimeResult::Failed(_) => {
                    return Err(refusal(
                        "ARM failed original continuation needs unresolved-effect custody",
                    ));
                }
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => {
                    validate_cached_outcome(
                        &ledger,
                        admission,
                        outcome,
                        &saved.original.route.owners,
                        &self.output,
                    )?;
                    let mut fresh = outcome.clone();
                    fresh.owners = self.preparation.route.owners.clone();
                    if let Some(scheduling) = &mut fresh.scheduling {
                        scheduling.owners = fresh.owners.clone();
                        for publication in &scheduling.publications {
                            let body = restored.object(&publication.payload)?;
                            if publication.payload_bytes != body.bytes {
                                return Err(refusal("ARM original publication bytes changed"));
                            }
                            ledger.retain_payload(
                                admission.token(),
                                &body.reference,
                                &body.bytes,
                            )?;
                        }
                    }
                    let original = ledger.original_mut(admission.token())?;
                    original.outcome = Some(fresh);
                    original.acknowledged =
                        matches!(saved.original.result, SavedRuntimeResult::Acknowledged(_));
                    if !original.acknowledged
                        && active.replace(saved.original.operation.clone()).is_some()
                    {
                        return Err(refusal("ARM source retains multiple held original ACKs"));
                    }
                }
            }
        }
        // All fallible authentication and allocation precedes this ownership
        // move; refusal leaves native and original signed data in this node.
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(restored.wire.observations.len() + self.observations.len())
            .map_err(|_| refusal("ARM restored stopped-observation slots are unavailable"))?;
        observations.extend(restored.wire.observations.iter().cloned());
        for reference in &self.observations {
            if !observations.contains(reference) {
                observations.push(reference.clone());
            }
        }
        self.observations = observations;
        self.ledger = ledger;
        self.active = active;
        self.sequence = restored.wire.output_sequence.get();
        self.activation_authority = Some(Rc::clone(&activation.authority));
        Ok(())
    }
}

fn validate_cached_outcome(
    ledger: &RootLedger,
    admission: &OperationAdmission,
    outcome: &OperationOutcome,
    source_owners: &[OwnerIdentity],
    output: &crucible_node_contract::Endpoint,
) -> Result<(), OperationFailure> {
    let original = ledger.original(admission.token())?;
    let terminal = original
        .prefixes
        .last()
        .ok_or_else(|| refusal("ARM cached terminal outcome has no original native prefix"))?;
    let ArmRootRunOutcome::Completed { prefix, .. } = &terminal.outcome else {
        return Err(refusal(
            "ARM refused native Poll cannot become a cached terminal outcome",
        ));
    };
    let limit = match admission.request() {
        OperationRequest::ExactRun { limit, .. }
        | OperationRequest::BoundarySettle { limit, .. } => *limit,
        _ => return Err(refusal("ARM cached operation class differs")),
    };
    let stop = if prefix.after.logical_position == limit {
        StopReason::HorizonPark
    } else if !prefix.publications.is_empty() {
        StopReason::Output
    } else if prefix.reason == "guest_exit" {
        StopReason::Lifecycle
    } else {
        return Err(refusal("ARM cached prefix is not a terminal common stop"));
    };
    let cap = prefix
        .original
        .exact_range
        .as_ref()
        .ok_or_else(|| refusal("ARM original exact range is absent"))?
        .maximum_microsteps;
    let expected_bound = match prefix.publications.first() {
        Some(publication) => crate::node_scheduling::NativeOutputBound::At(
            super::execution::serial_positions(publication.tick, publication.tick_ordinal, cap)?.1,
        ),
        None => match prefix
            .after
            .next_reaction(cap)
            .map_err(|error| refusal(&error.to_string()))?
        {
            Some(reaction) => crate::node_scheduling::NativeOutputBound::At(
                reaction
                    .reaction_publication(cap)
                    .map_err(|error| refusal(&error.to_string()))?,
            ),
            None => crate::node_scheduling::NativeOutputBound::AfterInstant(u64::MAX.into()),
        },
    };
    let scheduling = outcome
        .scheduling
        .as_ref()
        .ok_or_else(|| refusal("ARM cached outcome omits original native scheduling"))?;
    if outcome.operation != *admission.token().operation()
        || outcome.node != admission.token().route().node
        || outcome.progress
            != (ProgressEvidence::Exact {
                reached: prefix.after.logical_position,
                stop,
            })
        || scheduling.reached != prefix.after.logical_position
        || scheduling.closed_prefix != prefix.after.logical_position
        || scheduling.proof_ref != terminal.proof
        || !scheduling.external_inputs.is_empty()
        || scheduling.input_progress.is_some()
        || scheduling.bounds.len() != 1
        || scheduling.bounds[0].producer != outcome.node
        || scheduling.bounds[0].proof_ref != terminal.proof
        || scheduling.bounds[0].bound != expected_bound
        || outcome.owners != source_owners
        || scheduling.owners != outcome.owners
        || scheduling.node != outcome.node
        || scheduling.publications.len() != prefix.publications.len()
        || outcome.retained_outputs
            != scheduling
                .publications
                .iter()
                .map(|birth| birth.publication_id.clone())
                .collect::<Vec<_>>()
    {
        return Err(refusal(
            "ARM cached common terminal differs from original native progress",
        ));
    }
    for (publication, native) in scheduling.publications.iter().zip(&prefix.publications) {
        let (evaluation, position) = super::execution::serial_positions(
            native.tick,
            native.tick_ordinal,
            prefix
                .original
                .exact_range
                .as_ref()
                .ok_or_else(|| refusal("ARM original exact range absent"))?
                .maximum_microsteps,
        )?;
        if &publication.endpoint != output
            || publication.native_sequence != native.output_id
            || publication.publication != position
            || publication.evaluation != Some(evaluation)
            || publication.payload_bytes != native.payload
            || !publication.causal_parents.is_empty()
            || publication.publication_id.as_str()
                != format!("arm-root/serial/{}", native.output_id.get())
        {
            return Err(refusal(
                "ARM cached publication differs from its original native Serial birth",
            ));
        }
        publication
            .payload
            .verify(&native.payload)
            .map_err(|error| refusal(&error.to_string()))?;
    }
    Ok(())
}
