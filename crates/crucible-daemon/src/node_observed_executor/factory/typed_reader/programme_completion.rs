//! Joins actual common completions to previously enrolled native source seals.
//!
//! Expected outcomes are regenerated from the immutable programme and original
//! source callbacks. Common reports cannot enroll an oracle. This check performs
//! no native work or ACK and supplies no accepted class or ordinary admission.

use std::collections::BTreeMap;

use crucible::{
    node_contract::{
        OperationOutcome, OriginalInputEvidence, OwnerIdentity, PhysicalState, ProgressEvidence,
        QuantumClosureEvidence,
    },
    node_scheduling::{
        NativeInputProgress, NativeOutputBound, NativeProducerBound, NativePublication,
        NativeSchedulingObservation,
    },
};
use crucible_node_contract::{ContentRef, Phase, Position, U64, canonical};
use crucible_node_provider::{ProviderError, reference_lineage::InputLineageInventory};
use serde::Serialize;

use super::{
    TypedReaderNativeOracles,
    programme::{count, invalid},
    programme_seals::OriginalTypedWindowSeal,
};
use crate::node_qualification::{OriginalCompletionObservation, OriginalCompletionWitness};

impl TypedReaderNativeOracles {
    /// Regenerates the complete expected common outcome from an original source seal.
    ///
    /// This must be called after source enrollment and before reading a common
    /// outcome or report. Native measurements remain historical observations;
    /// physical state stays Unknown. The returned record grants no permission.
    ///
    /// # Errors
    /// Refuses an unenrolled or malformed source case, an overflowing boundary
    /// or unavailable complete canonical output/pending inventory credit.
    pub fn expected_outcome(&self, case: &str) -> Result<OperationOutcome, ProviderError> {
        let seal = self.original(case)?;
        let planned = self.programme.window(
            &seal
                .observation
                .events
                .first()
                .ok_or_else(invalid)?
                .source
                .node_id,
            seal.controlled.grant.quantum,
        )?;
        let peer = self.programme.peer(&planned.node)?;
        let [event] = seal.observation.events.as_slice() else {
            return Err(invalid());
        };
        let owners = vec![OwnerIdentity {
            owner: peer.owner.clone(),
            incarnation: peer.incarnation.clone(),
            generation: U64::new(1),
        }];
        let reached = Position::new(
            seal.controlled.grant.publication.time_ps,
            U64::new(0),
            Phase::BoundaryControl,
        );
        let next = seal
            .controlled
            .grant
            .publication
            .time_ps
            .get()
            .checked_add(1000)
            .ok_or_else(invalid)?;
        let payload_bytes = bytes(&planned.output)?;
        event.payload.verify(&payload_bytes)?;
        let scheduling = NativeSchedulingObservation {
            node: planned.node.clone(),
            owners: owners.clone(),
            reached,
            closed_prefix: reached,
            bounds: vec![NativeProducerBound {
                producer: planned.node.clone(),
                bound: NativeOutputBound::At(Position::new(
                    U64::new(next),
                    U64::new(0),
                    Phase::Publication,
                )),
                proof_ref: seal.measurement.clone(),
            }],
            publications: vec![NativePublication {
                publication_id: event.id.clone(),
                endpoint: event.source.clone(),
                native_sequence: event.source_sequence,
                publication: event.publication_position,
                evaluation: None,
                causal_parents: Vec::new(),
                payload: event.payload.clone(),
                payload_bytes,
            }],
            input_progress: Some(NativeInputProgress {
                batch: planned.batch.clone(),
                consumed: seal.consumed.clone(),
                proof_ref: seal.measurement.clone(),
            }),
            external_inputs: Vec::new(),
            proof_ref: seal.measurement.clone(),
        };
        let output_inventory = reference(&scheduling.publications)?;
        let pending_inventory = reference(&serde_json::json!({
            "schema_version": 1, "input_batch": planned.batch,
            "input_disposition": "consumed", "original_buffer_retained": true,
            "outputs_retained": true, "application_parked": seal.controlled.application_parked,
            "owner": owners[0],
        }))?;
        Ok(OperationOutcome {
            operation: planned.operation.clone(),
            node: planned.node.clone(),
            owners,
            progress: ProgressEvidence::Quantized {
                window: planned.window.clone(),
                publication: seal.controlled.grant.publication,
                physical: PhysicalState::Unknown,
                closure: Box::new(QuantumClosureEvidence {
                    input_batch: planned.batch.clone(),
                    close_receipt: seal.measurement.clone(),
                    output_inventory,
                    pending_inventory,
                    clock_evidence: seal.measurement.clone(),
                }),
            },
            retained_outputs: vec![event.id.clone()],
            scheduling: Some(scheduling),
        })
    }

    /// Authenticates a runner-origin completion against the original native programme.
    ///
    /// The private runner witness borrows the actual token, retained outcome,
    /// original staging and full input proof. Semantic and unpredictable native
    /// expectations come exclusively from earlier source callbacks. This method
    /// neither enrolls report-derived expectations nor alters a failed result.
    ///
    /// # Errors
    /// Refuses another timing family/case, changed grant, complete outcome,
    /// original world/owner scope, input lineage, ACK disposition, missing body
    /// or unauthenticated direct row. Publication must already be acknowledged.
    pub fn authenticate_completion(
        &self,
        case: &str,
        witness: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), ProviderError> {
        let expected = self.expected_outcome(case)?;
        let seal = self.original(case)?;
        let planned = self
            .programme
            .window(&expected.node, seal.controlled.grant.quantum)?;
        let original = witness.original();
        let admission = original.admission();
        let activation = admission.activation().record();
        if planned.case != case
            || admission.request() != &planned.request
            || admission.token().operation() != &planned.operation
            || admission.token().route().node != expected.node
            || admission.token().route().owners != expected.owners
            || activation.activation_id != seal.stop.activation_id
            || activation.world_binding_hash != seal.stop.world_binding_hash
            || activation.generation != seal.stop.world_generation
            || original.outcome() != &expected
            || !original.acknowledged()
        {
            return Err(invalid());
        }
        let OriginalCompletionObservation::Quantized(observation) = witness.observation() else {
            return Err(invalid());
        };
        if observation.case != case {
            return Err(invalid());
        }
        witness.reference().verify(witness.bytes())?;

        let staged = original
            .staged_inputs()
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let batch = staged.batch();
        let acknowledgement = staged.acknowledgement();
        if batch.node() != &planned.node
            || batch.stage_operation() != &planned.stage
            || batch.batch() != &planned.batch
            || batch.deliveries().len() != planned.producers.len()
            || acknowledgement.proof_ref != seal.stop.input_custody
            || !staged.committed()
            || staged.coordinator_commit().is_none()
        {
            return Err(invalid());
        }
        if !batch.deliveries().is_empty() {
            self.authenticate_inputs(
                batch,
                staged.provenance().ok_or_else(invalid)?,
                staged.lineage().ok_or_else(invalid)?,
            )?;
        }
        let native_input = witness.native_input().ok_or_else(invalid)?;
        authenticate_input_rows(&seal, staged, native_input)?;

        // Every observed completion body is a declared complete closure role or
        // the independently computed semantic payload. Extra unexplained roles
        // cannot become authenticated leaves by having a valid digest.
        let scheduling = expected.scheduling.as_ref().ok_or_else(invalid)?;
        let ProgressEvidence::Quantized { closure, .. } = &expected.progress else {
            return Err(invalid());
        };
        let output = bytes(&scheduling.publications)?;
        let pending = bytes(&serde_json::json!({
            "schema_version":1,"input_batch":planned.batch,
            "input_disposition":"consumed","original_buffer_retained":true,
            "outputs_retained":true,"application_parked":seal.controlled.application_parked,
            "owner":expected.owners[0],
        }))?;
        for object in &observation.objects {
            object.reference.verify(&object.bytes)?;
            let valid = if object.reference == closure.output_inventory {
                object.bytes == output
            } else if object.reference == closure.pending_inventory {
                object.bytes == pending
            } else if object.reference == scheduling.publications[0].payload {
                object.bytes == scheduling.publications[0].payload_bytes
            } else {
                seal.rows
                    .iter()
                    .any(|row| row.reference == object.reference && row.bytes == object.bytes)
            };
            if !valid {
                return Err(invalid());
            }
        }
        for required in [
            &closure.close_receipt,
            &closure.output_inventory,
            &closure.pending_inventory,
            &closure.clock_evidence,
            &scheduling.publications[0].payload,
        ] {
            if !observation
                .objects
                .iter()
                .any(|body| &body.reference == required)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

fn authenticate_input_rows(
    seal: &OriginalTypedWindowSeal,
    staged: &crucible::node_contract::OriginalStagedInput<'_>,
    evidence: &OriginalInputEvidence,
) -> Result<(), ProviderError> {
    if evidence.root != seal.stop.input_custody
        || evidence.objects.len() != evidence.rows.len()
        || evidence.objects.len() > 4096
        || evidence
            .objects
            .windows(2)
            .any(|pair| pair[0].reference >= pair[1].reference)
    {
        return Err(invalid());
    }
    // The source's accepted batch declares exactly one independently selected
    // inventory edge in addition to its original delivered Event roles.
    let input_body = bytes(&seal.input)?;
    let input_reference = reference(&seal.input)?;
    let source_batch = seal
        .rows
        .iter()
        .find(|row| row.reference == input_reference)
        .ok_or_else(invalid)?;
    if source_batch.bytes != input_body {
        return Err(invalid());
    }
    let inventory_ref = source_batch
        .dependencies
        .iter()
        .find(|reference| {
            reference.media_type
                == crucible_node_provider::reference_lineage::INPUT_LINEAGE_MEDIA_TYPE
        })
        .ok_or_else(invalid)?;
    let inventory_body = evidence
        .objects
        .iter()
        .find(|object| &object.reference == inventory_ref)
        .ok_or_else(invalid)?;
    count(&inventory_body.bytes, 16 * 1024 * 1024)?;
    inventory_ref.verify(&inventory_body.bytes)?;
    let inventory: InputLineageInventory = serde_json::from_slice(&inventory_body.bytes)
        .map_err(crucible_node_contract::ContractError::from)?;
    inventory.validate_bodies(&seal.input, seal.stop.owner_generation, |reference| {
        evidence
            .objects
            .iter()
            .find(|object| &object.reference == reference)
            .map(|object| object.bytes.as_slice())
            .ok_or_else(invalid)
    })?;
    if inventory.entries.len() != staged.batch().deliveries().len() {
        return Err(invalid());
    }
    let claims = staged
        .lineage()
        .map(|lineage| lineage.publications())
        .unwrap_or(&[]);
    if claims.len() != inventory.entries.len() {
        return Err(invalid());
    }
    let mut expected = BTreeMap::new();
    for row in &seal.rows {
        expected.insert(
            &row.reference,
            (row.bytes.as_slice(), row.dependencies.as_slice()),
        );
    }
    for claim in claims {
        if claim.objects.len() != claim.rows.len() {
            return Err(invalid());
        }
        for (object, row) in claim.objects.iter().zip(&claim.rows) {
            if object.reference != row.object || object.reference.verify(&object.bytes).is_err() {
                return Err(invalid());
            }
            if expected
                .insert(&object.reference, (&object.bytes, &row.dependencies))
                .is_some_and(|old| old != (object.bytes.as_slice(), row.dependencies.as_slice()))
            {
                return Err(invalid());
            }
        }
    }
    let mut inventory_edges = Vec::new();
    for (entry, claim) in inventory.entries.iter().zip(claims) {
        if entry.published != claim.published
            || entry.producer.measurement != claim.origin.measurement
            || entry.producer.stop_receipt != claim.origin.stop_receipt
            || entry.producer.observation_batch != claim.origin.observation_batch
        {
            return Err(invalid());
        }
        inventory_edges.extend([
            entry.delivered.clone(),
            entry.published.clone(),
            entry.producer.observation_batch.clone(),
            entry.producer.stop_receipt.clone(),
            entry.producer.measurement.clone(),
        ]);
    }
    inventory_edges.sort();
    inventory_edges.dedup();
    expected.insert(inventory_ref, (&inventory_body.bytes, &inventory_edges));
    require_complete_input_closure(&evidence.root, &expected, evidence)?;
    let mut total = 0usize;
    for (object, row) in evidence.objects.iter().zip(&evidence.rows) {
        total = total
            .checked_add(object.bytes.len())
            .filter(|bytes| *bytes <= 16 * 1024 * 1024)
            .ok_or_else(invalid)?;
        if row.object != object.reference
            || expected.get(&object.reference).copied()
                != Some((object.bytes.as_slice(), row.dependencies.as_slice()))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Requires exactly the expected source-selected closure reachable from Stage ACK.
/// Unrelated terminal-window rows are not required, and extra evidence is refused.
pub(super) fn require_complete_input_closure(
    root: &ContentRef,
    expected: &BTreeMap<&ContentRef, (&[u8], &[ContentRef])>,
    evidence: &OriginalInputEvidence,
) -> Result<(), ProviderError> {
    use std::collections::{BTreeSet, VecDeque};
    let mut pending = VecDeque::from([root]);
    let mut reachable = BTreeSet::new();
    let mut edges = 0usize;
    while let Some(reference) = pending.pop_front() {
        if !reachable.insert(reference) {
            continue;
        }
        if reachable.len() > 4096 {
            return Err(invalid());
        }
        let (_, dependencies) = expected.get(reference).ok_or_else(invalid)?;
        edges = edges
            .checked_add(dependencies.len())
            .filter(|n| *n <= 65536)
            .ok_or_else(invalid)?;
        pending.extend(dependencies.iter());
    }
    if reachable.len() != evidence.objects.len()
        || evidence
            .objects
            .iter()
            .any(|object| !reachable.contains(&object.reference))
    {
        return Err(invalid());
    }
    Ok(())
}

fn bytes(value: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    count(value, 65536)?;
    Ok(canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )?)
}

fn reference(value: &impl Serialize) -> Result<ContentRef, ProviderError> {
    Ok(canonical::content_ref(&bytes(value)?, "application/json")?)
}
