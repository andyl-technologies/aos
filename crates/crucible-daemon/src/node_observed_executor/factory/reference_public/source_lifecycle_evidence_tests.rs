//! Exercises typed reader refusal against inert copies of actual native evidence.
//!
//! These counterfactuals reuse the original committed publication latch and the
//! production reader. They neither dispatch controls nor issue qualification.

use crucible::node_adapters::cnp::{CnpCompletedLifecyclePhase, CnpCompletedLifecycleScope};
use crucible_node_contract::{
    ActivationManifest, Bytes, ContentRef, ObservationBatch, StopReceipt, canonical,
};
use crucible_node_provider::{
    ProviderError,
    bodies::{MethodResult, RequestBody},
    client::{ObservedContent, RecordedReferenceObservation},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::source_lifecycle_evidence::{SourceLifecycleEvidence, SourceLifecycleEvidenceContext};

/// Runs six inert counterfactuals against the actual retained source topology.
///
/// # Errors
/// Refuses unavailable originals, a failing positive premise, or any mutation
/// accepted by the production reader. Results are data-only test observations.
pub(super) fn verify_reader_adverse_controls(
    own_controls: &[(CnpCompletedLifecycleScope, RequestBody)],
    peer_controls: &[(CnpCompletedLifecycleScope, RequestBody)],
    context: SourceLifecycleEvidenceContext<'_>,
) -> Result<Value, ProviderError> {
    if own_controls.len() != 10 || peer_controls.len() != 10 {
        return Err(changed());
    }
    let own_windows = windows(own_controls);
    let peer_windows = windows(peer_controls);
    let first = *own_windows.first().ok_or_else(changed)?;
    let second = *own_windows.get(1).ok_or_else(changed)?;
    let foreign = *peer_windows.first().ok_or_else(changed)?;
    let world = own_controls
        .iter()
        .find(|(scope, _)| scope.phase == CnpCompletedLifecyclePhase::WorldActivated)
        .ok_or_else(changed)?;
    if context.peer_originals.len() != 2 || context.bindings.len() != 2 {
        return Err(changed());
    }

    // Each mutation starts from a positively verified actual callback premise.
    let mut reader = SourceLifecycleEvidence::reserve()?;
    for control in [first, second, foreign, world] {
        let original = if std::ptr::eq(control, foreign) {
            let peer = context
                .bindings
                .iter()
                .position(|(binding, _)| {
                    binding.identity().ok().as_ref() == Some(&control.0.binding_hash)
                })
                .ok_or_else(changed)?;
            &context.peer_originals[peer]
        } else {
            context.original
        };
        reader.verify(
            &control.0,
            &control.1,
            borrowed(&context, original, context.peer_originals),
        )?;
    }
    let first_result = quantum(&first.0)?;
    let second_result = quantum(&second.0)?;
    let foreign_result = quantum(&foreign.0)?;
    if first_result.physical_measurement_ref == second_result.physical_measurement_ref
        || first.0.binding_hash == foreign.0.binding_hash
    {
        return Err(changed());
    }
    let mut results = Vec::new();
    results.try_reserve_exact(6).map_err(|_| credits())?;

    let mut stop: StopReceipt = decode(&context, &first_result.stop_receipt)?;
    stop.physical_measurement_ref = second_result.physical_measurement_ref.clone();
    stop.evidence_refs = vec![stop.physical_measurement_ref.clone()];
    results.push(reject_rehashed(
        "reference/lifecycle-reader/wrong-stop-native-grant",
        "stop",
        first,
        &first_result.stop_receipt,
        encode(&stop)?,
        &context,
        &mut reader,
    )?);

    let mut observation: ObservationBatch = decode(&context, &first_result.observation_batch)?;
    observation.measurement_ref = foreign_result.physical_measurement_ref.clone();
    for event in &mut observation.events {
        event.provenance_ref = observation.measurement_ref.clone();
    }
    results.push(reject_rehashed(
        "reference/lifecycle-reader/foreign-observation-measurement",
        "observation",
        first,
        &first_result.observation_batch,
        encode(&observation)?,
        &context,
        &mut reader,
    )?);

    let foreign_owner = context
        .bindings
        .iter()
        .find(|(binding, _)| binding.identity().ok().as_ref() == Some(&foreign.0.binding_hash))
        .ok_or_else(changed)?;
    let mut observation: ObservationBatch = decode(&context, &first_result.observation_batch)?;
    observation.execution_owner_id = foreign_owner.1.owner.id.clone();
    observation.owner_binding_hash = foreign_owner.1.identity()?;
    observation.owner_generation = foreign_owner.0.authority.owner_generation;
    results.push(reject_rehashed(
        "reference/lifecycle-reader/foreign-observation-owner",
        "observation",
        first,
        &first_result.observation_batch,
        encode(&observation)?,
        &context,
        &mut reader,
    )?);

    let RequestBody::WorldActivate(request) = &world.1 else {
        return Err(changed());
    };
    let manifest: ActivationManifest = decode(&context, &request.activation_manifest)?;
    let foreign_ready = &manifest
        .owners
        .iter()
        .find(|owner| owner.owner_id == foreign_owner.1.owner.id)
        .ok_or_else(changed)?
        .ready_receipt;
    let mut own = context.original.clone();
    let mut peers = context.peer_originals.to_vec();
    let mut removed = 0;
    for snapshot in std::iter::once(&mut own).chain(peers.iter_mut()) {
        let before = snapshot.evidence.objects.len();
        snapshot
            .evidence
            .objects
            .retain(|object| object.reference != *foreign_ready);
        removed += before - snapshot.evidence.objects.len();
    }
    if removed == 0 {
        return Err(changed());
    }
    rejected(&mut reader, world, &context, &own, &peers, "missing-body")?;
    results.push(
        json!({"case":"reference/lifecycle-reader/missing-foreign-ready",
        "data_only":true,"refused":true,"removed_reference":foreign_ready,
        "removed_copies":removed}),
    );

    let mut incompatible = first.clone();
    let MethodResult::QuantumBegin(result) = &mut incompatible.0.original_result else {
        return Err(changed());
    };
    result.pending_inventory = result.observation_batch.clone();
    replace_roots(
        &mut incompatible.0,
        &first_result.pending_inventory,
        &first_result.observation_batch,
    )?;
    rejected(
        &mut reader,
        &incompatible,
        &context,
        context.original,
        context.peer_originals,
        "role-alias",
    )?;
    results.push(
        json!({"case":"reference/lifecycle-reader/incompatible-codec-role",
        "data_only":true,"refused":true,"counterfactual_scope":scope_data(&incompatible.0)}),
    );

    let mut retag = first_result.stop_receipt.clone();
    retag.media_type = "application/octet-stream".to_owned();
    let bytes = original_bytes(&context, &first_result.stop_receipt)?.to_vec();
    let object = ObservedContent {
        reference: retag.clone(),
        bytes: Bytes::new(bytes),
    };
    let mut own = context.original.clone();
    let mut peers = context.peer_originals.to_vec();
    insert(&mut own, &object)?;
    for snapshot in &mut peers {
        insert(snapshot, &object)?;
    }
    let mut control = first.clone();
    replace_control(&mut control.0, &first_result.stop_receipt, &retag)?;
    rejected(&mut reader, &control, &context, &own, &peers, "typed-media")?;
    results.push(
        json!({"case":"reference/lifecycle-reader/typed-root-media-retag",
        "data_only":true,"refused":true,"adverse_object":object,
        "counterfactual_scope":scope_data(&control.0)}),
    );

    Ok(json!({"schema":"reference.lifecycle-reader-adverse.v1",
        "data_only":true,"original_controls_unchanged":true,"cases":results}))
}

fn windows(
    controls: &[(CnpCompletedLifecycleScope, RequestBody)],
) -> Vec<&(CnpCompletedLifecycleScope, RequestBody)> {
    controls
        .iter()
        .filter(|(scope, _)| scope.phase == CnpCompletedLifecyclePhase::WindowCompleted)
        .collect()
}

fn quantum(
    scope: &CnpCompletedLifecycleScope,
) -> Result<&crucible_node_provider::bodies::QuantumBeginResult, ProviderError> {
    let MethodResult::QuantumBegin(result) = &scope.original_result else {
        return Err(changed());
    };
    Ok(result)
}

fn reject_rehashed(
    name: &str,
    expected_site: &str,
    original: &(CnpCompletedLifecycleScope, RequestBody),
    old: &ContentRef,
    object: ObservedContent,
    context: &SourceLifecycleEvidenceContext<'_>,
    reader: &mut SourceLifecycleEvidence,
) -> Result<Value, ProviderError> {
    let mut own = context.original.clone();
    let mut peers = context.peer_originals.to_vec();
    insert(&mut own, &object)?;
    for snapshot in &mut peers {
        insert(snapshot, &object)?;
    }
    let mut control = original.clone();
    replace_control(&mut control.0, old, &object.reference)?;
    rejected(reader, &control, context, &own, &peers, expected_site)?;
    Ok(json!({"case":name,"data_only":true,"refused":true,
        "adverse_object":object,"counterfactual_scope":scope_data(&control.0)}))
}

fn replace_control(
    scope: &mut CnpCompletedLifecycleScope,
    old: &ContentRef,
    new: &ContentRef,
) -> Result<(), ProviderError> {
    let MethodResult::QuantumBegin(result) = &mut scope.original_result else {
        return Err(changed());
    };
    if result.stop_receipt == *old {
        result.stop_receipt = new.clone();
    } else if result.observation_batch == *old {
        result.observation_batch = new.clone();
    } else {
        return Err(changed());
    }
    replace_roots(scope, old, new)
}

fn replace_roots(
    scope: &mut CnpCompletedLifecycleScope,
    old: &ContentRef,
    new: &ContentRef,
) -> Result<(), ProviderError> {
    let mut count = 0;
    for reference in &mut scope.evidence_roots {
        if reference == old {
            *reference = new.clone();
            count += 1;
        }
    }
    if count != 1 {
        return Err(changed());
    }
    Ok(())
}

fn rejected(
    reader: &mut SourceLifecycleEvidence,
    control: &(CnpCompletedLifecycleScope, RequestBody),
    context: &SourceLifecycleEvidenceContext<'_>,
    own: &RecordedReferenceObservation,
    peers: &[RecordedReferenceObservation],
    expected_site: &str,
) -> Result<(), ProviderError> {
    match reader
        .verify(&control.0, &control.1, borrowed(context, own, peers))
        .map(|_| ())
    {
        Err(ProviderError::Correlation("original typed lifecycle evidence differs"))
            if reader.refusal_site() == Some(expected_site) =>
        {
            Ok(())
        }
        _ => Err(changed()),
    }
}

fn borrowed<'a>(
    context: &'a SourceLifecycleEvidenceContext<'_>,
    original: &'a RecordedReferenceObservation,
    peers: &'a [RecordedReferenceObservation],
) -> SourceLifecycleEvidenceContext<'a> {
    SourceLifecycleEvidenceContext {
        original,
        peer_originals: peers,
        bindings: context.bindings,
        grants: context.grants,
        original_companion_pids: context.original_companion_pids,
        world: context.world,
    }
}

fn original_bytes<'a>(
    context: &'a SourceLifecycleEvidenceContext<'_>,
    reference: &ContentRef,
) -> Result<&'a [u8], ProviderError> {
    for snapshot in std::iter::once(context.original).chain(context.peer_originals.iter()) {
        if let Some(object) = snapshot
            .evidence
            .objects
            .iter()
            .find(|object| object.reference == *reference)
        {
            reference.verify(object.bytes.as_slice())?;
            return Ok(object.bytes.as_slice());
        }
    }
    Err(changed())
}

fn decode<T: DeserializeOwned>(
    context: &SourceLifecycleEvidenceContext<'_>,
    reference: &ContentRef,
) -> Result<T, ProviderError> {
    serde_json::from_slice(original_bytes(context, reference)?).map_err(|_| changed())
}

fn encode(value: &impl Serialize) -> Result<ObservedContent, ProviderError> {
    let bytes = canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    Ok(ObservedContent {
        reference,
        bytes: Bytes::new(bytes),
    })
}

fn insert(
    snapshot: &mut RecordedReferenceObservation,
    object: &ObservedContent,
) -> Result<(), ProviderError> {
    if snapshot.evidence.objects.len() >= 1024 {
        return Err(credits());
    }
    snapshot
        .evidence
        .objects
        .try_reserve(1)
        .map_err(|_| credits())?;
    snapshot.evidence.objects.push(object.clone());
    Ok(())
}

fn changed() -> ProviderError {
    ProviderError::Correlation("lifecycle reader adverse premise differs")
}

fn credits() -> ProviderError {
    ProviderError::ResourceExhausted("lifecycle reader adverse credits")
}

fn scope_data(scope: &CnpCompletedLifecycleScope) -> Value {
    json!({"phase":format!("{:?}", scope.phase), "request_id":scope.request_id,
    "operation_id":scope.operation_id,"method":scope.method,
    "binding_hash":scope.binding_hash,"owner_binding_hash":scope.owner_binding_hash,
    "grant":scope.grant,"evidence_roots":scope.evidence_roots,
    "counterfactual_result":match &scope.original_result {
        MethodResult::QuantumBegin(result) => json!(result),
        _ => Value::Null,
    }})
}
