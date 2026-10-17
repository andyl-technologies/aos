//! Checks successful discovery, realization, admission and readiness originals.
//!
//! The source-installed profile is the independent identity oracle. Readiness is
//! checked against the complete runtime preparation, and wire sequence supplies
//! chronology because the inert archive is a keyed inventory. This observation
//! does not infer refusal coverage, physical pausing or full-clause qualification.

use crucible::node_contract::WorldActivation;
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    bodies::*,
    client::{ObservedRequest, RecordedReferenceObservation, ReferenceObservationSnapshot},
    envelope::{Envelope, Method, RequestOrigin},
};
use serde::{Serialize, de::DeserializeOwned};

use super::installation::SourcePublicReferenceInstallation;

const MAXIMUM_OBJECT_BYTES: usize = 1024 * 1024;

/// Declares positive identities and record-only controls before native creation.
pub(super) fn fixture() -> serde_json::Value {
    serde_json::json!({
        "schema": "crucible.reference.supported-preparation-fixture.v1",
        "original_controls": ["discover", "realize", "admit", "activate", "world_activate"],
        "identity_oracle": "exact regenerated installed profiles and original complete runtime preparation",
        "chronology_oracle": "strict original controller wire-sequence ordering, independent of keyed inventory order",
        "record_only_refusals": ["incomplete_observation", "missing_discovery", "missing_original_gate", "changed_configuration", "discovery_after_activation"],
        "limitations": ["no physical-pause inference", "no refusal coverage from successful controls", "no ordinary qualification or whole-clause verdict"]
    })
}

/// Retains the exact successful controls without upgrading their evidence scope.
#[derive(Serialize)]
pub(super) struct SupportedLifecycleObservation {
    schema: &'static str,
    discovery: OriginalControl,
    realization: OriginalControl,
    admission: OriginalControl,
    readiness: OriginalControl,
    global_activation: OriginalControl,
    realized_binding: HashRef,
    original_gate: ContentRef,
    original_readiness: ContentRef,
}

#[derive(Serialize)]
struct OriginalControl {
    method: Method,
    request: ContentRef,
    response: ContentRef,
    wire_sequence: U64,
}

/// Verifies the successful preparation cohort against installed native scope.
///
/// # Errors
/// Refuses incomplete observations, foreign original scopes, missing or duplicate
/// controls, changed source identity, nonterminal replies, unavailable proof
/// bodies or readiness that differs from the complete runtime preparation.
pub(super) fn verify(
    installation: &SourcePublicReferenceInstallation,
    recorded: &RecordedReferenceObservation,
    activation: &WorldActivation,
) -> Result<SupportedLifecycleObservation, ProviderError> {
    if !recorded.recording_complete
        || recorded.observed_unknown
        || recorded.recording_failure.0.is_some()
    {
        return Err(refused());
    }
    let source = &recorded.evidence;
    let bootstrap = &installation.bootstrap;
    let profile = &installation.profile;
    let (binding, owner_binding) =
        profile.bind_qualified(bootstrap.authority.clone(), &installation.qualifications)?;
    if source.scope.provider_executable
        != *installation
            .package
            .artifact_content("provider")
            .map_err(|_| refused())?
        || source.scope.session_id != bootstrap.authority.session_id
        || source.scope.incarnation_id != bootstrap.authority.incarnation_id
        || source.scope.compatibility != binding.compatibility
        || source.scope.binding_hash != binding.identity()?
        || source.scope.selected_features != super::unit::required_features()?
    {
        return Err(refused());
    }

    let discover = completed(source, Method::Discover, installation)?;
    let realize = completed(source, Method::Realize, installation)?;
    let admit = completed(source, Method::Admit, installation)?;
    let activate = completed(source, Method::Activate, installation)?;
    let global = completed(source, Method::WorldActivate, installation)?;
    let chronology = [
        discover.0.sequence,
        realize.0.sequence,
        admit.0.sequence,
        activate.0.sequence,
        global.0.sequence,
    ];
    if chronology.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(refused());
    }

    let (RequestBody::Discover(request), Some(MethodResult::Discover(result))) =
        (&discover.1, &discover.2.result)
    else {
        return Err(refused());
    };
    if request.profile_ids != [profile.node_manifest.profile_id.clone()]
        || request.cursor.is_some()
        || !request.extensions.is_empty()
        || result.provider_manifest != profile.provider_manifest
        || result.profiles != [profile.node_manifest.clone()]
        || result.facet_schemas != profile.implementation.formats
        || !result.complete
        || result.next_cursor.0.is_some()
    {
        return Err(refused());
    }

    let (RequestBody::Realize(request), Some(MethodResult::Realize(result))) =
        (&realize.1, &realize.2.result)
    else {
        return Err(refused());
    };
    let provider_bytes = canonical::canonical_json(
        &serde_json::to_value(&profile.provider_manifest).map_err(ContractError::from)?,
    )?;
    let manifest = &result.realization_manifest;
    if request.realization_id != bootstrap.authority.realization_id
        || request.configuration != profile.configuration_ref
        || request.requested_node_ids != [bootstrap.node_id.clone()]
        || request.resource_limits != bootstrap.resource_limits
        || !request.extensions.is_empty()
        || manifest.realization_id != request.realization_id
        || manifest.provider_manifest
            != canonical::content_ref(&provider_bytes, "application/json")?
        || manifest.descriptors != [profile.descriptor.clone()]
        || manifest.bindings != [binding.clone()]
        || manifest.owners != [profile.owner.clone()]
        || manifest.owner_bindings != [owner_binding]
        || !manifest.extensions.is_empty()
        || result.prepared_token != bootstrap.prepared_token
    {
        return Err(refused());
    }
    let original_gate = result.closed_gate_receipt.clone();
    let gate_receipt: ControlReceipt = object(source, &original_gate)?;
    receipt_scope(
        &gate_receipt,
        installation,
        &realize.0,
        ControlReceiptKind::ClosedGate,
        U64::new(0),
    )?;
    let gate: ClosedGateRecord = object(source, &gate_receipt.record_ref)?;
    if gate.gate_id != bootstrap.gate_id
        || gate.prepared_token != bootstrap.prepared_token
        || gate.owner_ids != [bootstrap.owner_id.clone()]
        || !gate.gate_closed
        || !gate.extensions.is_empty()
    {
        return Err(refused());
    }
    // Keep the historical native status body available without interpreting a
    // parked application label as proof of physical pause or complete state.
    original_object(source, &gate.physical_status_ref)?;

    let (RequestBody::Admit(request), Some(MethodResult::Admit(result))) =
        (&admit.1, &admit.2.result)
    else {
        return Err(refused());
    };
    if request.bindings != [binding.clone()]
        || request.world_binding_hash != bootstrap.world_binding_hash
        || request.admission_receipt != bootstrap.admission_receipt
        || !request.extensions.is_empty()
        || result.admission_id != bootstrap.admission_id
        || result.accepted_binding_hashes != [binding.identity()?]
    {
        return Err(refused());
    }

    let (RequestBody::Activate(request), Some(MethodResult::Activate(result))) =
        (&activate.1, &activate.2.result)
    else {
        return Err(refused());
    };
    if request.admission_id != bootstrap.admission_id
        || request.activation_id != bootstrap.activation_id
        || request.world_generation != bootstrap.world_generation
        || request.prepared_token != bootstrap.prepared_token
        || request.world_binding_hash != bootstrap.world_binding_hash
        || request.gate_id != bootstrap.gate_id
        || !request.extensions.is_empty()
        || !result.staged
        || result.gate_id != bootstrap.gate_id
        || result.staged_owner_ids != [bootstrap.owner_id.clone()]
    {
        return Err(refused());
    }
    let original_readiness = result.activation_receipt.clone();
    let receipt: ControlReceipt = object(source, &original_readiness)?;
    // Staging retains the unactivated provider generation. The ready record
    // names the proposed generation separately; neither is silently rebound.
    receipt_scope(
        &receipt,
        installation,
        &activate.0,
        ControlReceiptKind::ActivationReady,
        U64::new(0),
    )?;
    let ready: ActivationReadyRecord = object(source, &receipt.record_ref)?;
    let own = activation
        .prepared_owners()
        .ok_or_else(refused)?
        .iter()
        .find(|owner| owner.owner_id == bootstrap.owner_id)
        .ok_or_else(refused)?;
    if ready.activation_id != bootstrap.activation_id
        || ready.world_generation != bootstrap.world_generation
        || ready.gate_id != bootstrap.gate_id
        || ready.prepared_token != bootstrap.prepared_token
        || ready.world_binding_hash != bootstrap.world_binding_hash
        || ready.owner_ids != [bootstrap.owner_id.clone()]
        || !ready.gate_closed
        || ready.evidence_refs != [original_gate.clone()]
        || !ready.extensions.is_empty()
        || own.ready_receipt != original_readiness
        || own.incarnation_id != bootstrap.authority.incarnation_id
        || own.owner_generation != bootstrap.authority.owner_generation
        || own.prepared_token != bootstrap.prepared_token
        || own.binding_hashes != [binding.identity()?]
        || !own.extensions.is_empty()
    {
        return Err(refused());
    }

    let (RequestBody::WorldActivate(request), Some(MethodResult::WorldActivate(result))) =
        (&global.1, &global.2.result)
    else {
        return Err(refused());
    };
    let record = activation.record();
    let coordinator = activation.coordinator_snapshot().ok_or_else(refused)?;
    let manifest: ActivationManifest = object(source, &request.activation_manifest)?;
    if request.transaction_id != bootstrap.transaction_id
        || request.activation_id != record.activation_id
        || request.world_generation != record.generation
        || request.prepared_token != bootstrap.prepared_token
        || request.world_binding_hash != record.world_binding_hash
        || request.gate_id != bootstrap.gate_id
        || !request.extensions.is_empty()
        || result.gate_id != bootstrap.gate_id
        || result.armed_owner_ids != [bootstrap.owner_id.clone()]
        || manifest.transaction_id != bootstrap.transaction_id
        || manifest.activation_id != record.activation_id
        || manifest.world_generation != record.generation
        || manifest.gate_id != bootstrap.gate_id
        || manifest.world_binding_hash != record.world_binding_hash
        || manifest.owners != activation.prepared_owners().ok_or_else(refused)?
        || manifest.coordinator_state_ref != coordinator.reference
        || original_object(source, &coordinator.reference)? != coordinator.bytes
        || !manifest.extensions.is_empty()
    {
        return Err(refused());
    }
    let committed: ControlReceipt = object(source, &result.activation_receipt)?;
    receipt_scope(
        &committed,
        installation,
        &global.0,
        ControlReceiptKind::ActivationReady,
        record.generation,
    )?;
    if committed.record_ref != receipt.record_ref {
        return Err(refused());
    }

    Ok(SupportedLifecycleObservation {
        schema: "crucible.reference.original-supported-preparation.v1",
        discovery: discover.3,
        realization: realize.3,
        admission: admit.3,
        readiness: activate.3,
        global_activation: global.3,
        realized_binding: binding.identity()?,
        original_gate,
        original_readiness,
    })
}

type CompletedControl = (Envelope, RequestBody, ResponseBody, OriginalControl);

fn completed(
    source: &ReferenceObservationSnapshot,
    method: Method,
    installation: &SourcePublicReferenceInstallation,
) -> Result<CompletedControl, ProviderError> {
    let mut found = None;
    for original in &source.requests {
        if original.key.origin != RequestOrigin::Controller {
            continue;
        }
        let request = Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_OBJECT_BYTES)?;
        if request.method != method {
            continue;
        }
        // Failed source probes use these methods too. Only the immutable
        // successful preparation IDs may enter this positive observation.
        let expected_id = match method {
            Method::Discover => Id::new(format!(
                "prepare-discover-{}",
                installation.bootstrap.authority.realization_id
            ))?,
            Method::Realize => Id::new(format!(
                "prepare-realize-{}",
                installation.bootstrap.authority.realization_id
            ))?,
            Method::Admit => {
                original_control_id("prepare-admit", &installation.bootstrap.admission_id)?
            }
            Method::Activate => {
                original_control_id("prepare-activate", &installation.bootstrap.activation_id)?
            }
            Method::WorldActivate => {
                original_control_id("world-activate", &installation.bootstrap.activation_id)?
            }
            _ => original.key.request_id.clone(),
        };
        if original.key.request_id != expected_id {
            continue;
        }
        if found.is_some() {
            return Err(refused());
        }
        found = Some(check_control(original, request, installation)?);
    }
    found.ok_or_else(refused)
}

fn original_control_id(kind: &str, identity: &Id) -> Result<Id, ProviderError> {
    let hash = canonical::hash(
        "cnp.installed-reference-request.v1",
        identity.as_str().as_bytes(),
    )?;
    Ok(Id::new(format!("{kind}-{}", hash.digest))?)
}

fn check_control(
    original: &ObservedRequest,
    request: Envelope,
    installation: &SourcePublicReferenceInstallation,
) -> Result<CompletedControl, ProviderError> {
    original
        .request
        .reference
        .verify(original.request.bytes.as_slice())?;
    let response = original.response.0.as_ref().ok_or_else(refused)?;
    response.reference.verify(response.bytes.as_slice())?;
    let reply = Envelope::decode(response.bytes.as_slice(), MAXIMUM_OBJECT_BYTES)?;
    request.matches_response(&reply)?;
    let bootstrap = &installation.bootstrap;
    if request.request_hash(RequestOrigin::Controller)? != original.identity
        || request.request_id.0.as_ref() != Some(&original.key.request_id)
        || request.session_id.0.as_ref() != Some(&bootstrap.authority.session_id)
        || request.incarnation_id.0.as_ref() != Some(&bootstrap.authority.incarnation_id)
        || request.node_id.0.is_some()
        || request.execution_owner_id.0.is_some()
        || request.capture_owner_id.0.is_some()
        || request.operation_id.0.is_some()
        || !request.extensions.is_empty()
    {
        return Err(refused());
    }
    let body = decode_request(request.method, &request.body)?;
    let result = decode_response(&body, &reply.body)?;
    if !matches!(result.shape, ResponseShape::Completed { .. }) {
        return Err(refused());
    }
    let evidence = OriginalControl {
        method: request.method,
        request: original.request.reference.clone(),
        response: response.reference.clone(),
        wire_sequence: request.sequence,
    };
    Ok((request, body, result, evidence))
}

fn receipt_scope(
    receipt: &ControlReceipt,
    installation: &SourcePublicReferenceInstallation,
    request: &Envelope,
    kind: ControlReceiptKind,
    generation: U64,
) -> Result<(), ProviderError> {
    let bootstrap = &installation.bootstrap;
    if receipt.kind != kind
        || receipt.issuer != ReceiptIssuer::Provider
        || receipt.session_id != bootstrap.authority.session_id
        || receipt.incarnation_id != bootstrap.authority.incarnation_id
        || receipt.request_id != request.request_id.0.clone().ok_or_else(refused)?
        || receipt.operation_id.is_some()
        || receipt.owner_ids != [bootstrap.owner_id.clone()]
        || receipt.world_generation != generation
        || !receipt.extensions.is_empty()
    {
        return Err(refused());
    }
    Ok(())
}

fn object<T: DeserializeOwned + Validate>(
    source: &ReferenceObservationSnapshot,
    reference: &ContentRef,
) -> Result<T, ProviderError> {
    Ok(canonical::decode(
        original_object(source, reference)?,
        MAXIMUM_OBJECT_BYTES,
    )?)
}

fn original_object<'a>(
    source: &'a ReferenceObservationSnapshot,
    reference: &ContentRef,
) -> Result<&'a [u8], ProviderError> {
    let mut originals = source
        .objects
        .iter()
        .filter(|object| &object.reference == reference);
    let original = originals.next().ok_or_else(refused)?;
    if originals.next().is_some() || original.bytes.as_slice().len() > MAXIMUM_OBJECT_BYTES {
        return Err(refused());
    }
    reference.verify(original.bytes.as_slice())?;
    Ok(original.bytes.as_slice())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original supported lifecycle differs from installed complete scope")
}

/// Applies record-only counterfactuals to a genuinely successful native cohort.
///
/// The mutated copies are refusal controls, not provider observations. Every
/// original raw body and native journal remains unchanged in caller custody.
#[cfg(test)]
pub(super) fn verify_counterfactuals(
    installation: &SourcePublicReferenceInstallation,
    recorded: &RecordedReferenceObservation,
    activation: &WorldActivation,
) -> Result<(), ProviderError> {
    let positive = verify(installation, recorded, activation)?;
    for counterfactual in 0..5 {
        let mut changed = recorded.clone();
        match counterfactual {
            0 => changed.recording_complete = false,
            1 => changed
                .evidence
                .requests
                .retain(|original| original.request.reference != positive.discovery.request),
            2 => changed
                .evidence
                .objects
                .retain(|original| original.reference != positive.original_gate),
            3 => {
                let original = changed
                    .evidence
                    .requests
                    .iter_mut()
                    .find(|original| original.request.reference == positive.realization.request)
                    .ok_or_else(refused)?;
                let mut request =
                    Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_OBJECT_BYTES)?;
                request.body.insert(
                    "configuration".into(),
                    serde_json::to_value(canonical::content_ref(
                        b"different original configuration",
                        "application/json",
                    )?)
                    .map_err(ContractError::from)?,
                );
                replace_request(original, &request)?;
            }
            4 => {
                let original = changed
                    .evidence
                    .requests
                    .iter_mut()
                    .find(|original| original.request.reference == positive.discovery.request)
                    .ok_or_else(refused)?;
                let mut request =
                    Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_OBJECT_BYTES)?;
                request.sequence = positive.global_activation.wire_sequence;
                replace_request(original, &request)?;
            }
            _ => return Err(refused()),
        }
        if verify(installation, &changed, activation).is_ok() {
            return Err(ProviderError::Correlation(
                "supported lifecycle accepted changed original evidence",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn replace_request(
    original: &mut ObservedRequest,
    request: &Envelope,
) -> Result<(), ProviderError> {
    let bytes =
        canonical::canonical_json(&serde_json::to_value(request).map_err(ContractError::from)?)?;
    original.identity = request.request_hash(RequestOrigin::Controller)?;
    original.request.reference = canonical::content_ref(&bytes, "application/json")?;
    original.request.bytes = Bytes::new(bytes);
    Ok(())
}
