//! Checks actual complete-world activation and original output-consumption frames.
//!
//! These checks supplement the checksum oracle. They use the runtime's genuine
//! all-owner activation and exact inert originals; neither an observed method
//! name nor a successful window can stand in for missing lifecycle evidence.

use crucible::node_contract::WorldActivation;
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    bodies::*,
    client::ReferenceObservationSnapshot,
    envelope::{Envelope, Method, RequestOrigin},
    reference_service::PublicationConsumption,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};

use super::installation::SourcePublicReferenceInstallation;
use crate::node_qualification::ReferenceWindowObservation;

#[derive(Serialize)]
pub(super) struct LifecycleObservation {
    pub(super) complete_world_activation: ContentRef,
    pub(super) original_consumptions: Vec<ContentRef>,
}

pub(super) fn verify(
    installation: &SourcePublicReferenceInstallation,
    source: &ReferenceObservationSnapshot,
    activation: &WorldActivation,
    windows: &[ReferenceWindowObservation],
) -> Result<LifecycleObservation, ProviderError> {
    let bootstrap = &installation.bootstrap;
    let record = activation.record();
    if record.activation_id != bootstrap.activation_id
        || record.generation != bootstrap.world_generation
        || record.world_binding_hash != bootstrap.world_binding_hash
    {
        return Err(refused());
    }
    let owners = activation.prepared_owners().ok_or_else(refused)?;
    let coordinator = activation.coordinator_snapshot().ok_or_else(refused)?;
    let expected = windows
        .iter()
        .map(|window| (window.original_grant.window_id.clone(), window))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != windows.len() {
        return Err(refused());
    }
    let mut begins = BTreeMap::new();
    let mut activated = None;
    let mut consumptions = Vec::with_capacity(windows.len());
    let mut consumed = BTreeSet::new();
    for original in &source.requests {
        if original.key.origin != RequestOrigin::Controller {
            continue;
        }
        let request = Envelope::decode(original.request.bytes.as_slice(), 1_048_576)?;
        if !matches!(
            request.method,
            Method::Begin | Method::WorldActivate | Method::Retire
        ) {
            continue;
        }
        let body = decode_request(request.method, &request.body)?;
        let response = original.response.0.as_ref().ok_or_else(refused)?;
        let envelope = Envelope::decode(response.bytes.as_slice(), 1_048_576)?;
        let result = decode_response(&body, &envelope.body)?;
        if !matches!(result.shape, ResponseShape::Completed { .. }) {
            return Err(refused());
        }
        match (body, result.result) {
            (RequestBody::Begin(begin), Some(MethodResult::QuantumBegin(result))) => {
                let BeginArguments::QuantumBegin(arguments) = begin.decoded_arguments()? else {
                    return Err(refused());
                };
                let observed = expected.get(&arguments.grant_id).ok_or_else(refused)?;
                if result.physical_measurement_ref != observed.receipt
                    || result.grant_id != arguments.grant_id
                    || result.quantum_index != observed.original_grant.quantum
                {
                    return Err(refused());
                }
                let operation = request.operation_id.0.clone().ok_or_else(refused)?;
                let request_id = request.request_id.0.clone().ok_or_else(refused)?;
                if begins
                    .insert(operation, (request_id, arguments.grant_id, result))
                    .is_some()
                {
                    return Err(refused());
                }
            }
            (
                RequestBody::WorldActivate(request_body),
                Some(MethodResult::WorldActivate(result)),
            ) => {
                if activated.is_some()
                    || request_body.activation_id != record.activation_id
                    || request_body.transaction_id != bootstrap.transaction_id
                    || request_body.world_generation != record.generation
                    || request_body.world_binding_hash != record.world_binding_hash
                    || request_body.gate_id != bootstrap.gate_id
                    || request_body.prepared_token != bootstrap.prepared_token
                    || !request_body.extensions.is_empty()
                    || result.gate_id != bootstrap.gate_id
                    || result.armed_owner_ids != [bootstrap.owner_id.clone()]
                {
                    return Err(refused());
                }
                let manifest: ActivationManifest =
                    object(source, &request_body.activation_manifest)?;
                manifest.validate()?;
                if manifest.transaction_id != bootstrap.transaction_id
                    || manifest.activation_id != record.activation_id
                    || manifest.world_generation != record.generation
                    || manifest.gate_id != bootstrap.gate_id
                    || manifest.world_binding_hash != record.world_binding_hash
                    || manifest.owners != owners
                    || manifest.coordinator_state_ref != coordinator.reference
                    || !manifest.extensions.is_empty()
                    || !source.objects.iter().any(|object| {
                        object.reference == coordinator.reference
                            && object.bytes.as_slice() == coordinator.bytes
                    })
                {
                    return Err(refused());
                }
                let receipt: ControlReceipt = object(source, &result.activation_receipt)?;
                receipt.validate()?;
                if receipt.kind != ControlReceiptKind::ActivationReady
                    || receipt.issuer != ReceiptIssuer::Provider
                    || receipt.session_id != bootstrap.authority.session_id
                    || receipt.incarnation_id != bootstrap.authority.incarnation_id
                    || receipt.request_id != request.request_id.0.clone().ok_or_else(refused)?
                    || receipt.operation_id.is_some()
                    || receipt.owner_ids != [bootstrap.owner_id.clone()]
                    || receipt.world_generation != record.generation
                    || !receipt.extensions.is_empty()
                {
                    return Err(refused());
                }
                let own = owners
                    .iter()
                    .find(|owner| owner.owner_id == bootstrap.owner_id)
                    .ok_or_else(refused)?;
                let readiness: ControlReceipt = object(source, &own.ready_receipt)?;
                if receipt.record_ref != readiness.record_ref {
                    return Err(refused());
                }
                activated = Some(result.activation_receipt);
            }
            (RequestBody::Retire(retire), Some(MethodResult::Retire(result))) => {
                if retire.disposition != RetirementDisposition::Consumed {
                    continue;
                }
                let reference = retire.custody_receipt.0.as_ref().ok_or_else(refused)?;
                let consumption: PublicationConsumption = object(source, reference)?;
                consumption.validate()?;
                let (begin_request, window, begin) =
                    begins.get(&consumption.operation_id).ok_or_else(refused)?;
                let observed = expected.get(window).ok_or_else(refused)?;
                let observations: ObservationBatch = object(source, &begin.observation_batch)?;
                observations.validate()?;
                if consumption.schema != "reference-device/publication-consumption-v1"
                    || consumption.session_id != bootstrap.authority.session_id
                    || consumption.incarnation_id != bootstrap.authority.incarnation_id
                    || consumption.world_binding_hash != record.world_binding_hash
                    || consumption.grant_id != *window
                    || consumption.stop_receipt != begin.stop_receipt
                    || consumption.observation_batch_hash != observations.identity()?
                    || consumption.publication != observed.original_grant.publication
                    || !consumption.extensions.is_empty()
                    || retire.operation_ids != [consumption.operation_id.clone()]
                    || retire.request_ids != [begin_request.clone()]
                    || result.retired_operation_ids != retire.operation_ids
                    || result.retired_request_ids != retire.request_ids
                    || request.operation_id.0.as_ref() != Some(&consumption.operation_id)
                    || !retire.extensions.is_empty()
                    || !consumed.insert(window.clone())
                {
                    return Err(refused());
                }
                consumptions.push(reference.clone());
            }
            _ => return Err(refused()),
        }
    }
    if consumed != expected.keys().cloned().collect() || begins.len() != windows.len() {
        return Err(refused());
    }
    Ok(LifecycleObservation {
        complete_world_activation: activated.ok_or_else(refused)?,
        original_consumptions: consumptions,
    })
}

fn object<T: DeserializeOwned>(
    source: &ReferenceObservationSnapshot,
    reference: &ContentRef,
) -> Result<T, ProviderError> {
    let original = source
        .objects
        .iter()
        .find(|object| &object.reference == reference)
        .ok_or_else(refused)?;
    original.reference.verify(original.bytes.as_slice())?;
    let value = canonical::parse_json(original.bytes.as_slice(), 1_048_576)?;
    Ok(serde_json::from_value(value).map_err(ContractError::from)?)
}
fn refused() -> ProviderError {
    ProviderError::Correlation("original complete-world or consumption evidence differs")
}
