//! Checks original input custody, window closure and consumption chronology.
//!
//! Original typed controls and immutable transferred bodies establish the
//! supported cycle. Input acceptance is distinct from native consumption; the
//! checksum oracle remains responsible for the actual consumed byte prefix.
//! These observations grant neither ordinary qualification nor physical pause.

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    bodies::*,
    client::ReferenceObservationSnapshot,
    envelope::{Envelope, Method, RequestOrigin},
    reference_service::PublicationConsumption,
};
use serde::{Serialize, de::DeserializeOwned};

use super::installation::SourcePublicReferenceInstallation;
use crate::node_qualification::ReferenceWindowObservation;

const MAXIMUM_BYTES: usize = 1024 * 1024;

/// Declares independent supported-cycle checks before native process creation.
pub(super) fn fixture() -> serde_json::Value {
    serde_json::json!({
        "schema": "crucible.reference.supported-cycle-fixture.v1",
        "original_controls": ["input", "quantum_begin", "quantum_close", "consumed_retire"],
        "oracles": ["original complete input-batch identity and accepted watermark", "complete input custody linked to original stop", "identical staged and committed event bodies", "original wire sequence input-before-begin-before-close-before-consume", "next cycle after previous consumption", "first input after original complete WorldActivate"],
        "record_only_refusals": ["missing_input", "changed_watermark", "missing_close", "changed_close_cut", "consume_before_close", "missing_input_custody_body", "foreign_owned_envelope", "input_before_world_activation"],
        "maximum_windows_per_owner": 16,
        "maximum_input_bytes_per_window": 4096,
        "limitations": ["input acceptance is not native consumption", "no physical-pause inference", "no ordinary qualification or whole-clause verdict"]
    })
}

/// Contains exactly the original supported cycle controls and byte commitments.
#[derive(Serialize)]
pub(super) struct SupportedCycleObservation {
    schema: &'static str,
    cycles: Vec<OriginalCycle>,
}

#[derive(Serialize)]
struct OriginalCycle {
    window: Id,
    input: OriginalControl,
    begin: OriginalControl,
    close: OriginalControl,
    consumption: OriginalControl,
    input_batch: ContentRef,
    input_custody: ContentRef,
    staged_observations: ContentRef,
    committed_observations: ContentRef,
}

#[derive(Serialize)]
struct OriginalControl {
    request: ContentRef,
    response: ContentRef,
    wire_sequence: U64,
}

struct AcceptedInput {
    receipt: ContentRef,
    pending: PendingInventory,
}

struct Control {
    envelope: Envelope,
    body: RequestBody,
    result: ResponseBody,
    original: OriginalControl,
}

/// Checks original acceptance, closure and acknowledgement for every window.
///
/// # Errors
/// Refuses incomplete populations, changed original scopes or input bytes,
/// missing proof bodies, nonterminal results, changed closure or consumption
/// records and incorrect wire ordering. No missing case is inferred successful.
pub(super) fn verify(
    installation: &SourcePublicReferenceInstallation,
    source: &ReferenceObservationSnapshot,
    windows: &[ReferenceWindowObservation],
) -> Result<SupportedCycleObservation, ProviderError> {
    if windows.is_empty() || windows.len() > 16 {
        return Err(refused());
    }
    let controls = controls(installation, source)?;
    let bootstrap = &installation.bootstrap;
    let activation_request = original_id("world-activate", &bootstrap.activation_id)?;
    let activated = unique(&controls, |control| {
        control.envelope.method == Method::WorldActivate
            && control.envelope.request_id.0.as_ref() == Some(&activation_request)
    })?;
    if controls
        .iter()
        .filter(|control| control.envelope.method == Method::WorldActivate)
        .count()
        != 1
    {
        return Err(refused());
    }
    let (_, owner) = installation
        .profile
        .bind_qualified(bootstrap.authority.clone(), &installation.qualifications)?;
    let binding = owner.identity()?;
    let mut cycles = Vec::with_capacity(windows.len());
    let mut previous = None::<(&Id, &Id, U64)>;
    for (index, observed) in windows.iter().enumerate() {
        let grant = &observed.original_grant;
        let begin = unique(&controls, |control| {
            matches!(&control.body, RequestBody::Begin(begin) if
                matches!(begin.decoded_arguments(), Ok(BeginArguments::QuantumBegin(arguments)) if arguments.grant_id == grant.window_id))
        })?;
        let operation = begin.envelope.operation_id.0.as_ref().ok_or_else(refused)?;
        let RequestBody::Begin(begin_body) = &begin.body else {
            return Err(refused());
        };
        let BeginArguments::QuantumBegin(arguments) = begin_body.decoded_arguments()? else {
            return Err(refused());
        };
        let Some(MethodResult::QuantumBegin(result)) = &begin.result.result else {
            return Err(refused());
        };
        let batch: InputBatch = object(source, &arguments.input_batch)?;
        let input = unique(
            &controls,
            |control| matches!(&control.body, RequestBody::Input(request) if request.batch_id == grant.input_batch_id),
        )?;
        let close = unique(
            &controls,
            |control| matches!(&control.body, RequestBody::QuantumClose(request) if request.grant_id == grant.window_id),
        )?;
        let consume = unique(
            &controls,
            |control| matches!(&control.body, RequestBody::Retire(request) if request.disposition == RetirementDisposition::Consumed && control.envelope.operation_id.0.as_ref() == Some(operation)),
        )?;
        if begin.envelope.request_id.0.as_ref() != Some(&original_id("begin", operation)?)
            || close.envelope.request_id.0.as_ref() != Some(&original_id("close", operation)?)
            || consume.envelope.request_id.0.as_ref() != Some(&original_id("consume", operation)?)
            || close.envelope.operation_id.0.as_ref() != Some(operation)
            || consume.envelope.operation_id.0.as_ref() != Some(operation)
            || !(input.envelope.sequence < begin.envelope.sequence
                && begin.envelope.sequence < close.envelope.sequence
                && close.envelope.sequence < consume.envelope.sequence)
            || input.envelope.sequence <= activated.envelope.sequence
            || previous.is_some_and(|(_, _, sequence)| sequence >= input.envelope.sequence)
        {
            return Err(refused());
        }
        let sequence = U64::new(
            u64::try_from(index)
                .map_err(|_| refused())?
                .checked_add(1)
                .ok_or_else(refused)?,
        );
        let accepted = verify_input(installation, source, input, &batch, observed, sequence)?;
        let pending_entry = PendingEntry {
            id: Id::new("accepted-input")?,
            kind: PendingKind::Input,
            owner_id: bootstrap.owner_id.clone(),
            deadline: Bound {
                kind: BoundKind::Unknown,
                position: None,
                evidence: None,
            },
            state_ref: arguments.input_batch.clone(),
            extensions: Extensions::new(),
        };
        if accepted.pending.operation_id.as_ref() != previous.map(|(operation, _, _)| operation)
            || accepted.pending.grant_id.as_ref() != previous.map(|(_, grant, _)| grant)
            || accepted.pending.revision != grant.quantum
            || accepted.pending.entries != [pending_entry]
        {
            return Err(refused());
        }
        let input_custody = accepted.receipt;
        if begin_body.binding_hash != binding
            || begin_body.owner_generation != grant.generation
            || begin_body.activation_id.0.as_ref() != Some(&bootstrap.activation_id)
            || begin_body.world_generation != bootstrap.world_generation
            || !begin_body.extensions.is_empty()
            || arguments.participant_ids != installation.profile.owner.participant_ids
            || arguments.realization_id != bootstrap.authority.realization_id
            || arguments.activation_id != bootstrap.activation_id
            || arguments.world_generation != bootstrap.world_generation
            || arguments.owner_generation != grant.generation
            || arguments.input_epoch != bootstrap.authority.input_epoch
            || arguments.mode != OperatingMode::Quantized
            || arguments.ordering_profile != "superdense-v1"
            || arguments.quantum_index != grant.quantum
            || arguments.from_ps != grant.start.time_ps
            || arguments.until_ps != grant.publication.time_ps
            || arguments.input_watermark != sequence
            || arguments.policy_hash != installation.profile.operating_contract.policy_ref.hash
            || arguments.wall_budget_ns != grant.host_budget_ns
            || result.grant_id != grant.window_id
            || result.quantum_index != grant.quantum
            || result.physical_measurement_ref != observed.receipt
            || result.budget_outcome != BudgetOutcome::WithinBudget
        {
            return Err(refused());
        }
        let stop: StopReceipt = object(source, &result.stop_receipt)?;
        if stop.input_custody != input_custody
            || stop.observation_batch != result.observation_batch
            || stop.pending_inventory != result.pending_inventory
            || stop.physical_measurement_ref != observed.receipt
            || stop.session_id != bootstrap.authority.session_id
            || stop.incarnation_id != bootstrap.authority.incarnation_id
            || stop.owner_binding_hash != binding
            || stop.world_binding_hash != bootstrap.world_binding_hash
            || stop.activation_id != bootstrap.activation_id
            || stop.world_generation != bootstrap.world_generation
            || stop.execution_owner_id != bootstrap.owner_id
            || stop.owner_generation != grant.generation
            || stop.operation_id != *operation
            || stop.grant_id.as_ref() != Some(&grant.window_id)
        {
            return Err(refused());
        }
        let staged: ObservationBatch = object(source, &result.observation_batch)?;
        let committed = verify_close(
            installation,
            source,
            close,
            result,
            &staged,
            observed,
            sequence,
        )?;
        verify_consumption(
            installation,
            source,
            consume,
            begin,
            result,
            &staged,
            observed,
        )?;
        cycles.push(OriginalCycle {
            window: grant.window_id.clone(),
            input: input.original_copy(),
            begin: begin.original_copy(),
            close: close.original_copy(),
            consumption: consume.original_copy(),
            input_batch: arguments.input_batch,
            input_custody,
            staged_observations: result.observation_batch.clone(),
            committed_observations: committed,
        });
        previous = Some((operation, &grant.window_id, consume.envelope.sequence));
    }
    for method in [
        Method::Input,
        Method::Begin,
        Method::QuantumClose,
        Method::Retire,
    ] {
        if controls
            .iter()
            .filter(|control| control.envelope.method == method)
            .count()
            != windows.len()
        {
            return Err(refused());
        }
    }
    Ok(SupportedCycleObservation {
        schema: "crucible.reference.original-supported-cycle.v1",
        cycles,
    })
}

fn verify_input(
    installation: &SourcePublicReferenceInstallation,
    source: &ReferenceObservationSnapshot,
    control: &Control,
    batch: &InputBatch,
    observed: &ReferenceWindowObservation,
    sequence: U64,
) -> Result<AcceptedInput, ProviderError> {
    let (RequestBody::Input(request), Some(MethodResult::Input(result))) =
        (&control.body, &control.result.result)
    else {
        return Err(refused());
    };
    let bootstrap = &installation.bootstrap;
    let (_, owner) = installation
        .profile
        .bind_qualified(bootstrap.authority.clone(), &installation.qualifications)?;
    let mut expected_ids = batch
        .events
        .iter()
        .map(|event| event.id.clone())
        .collect::<Vec<_>>();
    expected_ids.sort();
    expected_ids.dedup();
    let mut input_bytes = Vec::new();
    for event in &batch.events {
        let payload = original_object(source, &event.payload)?;
        if input_bytes
            .len()
            .checked_add(payload.len())
            .is_none_or(|size| size > 4096)
            || event.destination.node_id != bootstrap.node_id
            || event.destination.port_id.as_str() != "data"
            || event.destination.lane_id.as_str() != "input"
            || event.stage != EventStage::Delivery
            || !event.extensions.is_empty()
        {
            return Err(refused());
        }
        original_object(source, &event.provenance_ref)?;
        input_bytes.extend_from_slice(payload);
    }
    let identity = batch.identity()?;
    if batch.execution_owner_id != bootstrap.owner_id
        || batch.input_epoch != bootstrap.authority.input_epoch
        || batch.batch_id != observed.original_grant.input_batch_id
        || batch.batch_sequence != sequence
        || !batch.extensions.is_empty()
        || request.binding_hash != owner.identity()?
        || request.owner_generation != bootstrap.authority.owner_generation
        || request.batch_id != batch.batch_id
        || request.batch_sequence != sequence
        || request.input_epoch != batch.input_epoch
        || request.events != batch.events
        || request.batch_hash != identity
        || !request.extensions.is_empty()
        || control.envelope.operation_id.0.is_some()
        || result.accepted_event_ids != expected_ids
        || result.input_watermark != sequence
        || input_bytes != observed.input.as_slice()
    {
        return Err(refused());
    }
    let receipt: ControlReceipt = object(source, &result.custody_receipt)?;
    let custody: InputCustodyRecord = object(source, &receipt.record_ref)?;
    let pending: PendingInventory = object(source, &custody.pending_inventory)?;
    if receipt.kind != ControlReceiptKind::InputCustody
        || receipt.issuer != ReceiptIssuer::Provider
        || receipt.session_id != bootstrap.authority.session_id
        || receipt.incarnation_id != bootstrap.authority.incarnation_id
        || receipt.request_id != control.envelope.request_id.0.clone().ok_or_else(refused)?
        || receipt.operation_id.is_some()
        || receipt.owner_ids != [bootstrap.owner_id.clone()]
        || receipt.world_generation != bootstrap.world_generation
        || !receipt.extensions.is_empty()
        || custody.execution_owner_id != bootstrap.owner_id
        || custody.owner_generation != bootstrap.authority.owner_generation
        || custody.input_epoch != batch.input_epoch
        || custody.input_watermark != sequence
        || custody.batch_hashes != [identity]
        || custody.pending_inventory.hash != result.inventory_hash
        || !custody.extensions.is_empty()
        || !pending.complete
        || pending.execution_owner_id != bootstrap.owner_id
        || pending.owner_binding_hash != owner.identity()?
        || pending.world_binding_hash != bootstrap.world_binding_hash
        || pending.activation_id.as_ref() != Some(&bootstrap.activation_id)
        || pending.world_generation != bootstrap.world_generation
        || pending.owner_generation != bootstrap.authority.owner_generation
        || pending.input_epoch != batch.input_epoch
        || pending.input_watermark != sequence
        || !pending.extensions.is_empty()
    {
        return Err(refused());
    }
    for reference in &custody.evidence_refs {
        original_object(source, reference)?;
    }
    Ok(AcceptedInput {
        receipt: result.custody_receipt.clone(),
        pending,
    })
}

fn verify_close(
    installation: &SourcePublicReferenceInstallation,
    source: &ReferenceObservationSnapshot,
    close: &Control,
    begin: &QuantumBeginResult,
    staged: &ObservationBatch,
    observed: &ReferenceWindowObservation,
    watermark: U64,
) -> Result<ContentRef, ProviderError> {
    let (RequestBody::QuantumClose(request), Some(MethodResult::QuantumClose(result))) =
        (&close.body, &close.result.result)
    else {
        return Err(refused());
    };
    let bootstrap = &installation.bootstrap;
    let grant = &observed.original_grant;
    let cut = Position::new(
        grant.publication.time_ps,
        U64::new(0),
        Phase::BoundaryControl,
    );
    let committed: ObservationBatch = object(source, &result.committed_batch)?;
    let mut expected = staged.clone();
    expected.visibility = Visibility::Committed;
    if request.activation_id != bootstrap.activation_id
        || request.world_generation != bootstrap.world_generation
        || request.owner_generation != grant.generation
        || request.input_epoch != bootstrap.authority.input_epoch
        || request.quantum_index != grant.quantum
        || request.participant_ids != installation.profile.owner.participant_ids
        || request.cut != cut
        || request.policy_hash != installation.profile.operating_contract.policy_ref.hash
        || request.observation_batch_hash != staged.identity()?
        || request.input_watermark != watermark
        || request.deadline_disposition != BudgetOutcome::WithinBudget
        || !request.extensions.is_empty()
        || result.grant_id != request.grant_id
        || result.quantum_index != request.quantum_index
        || result.cut != cut
        || result.policy_hash != request.policy_hash
        || result.activation_id != request.activation_id
        || result.world_generation != request.world_generation
        || result.owner_generation != request.owner_generation
        || result.input_epoch != request.input_epoch
        || result.stop_receipt != begin.stop_receipt
        || result.pending_inventory != begin.pending_inventory
        // Close retains output custody. Only the later authentic consumption
        // discharges it; the response supplies no next-window permission.
        || result.next_allowed_quantum.0.is_some()
        || staged.visibility != Visibility::Staged
        || committed != expected
    {
        return Err(refused());
    }
    Ok(result.committed_batch.clone())
}

fn verify_consumption(
    installation: &SourcePublicReferenceInstallation,
    source: &ReferenceObservationSnapshot,
    consume: &Control,
    begin: &Control,
    native: &QuantumBeginResult,
    staged: &ObservationBatch,
    observed: &ReferenceWindowObservation,
) -> Result<(), ProviderError> {
    let (RequestBody::Retire(request), Some(MethodResult::Retire(result))) =
        (&consume.body, &consume.result.result)
    else {
        return Err(refused());
    };
    let reference = request.custody_receipt.0.as_ref().ok_or_else(refused)?;
    let consumption: PublicationConsumption = object(source, reference)?;
    consumption.validate()?;
    let bootstrap = &installation.bootstrap;
    if consumption.session_id != bootstrap.authority.session_id
        || consumption.incarnation_id != bootstrap.authority.incarnation_id
        || consumption.world_binding_hash != bootstrap.world_binding_hash
        || consumption.operation_id != begin.envelope.operation_id.0.clone().ok_or_else(refused)?
        || consumption.grant_id != observed.original_grant.window_id
        || consumption.stop_receipt != native.stop_receipt
        || consumption.observation_batch_hash != staged.identity()?
        || consumption.publication != observed.original_grant.publication
        || !consumption.extensions.is_empty()
        || request.request_ids != [begin.envelope.request_id.0.clone().ok_or_else(refused)?]
        || request.operation_ids != [consumption.operation_id]
        || !request.extensions.is_empty()
        || result.retired_operation_ids != request.operation_ids
        || result.retired_request_ids != request.request_ids
    {
        return Err(refused());
    }
    Ok(())
}

fn controls(
    installation: &SourcePublicReferenceInstallation,
    source: &ReferenceObservationSnapshot,
) -> Result<Vec<Control>, ProviderError> {
    let mut controls = Vec::new();
    for original in &source.requests {
        if original.key.origin != RequestOrigin::Controller {
            continue;
        }
        let envelope = Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_BYTES)?;
        if !matches!(
            envelope.method,
            Method::Input
                | Method::Begin
                | Method::QuantumClose
                | Method::Retire
                | Method::WorldActivate
        ) {
            continue;
        }
        let body = decode_request(envelope.method, &envelope.body)?;
        if matches!(&body, RequestBody::Begin(begin) if !matches!(begin.decoded_arguments()?, BeginArguments::QuantumBegin(_)))
        {
            continue;
        }
        if matches!(&body, RequestBody::Retire(request) if request.disposition != RetirementDisposition::Consumed)
        {
            continue;
        }
        let response = original.response.0.as_ref().ok_or_else(refused)?;
        original
            .request
            .reference
            .verify(original.request.bytes.as_slice())?;
        response.reference.verify(response.bytes.as_slice())?;
        let reply = Envelope::decode(response.bytes.as_slice(), MAXIMUM_BYTES)?;
        envelope.matches_response(&reply)?;
        let result = decode_response(&body, &reply.body)?;
        let bootstrap = &installation.bootstrap;
        let owned = envelope.method != Method::WorldActivate;
        if envelope.request_hash(RequestOrigin::Controller)? != original.identity
            || envelope.session_id.0.as_ref() != Some(&bootstrap.authority.session_id)
            || envelope.incarnation_id.0.as_ref() != Some(&bootstrap.authority.incarnation_id)
            || envelope.request_id.0.as_ref() != Some(&original.key.request_id)
            || envelope.node_id.0.as_ref() != owned.then_some(&bootstrap.node_id)
            || envelope.execution_owner_id.0.as_ref() != owned.then_some(&bootstrap.owner_id)
            || envelope.capture_owner_id.0.is_some()
            || !envelope.extensions.is_empty()
            || !matches!(result.shape, ResponseShape::Completed { .. })
        {
            return Err(refused());
        }
        controls.push(Control {
            envelope,
            body,
            result,
            original: OriginalControl {
                request: original.request.reference.clone(),
                response: response.reference.clone(),
                wire_sequence: Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_BYTES)?
                    .sequence,
            },
        });
    }
    Ok(controls)
}

impl Control {
    fn original_copy(&self) -> OriginalControl {
        OriginalControl {
            request: self.original.request.clone(),
            response: self.original.response.clone(),
            wire_sequence: self.original.wire_sequence,
        }
    }
}

fn unique(
    controls: &[Control],
    predicate: impl Fn(&Control) -> bool,
) -> Result<&Control, ProviderError> {
    let mut matches = controls.iter().filter(|control| predicate(control));
    let original = matches.next().ok_or_else(refused)?;
    if matches.next().is_some() {
        return Err(refused());
    }
    Ok(original)
}

fn original_id(kind: &str, identity: &Id) -> Result<Id, ProviderError> {
    let hash = canonical::hash(
        "cnp.installed-reference-request.v1",
        identity.as_str().as_bytes(),
    )?;
    Ok(Id::new(format!("{kind}-{}", hash.digest))?)
}

fn object<T: DeserializeOwned + Validate>(
    source: &ReferenceObservationSnapshot,
    reference: &ContentRef,
) -> Result<T, ProviderError> {
    Ok(canonical::decode(
        original_object(source, reference)?,
        MAXIMUM_BYTES,
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
    if originals.next().is_some() || original.bytes.as_slice().len() > MAXIMUM_BYTES {
        return Err(refused());
    }
    reference.verify(original.bytes.as_slice())?;
    Ok(original.bytes.as_slice())
}

fn refused() -> ProviderError {
    ProviderError::Correlation(
        "original supported execution differs from declared complete custody",
    )
}

/// Tests rehashed inert counterfactuals against actual successful originals.
///
/// # Errors
/// Refuses a missing genuine positive premise or a changed copy unexpectedly
/// accepted by the cycle verifier. Original controls and native custody stay put.
#[cfg(test)]
pub(super) fn verify_counterfactuals(
    installation: &SourcePublicReferenceInstallation,
    source: &ReferenceObservationSnapshot,
    windows: &[ReferenceWindowObservation],
) -> Result<(), ProviderError> {
    let positive = verify(installation, source, windows)?;
    let first = positive.cycles.first().ok_or_else(refused)?;
    for counterfactual in 0..8 {
        let mut changed = source.clone();
        match counterfactual {
            0 => changed
                .requests
                .retain(|original| original.request.reference != first.input.request),
            1 => change_request(&mut changed, &first.input.request, |request| {
                request
                    .body
                    .insert("batch_sequence".into(), serde_json::json!("2"));
                Ok(())
            })?,
            2 => changed
                .requests
                .retain(|original| original.request.reference != first.close.request),
            3 => change_request(&mut changed, &first.close.request, |request| {
                request.body.insert(
                    "cut".into(),
                    serde_json::to_value(Position::new(
                        U64::new(1),
                        U64::new(0),
                        Phase::BoundaryControl,
                    ))
                    .map_err(ContractError::from)?,
                );
                Ok(())
            })?,
            4 => change_request(&mut changed, &first.consumption.request, |request| {
                request.sequence = first.close.wire_sequence;
                Ok(())
            })?,
            5 => changed
                .objects
                .retain(|original| original.reference != first.input_custody),
            6 => change_request(&mut changed, &first.begin.request, |request| {
                request.execution_owner_id.0 = Some(Id::new("foreign-owner")?);
                Ok(())
            })?,
            7 => change_request(&mut changed, &first.input.request, |request| {
                request.sequence = U64::new(1);
                Ok(())
            })?,
            _ => return Err(refused()),
        }
        if verify(installation, &changed, windows).is_ok() {
            return Err(refused());
        }
    }
    Ok(())
}

#[cfg(test)]
fn change_request(
    source: &mut ReferenceObservationSnapshot,
    reference: &ContentRef,
    change: impl FnOnce(&mut Envelope) -> Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    let original = source
        .requests
        .iter_mut()
        .find(|original| &original.request.reference == reference)
        .ok_or_else(refused)?;
    let mut request = Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_BYTES)?;
    change(&mut request)?;
    let bytes =
        canonical::canonical_json(&serde_json::to_value(&request).map_err(ContractError::from)?)?;
    if bytes.len() > MAXIMUM_BYTES {
        return Err(refused());
    }
    original.identity = request.request_hash(RequestOrigin::Controller)?;
    original.request.reference = canonical::content_ref(&bytes, "application/json")?;
    original.request.bytes = Bytes::new(bytes);
    Ok(())
}
