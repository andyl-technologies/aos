//! Checks the fixed recorded native codec beneath signer-authenticated history.
//!
//! These checks bind typed original rows, ordered bytes and preceding receipts.
//! They cannot recreate a live owning controller or qualify a target model.

use super::InspectionError;

use std::collections::{BTreeMap, BTreeSet};

use crucible::node_contract::SavedOriginalPublication;
use crucible_node_contract::{
    ContentRef, Endpoint, Event, EventStage, Id, InputBatch, NodeBinding, ObservationBatch,
    StopReceipt, U64, Validate, Visibility,
};
use crucible_node_provider::{
    reference_device::{DeviceOutput, DeviceReceipt},
    reference_lineage::{LineageStage, NativeLineageReceipt},
};
use serde::Deserialize;

use super::decode;

const MEASUREMENT_MEDIA: &str = "application/json";
const RELATION_MEDIA: &str = "application/vnd.crucible.reference-consumption-relation+json";
const STAGE_MEDIA: &str = "application/vnd.crucible.reference-lineage-stage+json";
const RECEIPT_MEDIA: &str = "application/vnd.crucible.reference-lineage-native-receipt+json";
const WIRE_MEDIA: &str = "application/vnd.crucible.reference-native-wire";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Measurement {
    schema: String,
    native: DeviceReceipt,
    consumption_relation: ContentRef,
    accepted_input_custody: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    previous_publication: Option<Predecessor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Predecessor {
    measurement: ContentRef,
    stop_receipt: ContentRef,
    observation_batch: ContentRef,
    publication_consumption: ContentRef,
    committed_observation: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Relation {
    schema: String,
    owner: Id,
    incarnation: Id,
    owner_generation: U64,
    original_kernel_pid: U64,
    original_kernel_start_ticks: U64,
    native_window: Id,
    input_batch: ContentRef,
    native_stage: ContentRef,
    native_receipt: ContentRef,
    initialize_request: ContentRef,
    initialize_response_wire: ContentRef,
    close_request: ContentRef,
    close_response_wire: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    previous_closed: Option<ContentRef>,
    preceding_publication_acknowledged: bool,
    complete_consumed_prefix: U64,
    measured_host_ns: U64,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    original_index: U64,
    original_event: ContentRef,
    producer: Endpoint,
    event_id: Id,
    native_sequence: U64,
    byte_start: U64,
    byte_end: U64,
    checksum_after: U64,
    zero_byte_consumed: bool,
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Initialize {
    Initialize {
        dialect: String,
        owner: Id,
        incarnation: Id,
        generation: U64,
    },
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Close {
    Close { window: Id },
}

#[derive(Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum Ready {
    Ready {
        dialect: String,
        owner: Id,
        incarnation: Id,
        generation: U64,
        child_pid: U64,
    },
}

#[derive(Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum Closed {
    Closed { original: Box<NativeLineageReceipt> },
}

pub(super) fn verify_all(
    publications: &[SavedOriginalPublication],
    bindings: &BTreeMap<Id, NodeBinding>,
    objects: &BTreeMap<ContentRef, Vec<u8>>,
) -> Result<(), InspectionError> {
    let mut windows = BTreeSet::new();
    for claim in publications {
        verify_window(claim, publications, bindings, objects)?;
        let event: Event = read(objects, &claim.published, "application/json")?;
        let measurement: Measurement = read(objects, &claim.origin.measurement, MEASUREMENT_MEDIA)?;
        let quantum = measurement.native.grant.quantum.get();
        if quantum >= 3 || !windows.insert((event.source.node_id, quantum)) {
            return Err("recorded native window roster differs".into());
        }
    }
    if windows.len() != 9 {
        return Err("recorded native nine-window roster incomplete".into());
    }
    Ok(())
}

fn verify_window(
    claim: &SavedOriginalPublication,
    publications: &[SavedOriginalPublication],
    bindings: &BTreeMap<Id, NodeBinding>,
    objects: &BTreeMap<ContentRef, Vec<u8>>,
) -> Result<(), InspectionError> {
    let event: Event = read(objects, &claim.published, "application/json")?;
    let binding = bindings
        .get(&event.source.node_id)
        .ok_or("original publication node absent")?;
    let measurement: Measurement = read(objects, &claim.origin.measurement, MEASUREMENT_MEDIA)?;
    let relation: Relation = read(objects, &measurement.consumption_relation, RELATION_MEDIA)?;
    let stage: LineageStage = read(objects, &relation.native_stage, STAGE_MEDIA)?;
    let receipt: NativeLineageReceipt = read(objects, &relation.native_receipt, RECEIPT_MEDIA)?;
    let stop: StopReceipt = read(objects, &claim.origin.stop_receipt, "application/json")?;
    let observation: ObservationBatch =
        read(objects, &claim.origin.observation_batch, "application/json")?;
    let input: InputBatch = read(objects, &relation.input_batch, "application/json")?;
    // This fixed source codec emits its checksum JSON as opaque port bytes.
    // Its independently regenerated profile supplies the decoder semantics.
    let output: DeviceOutput = read(objects, &event.payload, "application/octet-stream")?;
    let prior: Option<NativeLineageReceipt> = relation
        .previous_closed
        .as_ref()
        .map(|reference| read(objects, reference, RECEIPT_MEDIA))
        .transpose()?;
    receipt
        .validate_against(&stage, prior.as_ref())
        .map_err(InspectionError::from_error)?;

    if measurement.schema != "crucible.reference.lineage-measurement.v1"
        || relation.schema != "crucible.reference.consumption-relation.v1"
        || relation.native_stage != stage.identity().map_err(InspectionError::from_error)?
        || relation.native_receipt != receipt.identity().map_err(InspectionError::from_error)?
        || relation.previous_closed != receipt.previous_closed
        || relation.owner != claim.origin.execution_owner_id
        || relation.incarnation != claim.origin.incarnation_id
        || relation.owner_generation != claim.origin.owner_generation
        || relation.native_window != claim.origin.grant_id
        || relation.original_kernel_pid.get() == 0
        || relation.original_kernel_start_ticks.get() == 0
        || relation.complete_consumed_prefix.get() != relation.entries.len() as u64
        || relation.entries.len() != input.events.len()
        || relation.entries.len() != stage.entries.len()
        || relation.measured_host_ns != measurement.native.measured_host_ns
        || relation.measured_host_ns > stage.grant.host_budget_ns
        || measurement.native.grant != stage.grant
        || measurement.native.output != receipt.output
        || !measurement.native.application_parked
        || output != receipt.output
        || stage.original_batch != relation.input_batch
        || input.batch_id != stage.grant.input_batch_id
        || input.execution_owner_id != stage.grant.owner_id
        || input.input_epoch != binding.authority.input_epoch
        || stage.grant.owner_id != claim.origin.execution_owner_id
        || stage.grant.incarnation_id != claim.origin.incarnation_id
        || stage.grant.generation != claim.origin.owner_generation
        || stage.grant.window_id != claim.origin.grant_id
        || binding.authority.session_id != claim.origin.session_id
        || binding.compatibility.execution_owner.id != claim.origin.execution_owner_id
        || event.stage != EventStage::Publication
        || event.provenance_ref != claim.origin.measurement
        || !event.causal_parent_ids.is_empty()
        || event.position != stage.grant.publication
        || event.publication_position != stage.grant.publication
        || event.source_sequence.get() != stage.grant.quantum.get() + 1
    {
        return Err("recorded native/publication association differs".into());
    }
    if observation.events != [event] {
        return Err("recorded publication differs from its original observation".into());
    }

    verify_public_scope(claim, &stop, &observation, &measurement)?;
    let mut checksum = receipt.checksum_before.get();
    let mut byte_end = 0u64;
    for (index, ((entry, staged), consumed)) in relation
        .entries
        .iter()
        .zip(&stage.entries)
        .zip(&receipt.consumed)
        .enumerate()
    {
        let original: Event = read(objects, &entry.original_event, "application/json")?;
        let delivered = &input.events[index];
        let payload = body(objects, &original.payload)?;
        let next_end = byte_end
            .checked_add(payload.len() as u64)
            .filter(|end| *end <= 4096)
            .ok_or("recorded payload range exceeds native input credit")?;
        for byte in payload {
            checksum = checksum.wrapping_mul(257).wrapping_add(u64::from(*byte));
        }
        if entry.byte_start.get() != byte_end
            || entry.byte_end.get() != next_end
            || entry.checksum_after.get() != checksum
        {
            return Err("recorded independent native checksum differs".into());
        }
        byte_end = next_end;
        if original != *delivered
            || original.stage != EventStage::Delivery
            || entry.original_index.get() != index as u64
            || entry.producer != original.source
            || entry.event_id != original.id
            || entry.native_sequence != original.source_sequence
            || staged.payload != original.payload
            || entry.byte_start != staged.byte_start
            || entry.byte_end != staged.byte_end
            || entry.checksum_after != consumed.checksum_after
            || entry.zero_byte_consumed != (entry.byte_start == entry.byte_end)
        {
            return Err("recorded ordered consumed event differs".into());
        }
    }
    if receipt.output.bytes_processed.get() != byte_end || receipt.output.checksum.get() != checksum
    {
        return Err("recorded original checksum output differs".into());
    }
    verify_wires(&relation, &receipt, objects)?;
    verify_predecessor(claim, publications, &measurement, &relation, objects)?;
    Ok(())
}

fn verify_public_scope(
    claim: &SavedOriginalPublication,
    stop: &StopReceipt,
    observation: &ObservationBatch,
    measurement: &Measurement,
) -> Result<(), InspectionError> {
    let origin = &claim.origin;
    if stop.session_id != origin.session_id
        || stop.incarnation_id != origin.incarnation_id
        || stop.owner_binding_hash != origin.owner_binding_hash
        || stop.world_binding_hash != origin.world_binding_hash
        || stop.activation_id != origin.activation_id
        || stop.world_generation != origin.world_generation
        || stop.execution_owner_id != origin.execution_owner_id
        || stop.owner_generation != origin.owner_generation
        || stop.operation_id != origin.operation_id
        || stop.grant_id.as_ref() != Some(&origin.grant_id)
        || stop.physical_measurement_ref != origin.measurement
        || stop.observation_batch != origin.observation_batch
        || stop.input_custody != measurement.accepted_input_custody
        || stop.production_prefix != measurement.native.grant.publication
        || observation.execution_owner_id != origin.execution_owner_id
        || observation.owner_binding_hash != origin.owner_binding_hash
        || observation.world_binding_hash != origin.world_binding_hash
        || observation.activation_id != origin.activation_id
        || observation.world_generation != origin.world_generation
        || observation.owner_generation != origin.owner_generation
        || observation.operation_id != origin.operation_id
        || observation.grant_id.as_ref() != Some(&origin.grant_id)
        || observation.measurement_ref != origin.measurement
        || observation.visibility != Visibility::Staged
        || observation.events.len() != 1
    {
        return Err("recorded public native scope differs".into());
    }
    Ok(())
}

fn verify_wires(
    relation: &Relation,
    receipt: &NativeLineageReceipt,
    objects: &BTreeMap<ContentRef, Vec<u8>>,
) -> Result<(), InspectionError> {
    let Initialize::Initialize {
        dialect,
        owner,
        incarnation,
        generation,
    } = read(objects, &relation.initialize_request, "application/json")?;
    let Ready::Ready {
        dialect: ready_dialect,
        owner: ready_owner,
        incarnation: ready_incarnation,
        generation: ready_generation,
        child_pid,
    } = read_wire(objects, &relation.initialize_response_wire)?;
    let Close::Close { window } = read(objects, &relation.close_request, "application/json")?;
    let Closed::Closed { original } = read_wire(objects, &relation.close_response_wire)?;
    if dialect != "crucible.reference.lineage-native.v1"
        || ready_dialect != dialect
        || owner != relation.owner
        || ready_owner != owner
        || incarnation != relation.incarnation
        || ready_incarnation != incarnation
        || generation != relation.owner_generation
        || ready_generation != generation
        || child_pid != relation.original_kernel_pid
        || window != relation.native_window
        || *original != *receipt
    {
        return Err("recorded native original wire differs".into());
    }
    Ok(())
}

fn verify_predecessor(
    claim: &SavedOriginalPublication,
    publications: &[SavedOriginalPublication],
    measurement: &Measurement,
    relation: &Relation,
    objects: &BTreeMap<ContentRef, Vec<u8>>,
) -> Result<(), InspectionError> {
    let quantum = measurement.native.grant.quantum.get();
    let Some(predecessor) = &measurement.previous_publication else {
        return if quantum == 0
            && relation.previous_closed.is_none()
            && !relation.preceding_publication_acknowledged
        {
            Ok(())
        } else {
            Err("recorded public predecessor absent".into())
        };
    };
    let prior = publications
        .iter()
        .find(|prior| prior.origin.measurement == predecessor.measurement)
        .ok_or("recorded predecessor has no original publication")?;
    let prior_measurement: Measurement =
        read(objects, &predecessor.measurement, MEASUREMENT_MEDIA)?;
    let prior_relation: Relation = read(
        objects,
        &prior_measurement.consumption_relation,
        RELATION_MEDIA,
    )?;
    let consumption: crucible_node_provider::reference_service::PublicationConsumption = read(
        objects,
        &predecessor.publication_consumption,
        "application/json",
    )?;
    let committed: ObservationBatch = read(
        objects,
        &predecessor.committed_observation,
        "application/json",
    )?;
    let staged: ObservationBatch =
        read(objects, &predecessor.observation_batch, "application/json")?;
    consumption
        .validate()
        .map_err(InspectionError::from_error)?;
    if quantum == 0
        || !relation.preceding_publication_acknowledged
        || prior.origin.execution_owner_id != claim.origin.execution_owner_id
        || prior.origin.incarnation_id != claim.origin.incarnation_id
        || prior.origin.owner_generation != claim.origin.owner_generation
        || prior.origin.stop_receipt != predecessor.stop_receipt
        || prior.origin.observation_batch != predecessor.observation_batch
        || prior_measurement.native.grant.quantum.get().checked_add(1) != Some(quantum)
        || relation.previous_closed.as_ref() != Some(&prior_relation.native_receipt)
        || consumption.operation_id != prior.origin.operation_id
        || consumption.grant_id != prior.origin.grant_id
        || consumption.observation_batch_hash
            != staged.identity().map_err(InspectionError::from_error)?
        || consumption.stop_receipt != prior.origin.stop_receipt
        || consumption.session_id != prior.origin.session_id
        || consumption.incarnation_id != prior.origin.incarnation_id
        || consumption.world_binding_hash != prior.origin.world_binding_hash
        || consumption.publication != prior_measurement.native.grant.publication
        || committed.visibility != Visibility::Committed
    {
        return Err("recorded predecessor ACK association differs".into());
    }
    let mut expected = staged;
    expected.visibility = Visibility::Committed;
    if expected != committed {
        return Err("recorded committed predecessor body differs".into());
    }
    Ok(())
}

fn read<T: serde::de::DeserializeOwned>(
    objects: &BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
    media: &str,
) -> Result<T, InspectionError> {
    if reference.media_type != media {
        return Err(format!("recorded native role differs: {}", reference.media_type).into());
    }
    decode(body(objects, reference)?)
}

fn read_wire<T: serde::de::DeserializeOwned>(
    objects: &BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
) -> Result<T, InspectionError> {
    if reference.media_type != WIRE_MEDIA {
        return Err("recorded native wire role differs".into());
    }
    let bytes = body(objects, reference)?;
    let header: [u8; 4] = bytes
        .get(..4)
        .ok_or("recorded native header incomplete")?
        .try_into()
        .map_err(|_| "recorded native header format")?;
    let length = u32::from_be_bytes(header) as usize;
    if length > 65_536 || bytes.len() != length + 4 {
        return Err("recorded native wire extent differs".into());
    }
    decode(&bytes[4..])
}

/// Authenticates complete reference metadata even for opaque port bytes.
fn body<'a>(
    objects: &'a BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
) -> Result<&'a [u8], InspectionError> {
    let bytes = objects
        .get(reference)
        .ok_or("recorded native body absent")?;
    reference
        .verify(bytes)
        .map_err(InspectionError::from_error)?;
    Ok(bytes)
}

fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}
