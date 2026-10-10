//! Checks the selected source staging codec and retains complete public bodies.
//!
//! The only parsed document is the source-authenticated StagedView v1 body.
//! Its native input rows are data, never a constructed original witness. All
//! other fields are regenerated from the same borrowed common completion.

use crucible::{
    node_admission::ConformancePlanEvidence,
    node_contract::{
        InputProvenanceClosure, OperationOutcome, OriginalCompletedOperation,
        OriginalPublicationClaim, OriginalStagedInput, OwnerIdentity, ProgressEvidence,
        RuntimeError, WorldActivation,
    },
    node_scheduling::{
        InputCustodyCommit, InputPayload, NativeInputAcknowledgement, RuntimeInputBatch,
    },
};
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_node_contract::{ContentRef, HashRef, Id, Position, U64, canonical};
use serde::{Serialize, Serializer, ser::SerializeSeq};

use super::super::{OriginalTypedWindowSeal, TypedReaderWitnessAuthority, programme};

#[path = "geometry.rs"]
mod geometry;

use geometry::{InputEvidence, parse_staging, validate_rows};

const MAXIMUM_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_INPUT_OBJECTS: usize = 4096;
const MAXIMUM_EDGES: usize = 16_384;

pub(super) struct EncodedRecord {
    pub(super) identity: ContentId,
    pub(super) bytes: Vec<u8>,
}

type Activation<'a> = (U64, &'a Id, &'a HashRef, &'a [OwnerIdentity], Position);

fn activation(value: &WorldActivation) -> Activation<'_> {
    let record = value.record();
    (
        record.generation,
        &record.activation_id,
        &record.world_binding_hash,
        &record.owners,
        record.boundary,
    )
}

#[derive(Serialize)]
struct Input<'a> {
    node: &'a Id,
    stage: &'a Id,
    batch: &'a Id,
    owners: &'a [OwnerIdentity],
    cutoff: Position,
    inventory: &'a ContentRef,
    deliveries: &'a [crucible::node_scheduling::event::Delivery],
    payloads: &'a [InputPayload],
}

impl<'a> From<&'a RuntimeInputBatch> for Input<'a> {
    fn from(batch: &'a RuntimeInputBatch) -> Self {
        Self {
            node: batch.node(),
            stage: batch.stage_operation(),
            batch: batch.batch(),
            owners: batch.owners(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory(),
            deliveries: batch.deliveries(),
            payloads: batch.payloads(),
        }
    }
}

#[derive(Serialize)]
struct Provenance<'a> {
    version: u16,
    activation: Activation<'a>,
    node: &'a Id,
    stage: &'a Id,
    batch: &'a Id,
    inventory: &'a ContentRef,
    roots: &'a [ContentRef],
    objects: &'a [InputPayload],
}

impl<'a> From<&'a InputProvenanceClosure> for Provenance<'a> {
    fn from(value: &'a InputProvenanceClosure) -> Self {
        Self {
            version: value.version(),
            activation: activation(value.activation()),
            node: value.node(),
            stage: value.stage_operation(),
            batch: value.batch(),
            inventory: value.inventory(),
            roots: value.roots(),
            objects: value.objects(),
        }
    }
}

#[derive(Serialize)]
struct Commit<'a> {
    activation: Activation<'a>,
    node: &'a Id,
    stage: &'a Id,
    batch: &'a Id,
    inventory: &'a ContentRef,
    cutoff: Position,
}

impl<'a> From<&'a InputCustodyCommit> for Commit<'a> {
    fn from(value: &'a InputCustodyCommit) -> Self {
        Self {
            activation: activation(value.activation()),
            node: value.node(),
            stage: value.stage_operation(),
            batch: value.batch(),
            inventory: value.inventory(),
            cutoff: value.cutoff(),
        }
    }
}

struct Publications<'a>(&'a [OriginalPublicationClaim]);

impl Serialize for Publications<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for claim in self.0 {
            sequence.serialize_element(&(
                &claim.event,
                &claim.origin,
                &claim.published,
                &claim.objects,
                &claim.rows,
            ))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct Staging<'a> {
    schema: &'static str,
    input: Input<'a>,
    provenance: Option<Provenance<'a>>,
    publications: Option<Publications<'a>>,
    acknowledgement: &'a NativeInputAcknowledgement,
    native_evidence: &'a InputEvidence,
    coordinator_commit: Option<Commit<'a>>,
    committed: bool,
}

fn staging<'a>(original: &'a OriginalStagedInput<'_>, native: &'a InputEvidence) -> Staging<'a> {
    Staging {
        schema: "crucible.original-staged-input-witness.v1",
        input: original.batch().into(),
        provenance: original.provenance().map(Into::into),
        publications: original
            .lineage()
            .map(|lineage| Publications(lineage.publications())),
        acknowledgement: original.acknowledgement(),
        native_evidence: native,
        coordinator_commit: original.coordinator_commit().map(Into::into),
        committed: original.committed(),
    }
}

struct NativeRows<'a>(&'a OriginalTypedWindowSeal);

impl Serialize for NativeRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.rows().len()))?;
        for row in self.0.rows() {
            sequence.serialize_element(&(&row.reference, &row.bytes, &row.dependencies))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct Pending<'a> {
    schema_version: u16,
    input_batch: &'a Id,
    input_disposition: &'static str,
    original_buffer_retained: bool,
    outputs_retained: bool,
    application_parked: bool,
    owner: &'a OwnerIdentity,
}

#[derive(Serialize)]
struct Record<'a> {
    schema: &'static str,
    case: &'a str,
    plan: &'a ContentRef,
    plan_bytes: &'a [u8],
    limitations: (&'a ContentRef, &'a [u8]),
    refused: &'a ContentRef,
    refused_bytes: &'a [u8],
    sources: &'a [ContentRef],
    activation: Activation<'a>,
    operation: &'a Id,
    request: &'a crucible::node_contract::OperationRequest,
    outcome: &'a OperationOutcome,
    measurement: &'a ContentRef,
    native_stage: &'a crucible_node_provider::reference_lineage::LineageStage,
    native_close: &'a crucible_node_provider::reference_lineage::NativeLineageReceipt,
    controlled: &'a crucible_node_provider::reference_device::DeviceReceipt,
    stop: &'a crucible_node_contract::StopReceipt,
    observation: &'a crucible_node_contract::ObservationBatch,
    native_rows: NativeRows<'a>,
    input: &'a ContentRef,
    staging: &'a ContentRef,
    staging_bytes: &'a [u8],
    output_inventory: (&'a ContentRef, EncodedBytes<'a>, PayloadRoots<'a>),
    pending_inventory: (&'a ContentRef, EncodedBytes<'a>, &'a [ContentRef]),
}

enum EncodedBytes<'a> {
    Original(&'a [u8]),
    Ceiling(usize),
}

impl Serialize for EncodedBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Original(bytes) => bytes.serialize(serializer),
            Self::Ceiling(length) => {
                // Every actual byte uses at most three decimal digits. This
                // nonretaining pass charges the complete enclosing record with
                // a worst-case byte array before auxiliary bytes are allocated.
                let mut sequence = serializer.serialize_seq(Some(*length))?;
                for _ in 0..*length {
                    sequence.serialize_element(&255u8)?;
                }
                sequence.end()
            }
        }
    }
}

struct PayloadRoots<'a>(&'a [crucible::node_scheduling::NativePublication]);

impl Serialize for PayloadRoots<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for publication in self.0 {
            sequence.serialize_element(&publication.payload)?;
        }
        sequence.end()
    }
}

pub(super) fn record(
    authority: &TypedReaderWitnessAuthority,
    plan: &ConformancePlanEvidence<'_>,
    original: &OriginalCompletedOperation<'_>,
    case: &str,
    maximum: usize,
) -> Result<EncodedRecord, RuntimeError> {
    let admission = original.admission();
    let planned = authority
        .programme()
        .windows()
        .iter()
        .find(|planned| planned.case == case)
        .ok_or(RuntimeError::InvalidReceipt)?;
    let seal = authority
        .original_window_evidence(case)
        .map_err(|_| RuntimeError::ForeignAuthority)?;
    let limitations = authority
        .source()
        .original_limitations_bytes()
        .map_err(|_| RuntimeError::ForeignAuthority)?;
    let source_bytes = authority
        .source()
        .original_staging_bytes(case)
        .map_err(|_| RuntimeError::ForeignAuthority)?;
    let staged = original
        .staged_inputs()?
        .ok_or(RuntimeError::InvalidReceipt)?;
    let outcome = original.outcome();
    if original.acknowledged()
        || admission.token().operation() != &planned.operation
        || admission.token().route().node != planned.node
        || admission.request() != &planned.request
        || outcome.operation != planned.operation
        || outcome.node != planned.node
        || outcome.owners != admission.token().route().owners
        || admission.activation().record().world_binding_hash != *plan.world
        || seal.stop().activation_id != admission.activation().record().activation_id
        || seal.stop().world_generation != admission.activation().record().generation
        || staged.acknowledgement().proof_ref != seal.stop().input_custody
        || !staged.committed()
        || staged.coordinator_commit().is_none()
        || source_bytes.len() > MAXIMUM_SOURCE_BYTES
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    plan.plan_ref
        .verify(plan.plan_bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    plan.refused_ref
        .verify(plan.refused_bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;

    let scheduling = outcome
        .scheduling
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    let ProgressEvidence::Quantized { closure, .. } = &outcome.progress else {
        return Err(RuntimeError::InvalidReceipt);
    };
    let [owner] = outcome.owners.as_slice() else {
        return Err(RuntimeError::InvalidReceipt);
    };
    let pending_view = Pending {
        schema_version: 1,
        input_batch: &planned.batch,
        input_disposition: "consumed",
        original_buffer_retained: true,
        outputs_retained: true,
        application_parked: seal.controlled().application_parked,
        owner,
    };
    let (input_ref, staging_ref) = authority
        .source()
        .completion_input_oracles(case)
        .map_err(|_| RuntimeError::ForeignAuthority)?;
    let mut record = Record {
        schema: "crucible.typed-conformance-original-result.v1",
        case,
        plan: plan.plan_ref,
        plan_bytes: plan.plan_bytes,
        limitations,
        refused: plan.refused_ref,
        refused_bytes: plan.refused_bytes,
        sources: plan.sources,
        activation: activation(admission.activation()),
        operation: admission.token().operation(),
        request: admission.request(),
        outcome,
        measurement: seal.measurement(),
        native_stage: seal.stage(),
        native_close: seal.native(),
        controlled: seal.controlled(),
        stop: seal.stop(),
        observation: seal.observation(),
        native_rows: NativeRows(&seal),
        input: &input_ref,
        staging: &staging_ref,
        staging_bytes: &source_bytes,
        output_inventory: (
            &closure.output_inventory,
            EncodedBytes::Ceiling(encoded_size(&scheduling.publications, maximum)?),
            PayloadRoots(&scheduling.publications),
        ),
        // The exact pending codec has IDs/state fields, no CF children. Its
        // regenerated full body establishes that selected leaf role.
        pending_inventory: (
            &closure.pending_inventory,
            EncodedBytes::Ceiling(encoded_size(&pending_view, maximum)?),
            &[],
        ),
    };
    // Charge the whole final record, including conservative byte-array credit
    // for both auxiliary bodies, before parsing or allocating any body/value.
    programme::count(&record, maximum).map_err(|_| RuntimeError::ResourceLimit)?;
    let expected = authority
        .expected_outcome(case)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if expected != *outcome {
        return Err(RuntimeError::InvalidReceipt);
    }
    staging_ref
        .verify(&source_bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let source = parse_staging(&source_bytes)?;
    if source.schema != "crucible.original-staged-input-witness.v1"
        || !source.committed
        || source.native_evidence.root != staged.acknowledgement().proof_ref
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    validate_rows(
        &source.native_evidence.root,
        &source.native_evidence.objects,
        &source.native_evidence.rows,
    )?;
    let reconstructed = encode(&staging(staged, &source.native_evidence), maximum)?;
    // Full canonical equality checks every selected field; ignored parser
    // fields cannot introduce an extra role, alternate spelling or leaf.
    if reconstructed != *source_bytes {
        return Err(RuntimeError::InvalidReceipt);
    }
    input_ref
        .verify(&encode(&Input::from(staged.batch()), maximum)?)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    verify_original_bodies(&seal, staged, &source.native_evidence)?;

    let output = encode(&scheduling.publications, maximum)?;
    let pending = encode(&pending_view, maximum)?;
    closure
        .output_inventory
        .verify(&output)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    closure
        .pending_inventory
        .verify(&pending)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    for publication in &scheduling.publications {
        publication
            .payload
            .verify(&publication.payload_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    record.output_inventory.1 = EncodedBytes::Original(&output);
    record.pending_inventory.1 = EncodedBytes::Original(&pending);
    let bytes = encode(&record, maximum)?;
    // The slot key excludes result bytes. A changed result for the same full
    // plan/world/operation identity must conflict, never obtain a new root.
    let identity = encode(
        &(
            "crucible.typed-conformance-result-slot.v1",
            plan.plan_ref,
            activation(admission.activation()),
            &admission.token().route().node,
            admission.token().operation(),
        ),
        maximum,
    )?;
    Ok(EncodedRecord {
        identity: ContentId::for_bytes(ObjectKind::Trace, 1, &identity),
        bytes,
    })
}

fn verify_original_bodies(
    seal: &OriginalTypedWindowSeal,
    staged: &OriginalStagedInput<'_>,
    native: &InputEvidence,
) -> Result<(), RuntimeError> {
    if seal.rows().len() > 80
        || !seal
            .rows()
            .iter()
            .any(|row| &row.reference == seal.measurement())
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let mut bytes = 0usize;
    let mut edges = 0usize;
    for (index, row) in seal.rows().iter().enumerate() {
        bytes = bytes
            .checked_add(row.bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        edges = edges
            .checked_add(row.dependencies.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        if bytes > MAXIMUM_SOURCE_BYTES
            || edges > MAXIMUM_EDGES
            || seal.rows()[..index]
                .iter()
                .any(|prior| prior.reference == row.reference)
            || row.dependencies.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        row.reference
            .verify(&row.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    for payload in staged.batch().payloads() {
        payload
            .reference
            .verify(&payload.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    if let Some(provenance) = staged.provenance() {
        for body in provenance.objects() {
            body.reference
                .verify(&body.bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
    }
    if let Some(lineage) = staged.lineage() {
        for claim in lineage.publications() {
            validate_rows(&claim.published, &claim.objects, &claim.rows)?;
        }
    }
    let mut count = seal
        .rows()
        .len()
        .checked_add(native.objects.len())
        .and_then(|count| count.checked_add(staged.batch().payloads().len()))
        .ok_or(RuntimeError::ResourceLimit)?;
    if let Some(provenance) = staged.provenance() {
        count = count
            .checked_add(provenance.objects().len())
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    if let Some(lineage) = staged.lineage() {
        for claim in lineage.publications() {
            count = count
                .checked_add(claim.objects.len())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
    }
    if count > MAXIMUM_INPUT_OBJECTS * 4 + 80 {
        return Err(RuntimeError::ResourceLimit);
    }
    let mut bodies = Vec::new();
    bodies
        .try_reserve_exact(count)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    bodies.extend(
        seal.rows()
            .iter()
            .map(|row| (&row.reference, row.bytes.as_slice())),
    );
    bodies.extend(
        native
            .objects
            .iter()
            .map(|body| (&body.reference, body.bytes.as_slice())),
    );
    bodies.extend(
        staged
            .batch()
            .payloads()
            .iter()
            .map(|body| (&body.reference, body.bytes.as_slice())),
    );
    if let Some(provenance) = staged.provenance() {
        bodies.extend(
            provenance
                .objects()
                .iter()
                .map(|body| (&body.reference, body.bytes.as_slice())),
        );
    }
    if let Some(lineage) = staged.lineage() {
        for claim in lineage.publications() {
            bodies.extend(
                claim
                    .objects
                    .iter()
                    .map(|body| (&body.reference, body.bytes.as_slice())),
            );
        }
    }
    for (index, (reference, bytes)) in bodies.iter().enumerate() {
        if bodies[..index].iter().any(|(other, body)| {
            other.hash == reference.hash && (other.length != reference.length || body != bytes)
        }) {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    // Native measurement rows may explicitly point to original producer roles.
    // Those full bodies must be present in this same staging/publication union;
    // a missing dependency is never reclassified as an external leaf.
    if seal.rows().iter().any(|row| {
        row.dependencies
            .iter()
            .any(|dependency| !bodies.iter().any(|(reference, _)| *reference == dependency))
    }) {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

fn encode(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, RuntimeError> {
    programme::count(value, maximum).map_err(|_| RuntimeError::ResourceLimit)?;
    let value = serde_json::to_value(value).map_err(|_| RuntimeError::InvalidReceipt)?;
    let bytes = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
    if bytes.len() > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(bytes)
}

fn encoded_size(value: &impl Serialize, maximum: usize) -> Result<usize, RuntimeError> {
    struct Counter(usize);

    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("original auxiliary body byte ceiling"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // Both selected auxiliary codecs contain only strings, integers, booleans
    // and byte arrays. Canonical key ordering preserves this serialized extent;
    // neither codec has floating-point JSON or source-selected arbitrary Values.
    let mut counter = Counter(maximum);
    serde_json::to_writer(&mut counter, value).map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(maximum - counter.0)
}
