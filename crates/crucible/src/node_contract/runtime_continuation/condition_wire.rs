//! Selected condition-runtime indexes with one immutable body per content identity.
//!
//! Edition six retains every original input/provenance/control association in
//! small indexes and a complete byte-bearing dependency DAG. This decoder
//! authenticates content only; the installed native gate must separately prove
//! original source lineage and actual fresh custody before restoring authority.
//! Legacy declaration-order serializers and field grammars remain unchanged.
//!
//! ```text
//! {"schema_version":6,"source_activation":{...},"inputs":[...],
//!  "condition_stop":{...},"original_bodies":"<opaque canonical DAG bytes>"}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Bytes, Validate};
use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};

use super::*;
use crate::node_contract::{SavedConditionStop, SavedInputProvenance};

const MAXIMUM_OBJECTS: usize = 65_536;
const MAXIMUM_BYTES: usize = 64 << 20;

// The remote derive preserves exact old field ordering and per-field serde
// rules. Its skipped condition field cannot silently create new native custody.
#[derive(Serialize, Deserialize)]
#[serde(remote = "RuntimeSnapshot", deny_unknown_fields)]
struct Legacy {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    source_activation: SavedRuntimeActivation,
    capture_cut: Position,
    capture_ordinal: U64,
    owners: Vec<SavedRuntimeOwner>,
    operations: Vec<SavedRuntimeOperation>,
    inputs: Vec<SavedRuntimeInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<crate::node_contract::SavedWorldTerminal>,
    #[serde(skip)]
    condition_stop: Option<SavedConditionStop>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selected {
    #[serde(deserialize_with = "edition_six")]
    schema_version: u16,
    source_activation: SavedRuntimeActivation,
    capture_cut: Position,
    capture_ordinal: U64,
    owners: Vec<SavedRuntimeOwner>,
    operations: Vec<SavedRuntimeOperation>,
    inputs: Vec<InputIndex>,
    condition_stop: StopIndex,
    original_bodies: Bytes,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputIndex {
    node: Id,
    stage_operation: Id,
    batch: Id,
    owners: Vec<OwnerIdentity>,
    cutoff: Position,
    inventory: ContentRef,
    deliveries: Vec<crate::node_scheduling::event::Delivery>,
    payloads: Vec<ContentRef>,
    #[serde(deserialize_with = "required_nullable")]
    provenance: Option<ProvenanceIndex>,
    #[serde(deserialize_with = "required_nullable")]
    acknowledgement: Option<NativeInputAcknowledgement>,
    #[serde(deserialize_with = "required_nullable")]
    failure: Option<OperationFailure>,
    committed: bool,
    coordinator_committed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceIndex {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    node: Id,
    stage_operation: Id,
    batch: Id,
    inventory: ContentRef,
    roots: Vec<ContentRef>,
    objects: Vec<ContentRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopIndex {
    record: crate::node_contract::ConditionStopRecord,
    reference: ContentRef,
    submitted: bool,
    #[serde(deserialize_with = "required_nullable")]
    report: Option<ContentRef>,
    #[serde(deserialize_with = "required_nullable")]
    publication: Option<crate::node_contract::ConditionPublicationState>,
    acknowledged: bool,
    #[serde(deserialize_with = "required_nullable")]
    resume_operation: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    resume_receipt: Option<ContentRef>,
    #[serde(deserialize_with = "required_nullable")]
    resume_publication: Option<crate::node_contract::ConditionPublicationState>,
    resumed: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Decode {
    Selected(Box<Selected>),
    Legacy(#[serde(deserialize_with = "legacy_box")] Box<RuntimeSnapshot>),
}

impl Serialize for RuntimeSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.schema_version != 6 {
            if self.condition_stop.is_some() {
                return Err(S::Error::custom(
                    "condition custody requires runtime edition six",
                ));
            }
            return Legacy::serialize(self, serializer);
        }
        Selected::capture(self)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RuntimeSnapshot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Decode::deserialize(deserializer)? {
            Decode::Selected(selected) => selected.reopen().map_err(D::Error::custom),
            Decode::Legacy(legacy) if legacy.schema_version != 6 => Ok(*legacy),
            Decode::Legacy(_) => Err(D::Error::custom(
                "runtime six requires complete original bodies",
            )),
        }
    }
}

impl Selected {
    fn capture(source: &RuntimeSnapshot) -> Result<Self, RuntimeError> {
        condition::validate(source)?;
        preflight_saved_expansion(source)?;
        let saved = source
            .condition_stop
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?;
        let mut pool = BodyPool::default();
        let mut inputs = Vec::new();
        inputs
            .try_reserve_exact(source.inputs.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for input in &source.inputs {
            let payloads = input
                .payloads
                .iter()
                .map(|body| pool.retain(body))
                .collect::<Result<_, _>>()?;
            let provenance = input
                .provenance
                .as_ref()
                .map(|provenance| {
                    Ok::<_, RuntimeError>(ProvenanceIndex {
                        schema_version: provenance.schema_version,
                        node: provenance.node.clone(),
                        stage_operation: provenance.stage_operation.clone(),
                        batch: provenance.batch.clone(),
                        inventory: provenance.inventory.clone(),
                        roots: provenance.roots.clone(),
                        objects: provenance
                            .objects
                            .iter()
                            .map(|body| pool.retain(body))
                            .collect::<Result<_, _>>()?,
                    })
                })
                .transpose()?;
            inputs.push(InputIndex {
                node: input.node.clone(),
                stage_operation: input.stage_operation.clone(),
                batch: input.batch.clone(),
                owners: input.owners.clone(),
                cutoff: input.cutoff,
                inventory: input.inventory.clone(),
                deliveries: input.deliveries.clone(),
                payloads,
                provenance,
                acknowledgement: input.acknowledgement.clone(),
                failure: input.failure.clone(),
                committed: input.committed,
                coordinator_committed: input.coordinator_committed,
            });
        }
        for object in saved.record.dependency_objects() {
            pool.retain(object)?;
        }
        let stop = StopIndex {
            record: saved.record.clone(),
            reference: saved.reference.clone(),
            submitted: saved.submitted,
            report: saved
                .report
                .as_ref()
                .map(|body| pool.retain(body))
                .transpose()?,
            publication: saved.publication,
            acknowledged: saved.acknowledged,
            resume_operation: saved.resume_operation.clone(),
            resume_receipt: saved
                .resume_receipt
                .as_ref()
                .map(|body| pool.retain(body))
                .transpose()?,
            resume_publication: saved.resume_publication,
            resumed: saved.resumed,
        };
        let original_bodies = crate::node_adapters::encode_condition_dependency_dag(
            pool.references.keys().cloned().collect(),
            &pool.references.values().copied().collect::<Vec<_>>(),
            MAXIMUM_OBJECTS,
            MAXIMUM_BYTES,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(Self {
            schema_version: 6,
            source_activation: source.source_activation.clone(),
            capture_cut: source.capture_cut,
            capture_ordinal: source.capture_ordinal,
            owners: source.owners.clone(),
            operations: source.operations.clone(),
            inputs,
            condition_stop: stop,
            original_bodies: Bytes::new(original_bodies),
        })
    }

    fn reopen(self) -> Result<RuntimeSnapshot, RuntimeError> {
        if self.inputs.len() > MAXIMUM_OBJECTS || self.operations.len() > MAXIMUM_OBJECTS {
            return Err(RuntimeError::ResourceLimit);
        }
        let (bodies, roots) = crate::node_adapters::decode_condition_dependency_dag(
            self.original_bodies.as_slice(),
            MAXIMUM_OBJECTS,
            MAXIMUM_BYTES,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let bodies: BTreeMap<_, _> = bodies
            .into_iter()
            .map(|body| (body.reference.clone(), body))
            .collect();
        // Resolve and charge every expanded association before cloning any
        // body. A deduplicated wire DAG alone cannot bound repeated references.
        let dependency_plan = self.expansion_plan(&bodies)?;
        let mut used = BTreeSet::new();
        let mut body = |reference: &ContentRef| -> Result<InputPayload, RuntimeError> {
            used.insert(reference.clone());
            bodies
                .get(reference)
                .cloned()
                .ok_or(RuntimeError::InvalidReceipt)
        };
        let inputs = self
            .inputs
            .into_iter()
            .map(|input| {
                let payloads = input
                    .payloads
                    .iter()
                    .map(&mut body)
                    .collect::<Result<_, _>>()?;
                let provenance = input
                    .provenance
                    .map(|provenance| {
                        Ok::<_, RuntimeError>(SavedInputProvenance {
                            schema_version: provenance.schema_version,
                            node: provenance.node,
                            stage_operation: provenance.stage_operation,
                            batch: provenance.batch,
                            inventory: provenance.inventory,
                            roots: provenance.roots,
                            objects: provenance
                                .objects
                                .iter()
                                .map(&mut body)
                                .collect::<Result<_, _>>()?,
                        })
                    })
                    .transpose()?;
                Ok::<_, RuntimeError>(SavedRuntimeInput {
                    node: input.node,
                    stage_operation: input.stage_operation,
                    batch: input.batch,
                    owners: input.owners,
                    cutoff: input.cutoff,
                    inventory: input.inventory,
                    deliveries: input.deliveries,
                    payloads,
                    provenance,
                    acknowledgement: input.acknowledgement,
                    failure: input.failure,
                    committed: input.committed,
                    coordinator_committed: input.coordinator_committed,
                })
            })
            .collect::<Result<_, _>>()?;
        let stop = self.condition_stop;
        let report = stop.report.as_ref().map(&mut body).transpose()?;
        let resume_receipt = stop.resume_receipt.as_ref().map(&mut body).transpose()?;
        let mut record = stop.record;
        let mut dependencies = BTreeSet::new();
        for (inventory, references) in record.native.iter_mut().zip(dependency_plan) {
            inventory.receipt = body(&inventory.receipt.reference)?;
            // The authenticated complete DAG carries exact dependency edges.
            // Reopening source bodies remains a data operation, not native proof.
            inventory.proof_objects = references
                .into_iter()
                .map(|reference| body(&reference))
                .collect::<Result<_, _>>()?;
            dependencies.extend(
                inventory
                    .proof_objects
                    .iter()
                    .map(|object| object.reference.clone()),
            );
        }
        used.extend(dependencies);
        if used != roots.into_iter().collect() || used != bodies.keys().cloned().collect() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let mut operations = self.operations;
        for operation in &mut operations {
            if let OperationRequest::DebugConditionV1(request) = &mut operation.request
                && let crate::node_contract::ConditionControlRequest::Stop { barrier, .. } =
                    request.as_mut()
            {
                let bytes = crucible_node_contract::canonical::canonical_json(
                    &serde_json::to_value(barrier.as_ref())
                        .map_err(|_| RuntimeError::InvalidReceipt)?,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
                stop.reference
                    .verify(&bytes)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                **barrier = record.clone();
            }
        }
        let snapshot = RuntimeSnapshot {
            schema_version: 6,
            source_activation: self.source_activation,
            capture_cut: self.capture_cut,
            capture_ordinal: self.capture_ordinal,
            owners: self.owners,
            operations,
            inputs,
            terminal: None,
            condition_stop: Some(SavedConditionStop {
                record,
                reference: stop.reference,
                submitted: stop.submitted,
                report,
                publication: stop.publication,
                acknowledged: stop.acknowledged,
                resume_operation: stop.resume_operation,
                resume_receipt,
                resume_publication: stop.resume_publication,
                resumed: stop.resumed,
            }),
        };
        condition::validate(&snapshot)?;
        Ok(snapshot)
    }

    fn expansion_plan(
        &self,
        bodies: &BTreeMap<ContentRef, InputPayload>,
    ) -> Result<Vec<Vec<ContentRef>>, RuntimeError> {
        let mut expanded = ExpansionBudget::default();
        for input in &self.inputs {
            for reference in &input.payloads {
                expanded.reference(reference, bodies)?;
            }
            if let Some(provenance) = &input.provenance {
                for reference in &provenance.objects {
                    expanded.reference(reference, bodies)?;
                }
            }
        }
        for reference in self
            .condition_stop
            .report
            .iter()
            .chain(&self.condition_stop.resume_receipt)
        {
            expanded.reference(reference, bodies)?;
        }

        let mut plans = Vec::new();
        let (mut record_entries, mut record_bytes) =
            record_index_credit(&self.condition_stop.record, &self.condition_stop.reference)?;
        expanded.charge(record_entries, record_bytes)?;
        for inventory in &self.condition_stop.record.native {
            let root = bodies
                .get(&inventory.receipt.reference)
                .ok_or(RuntimeError::InvalidReceipt)?;
            expanded.charge(1, root.bytes.len())?;
            let references =
                dependency_references(root, bodies, MAXIMUM_OBJECTS - expanded.entries)?;
            record_bytes = record_bytes
                .checked_add(root.bytes.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            record_entries = record_entries
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            for reference in &references {
                let original = bodies.get(reference).ok_or(RuntimeError::InvalidReceipt)?;
                expanded.charge(1, original.bytes.len())?;
                record_bytes = record_bytes
                    .checked_add(original.bytes.len())
                    .ok_or(RuntimeError::ResourceLimit)?;
                record_entries = record_entries
                    .checked_add(1)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            plans.push(references);
        }

        // Each retained Stop request owns its original complete record. Preserve
        // those entries, but reserve their actual expanded ownership in advance.
        for operation in &self.operations {
            if matches!(&operation.request,
                OperationRequest::DebugConditionV1(request)
                if matches!(request.as_ref(), crate::node_contract::ConditionControlRequest::Stop { .. }))
            {
                expanded.charge(record_entries, record_bytes)?;
            }
        }
        Ok(plans)
    }
}

// Serialization also clones the retained complete source record and operation
// requests. Charge all repeated byte-bearing associations before extraction.
fn preflight_saved_expansion(source: &RuntimeSnapshot) -> Result<(), RuntimeError> {
    let saved = source
        .condition_stop
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    let mut expanded = ExpansionBudget::default();
    for input in &source.inputs {
        for body in &input.payloads {
            expanded.charge(1, body.bytes.len())?;
        }
        if let Some(provenance) = &input.provenance {
            for body in &provenance.objects {
                expanded.charge(1, body.bytes.len())?;
            }
        }
    }
    for body in saved.report.iter().chain(&saved.resume_receipt) {
        expanded.charge(1, body.bytes.len())?;
    }
    let (entries, bytes) = record_index_credit(&saved.record, &saved.reference)?;
    expanded.charge(entries, bytes)?;
    for body in saved.record.dependency_objects() {
        expanded.charge(1, body.bytes.len())?;
    }
    for operation in &source.operations {
        if let OperationRequest::DebugConditionV1(request) = &operation.request
            && let crate::node_contract::ConditionControlRequest::Stop { barrier, .. } =
                request.as_ref()
        {
            let (entries, bytes) = record_index_credit(barrier, &saved.reference)?;
            expanded.charge(entries, bytes)?;
            for body in barrier.dependency_objects() {
                expanded.charge(1, body.bytes.len())?;
            }
        }
    }
    Ok(())
}

// Inspect unique raw ownership before snapshot extraction clones any large
// source buffers. Legacy per-entry numeric JSON estimates do not describe the
// selected DAG; final encoded bounds remain enforced on the complete snapshot.
pub(super) fn preflight(runtime: &NodeRuntime, maximum_bytes: usize) -> Result<(), RuntimeError> {
    if maximum_bytes == 0 || maximum_bytes > MAXIMUM_BYTES {
        return Err(RuntimeError::ResourceLimit);
    }
    let saved = runtime
        .condition_stop
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    let mut pool = BodyPool::default();
    let mut expanded = ExpansionBudget::default();
    for input in runtime.input_batches.values() {
        for body in input.batch.payloads() {
            expanded.charge(1, body.bytes.len())?;
            pool.retain(body)?;
        }
        if let Some(provenance) = &input.provenance {
            for body in &provenance.saved().objects {
                expanded.charge(1, body.bytes.len())?;
                pool.retain(body)?;
            }
        }
    }
    for body in saved
        .saved
        .record
        .dependency_objects()
        .chain(saved.saved.report.iter())
        .chain(saved.saved.resume_receipt.iter())
    {
        expanded.charge(1, body.bytes.len())?;
        pool.retain(body)?;
    }
    let (entries, bytes) = record_index_credit(&saved.saved.record, &saved.saved.reference)?;
    expanded.charge(entries, bytes)?;
    for operation in runtime.operations.values() {
        if let OperationRequest::DebugConditionV1(request) = &operation.admission.request
            && let crate::node_contract::ConditionControlRequest::Stop { barrier, .. } =
                request.as_ref()
        {
            let (entries, bytes) = record_index_credit(barrier, &saved.saved.reference)?;
            expanded.charge(entries, bytes)?;
            for body in barrier.dependency_objects() {
                expanded.charge(1, body.bytes.len())?;
            }
        }
    }
    if pool.bytes > maximum_bytes || expanded.bytes > maximum_bytes {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(())
}

#[derive(Default)]
struct BodyPool<'a> {
    references: BTreeMap<ContentRef, &'a InputPayload>,
    hashes: BTreeMap<HashRef, ContentRef>,
    bytes: usize,
}

impl<'a> BodyPool<'a> {
    fn retain(&mut self, body: &'a InputPayload) -> Result<ContentRef, RuntimeError> {
        body.reference
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if body.reference.verify(&body.bytes).is_err() {
            return Err(RuntimeError::InvalidReceipt);
        }
        if let Some(original) = self.references.get(&body.reference) {
            return if **original == *body {
                Ok(body.reference.clone())
            } else {
                Err(RuntimeError::InvalidReceipt)
            };
        }
        if self.hashes.contains_key(&body.reference.hash)
            || self.references.len() >= MAXIMUM_OBJECTS
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let bytes = self
            .bytes
            .checked_add(body.bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        if bytes > MAXIMUM_BYTES {
            return Err(RuntimeError::ResourceLimit);
        }
        self.bytes = bytes;
        self.hashes
            .insert(body.reference.hash.clone(), body.reference.clone());
        self.references.insert(body.reference.clone(), body);
        Ok(body.reference.clone())
    }
}

// Resolves only references. The caller charges their complete expanded bytes
// before this closure is materialized into independently owned body vectors.
fn dependency_references(
    root: &InputPayload,
    bodies: &BTreeMap<ContentRef, InputPayload>,
    remaining_entries: usize,
) -> Result<Vec<ContentRef>, RuntimeError> {
    let mut references = BTreeSet::new();
    let mut pending: BTreeSet<_> =
        crate::node_adapters::condition_evidence_dependencies(&root.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?
            .into_iter()
            .collect();
    if pending.len() > remaining_entries {
        return Err(RuntimeError::ResourceLimit);
    }
    while let Some(reference) = pending.pop_first() {
        references.insert(reference.clone());
        let body = bodies.get(&reference).ok_or(RuntimeError::InvalidReceipt)?;
        for dependency in crate::node_adapters::condition_evidence_dependencies(&body.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?
        {
            if !references.contains(&dependency) {
                pending.insert(dependency);
                if pending
                    .len()
                    .checked_add(references.len())
                    .ok_or(RuntimeError::ResourceLimit)?
                    > remaining_entries
                {
                    return Err(RuntimeError::ResourceLimit);
                }
            }
        }
    }
    Ok(references.into_iter().collect())
}

// Raw scheduler/outcome buffers and ownership rows are charged independently
// of the declared index length, which is not trusted until original validation.
fn record_index_credit(
    record: &crate::node_contract::ConditionStopRecord,
    reference: &ContentRef,
) -> Result<(usize, usize), RuntimeError> {
    let bytes = usize::try_from(reference.length.get())
        .map_err(|_| RuntimeError::ResourceLimit)?
        .checked_add(record.scheduler.as_slice().len())
        .and_then(|bytes| bytes.checked_add(record.hit.outcome.bytes.as_slice().len()))
        .ok_or(RuntimeError::ResourceLimit)?;
    let mut entries = 1usize
        .checked_add(record.source.owners.len())
        .and_then(|entries| entries.checked_add(record.hit.outcome.parents.len()))
        .ok_or(RuntimeError::ResourceLimit)?;
    for inventory in &record.native {
        entries = entries
            .checked_add(1)
            .and_then(|entries| entries.checked_add(inventory.owners.len()))
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    if bytes > MAXIMUM_BYTES || entries > MAXIMUM_OBJECTS || record.native.len() > 256 {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok((entries, bytes))
}

#[derive(Default)]
struct ExpansionBudget {
    entries: usize,
    bytes: usize,
}

impl ExpansionBudget {
    fn charge(&mut self, entries: usize, bytes: usize) -> Result<(), RuntimeError> {
        let next_entries = self
            .entries
            .checked_add(entries)
            .ok_or(RuntimeError::ResourceLimit)?;
        let next_bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        if next_entries > MAXIMUM_OBJECTS || next_bytes > MAXIMUM_BYTES {
            return Err(RuntimeError::ResourceLimit);
        }
        self.entries = next_entries;
        self.bytes = next_bytes;
        Ok(())
    }

    fn reference(
        &mut self,
        reference: &ContentRef,
        bodies: &BTreeMap<ContentRef, InputPayload>,
    ) -> Result<(), RuntimeError> {
        let original = bodies.get(reference).ok_or(RuntimeError::InvalidReceipt)?;
        self.charge(1, original.bytes.len())
    }
}

fn edition_six<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
    let version = crucible_node_contract::deserialize_version(deserializer)?;
    if version != 6 {
        return Err(D::Error::custom(
            "condition-runtime index requires edition six",
        ));
    }
    Ok(version)
}

fn legacy_box<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Box<RuntimeSnapshot>, D::Error> {
    Legacy::deserialize(deserializer).map(Box::new)
}

#[cfg(test)]
#[path = "condition_wire_tests.rs"]
mod tests;
