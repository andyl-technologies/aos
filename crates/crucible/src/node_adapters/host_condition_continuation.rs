//! Selected stopped-condition native continuation without restored permissions.
//!
//! Native edition six wraps the exact original live edition-four DAG. The
//! complete source runtime and installed model remain independent authorities;
//! this codec only materializes byte-bearing original ledgers for their checks.
//!
//! ```text
//! {"format":"crucible.host-condition-continuation","schema_version":6,
//!  "profile":"host/condition-preservation-v1","original":"<opaque bytes>"}
//! ```

use super::*;
use crate::node_adapters::condition_debug_model::dag::EvidenceDag;
use crucible_node_contract::Bytes;

#[path = "host_condition_geometry.rs"]
mod geometry;

pub(in crate::node_adapters) const PRESERVATION_PROFILE: &str = "host/condition-preservation-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    schema_version: u16,
    profile: String,
    original: Bytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    format: String,
    schema_version: u16,
    profile: String,
    node: Id,
    owners: Vec<OwnerIdentity>,
    boundary: Position,
    native: ContentRef,
    native_sequence: U64,
    staged: Option<InputIndex>,
    input_history: Vec<InputIndex>,
    pending_causes: ContentRef,
    operations: Vec<OperationIndex>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputIndex {
    stage_operation: Id,
    batch: Id,
    cutoff: Position,
    inventory: ContentRef,
    deliveries: ContentRef,
    payloads: Vec<ContentRef>,
    acknowledgement: NativeInputAcknowledgement,
    consumed: U64,
    acknowledgement_body: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationIndex {
    operation: Id,
    request: ContentRef,
    outcome: ContentRef,
    acknowledged: bool,
    capture: Option<ContentRef>,
    evidence: Vec<ContentRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Causes {
    schema: String,
    causes: Vec<CapturedCause>,
}

pub(in crate::node_adapters) fn selected(binding: &NodeBinding) -> bool {
    binding
        .compatibility
        .operating_contract
        .facets
        .iter()
        .any(|facet| facet.id.as_str() == PRESERVATION_PROFILE && facet.version == 1)
        && binding
            .compatibility
            .implementation
            .formats
            .iter()
            .any(|schema| {
                schema.id.as_str() == "host/native-condition-continuation-v1" && schema.version == 1
            })
}

pub(super) fn encode(
    node: &HostModelNode,
    source: &RuntimeSnapshot,
    maximum: usize,
) -> Result<Vec<u8>, OperationFailure> {
    let saved = source
        .condition_stop
        .as_ref()
        .ok_or_else(|| failure("condition native capture has no original stopped source"))?;
    if !node.condition_preservation
        || !selected(&node.binding)
        || source.schema_version != 6
        || !saved.acknowledged
        || saved.resumed
        || saved.resume_operation.is_some()
        || saved.record.cut != source.capture_cut
    {
        return Err(failure(
            "condition native capture lacks qualified acknowledged Stop custody",
        ));
    }
    let original = condition_state::encode(node, maximum)?;
    bounded_bytes(
        &Envelope {
            format: "crucible.host-condition-continuation".into(),
            schema_version: 6,
            profile: PRESERVATION_PROFILE.into(),
            original: Bytes::new(original),
        },
        maximum,
    )
}

pub(super) fn decode(
    bytes: &[u8],
    source: &RuntimeSnapshot,
    descriptor: &NodeDescriptor,
    binding: &NodeBinding,
    limits: HostModelResources,
) -> Result<Captured, OperationFailure> {
    let limits = HostModelResources {
        maximum_capture_bytes: limits.maximum_capture_bytes.min(16 << 20),
        maximum_operations: limits.maximum_operations,
    };
    let saved = source
        .condition_stop
        .as_ref()
        .ok_or_else(|| failure("condition native source lacks original Stop custody"))?;
    if bytes.len() > limits.maximum_capture_bytes
        || limits.maximum_capture_bytes == 0
        || limits.maximum_capture_bytes > 16 << 20
        || limits.maximum_operations == 0
        || limits.maximum_operations > 65_536
        || source.schema_version != 6
        || !saved.acknowledged
        || saved.resumed
        || saved.resume_operation.is_some()
        || saved.record.cut != source.capture_cut
    {
        return Err(failure(
            "condition native source scope or finite limits refused",
        ));
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|error| failure(&error.to_string()))?;
    if envelope.format != "crucible.host-condition-continuation"
        || envelope.schema_version != 6
        || envelope.profile != PRESERVATION_PROFILE
    {
        return Err(failure("condition native selected envelope differs"));
    }
    let maximum_objects = condition_state::maximum_objects(limits.maximum_operations)?;
    let (store, roots) = EvidenceDag::decode(
        envelope.original.as_slice(),
        maximum_objects,
        limits.maximum_capture_bytes,
    )?;
    if roots.len() != 1 {
        return Err(failure("condition native original index is not unique"));
    }
    let index: Index = read(&store, &roots[0])?;
    let owners: Vec<_> = source
        .owners
        .iter()
        .filter_map(|owner| {
            (binding.compatibility.execution_owner.id == owner.identity.owner)
                .then_some(owner.identity.clone())
        })
        .collect();
    if index.format != "crucible.host-condition-native-index"
        || index.schema_version != 4
        || index.profile != HOST_CONDITION_INVENTORY_PROFILE
        || index.node != descriptor.id
        || index.owners != owners
        || index.boundary != source.capture_cut
        || index.operations.len() > limits.maximum_operations.min(4096)
        || index
            .input_history
            .len()
            .checked_add(usize::from(index.staged.is_some()))
            .is_none_or(|count| count > limits.maximum_operations.min(4096))
    {
        return Err(failure(
            "condition original native index scope differs from signed runtime",
        ));
    }

    // Charge repeated historical associations before expanding them into the
    // common closed ledger representation. The DAG deduplicates body ownership;
    // it does not silently drop repeated original operation evidence entries.
    let mut credit = ExpansionCredit::new(limits.maximum_capture_bytes, maximum_objects);
    for operation in &index.operations {
        credit.body(&store, &operation.request)?;
        let request: OperationRequest = read(&store, &operation.request)?;
        if let OperationRequest::DebugConditionV1(control) = &request
            && let crate::node_contract::ConditionControlRequest::Stop { barrier, .. } =
                control.as_ref()
        {
            for inventory in &barrier.native {
                let closure = store.closure_with_limit(
                    &inventory.receipt.reference,
                    credit.maximum_entries.saturating_sub(credit.entries),
                )?;
                for object in closure {
                    credit.body(&store, &object.reference)?;
                }
            }
        }
        credit.body(&store, &operation.outcome)?;
        if let Some(capture) = &operation.capture {
            credit.body(&store, capture)?;
        }
        for reference in &operation.evidence {
            credit.body(&store, reference)?;
        }
    }
    for input in index.input_history.iter().chain(index.staged.iter()) {
        credit.body(&store, &input.deliveries)?;
        credit.body(&store, &input.acknowledgement_body)?;
        for reference in &input.payloads {
            credit.body(&store, reference)?;
        }
    }
    credit.body(&store, &index.pending_causes)?;
    let native = model_bytes(&store, &index.native, descriptor, limits, &mut credit)?;

    let causes: Causes = read(&store, &index.pending_causes)?;
    if causes.schema != "crucible.condition-pending-causes.v1"
        || causes.causes.len() > limits.maximum_operations
    {
        return Err(failure("condition original pending native causes differ"));
    }
    let mut operations = reserve(index.operations.len())?;
    for operation in index.operations {
        let mut evidence = reserve(operation.evidence.len())?;
        for reference in operation.evidence {
            evidence.push(object(&store, reference)?);
        }
        let mut request: OperationRequest = read(&store, &operation.request)?;
        if let OperationRequest::DebugConditionV1(control) = &mut request
            && let crate::node_contract::ConditionControlRequest::Stop { barrier, .. } =
                control.as_mut()
        {
            // The immutable request index omits native body ownership. Reopen
            // the exact credited original closure before retaining this request.
            for inventory in &mut barrier.native {
                let closure = store.closure(&inventory.receipt.reference)?;
                let mut objects = reserve(closure.len().saturating_sub(1))?;
                for original in closure {
                    if original.reference != inventory.receipt.reference {
                        objects.push(object(&store, original.reference.clone())?);
                    }
                }
                inventory.receipt.bytes = store.body(&inventory.receipt.reference)?.to_vec();
                inventory.proof_objects = objects;
            }
        }
        operations.push(CapturedOperation {
            operation: operation.operation,
            request,
            outcome: read(&store, &operation.outcome)?,
            acknowledged: operation.acknowledged,
            capture: operation
                .capture
                .map(|reference| store.body(&reference).map(<[u8]>::to_vec))
                .transpose()?,
            evidence,
        });
    }
    let staged = index
        .staged
        .map(|input| materialize_input(&store, input))
        .transpose()?;
    let mut input_history = reserve(index.input_history.len())?;
    for input in index.input_history {
        input_history.push(materialize_input(&store, input)?);
    }
    Ok(Captured {
        schema_version: 6,
        profile: HOST_EXACT_PROFILE.into(),
        boundary: index.boundary,
        native,
        native_sequence: index.native_sequence,
        staged,
        input_history,
        pending_causes: causes.causes,
        operations,
        recorded_ingress: None,
    })
}

fn materialize_input(
    store: &EvidenceDag,
    input: InputIndex,
) -> Result<CapturedInput, OperationFailure> {
    if input.deliveries != input.inventory {
        return Err(failure("condition original delivery inventory differs"));
    }
    let mut payloads = reserve(input.payloads.len())?;
    for reference in input.payloads {
        payloads.push(object(store, reference)?);
    }
    Ok(CapturedInput {
        stage_operation: input.stage_operation,
        batch: input.batch,
        cutoff: input.cutoff,
        inventory: input.inventory,
        deliveries: read(store, &input.deliveries)?,
        payloads,
        acknowledgement: input.acknowledgement,
        consumed: input.consumed,
        acknowledgement_body: object(store, input.acknowledgement_body)?,
    })
}

fn model_bytes(
    store: &EvidenceDag,
    reference: &ContentRef,
    descriptor: &NodeDescriptor,
    limits: HostModelResources,
    credit: &mut ExpansionCredit,
) -> Result<Vec<u8>, OperationFailure> {
    if descriptor
        .roles
        .as_slice()
        .iter()
        .any(|role| role.as_str() == "condition_observer")
    {
        let remaining_entries = credit
            .maximum_entries
            .checked_sub(credit.entries)
            .ok_or_else(|| failure("condition native expanded entry credit exhausted"))?;
        let objects = store.closure_with_limit(reference, remaining_entries)?;
        let encoded_bytes = geometry::encoded_dag_length(reference, &objects)?;
        credit.entries(objects.len())?;
        credit.bytes(encoded_bytes)?;

        // Both retained object bodies and their complete encoding are charged
        // before the first model body or dependency list is copied.
        let mut native = EvidenceDag::new(
            condition_state::maximum_objects(limits.maximum_operations)?,
            limits.maximum_capture_bytes,
        );
        for object in objects {
            native.insert(
                object.reference.clone(),
                object.bytes.as_slice(),
                object.dependencies.clone(),
            )?;
        }
        let bytes = native.encode(vec![reference.clone()])?;
        if bytes.len() != encoded_bytes {
            return Err(failure("condition native encoded geometry changed"));
        }
        Ok(bytes)
    } else {
        credit.body(store, reference)?;
        Ok(store.body(reference)?.to_vec())
    }
}

fn object(store: &EvidenceDag, reference: ContentRef) -> Result<InputPayload, OperationFailure> {
    Ok(InputPayload {
        bytes: store.body(&reference)?.to_vec(),
        reference,
    })
}

fn read<T: serde::de::DeserializeOwned>(
    store: &EvidenceDag,
    reference: &ContentRef,
) -> Result<T, OperationFailure> {
    serde_json::from_slice(store.body(reference)?).map_err(|error| failure(&error.to_string()))
}

fn reserve<T>(count: usize) -> Result<Vec<T>, OperationFailure> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| failure("condition native materialization credit unavailable"))?;
    Ok(values)
}

struct ExpansionCredit {
    bytes: usize,
    entries: usize,
    maximum_bytes: usize,
    maximum_entries: usize,
}

impl ExpansionCredit {
    fn new(maximum_bytes: usize, maximum_entries: usize) -> Self {
        Self {
            bytes: 0,
            entries: 0,
            maximum_bytes,
            maximum_entries,
        }
    }

    fn body(
        &mut self,
        store: &EvidenceDag,
        reference: &ContentRef,
    ) -> Result<(), OperationFailure> {
        self.entries(1)?;
        self.bytes(store.body(reference)?.len())
    }

    fn entries(&mut self, count: usize) -> Result<(), OperationFailure> {
        self.entries = self
            .entries
            .checked_add(count)
            .ok_or_else(|| failure("condition native entry count overflow"))?;
        if self.entries > self.maximum_entries {
            return Err(failure("condition native expanded entry credit exhausted"));
        }
        Ok(())
    }

    fn bytes(&mut self, length: usize) -> Result<(), OperationFailure> {
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or_else(|| failure("condition native expanded byte count overflow"))?;
        if self.bytes > self.maximum_bytes {
            return Err(failure("condition native expanded byte credit exhausted"));
        }
        Ok(())
    }
}

// Canonical indexes deliberately omit Stop receipt bodies. Their independently
// reopened complete DAG is checked by this native codec and the restored model.
pub(super) fn same_request(
    original: &OperationRequest,
    captured: &OperationRequest,
) -> Result<bool, OperationFailure> {
    let bytes = |request: &OperationRequest| {
        canonical::canonical_json(
            &serde_json::to_value(request).map_err(|error| failure(&error.to_string()))?,
        )
        .map_err(|error| failure(&error.to_string()))
    };
    if bytes(original)? != bytes(captured)? {
        return Ok(false);
    }
    if let (
        OperationRequest::DebugConditionV1(original),
        OperationRequest::DebugConditionV1(captured),
    ) = (original, captured)
        && let (
            crate::node_contract::ConditionControlRequest::Stop {
                barrier: original, ..
            },
            crate::node_contract::ConditionControlRequest::Stop {
                barrier: captured, ..
            },
        ) = (original.as_ref(), captured.as_ref())
    {
        // A parsed index may lack bodies. Present source bodies must still be
        // the actual full originals; canonical equality never discards them.
        for (source, native) in original.native.iter().zip(&captured.native) {
            if (!source.receipt.bytes.is_empty() && source.receipt.bytes != native.receipt.bytes)
                || (!source.proof_objects.is_empty()
                    && source.proof_objects != native.proof_objects)
                || native.receipt.bytes.is_empty()
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
