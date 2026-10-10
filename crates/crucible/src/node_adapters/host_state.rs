//! Bounded complete native host continuation and closed-gate original rebinding.
//!
//! Edition one uses deterministic declaration-order JSON with integer times and
//! counters encoded as decimal strings. The nested `native` byte array preserves
//! the legacy model codec unchanged. This is a native format; it issues no local
//! runtime permissions.

use std::io::{self, Write};

use crucible_node_contract::U64;
use serde::{Deserialize, Serialize, ser::SerializeSeq};

use crate::node_scheduling::{InputPayload, NativeInputAcknowledgement, event::Delivery};

use super::*;

#[path = "host_archive.rs"]
pub(super) mod archive;

#[path = "host_recorded_state.rs"]
pub(crate) mod recorded;

#[path = "host_condition_continuation.rs"]
pub(crate) mod condition;

#[derive(Serialize)]
struct Wire<'a> {
    schema_version: u16,
    profile: &'static str,
    boundary: Position,
    native: &'a [u8],
    native_sequence: U64,
    staged: Option<InputWire<'a>>,
    input_history: InputHistoryWire<'a>,
    pending_causes: CausesWire<'a>,
    operations: OperationsWire<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recorded_ingress: Option<recorded::RecordedCursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    producer_observations: Option<&'a [rate_alarm_evidence::OriginalReceipt]>,
}

#[derive(Serialize)]
struct InputWire<'a> {
    stage_operation: &'a Id,
    batch: &'a Id,
    cutoff: Position,
    inventory: &'a ContentRef,
    deliveries: &'a [Delivery],
    payloads: &'a [InputPayload],
    acknowledgement: &'a NativeInputAcknowledgement,
    consumed: U64,
    acknowledgement_body: &'a InputPayload,
}

#[derive(Serialize)]
struct CauseWire<'a> {
    time_ps: U64,
    source: u32,
    sequence: u32,
    parents: &'a [Position],
}

#[derive(Serialize)]
struct OperationWire<'a> {
    operation: &'a Id,
    request: &'a OperationRequest,
    outcome: &'a OperationOutcome,
    acknowledged: bool,
    capture: Option<&'a [u8]>,
    evidence: &'a [InputPayload],
}

struct InputHistoryWire<'a>(&'a BTreeMap<Id, execution::Staged>);

impl Serialize for InputHistoryWire<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for staged in self.0.values() {
            sequence.serialize_element(&input_wire(staged))?;
        }
        sequence.end()
    }
}

struct CausesWire<'a>(&'a BTreeMap<(u64, u32, u32), Vec<Position>>);

impl Serialize for CausesWire<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (key, parents) in self.0 {
            sequence.serialize_element(&CauseWire {
                time_ps: key.0.into(),
                source: key.1,
                sequence: key.2,
                parents,
            })?;
        }
        sequence.end()
    }
}

struct OperationsWire<'a>(&'a BTreeMap<Id, Completed>);

impl Serialize for OperationsWire<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (operation, completed) in self.0 {
            sequence.serialize_element(&OperationWire {
                operation,
                request: completed.original.request(),
                outcome: &completed.outcome,
                acknowledged: completed.acknowledged,
                capture: completed.capture.as_ref().map(|bytes| bytes.as_slice()),
                evidence: &completed.evidence,
            })?;
        }
        sequence.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Captured {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    profile: String,
    boundary: Position,
    native: Vec<u8>,
    native_sequence: U64,
    staged: Option<CapturedInput>,
    input_history: Vec<CapturedInput>,
    pending_causes: Vec<CapturedCause>,
    operations: Vec<CapturedOperation>,
    #[serde(default, deserialize_with = "recorded::present_cursor")]
    recorded_ingress: Option<recorded::RecordedCursor>,
    #[serde(default, deserialize_with = "rate_alarm_evidence::present_originals")]
    producer_observations: Option<Vec<rate_alarm_evidence::OriginalReceipt>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedInput {
    stage_operation: Id,
    batch: Id,
    cutoff: Position,
    inventory: ContentRef,
    deliveries: Vec<Delivery>,
    payloads: Vec<InputPayload>,
    acknowledgement: NativeInputAcknowledgement,
    consumed: U64,
    acknowledgement_body: InputPayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedCause {
    time_ps: U64,
    source: u32,
    sequence: u32,
    parents: Vec<Position>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedOperation {
    operation: Id,
    request: OperationRequest,
    outcome: OperationOutcome,
    acknowledged: bool,
    capture: Option<Vec<u8>>,
    evidence: Vec<InputPayload>,
}

pub(super) struct PreparedHostContinuation {
    target: ActivationRecord,
    source: SourceScope,
    captured: Captured,
    fresh_acknowledgements: BTreeMap<Id, NativeInputAcknowledgement>,
    fresh_acknowledgement_bodies: BTreeMap<Id, InputPayload>,
}

// Other components' native state is covered by the complete host restore
// barrier. Retaining only this component's checked original ledgers avoids an
// entire-world snapshot clone for every node in a heterogeneous world.
#[derive(PartialEq)]
struct SourceScope {
    generation: U64,
    activation_id: Id,
    world_hash: HashRef,
    cut: Position,
    ordinal: U64,
    operations: Vec<SavedRuntimeOperation>,
    inputs: Vec<SavedRuntimeInput>,
}

impl SourceScope {
    fn checked(
        source: &RuntimeSnapshot,
        node: &Id,
        limits: HostModelResources,
    ) -> Result<Self, OperationFailure> {
        let operation_count = source
            .operations
            .iter()
            .filter(|operation| &operation.route.node == node)
            .count();
        let input_count = source
            .inputs
            .iter()
            .filter(|input| &input.node == node)
            .count();
        if operation_count
            .checked_add(input_count)
            .is_none_or(|count| count > limits.maximum_operations)
        {
            return Err(failure(
                "host original source ledger exceeds native record ceiling",
            ));
        }
        let bytes = source
            .inputs
            .iter()
            .filter(|input| &input.node == node)
            .flat_map(|input| &input.payloads)
            .map(|payload| payload.bytes.len())
            .chain(
                source
                    .operations
                    .iter()
                    .filter(|operation| &operation.route.node == node)
                    .filter_map(|operation| match &operation.result {
                        SavedRuntimeResult::Complete(outcome)
                        | SavedRuntimeResult::Acknowledged(outcome) => outcome.scheduling.as_ref(),
                        _ => None,
                    })
                    .flat_map(|observation| &observation.publications)
                    .map(|publication| publication.payload_bytes.len()),
            )
            .try_fold(0usize, |total, length| {
                total
                    .checked_add(length)
                    .ok_or_else(|| failure("host original source retained-byte overflow"))
            })?;
        if bytes > limits.maximum_capture_bytes {
            return Err(failure(
                "host original source custody exceeds retained-byte ceiling",
            ));
        }
        Ok(Self {
            generation: source.source_activation.generation,
            activation_id: source.source_activation.activation_id.clone(),
            world_hash: source.source_activation.world_binding_hash.clone(),
            cut: source.capture_cut,
            ordinal: source.capture_ordinal,
            operations: source
                .operations
                .iter()
                .filter(|operation| &operation.route.node == node)
                .cloned()
                .collect(),
            inputs: source
                .inputs
                .iter()
                .filter(|input| &input.node == node)
                .cloned()
                .collect(),
        })
    }
}

struct LimitedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("host continuation size overflow"))?;
        if length > self.maximum {
            return Err(io::Error::other(
                "host continuation exceeds admitted byte ceiling",
            ));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn input_wire(staged: &execution::Staged) -> InputWire<'_> {
    InputWire {
        stage_operation: staged.original.stage_operation(),
        batch: staged.original.batch(),
        cutoff: staged.original.cutoff(),
        inventory: staged.original.inventory(),
        deliveries: staged.original.deliveries(),
        payloads: staged.original.payloads(),
        acknowledgement: &staged.acknowledgement,
        consumed: U64::new(staged.consumed as u64),
        acknowledgement_body: &staged.acknowledgement_body,
    }
}

pub(super) fn encode(node: &HostModelNode) -> Result<Vec<u8>, OperationFailure> {
    encode_with_limit(node, node.limits.maximum_capture_bytes)
}

pub(super) fn encode_with_limit(
    node: &HostModelNode,
    maximum: usize,
) -> Result<Vec<u8>, OperationFailure> {
    let maximum = maximum.min(node.limits.maximum_capture_bytes);
    if condition_state::selected(node) {
        return condition_state::encode(node, maximum);
    }
    let native = node
        .model
        .as_ref()
        .ok_or_else(|| failure("host native model unavailable"))?
        .capture(maximum)?;
    let staged = node.staged.as_ref().map(input_wire);
    let wire = Wire {
        schema_version: if rate_alarm_evidence::selected(&node.binding) {
            8
        } else if matches!(&node.model, Some(HostModel::RateAlarmClock(_))) {
            7
        } else if node
            .recorded_ingress
            .as_ref()
            .is_some_and(|ingress| ingress.preserved)
        {
            5
        } else if matches!(&node.model, Some(HostModel::ControlledFaultLink(_))) {
            3
        } else if matches!(&node.model, Some(HostModel::Semantics(model)) if model.definition().version == 2)
        {
            2
        } else {
            1
        },
        profile: HOST_EXACT_PROFILE,
        boundary: node.boundary,
        native: &native,
        native_sequence: node.native_sequence.into(),
        staged,
        input_history: InputHistoryWire(&node.input_history),
        pending_causes: CausesWire(&node.pending_causes),
        operations: OperationsWire(&node.completed),
        recorded_ingress: node
            .recorded_ingress
            .as_ref()
            .filter(|ingress| ingress.preserved)
            .map(recorded::capture)
            .transpose()?,
        producer_observations: rate_alarm_evidence::selected(&node.binding)
            .then_some(node.producer_observations.as_slice()),
    };
    bounded_bytes(&wire, maximum)
}

fn inventory_length(value: &(impl Serialize + ?Sized)) -> Result<usize, OperationFailure> {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("host inventory size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|error| failure(&error.to_string()))?;
    Ok(counter.0)
}

pub(super) fn capture_live(
    node: &HostModelNode,
    activation: &WorldActivation,
    source: &RuntimeSnapshot,
    maximum: usize,
) -> Result<HostNativeCapture, OperationFailure> {
    if node.quarantined
        || node.model.is_none()
        || !node.failed.is_empty()
        || !node.facets.contains(&FacetKind::Preservation)
        || !node.facets.contains(&FacetKind::ExactExecution)
        || !node.same_world(activation)
        || node
            .activation_authority
            .as_ref()
            .is_some_and(|authority| !Rc::ptr_eq(authority, &activation.authority))
        || source.source_activation != activation.record().into()
        || source.capture_cut != node.boundary
        || node.route.owners.iter().any(|owner| {
            !source.owners.iter().any(|saved| {
                if &saved.identity != owner
                    || !matches!(saved.lifecycle, Lifecycle::Stopped | Lifecycle::Executing)
                {
                    return false;
                }
                saved.operation.as_ref().is_none_or(|operation| {
                    node.completed
                        .get(operation)
                        .is_some_and(|completed| !completed.acknowledged)
                        || node
                            .staged
                            .as_ref()
                            .is_some_and(|staged| staged.original.stage_operation() == operation)
                })
            })
        })
    {
        return Err(failure(
            "host native capture lacks authentic live stopped source custody",
        ));
    }
    let maximum = maximum.min(node.limits.maximum_capture_bytes);
    let bytes = if node.condition_preservation {
        condition::encode(node, source, maximum)?
    } else {
        encode_with_limit(node, maximum)?
    };
    // Count immutable evidence before copying any receipt registry. Canonical
    // key ordering changes no serialized length for this closed inventory.
    let mut total = bytes.len();
    for object in node
        .completed
        .values()
        .flat_map(|operation| &operation.evidence)
    {
        total = total
            .checked_add(object.bytes.len())
            .ok_or_else(|| failure("host capture evidence size overflow"))?;
    }
    for staged in node.input_history.values().chain(node.staged.iter()) {
        let inventory_bytes = inventory_length(staged.original.deliveries())?;
        total = total
            .checked_add(inventory_bytes)
            .and_then(|size| size.checked_add(staged.acknowledgement_body.bytes.len()))
            .ok_or_else(|| failure("host capture original staging evidence size overflow"))?;
        for payload in staged.original.payloads() {
            total = total
                .checked_add(payload.bytes.len())
                .ok_or_else(|| failure("host capture payload size overflow"))?;
        }
    }
    if total > maximum {
        return Err(failure(
            "host complete native capture and evidence exceed preallocation ceiling",
        ));
    }
    let inventory = archive::validate_host_continuation(
        &bytes,
        source,
        &node.descriptor,
        &node.binding,
        node.limits,
    )?;
    let reference = canonical::content_ref(&bytes, "application/octet-stream")
        .map_err(|error| failure(&error.to_string()))?;
    Ok(HostNativeCapture {
        node: node.route.node.clone(),
        profile: Id::new(HOST_EXACT_PROFILE).map_err(|error| failure(&error.to_string()))?,
        state: InputPayload { reference, bytes },
        native_model: inventory.native_model,
        evidence: inventory.evidence,
    })
}

fn bounded_bytes(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
    let mut output = LimitedWriter {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut output, value).map_err(|error| failure(&error.to_string()))?;
    Ok(output.bytes)
}

/// Commits the actual current mechanical state without recursively embedding
/// earlier operation captures. The immutable body is retained at completion.
pub(super) fn state_receipt(node: &HostModelNode) -> Result<Vec<u8>, OperationFailure> {
    if condition_state::selected(node) {
        let objects = condition_state::receipt_objects(node)?;
        return objects
            .into_iter()
            .next()
            .map(|receipt| receipt.bytes)
            .ok_or_else(|| failure("condition native original receipt omitted"));
    }
    let [receipt, _, _] = state_receipt_objects(node)?;
    Ok(receipt.bytes)
}

pub(super) fn state_receipt_objects(
    node: &HostModelNode,
) -> Result<[InputPayload; 3], OperationFailure> {
    #[derive(Serialize)]
    struct Receipt<'a> {
        schema_version: u16,
        profile: &'static str,
        node: &'a Id,
        owners: &'a [OwnerIdentity],
        boundary: Position,
        native: ContentRef,
        native_sequence: U64,
        input: Option<(&'a Id, &'a ContentRef, U64)>,
        pending_causes: ContentRef,
    }

    #[derive(Serialize)]
    struct CauseEvidence<'a> {
        schema: &'static str,
        causes: CausesWire<'a>,
    }

    let native = node.capture()?;
    // A bare empty array is also a legitimate input-inventory body. Scope
    // newly issued causal evidence so one byte hash never acquires conflicting
    // media metadata. Historical receipt bodies remain opaque preserved bytes.
    let causes_bytes = bounded_bytes(
        &CauseEvidence {
            schema: "crucible.host-pending-causes.v1",
            causes: CausesWire(&node.pending_causes),
        },
        node.limits.maximum_capture_bytes,
    )?;
    let receipt = Receipt {
        schema_version: 1,
        profile: HOST_EXACT_PROFILE,
        node: &node.route.node,
        owners: &node.route.owners,
        boundary: node.boundary,
        native: canonical::content_ref(&native, "application/octet-stream")
            .map_err(|error| failure(&error.to_string()))?,
        native_sequence: node.native_sequence.into(),
        input: node.staged.as_ref().map(|staged| {
            (
                staged.original.batch(),
                staged.original.inventory(),
                U64::new(staged.consumed as u64),
            )
        }),
        pending_causes: canonical::content_ref(&causes_bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?,
    };
    let bytes = bounded_bytes(&receipt, node.limits.maximum_capture_bytes)?;
    let reference = canonical::content_ref(&bytes, "application/octet-stream")
        .map_err(|error| failure(&error.to_string()))?;
    Ok([
        InputPayload { reference, bytes },
        InputPayload {
            reference: receipt.native,
            bytes: native,
        },
        InputPayload {
            reference: receipt.pending_causes,
            bytes: causes_bytes,
        },
    ])
}

impl HostModelNode {
    /// Encodes complete native model, input, publication and original operation custody.
    ///
    /// The exact edition embeds unchanged device/link codecs and also preserves
    /// causal parents, the superdense boundary, original staged payloads and
    /// acknowledgements, consumption prefix and native publication counter.
    ///
    /// # Errors
    /// Refuses unavailable or quarantined native state and exceeded byte ceilings.
    pub fn continuation_bytes(&self) -> Result<Vec<u8>, OperationFailure> {
        if self.quarantined || self.model.is_none() || !self.failed.is_empty() {
            return Err(failure(
                "host continuation lacks fully classified native custody",
            ));
        }
        self.capture_continuation()
    }

    /// Prepares authenticated original native continuation under closed gates.
    ///
    /// This method neither activates a world nor creates local permissions. The
    /// installed qualifier must authenticate the complete source capture and
    /// immutable inputs. Genuine fresh opaque inputs and operation admissions
    /// are installed only after the common runtime publishes the whole world.
    ///
    /// # Errors
    /// Refuses unqualified source lineage, incomplete original native ledgers,
    /// pending/failed work unsupported by this synchronous profile, mismatched
    /// cuts/owners, changed immutable artifacts or exceeded resource ceilings.
    pub fn prepare_continuation(
        &mut self,
        bytes: &[u8],
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
        qualification: &dyn HostModelQualification,
    ) -> Result<NativeRuntimeContinuationEvidence, OperationFailure> {
        if self.quarantined
            || self.readiness.is_some()
            || self.activation_authority.is_some()
            || self.prepared_continuation.is_some()
            || self.public_preparation.is_some()
            || !self.completed.is_empty()
            || self.staged.is_some()
            || !self.facets.contains(&FacetKind::ExactExecution)
            || bytes.len() > self.limits.maximum_capture_bytes
            || target.world_binding_hash != self.world_hash
            || target.generation <= source.source_activation.generation
            || target.activation_id == source.source_activation.activation_id
            || source.source_activation.world_binding_hash != self.world_hash
            || target.boundary != source.capture_cut
            || !self
                .route
                .owners
                .iter()
                .all(|owner| target.owners.contains(owner))
        {
            return Err(failure(
                "host restored custody requires unused isolated native state and matching complete cut",
            ));
        }
        let model = self
            .model
            .as_ref()
            .ok_or_else(|| failure("host target model missing"))?;
        qualification.authenticate_continuation(
            model,
            &self.descriptor,
            &self.binding,
            bytes,
            source,
            target,
        )?;
        archive::validate_host_continuation(
            bytes,
            source,
            &self.descriptor,
            &self.binding,
            self.limits,
        )?;
        let source_scope = SourceScope::checked(source, &self.route.node, self.limits)?;
        let mut captured =
            decode_captured(bytes, source, &self.descriptor, &self.binding, self.limits)?;
        validate_rate_alarm_capture(
            &captured,
            super::super::rate_alarm_clock::selected(&self.binding),
        )?;
        if captured.schema_version
            != if rate_alarm_evidence::selected(&self.binding) {
                8
            } else if matches!(&self.model, Some(HostModel::RateAlarmClock(_))) {
                7
            } else if self.condition_preservation {
                6
            } else if self
                .recorded_ingress
                .as_ref()
                .is_some_and(|ingress| ingress.preserved)
            {
                5
            } else if matches!(&self.model, Some(HostModel::ControlledFaultLink(_))) {
                3
            } else if matches!(&self.model, Some(HostModel::Semantics(model)) if model.definition().version == 2)
            {
                2
            } else {
                1
            }
            || captured.profile != HOST_EXACT_PROFILE
            || captured.boundary != source.capture_cut
            || captured.operations.len() > self.limits.maximum_operations
            || captured.pending_causes.len() > self.limits.maximum_operations
            || captured.input_history.len() > self.limits.maximum_operations
        {
            return Err(failure(
                "host capture edition, boundary or resource inventory mismatch",
            ));
        }
        let expected_sequence = captured
            .operations
            .iter()
            .flat_map(|operation| operation.outcome.scheduling.iter())
            .flat_map(|observation| &observation.publications)
            .map(|publication| publication.native_sequence.get())
            .max()
            .map(|last| {
                last.checked_add(1)
                    .ok_or_else(|| failure("captured host publication sequence exhausted"))
            })
            .transpose()?
            .unwrap_or(0);
        if captured.native_sequence.get() != expected_sequence {
            return Err(failure(
                "captured host native publication counter does not match actual original outputs",
            ));
        }
        let mut expected = BTreeMap::new();
        for operation in source
            .operations
            .iter()
            .filter(|operation| operation.route.node == self.route.node)
        {
            match &operation.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => {
                    if expected
                        .insert(operation.operation.clone(), (operation, outcome))
                        .is_some()
                    {
                        return Err(failure("host source operation identity is duplicated"));
                    }
                }
                _ => {
                    return Err(failure(
                        "synchronous host continuation contains unsupported pending or failed original operation",
                    ));
                }
            }
        }
        if expected.len() != captured.operations.len() {
            return Err(failure(
                "host captured original operation inventory is incomplete",
            ));
        }
        let mut previous = None;
        for operation in &captured.operations {
            let (saved, outcome) = expected
                .get(&operation.operation)
                .ok_or_else(|| failure("host capture contains unknown original operation"))?;
            if previous
                .as_ref()
                .is_some_and(|id| id >= &operation.operation)
                || if captured.schema_version == 6 {
                    !condition::same_request(&saved.request, &operation.request)?
                } else {
                    saved.request != operation.request
                }
                || **outcome != operation.outcome
                || operation.acknowledged
                    != matches!(saved.result, SavedRuntimeResult::Acknowledged(_))
            {
                return Err(failure(
                    "host captured request, result or original ACK knowledge changed",
                ));
            }
            let maximum_objects = operation.outcome.scheduling.as_ref().map_or_else(
                || match &operation.outcome.progress {
                    ProgressEvidence::AssertionsFinalized { .. } => 2,
                    _ => 1,
                },
                |observation| observation.publications.len().saturating_add(3),
            );
            if recorded::native_receipt_count(
                captured.recorded_ingress.as_ref(),
                &operation.evidence,
            )? > maximum_objects
                && captured.schema_version != 6
            {
                return Err(failure(
                    "captured host receipt registry exceeds original object inventory",
                ));
            }
            let mut references = std::collections::BTreeSet::new();
            for object in &operation.evidence {
                if (!references.insert(&object.reference) && captured.schema_version != 6)
                    || canonical::content_ref(&object.bytes, &object.reference.media_type)
                        .map_err(|error| failure(&error.to_string()))?
                        != object.reference
                {
                    return Err(failure(
                        "captured host original receipt bytes or identities changed",
                    ));
                }
            }
            if let ProgressEvidence::AssertionsFinalized {
                barrier, report, ..
            } = &operation.outcome.progress
                && (captured.schema_version != 2
                    || source.schema_version != 3
                    || operation.outcome.scheduling.is_some()
                    || references.len() != 2
                    || !references.contains(barrier)
                    || !references.contains(report))
            {
                return Err(failure(
                    "captured host original terminal evidence is incomplete",
                ));
            }
            if let Some(observation) = &operation.outcome.scheduling
                && (!references.contains(&observation.proof_ref)
                    || observation
                        .bounds
                        .iter()
                        .any(|bound| !references.contains(&bound.proof_ref))
                    || observation
                        .input_progress
                        .as_ref()
                        .is_some_and(|progress| !references.contains(&progress.proof_ref))
                    || observation.publications.iter().any(|publication| {
                        !operation.evidence.iter().any(|object| {
                            object.reference == publication.payload
                                && object.bytes == publication.payload_bytes
                        })
                    }))
            {
                return Err(failure(
                    "captured host original native evidence is incomplete",
                ));
            }
            previous = Some(operation.operation.clone());
        }
        let mut fresh_acknowledgements = BTreeMap::new();
        let mut fresh_acknowledgement_bodies = BTreeMap::new();
        for input in captured.input_history.iter().chain(captured.staged.iter()) {
            let saved = source
                .inputs
                .iter()
                .find(|saved| {
                    saved.node == self.route.node && saved.stage_operation == input.stage_operation
                })
                .ok_or_else(|| failure("host captured input has no original runtime inventory"))?;
            if saved.batch != input.batch
                || saved.cutoff != input.cutoff
                || saved.inventory != input.inventory
                || saved.deliveries != input.deliveries
                || saved.payloads != input.payloads
                || saved.acknowledgement.as_ref() != Some(&input.acknowledgement)
                || saved.failure.is_some()
                || usize::try_from(input.consumed.get()).is_err()
                || input.consumed.get() > input.deliveries.len() as u64
                || input.acknowledgement_body.reference != input.acknowledgement.proof_ref
                || canonical::content_ref(
                    &input.acknowledgement_body.bytes,
                    &input.acknowledgement_body.reference.media_type,
                )
                .map_err(|error| failure(&error.to_string()))?
                    != input.acknowledgement_body.reference
            {
                return Err(failure(
                    "host original staged buffer, prefix or acknowledgement mismatch",
                ));
            }
            let consumed = captured
                .operations
                .iter()
                .filter_map(|operation| operation.outcome.scheduling.as_ref())
                .filter_map(|observation| observation.input_progress.as_ref())
                .filter(|progress| progress.batch == input.batch)
                .map(|progress| progress.consumed.len() as u64)
                .max()
                .unwrap_or(0);
            if consumed != input.consumed.get()
                || captured.input_history.iter().any(|historical| {
                    historical.stage_operation == input.stage_operation
                        && input.consumed.get() != input.deliveries.len() as u64
                })
            {
                return Err(failure(
                    "host captured input prefix is not authenticated by original semantic receipts",
                ));
            }
            let source_capture = canonical::content_ref(bytes, "application/octet-stream")
                .map_err(|error| failure(&error.to_string()))?;
            let proof_bytes = canonical::canonical_json(&serde_json::json!({
                "schema_version":1,"source_capture":source_capture,
                "activation_id":target.activation_id,"generation":target.generation,
                "owners":self.route.owners,"node":self.route.node,
                "stage_operation":input.stage_operation,"batch":input.batch,
                "cutoff":input.cutoff,"inventory":input.inventory,
                "original_acknowledgement":input.acknowledgement.proof_ref,
            }))
            .map_err(|error| failure(&error.to_string()))?;
            let proof_ref = canonical::content_ref(&proof_bytes, "application/json")
                .map_err(|error| failure(&error.to_string()))?;
            let acknowledgement = NativeInputAcknowledgement {
                stage_operation: input.stage_operation.clone(),
                batch: input.batch.clone(),
                node: self.route.node.clone(),
                owners: self.route.owners.clone(),
                cutoff: input.cutoff,
                inventory: input.inventory.clone(),
                proof_ref: proof_ref.clone(),
            };
            fresh_acknowledgement_bodies.insert(
                input.stage_operation.clone(),
                InputPayload {
                    reference: proof_ref,
                    bytes: proof_bytes,
                },
            );
            if fresh_acknowledgements
                .insert(input.stage_operation.clone(), acknowledgement)
                .is_some()
            {
                return Err(failure(
                    "host captured native input history repeats original staging identity",
                ));
            }
        }
        if source.inputs.iter().any(|input| {
            input.node == self.route.node
                && input.failure.is_none()
                && input.acknowledgement.is_some()
                && !fresh_acknowledgements.contains_key(&input.stage_operation)
        }) {
            return Err(failure(
                "host native capture lacks an original acknowledged input buffer",
            ));
        }
        let mut pending = BTreeMap::new();
        for cause in &captured.pending_causes {
            let key = (cause.time_ps.get(), cause.source, cause.sequence);
            if pending.insert(key, cause.parents.clone()).is_some()
                || cause.parents.len() > self.limits.maximum_operations
                || cause.parents.iter().any(|parent| {
                    captured.schema_version != 7
                        && captured.schema_version != 8
                        && parent.time_ps >= cause.time_ps
                })
                || cause.parents.iter().any(|parent| {
                    !captured
                        .input_history
                        .iter()
                        .chain(captured.staged.iter())
                        .any(|input| {
                            input
                                .deliveries
                                .iter()
                                .take(input.consumed.get() as usize)
                                .any(|delivery| &delivery.delivery == parent)
                        })
                })
            {
                return Err(failure(
                    "host response causal inventory is duplicated or violates positive latency",
                ));
            }
        }
        if let Some(cursor) = &captured.recorded_ingress {
            let restored = recorded::restore(cursor, &captured, source, &self.binding)?;
            if self.recorded_ingress.as_ref().is_none_or(|initial| {
                !initial.preserved || initial.definition != restored.definition
            }) {
                return Err(failure(
                    "recorded cursor differs from independently installed source",
                ));
            }
            self.recorded_ingress = Some(restored);
        }

        // Native restoration preserves base/tree identity through existing
        // device validators. No request is re-submitted and no queue is drained.
        // Successful source authentication selects a restored birth before any
        // native model effect. Event-zero restoration cannot become fresh Realize.
        self.producer_observations = captured.producer_observations.take().unwrap_or_default();
        self.preparation_origin = HostPreparationOrigin::Restored;
        let native_result = restore_model(
            self.model
                .as_mut()
                .ok_or_else(|| failure("host target disappeared"))?,
            &captured.native,
            self.limits.maximum_capture_bytes,
        );
        if let Err(mut error) = native_result {
            self.quarantined = true;
            error.effects = EffectKnowledge::Unknown;
            return Err(error);
        }
        let finalize = (|| -> Result<(Vec<u8>, ContentRef), OperationFailure> {
            if let Some(HostModel::ScriptedSource(source)) = self.model.as_ref()
                && (source.time_ps() != captured.boundary.time_ps.get()
                    || source.evaluated()
                    || source.cursor() as u64 != captured.native_sequence.get()
                    || source
                        .next_position()
                        .is_some_and(|next| next < captured.boundary)
                    || !pending.is_empty())
            {
                return Err(failure(
                    "restored script cursor, publication sequence or causal cut differs from actual native state",
                ));
            }
            let queued: std::collections::BTreeSet<_> = match self.model.as_ref() {
                Some(HostModel::Io(io)) => io.pending_completion_keys().collect(),
                Some(HostModel::PacketReceiver(receiver)) => receiver.pending_keys().collect(),
                Some(HostModel::RateAlarmClock(clock)) => clock.pending_keys().collect(),
                Some(
                    HostModel::Link(link)
                    | HostModel::SeededLink { link, .. }
                    | HostModel::FaultedLink { link, .. },
                ) => link
                    .snapshot()
                    .inflight
                    .iter()
                    .map(|frame| (frame.key.delivery_icount, frame.key.src_node, frame.key.seq))
                    .collect(),
                Some(HostModel::ControlledFaultLink(controller)) => controller
                    .native()
                    .snapshot()
                    .inflight
                    .iter()
                    .map(|frame| (frame.key.delivery_icount, frame.key.src_node, frame.key.seq))
                    .collect(),
                _ => std::collections::BTreeSet::new(),
            };
            if pending.keys().any(|key| !queued.contains(key))
                || self.output_endpoint.as_ref().is_some_and(|endpoint| {
                    self.lane(Some(endpoint))
                        .is_ok_and(|lane| queued.len() as u64 > lane.maximum_pending_events.get())
                })
            {
                return Err(failure(
                    "restored host causal/event inventory differs from actual native queues",
                ));
            }
            let initial = self.capture()?;
            let inventory = canonical::content_ref(bytes, "application/octet-stream")
                .map_err(|error| failure(&error.to_string()))?;
            Ok((initial, inventory))
        })();
        let (initial, inventory) = match finalize {
            Ok(prepared) => prepared,
            Err(mut error) => {
                self.quarantined = true;
                error.effects = EffectKnowledge::Unknown;
                return Err(error);
            }
        };
        self.boundary = captured.boundary;
        self.native_sequence = captured.native_sequence.get();
        self.pending_causes = pending;
        self.initial = Rc::new(initial);
        self.readiness_inventory = inventory;
        let evidence = NativeRuntimeContinuationEvidence {
            proof: self.readiness_inventory.clone(),
            input_acknowledgements: fresh_acknowledgements.values().cloned().collect(),
        };
        self.prepared_continuation = Some(PreparedHostContinuation {
            target: target.clone(),
            source: source_scope,
            captured,
            fresh_acknowledgements,
            fresh_acknowledgement_bodies,
        });
        Ok(evidence)
    }

    pub(crate) fn reopen_condition_history(
        &self,
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<crate::node_contract::SavedConditionStop, OperationFailure> {
        let prepared = self
            .prepared_continuation
            .as_ref()
            .ok_or_else(|| failure("condition original native preparation absent"))?;
        if !self.condition_preservation
            || &prepared.target != target
            || prepared.source != SourceScope::checked(source, &self.route.node, self.limits)?
        {
            return Err(failure(
                "condition original native source preparation differs",
            ));
        }
        let saved = source
            .condition_stop
            .as_ref()
            .ok_or_else(|| failure("condition original source Stop absent"))?;
        if saved.record.node != self.route.node {
            return Err(failure("condition original native observer differs"));
        }
        let Some(HostModel::ConditionObserver(model)) = self.model.as_ref() else {
            return Err(failure("condition original native observer unavailable"));
        };
        let (record, report) = model.preserved_stop_history()?;
        let canonical_record = canonical::canonical_json(
            &serde_json::to_value(&record).map_err(|error| failure(&error.to_string()))?,
        )
        .map_err(|error| failure(&error.to_string()))?;
        saved
            .reference
            .verify(&canonical_record)
            .map_err(|error| failure(&error.to_string()))?;
        if saved.report.as_ref() != Some(&report) {
            return Err(failure("condition original native report body changed"));
        }
        let mut reopened = saved.clone();
        reopened.record = record;
        Ok(reopened)
    }

    pub(super) fn install_native_custody(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        operations: &[OperationAdmission],
        inputs: &[Rc<crate::node_scheduling::RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        let prepared = self
            .prepared_continuation
            .as_ref()
            .ok_or_else(|| failure("host original native restore preparation unavailable"))?;
        if prepared.target != *activation.record()
            || prepared.source != SourceScope::checked(source, &self.route.node, self.limits)?
            || !self.same_world_for_restore(activation)
            || operations.len() != prepared.captured.operations.len()
        {
            return Err(failure(
                "host fresh authority does not match complete prepared original native custody",
            ));
        }
        let mut completed = BTreeMap::new();
        for admission in operations {
            let captured = prepared
                .captured
                .operations
                .iter()
                .find(|operation| &operation.operation == admission.token().operation())
                .ok_or_else(|| failure("host fresh operation has no original native state"))?;
            if admission.request() != &captured.request
                || admission.token().route() != &self.route
                || !Rc::ptr_eq(&admission.activation.authority, &activation.authority)
            {
                return Err(failure(
                    "host fresh original admission changed request, route or activation",
                ));
            }
            let mut outcome = captured.outcome.clone();
            outcome.owners = self.route.owners.clone();
            if let Some(observation) = &mut outcome.scheduling {
                observation.owners = self.route.owners.clone();
            }
            if completed
                .insert(
                    captured.operation.clone(),
                    Completed {
                        original: admission.clone(),
                        outcome,
                        capture: captured.capture.clone().map(Rc::new),
                        acknowledged: captured.acknowledged,
                        evidence: captured.evidence.clone(),
                    },
                )
                .is_some()
            {
                return Err(failure("host fresh operation identity duplicated"));
            }
        }
        let install_input =
            |captured: &CapturedInput| -> Result<execution::Staged, OperationFailure> {
                let input = inputs
                    .iter()
                    .find(|input| input.stage_operation() == &captured.stage_operation)
                    .ok_or_else(|| failure("host fresh original native input handle missing"))?;
                if input.batch() != &captured.batch
                    || input.node() != &self.route.node
                    || input.owners() != self.route.owners
                    || input.cutoff() != captured.cutoff
                    || input.inventory() != &captured.inventory
                    || input.deliveries() != captured.deliveries
                    || input.payloads() != captured.payloads
                    || !Rc::ptr_eq(&input.activation().authority, &activation.authority)
                {
                    return Err(failure(
                        "host fresh input permission does not cover unchanged native original buffers",
                    ));
                }
                Ok(execution::Staged {
                    original: Rc::clone(input),
                    acknowledgement: prepared
                        .fresh_acknowledgements
                        .get(&captured.stage_operation)
                        .cloned()
                        .ok_or_else(|| failure("host fresh native ACK missing"))?,
                    consumed: usize::try_from(captured.consumed.get())
                        .map_err(|_| failure("host consumed prefix exceeds native width"))?,
                    acknowledgement_body: prepared
                        .fresh_acknowledgement_bodies
                        .get(&captured.stage_operation)
                        .cloned()
                        .ok_or_else(|| failure("host fresh native ACK body missing"))?,
                })
            };
        let staged = prepared
            .captured
            .staged
            .as_ref()
            .map(install_input)
            .transpose()?;
        let mut input_history = BTreeMap::new();
        for captured in &prepared.captured.input_history {
            input_history.insert(captured.stage_operation.clone(), install_input(captured)?);
        }
        if self.condition_preservation && self.pooled_condition_objects() {
            for (operation, retained) in &mut completed {
                let objects = std::mem::take(&mut retained.evidence);
                retained.evidence = self.retain_condition_objects(operation, objects)?;
            }
        }
        self.completed = completed;
        self.staged = staged;
        self.input_history = input_history;
        self.activation_authority = Some(Rc::clone(&activation.authority));
        Ok(())
    }

    fn same_world_for_restore(&self, activation: &WorldActivation) -> bool {
        self.readiness.as_ref().map(|ready| &ready.0) == Some(activation.record())
            && self.model.is_some()
            && !self.quarantined
    }
}

fn restore_model(
    model: &mut HostModel,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), OperationFailure> {
    match model {
        HostModel::Io(io) => {
            let snapshot =
                crate::device_subnode::DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(
                    bytes,
                )
                .map_err(|error| failure(&error.to_string()))?;
            io.restore_checkpoint(&snapshot)
                .map_err(|error| failure(&error.to_string()))
        }
        HostModel::Link(link) => {
            let snapshot = crucible_device::netlink::LinkSnapshot::from_canonical_bytes_with_limit(
                bytes,
                maximum as u64,
            )
            .map_err(|error| failure(&error.to_string()))?;
            let installed = link.snapshot();
            if snapshot.ticks_per_ns != installed.ticks_per_ns
                || snapshot.src_node != installed.src_node
                || snapshot.base_latency_ticks != installed.base_latency_ticks
                || snapshot.floor_ticks != installed.floor_ticks
                || snapshot.faults != crucible_device::netlink::LinkFaults::none()
            {
                return Err(failure(
                    "host link continuation changed the installed immutable timing/fault profile",
                ));
            }
            **link = NetLink::restore(&snapshot).map_err(|error| failure(&error.to_string()))?;
            Ok(())
        }
        HostModel::SeededLink { link, definition } => {
            **link = definition.restore(bytes, maximum)?;
            Ok(())
        }
        HostModel::FaultedLink {
            link,
            definition,
            decisions,
        } => {
            let (restored, original) = definition.restore(bytes, maximum)?;
            **link = restored;
            *decisions = original;
            Ok(())
        }
        HostModel::PacketReceiver(receiver) => receiver.restore(bytes),
        HostModel::RateAlarmClock(clock) => clock.restore(bytes),
        HostModel::ControlledFaultLink(controller) => {
            let restored =
                super::super::ControlledFaultLink::restore(controller.program(), bytes, maximum)?;
            **controller = restored;
            Ok(())
        }
        HostModel::ScriptedSource(source) => source.restore(bytes),
        HostModel::Semantics(model) => model.restore_continuation(bytes),
        HostModel::ConditionObserver(model) => model.restore_continuation(bytes),
        HostModel::Clock(clock) => {
            let prefix = b"crucible.host-clock.v1\0";
            let ticks = bytes
                .strip_prefix(prefix)
                .and_then(|remaining| <[u8; 8]>::try_from(remaining).ok())
                .map(u64::from_le_bytes)
                .ok_or_else(|| {
                    failure("host clock continuation has invalid native edition or length")
                })?;
            *clock = VirtualClock::new();
            clock
                .advance_to(ticks)
                .map_err(|error| failure(&error.to_string()))
        }
    }
}

fn decode_captured(
    bytes: &[u8],
    source: &RuntimeSnapshot,
    descriptor: &NodeDescriptor,
    binding: &NodeBinding,
    limits: HostModelResources,
) -> Result<Captured, OperationFailure> {
    #[derive(Deserialize)]
    struct NativeEnvelopeHeader {
        schema_version: u16,
    }
    let header: NativeEnvelopeHeader =
        serde_json::from_slice(bytes).map_err(|error| failure(&error.to_string()))?;
    let rate_alarm = super::super::rate_alarm_clock::selected(binding);
    // Skip unknown fields while probing the scalar family discriminator. Older
    // codecs never reconstruct unfamiliar alarm state, including late headers.
    let producer = rate_alarm_evidence::selected(binding);
    if (producer && (header.schema_version != 8 || source.schema_version != 1))
        || (!producer && rate_alarm && (header.schema_version != 7 || source.schema_version != 1))
        || (!producer && !rate_alarm && header.schema_version > 6)
    {
        return Err(failure(
            "selected native codec does not preserve rate-alarm/lineage combination",
        ));
    }
    if condition::selected(binding) {
        condition::decode(bytes, source, descriptor, binding, limits)
    } else {
        let captured: Captured =
            serde_json::from_slice(bytes).map_err(|error| failure(&error.to_string()))?;
        if captured.producer_observations.is_some() != producer {
            return Err(failure(
                "selected producer evidence inventory is absent or unexpected",
            ));
        }
        if let Some(originals) = &captured.producer_observations {
            rate_alarm_evidence::validate_originals(
                originals,
                source,
                &descriptor.id,
                binding,
                &captured.native,
                limits,
            )?;
        }
        Ok(captured)
    }
}

// Edition7 validates exact native request/output and full-position causality.
// This inert check does not provide installed-policy or fresh owner authority.
fn validate_rate_alarm_capture(
    captured: &Captured,
    rate_alarm: bool,
) -> Result<(), OperationFailure> {
    if !rate_alarm {
        return Ok(());
    }
    let clock = super::super::rate_alarm_clock::RateAlarmClock::validate_native(&captured.native)?;
    if clock.position() != captured.boundary
        || clock.issued().len() as u64 != captured.native_sequence.get()
    {
        return Err(failure(
            "clock native boundary or original output count differs",
        ));
    }
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(super::super::rate_alarm_clock::MAXIMUM_CLOCK_REQUESTS)
        .map_err(|_| failure("clock input validation credit unavailable"))?;
    for input in captured.input_history.iter().chain(captured.staged.iter()) {
        for delivery in input.deliveries.iter().take(input.consumed.get() as usize) {
            if inputs.len() >= super::super::rate_alarm_clock::MAXIMUM_CLOCK_REQUESTS {
                return Err(failure("clock original input validation credit exhausted"));
            }
            let bytes = &input
                .payloads
                .iter()
                .find(|payload| payload.reference == delivery.payload)
                .ok_or_else(|| failure("clock original consumed input body absent"))?
                .bytes;
            inputs.push((
                delivery.delivery,
                delivery.source_sequence,
                bytes.as_slice(),
            ));
        }
    }
    inputs.sort_by_key(|(position, sequence, _)| (*position, *sequence));
    clock.validate_original_inputs(&inputs)?;
    if captured.pending_causes.len() != clock.pending_count()
        || captured
            .pending_causes
            .iter()
            .any(|cause| cause.parents.len() != 1)
    {
        return Err(failure(
            "clock original parent geometry exceeds exact native credit",
        ));
    }
    let causes = captured
        .pending_causes
        .iter()
        .map(|cause| {
            (
                (cause.time_ps.get(), cause.source, cause.sequence),
                cause.parents.clone(),
            )
        })
        .collect();
    clock.validate_pending_causes(&causes)?;
    let mut outputs = Vec::new();
    outputs
        .try_reserve_exact(clock.issued().len())
        .map_err(|_| failure("clock original output validation credit unavailable"))?;
    for operation in &captured.operations {
        if let Some(scheduling) = &operation.outcome.scheduling {
            for output in &scheduling.publications {
                if outputs.len() >= clock.issued().len() {
                    return Err(failure("clock original publication roster is excessive"));
                }
                outputs.push(output);
            }
        }
    }
    outputs.sort_by_key(|output| output.native_sequence);
    if outputs.len() != clock.issued().len() {
        return Err(failure("clock original publication roster is incomplete"));
    }
    for (index, (output, event)) in outputs.iter().zip(clock.issued()).enumerate() {
        let value = serde_json::to_value(event).map_err(|e| failure(&e.to_string()))?;
        let bytes = canonical::canonical_json(&value).map_err(|e| failure(&e.to_string()))?;
        if output.native_sequence.get() != index as u64
            || output.evaluation != Some(event.reaction)
            || output.payload_bytes != bytes
            || output.causal_parents.as_slice() != [clock.original_parent(event)?]
        {
            return Err(failure(
                "clock original issued event differs from native runtime publication",
            ));
        }
    }
    Ok(())
}
