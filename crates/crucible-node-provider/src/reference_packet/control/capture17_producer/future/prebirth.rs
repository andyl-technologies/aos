//! Projects Initial15 inventory and supported old12 proof demand before birth.
//!
//! The actual modeled inventory is never replaced by a population ceiling.
//! Future original/PID/reference leaves follow their closed protocol grammars;
//! new receipt configuration comes from the actual launch. New fresh17 proof
//! wrappers require their own defining future projection and remain unsupported.

use super::*;
use crate::protocol_snapshot::restored_settled17::{
    RestoredSettledNative17Input, RestoredSettledNativeImportGeometryData,
};
use crate::reference_packet::control::PacketDecodedCaptureFutureControlData;
use crate::reference_packet::{
    continuation_models::{PacketDecodedModelSnapshot, PacketModelKind},
    service::{
        PacketConnectedSourceProgram, PacketNative5CaptureProfile,
        complete_restore::restoration_observe::{
            PACKET_RESTORATION_OBSERVE_FEATURE, restoration_observe_proof_layout_data,
        },
        restored_input_reactive17::observation_geometry::hash,
        restored_input_reactive17::{
            RESTORED_INPUT_REACTIVE17_FEATURE, restored_input_reactive17_proof_layout_data,
            restored_input_reactive17_request_schema_data,
        },
    },
};

/// Names the formatter demand of the actual retained Initial15 decode.
///
/// No state is deserialized again. The caller separately admits the fixed
/// prebirth counter before this walk and the returned T before projection.
///
/// # Errors
/// Refuses actual metadata exhaustion or checked formatter overflow.
pub fn restored_settled_capture_control_model_future_initial15_prequote_data(
    decoded: &PacketDecodedCaptureFutureControlData,
) -> Result<(usize, usize), ProviderError> {
    Ok((
        formatter(decoded.control_data().model())?.max(43).max(20),
        counter_scratch_data(),
    ))
}

/// Quotes supported future demand from the exact retained Initial15 Control decode.
///
/// The existing decoder ran once under its independent constructor allowance.
/// This walk neither reconstructs typed model state nor obtains native credit.
/// The actual defining caller separately authenticates typed launch/raw5 equality.
/// Only Initial15 adoption with restored12 and its existing first/signed17
/// observations is covered. A fresh17 proof wrapper has a different grammar.
///
/// # Errors
/// Refuses another import class/body/fullref, changed model kind, unsupported
/// launch profile, incomplete model, arithmetic overflow or short maxima.
pub fn restored_settled_capture_control_model_future_from_initial15_data(
    launch: &PacketNative5SourceLaunch,
    canonical_raw5: &[u8],
    decoded: &PacketDecodedCaptureFutureControlData,
    input: &RestoredSettledNative17Input<'_>,
    geometry: &RestoredSettledNativeImportGeometryData,
    maximum: usize,
) -> Result<PacketRestoredSettledCaptureControlModelFutureData, ProviderError> {
    if geometry.initial15_decoder_geometry_data().is_none() {
        return Err(refused());
    }
    geometry.authenticate_same_inputs_data(input, geometry.normalization_maximum_data())?;
    decoded.authenticate_body_data(input.control.0, input.control.1)?;
    supported_model_data(
        launch,
        canonical_raw5,
        decoded.control_data().model(),
        geometry.import_correspondence_data(),
        maximum,
    )
}

fn formatter(model: &PacketDecodedModelSnapshot) -> Result<usize, ProviderError> {
    model.capture17_inventory_future_formatter_data()
}

fn supported_model_data(
    launch: &PacketNative5SourceLaunch,
    canonical_raw5: &[u8],
    model: &PacketDecodedModelSnapshot,
    import: [u8; 32],
    maximum: usize,
) -> Result<PacketRestoredSettledCaptureControlModelFutureData, ProviderError> {
    launch.limits.validate()?;
    if canonical_raw5.is_empty() {
        return Err(refused());
    }
    let kind = model.capture17_future_kind_data();
    if !matches!(
        (&launch.program, kind),
        (
            PacketConnectedSourceProgram::Producer { .. },
            PacketModelKind::Producer
        ) | (
            PacketConnectedSourceProgram::Reactive { .. },
            PacketModelKind::Reactive
        )
    ) || !matches!(
        launch.capture_profile,
        PacketNative5CaptureProfile::OwnedProtocol11 { .. }
    ) || launch.protocol_metadata_limits.is_none()
        || launch.complete_restore_selection.is_none()
    {
        return Err(refused());
    }
    let formatter = formatter(model)?.max(43).max(20);
    let first = project(maximum, |out| original(out, launch, false))?;
    let recurring = project(maximum, |out| original(out, launch, true))?;
    let prior = maximum_shape(&first, &recurring);
    let frame = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?;
    if prior.maximum_encoded_bytes > frame {
        return Err(exhausted());
    }
    let mut inventory = project(maximum, |out| {
        model.project_capture17_inventory_future_data(out)
    })?;
    inventory.serializer_temporary_requested_bytes = formatter;
    let shell = project(maximum, |out| {
        project_object(
            out,
            &["schema", "native_pid", "original", "inventory", "grant"],
        )?;
        out.add_string(match kind {
            PacketModelKind::Producer => "source-owned.packet-native/2",
            PacketModelKind::Reactive => "source-owned.packet-native/4",
        })?;
        decimal(out)?;
        out.add_value(&())
    })?;
    let model = combine(&[&shell, &inventory, &prior], maximum)?;
    let shell = project(maximum, |out| restored(out, launch))?;
    let mut restored = combine(&[&shell, &prior], maximum)?;
    restored.serializer_temporary_requested_bytes = formatter;
    if model.requested_total()? > maximum || restored.requested_total()? > maximum {
        return Err(exhausted());
    }
    Ok(
        PacketRestoredSettledCaptureControlModelFutureData::supported_from_shapes(
            &model,
            &restored,
            &prior,
            formatter,
            import,
            canonical_raw5,
        ),
    )
}

fn project(
    maximum: usize,
    fields: impl FnOnce(&mut Projection) -> Result<(), ProviderError>,
) -> Result<Shape, ProviderError> {
    let mut out = Projection::new(maximum)?;
    fields(&mut out)?;
    out.finish(maximum)
}

fn maximum_shape(left: &Shape, right: &Shape) -> Shape {
    let left = pack(left);
    let right = pack(right);
    let mut result = [0usize; 11];
    for (index, item) in result.iter_mut().enumerate() {
        *item = left[index].max(right[index]);
    }
    unpack(result)
}

// Closed subtree demands are added without subtracting old DOM or parser work.
// Object-shell field visits already include their keys and punctuation. Extra
// independent roots/bank preparation are conservative demand, never JSON bytes
// or observed future facts, and they create no canonical hash/witness.
fn combine(parts: &[&Shape], maximum: usize) -> Result<Shape, ProviderError> {
    let mut combined = [0usize; 11];
    for part in parts {
        for (target, source) in combined.iter_mut().zip(pack(part)) {
            *target = target.checked_add(source).ok_or_else(exhausted)?;
        }
    }
    let combined = unpack(combined);
    if combined.requested_total()? > maximum {
        return Err(exhausted());
    }
    Ok(combined)
}

fn original(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    signed: bool,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    project_object(
        out,
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ],
    )?;
    out.add_string("CNP/1")?;
    out.add_value(&MessageKind::Request)?;
    out.add_value(&binding.authority.session_id)?;
    out.add_value(&binding.authority.incarnation_id)?;
    out.add_value(&binding.compatibility.node_id)?;
    identifier(out)?;
    out.add_value(&())?;
    identifier(out)?;
    out.add_value(&())?;
    decimal(out)?;
    out.add_value(&Method::Observe)?;
    project_object(
        out,
        &[
            "binding_hash",
            "owner_generation",
            "after_observation_sequence",
            "maximum_items",
            "extensions",
        ],
    )?;
    hash(out, "cnp.owner-binding.v1")?;
    decimal(out)?;
    out.add_value(&U64::new(0))?;
    out.add_value(&U64::new(1))?;
    out.add_object()?;
    project_object(
        out,
        &[if signed {
            RESTORED_INPUT_REACTIVE17_FEATURE
        } else {
            PACKET_RESTORATION_OBSERVE_FEATURE
        }],
    )?;
    project_object(out, &["request", "proof"])?;
    if signed {
        project_object(
            out,
            &[
                "schema",
                "command",
                "scope",
                "first_observation",
                "current_record",
                "current_model",
                "history_prefix",
                "history_next_sequence",
                "native_allocation",
            ],
        )?;
        out.add_string(restored_input_reactive17_request_schema_data())?;
        project_object(out, &["action"])?;
        out.add_string("observe")?;
        scope(out, launch)?;
        for _ in 0..4 {
            project_reference(out)?;
        }
        decimal(out)?;
        allocation(out)?;
        proof(out, restored_input_reactive17_proof_layout_data())
    } else {
        project_object(
            out,
            &[
                "schema",
                "scope",
                "world_original",
                "world_terminal",
                "maximum_items",
                "native_allocation",
            ],
        )?;
        out.add_string(PACKET_RESTORATION_OBSERVE_FEATURE)?;
        scope(out, launch)?;
        project_reference(out)?;
        project_reference(out)?;
        out.add_value(&U64::new(1))?;
        allocation(out)?;
        proof(out, restoration_observe_proof_layout_data())
    }
}

pub(super) fn scope(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    project_object(
        out,
        &[
            "source_birth",
            "source_runtime",
            "scope_proof",
            "target",
            "restoration",
        ],
    )?;
    for _ in 0..3 {
        reference(out)?;
    }
    project_object(
        out,
        &[
            "native_pid",
            "session",
            "incarnation",
            "node",
            "owner",
            "owner_generation",
            "binding_hash",
            "world",
            "activation",
            "generation",
            "prepared_token",
            "gate",
            "admission",
            "transaction",
        ],
    )?;
    decimal(out)?;
    out.add_value(&binding.authority.session_id)?;
    out.add_value(&binding.authority.incarnation_id)?;
    out.add_value(&binding.compatibility.node_id)?;
    identifier(out)?;
    decimal(out)?;
    hash(out, "cnp.owner-binding.v1")?;
    out.add_value(&launch.selection.world)?;
    identifier(out)?;
    decimal(out)?;
    out.add_value(&launch.selection.prepared_token)?;
    out.add_value(&launch.selection.gate)?;
    out.add_value(&launch.selection.admission)?;
    out.add_value(&launch.selection.transaction)?;
    project_object(
        out,
        &[
            "captured_owner_state",
            "captured_control",
            "captured_journal",
            "mapping",
            "commit_request",
            "commit_response",
            "context_digest",
        ],
    )?;
    for _ in 0..6 {
        reference(out)?;
    }
    out.add_unescaped_ascii_extent(43)
}

fn restored(out: &mut Projection, launch: &PacketNative5SourceLaunch) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "schema",
            "native_receipt",
            "captured_owner_state",
            "captured_journal",
            "mapping",
            "restore_commit",
            "restore_response",
            "context_digest",
            "physical_gate_held",
        ],
    )?;
    out.add_string("source-owned.packet-restored-native/12")?;
    receipt(out, launch)?;
    for _ in 0..5 {
        reference(out)?;
    }
    out.add_unescaped_ascii_extent(43)?;
    out.add_value(&false)
}

fn receipt(out: &mut Projection, launch: &PacketNative5SourceLaunch) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    // This exact born17 successful family requires owned profile/metadata. Other
    // optional selectors follow the actual launch's defining skip-none recipe.
    project_object(
        out,
        &[
            "schema",
            "native_pid",
            "original",
            "binding_hash",
            "session",
            "incarnation",
            "node",
            "owner",
            "owner_generation",
            "input_epoch",
            "world",
            "native_record",
            "storage_selection",
            "capture_profile",
            "protocol_metadata_limits",
            "protocol_metadata_birth_facts",
        ],
    )?;
    for (present, name) in [
        (
            launch.confirmation_selection.is_some(),
            "confirmation_selection",
        ),
        (
            launch.ack_emitter_selection.is_some(),
            "ack_emitter_selection",
        ),
        (
            launch.complete_restore_selection.is_some(),
            "complete_restore_selection",
        ),
        (
            launch.restore_input_emitter_selection.is_some(),
            "restore_input_emitter_selection",
        ),
    ] {
        if present {
            out.add_field(name)?;
        }
    }
    out.add_string("source-owned.packet-receipt/5")?;
    decimal(out)?;
    // The complete original subtree is independently added by combine().
    hash(out, "cnp.owner-binding.v1")?;
    out.add_value(&binding.authority.session_id)?;
    out.add_value(&binding.authority.incarnation_id)?;
    out.add_value(&binding.compatibility.node_id)?;
    out.add_value(&binding.compatibility.capture_owner.id)?;
    decimal(out)?;
    out.add_value(&binding.authority.input_epoch)?;
    out.add_value(&launch.selection.world)?;
    project_reference(out)?;
    project_object(out, &["storage", "limits"])?;
    out.add_value(&launch.storage)?;
    out.add_value(&launch.limits)?;
    out.add_value(&launch.capture_profile)?;
    out.add_value(
        launch
            .protocol_metadata_limits
            .as_ref()
            .ok_or_else(refused)?,
    )?;
    project_object(out, &["before", "after"])?;
    for _ in 0..2 {
        project_object(
            out,
            &[
                "selected_rows",
                "record_capacity",
                "record_bytes",
                "alias_row_capacity",
                "alias_lookup_capacity",
                "alias_row_bytes",
                "alias_lookup_bytes",
            ],
        )?;
        for _ in 0..7 {
            decimal(out)?;
        }
    }
    if let Some(value) = &launch.confirmation_selection {
        out.add_value(value)?;
    }
    if let Some(value) = &launch.ack_emitter_selection {
        out.add_value(value)?;
    }
    if let Some(value) = &launch.complete_restore_selection {
        out.add_value(value)?;
    }
    if let Some(value) = &launch.restore_input_emitter_selection {
        out.add_value(value)?;
    }
    Ok(())
}

fn allocation(out: &mut Projection) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    decimal(out)?;
    decimal(out)?;
    decimal(out)
}
fn reference(out: &mut Projection) -> Result<(), ProviderError> {
    project_object(out, &["hash", "length", "media_type"])?;
    hash(out, "cnp.blob.v1")?;
    decimal(out)?;
    out.add_string_extent(128)
}
fn proof(
    out: &mut Projection,
    (schema, algorithm, digest, mac): (&str, &str, usize, usize),
) -> Result<(), ProviderError> {
    project_object(out, &["schema", "algorithm", "context_digest", "mac"])?;
    out.add_string(schema)?;
    out.add_string(algorithm)?;
    out.add_unescaped_ascii_extent(encoded(digest)?)?;
    out.add_unescaped_ascii_extent(encoded(mac)?)
}
fn encoded(bytes: usize) -> Result<usize, ProviderError> {
    bytes
        .checked_div(3)
        .and_then(|groups| groups.checked_mul(4))
        .and_then(|whole| {
            whole.checked_add(match bytes % 3 {
                0 => 0,
                1 => 2,
                _ => 3,
            })
        })
        .ok_or_else(exhausted)
}
fn identifier(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(128)
}
fn decimal(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(20)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<PacketRestoredSettledCaptureControlModelFutureData>()
        + size_of::<Result<PacketRestoredSettledCaptureControlModelFutureData, ProviderError>>()
        + size_of::<Projection>()
        + size_of::<Shape>() * 7
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&NodeBinding>()
        + size_of::<&PacketDecodedModelSnapshot>()
        + size_of::<&PacketDecodedCaptureFutureControlData>()
        + size_of::<&RestoredSettledNative17Input<'static>>()
        + size_of::<&RestoredSettledNativeImportGeometryData>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<[u8; 32]>()
        + size_of::<&[u8]>()
        + size_of::<[usize; 11]>() * 3
        + size_of::<std::array::IntoIter<usize, 11>>()
        + size_of::<std::iter::Enumerate<std::slice::IterMut<'static, usize>>>()
        + size_of::<
            std::iter::Zip<std::slice::IterMut<'static, usize>, std::array::IntoIter<usize, 11>>,
        >()
        + size_of::<std::slice::Iter<'static, &'static Shape>>()
        + size_of::<[&Shape; 3]>()
        + size_of::<[&Shape; 2]>()
        + size_of::<[&str; 16]>()
        + size_of::<[&str; 14]>()
        + size_of::<[&str; 13]>()
        + size_of::<[&str; 9]>()
        + size_of::<[&str; 7]>()
        + size_of::<[&str; 6]>()
        + size_of::<[&str; 5]>()
        + size_of::<[&str; 4]>()
        + size_of::<[&str; 3]>()
        + size_of::<[&str; 2]>()
        + size_of::<[(bool, &str); 4]>()
        + size_of::<std::array::IntoIter<(bool, &'static str), 4>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<(&str, &str, usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + PacketDecodedModelSnapshot::capture17_inventory_future_counter_scratch_data()
        + PacketDecodedCaptureFutureControlData::provenance_counter_scratch_data()
        + RestoredSettledNativeImportGeometryData::counter_scratch_data()
}

// Exhaustive DTO rosters keep the closed future projection coupled to actual
// receipt, proof and observation formats without constructing any authority.
const _: fn(
    &PacketNative5Record,
    &PacketNativeRestoredRecord,
    &crate::reference_packet::service::PacketNative5ProtocolMetadataBirthFacts,
    &crate::reference_packet::service::PacketNative5ProtocolMetadataBankFacts,
    &crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationRequest,
    &crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationProof,
    &crate::reference_packet::service::restored_input_reactive17::PacketRestoredInputReactive17Request,
    &crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationProof,
) = |receipt, restored, birth, bank, first, first_proof, recurring, recurring_proof| {
    let PacketNative5Record {
        schema: _,
        native_pid: _,
        original: _,
        binding_hash: _,
        session: _,
        incarnation: _,
        node: _,
        owner: _,
        owner_generation: _,
        input_epoch: _,
        world: _,
        native_record: _,
        storage_selection: _,
        capture_profile: _,
        confirmation_selection: _,
        ack_emitter_selection: _,
        complete_restore_selection: _,
        protocol_metadata_limits: _,
        protocol_metadata_birth_facts: _,
        restore_input_emitter_selection: _,
    } = receipt;

    let PacketNativeRestoredRecord {
        schema: _,
        native_receipt: _,
        captured_owner_state: _,
        captured_journal: _,
        mapping: _,
        restore_commit: _,
        restore_response: _,
        context_digest: _,
        physical_gate_held: _,
    } = restored;

    let crate::reference_packet::service::PacketNative5ProtocolMetadataBirthFacts {
        before: _,
        after: _
    } = birth;

    let crate::reference_packet::service::PacketNative5ProtocolMetadataBankFacts {
        selected_rows: _,
        record_capacity: _,
        record_bytes: _,
        alias_row_capacity: _,
        alias_lookup_capacity: _,
        alias_row_bytes: _,
        alias_lookup_bytes: _,
    } = bank;

    let crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationRequest {
        schema: _,
        scope: _,
        world_original: _,
        world_terminal: _,
        maximum_items: _,
        native_allocation: _,
    } = first;

    let crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationProof {
        schema: _,
        algorithm: _,
        context_digest: _,
        mac: _,
    } = first_proof;

    let crate::reference_packet::service::restored_input_reactive17::PacketRestoredInputReactive17Request {
        schema: _,
        command: _,
        scope: _,
        first_observation: _,
        current_record: _,
        current_model: _,
        history_prefix: _,
        history_next_sequence: _,
        native_allocation: _,
    } = recurring;

    let crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationProof {
        schema: _,
        algorithm: _,
        context_digest: _,
        mac: _,
    } = recurring_proof;
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bodies::ObserveRequest;
    use crate::envelope::Nullable;
    use crate::reference_packet::service::{
        complete_restore::{
            activation::{
                PacketRestorationActivationAllocationRow, PacketRestorationActivationProof,
            },
            restoration_observe::{
                PacketRestorationObservationArtifact, PacketRestorationObservationProof,
                PacketRestorationObservationRequest,
            },
        },
        restored_input_reactive17::{
            PacketRestoredInputReactive17Artifact, PacketRestoredInputReactive17Command,
            PacketRestoredInputReactive17Request,
        },
    };
    use crucible_node_contract::Bytes;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // Real typed serializers are compared as DATA. Neither arbitrary proof
    // bytes nor equal DTO geometry is claimed to be a genuine Source MAC.
    #[test]
    fn both_closed_supported_originals_dominate_their_actual_typed_wire() -> TestResult {
        let fixture = super::super::tests::Fixture::new(false)?;
        for signed in [false, true] {
            let mut actual = fixture.record.native_receipt.original.clone();
            let binding = &fixture.launch.selection.realization.bindings[0];
            actual.session_id = Nullable(Some(binding.authority.session_id.clone()));
            actual.incarnation_id = Nullable(Some(binding.authority.incarnation_id.clone()));
            actual.node_id = Nullable(Some(binding.compatibility.node_id.clone()));
            actual.execution_owner_id = Nullable(Some(fixture.scope.target.owner.clone()));
            actual.capture_owner_id = Nullable(None);
            actual.request_id = Nullable(Some(Id::new("actual-observe-data")?));
            actual.operation_id = Nullable(None);
            actual.sequence = U64::new(50);
            actual.method = Method::Observe;
            actual.body = serde_json::from_value(serde_json::to_value(ObserveRequest {
                binding_hash: fixture.record.native_receipt.binding_hash.clone(),
                owner_generation: U64::new(1),
                after_observation_sequence: U64::new(0),
                maximum_items: U64::new(1),
                extensions: Default::default(),
            })?)?;
            actual.extensions.clear();
            if signed {
                let (schema, algorithm, digest, mac) =
                    restored_input_reactive17_proof_layout_data();
                let artifact = PacketRestoredInputReactive17Artifact {
                    request: PacketRestoredInputReactive17Request {
                        schema: restored_input_reactive17_request_schema_data().into(),
                        command: PacketRestoredInputReactive17Command::Observe,
                        scope: fixture.scope.clone(),
                        first_observation: fixture.first.clone(),
                        current_record: fixture.current.clone(),
                        current_model: fixture.current.clone(),
                        history_prefix: fixture.first.clone(),
                        history_next_sequence: actual.sequence,
                        native_allocation: PacketNativeStartupAllocationRow {
                            retained_requested_bytes: U64::new(1),
                            maximum_simultaneous_transient_bytes: U64::new(1),
                            declared_counter_scratch_bytes: U64::new(1),
                        },
                    },
                    proof: PacketRestorationActivationProof {
                        schema: schema.into(),
                        algorithm: algorithm.into(),
                        context_digest: Bytes::new(vec![7; digest]),
                        mac: Bytes::new(vec![8; mac]),
                    },
                };
                actual.extensions.insert(
                    RESTORED_INPUT_REACTIVE17_FEATURE.into(),
                    serde_json::to_value(artifact)?,
                );
            } else {
                let (schema, algorithm, digest, mac) = restoration_observe_proof_layout_data();
                let artifact = PacketRestorationObservationArtifact {
                    request: PacketRestorationObservationRequest {
                        schema: PACKET_RESTORATION_OBSERVE_FEATURE.into(),
                        scope: fixture.scope.clone(),
                        world_original: fixture.first.clone(),
                        world_terminal: fixture.current.clone(),
                        maximum_items: U64::new(1),
                        native_allocation: PacketRestorationActivationAllocationRow {
                            retained_requested_bytes: U64::new(1),
                            maximum_simultaneous_transient_bytes: U64::new(1),
                            declared_counter_scratch_bytes: U64::new(1),
                        },
                    },
                    proof: PacketRestorationObservationProof {
                        schema: schema.into(),
                        algorithm: algorithm.into(),
                        context_digest: Bytes::new(vec![7; digest]),
                        mac: Bytes::new(vec![8; mac]),
                    },
                };
                actual.extensions.insert(
                    PACKET_RESTORATION_OBSERVE_FEATURE.into(),
                    serde_json::to_value(artifact)?,
                );
            }

            let bound = project(usize::MAX, |out| original(out, &fixture.launch, signed))?;
            let actual =
                actual_serialization_storage_data(&actual, Default::default(), usize::MAX)?;
            within(&actual, &bound)?;
        }
        Ok(())
    }

    #[test]
    fn closed_receipt_restoration_shell_dominates_actual_immutable_fields() -> TestResult {
        let mut fixture = super::super::tests::Fixture::new(false)?;
        fixture.launch.protocol_metadata_limits = Some(
            crate::reference_packet::service::PacketNative5ProtocolMetadataLimits {
                native_before_rows: U64::new(131_072),
                native_after_rows: U64::new(131_072),
            },
        );
        let prior = project(usize::MAX, |out| original(out, &fixture.launch, true))?;
        let shell = project(usize::MAX, |out| restored(out, &fixture.launch))?;
        let bound = combine(&[&shell, &prior], usize::MAX)?;
        let actual =
            actual_serialization_storage_data(&fixture.record, Default::default(), usize::MAX)?;

        within(&actual, &bound)?;
        Ok(())
    }
}
