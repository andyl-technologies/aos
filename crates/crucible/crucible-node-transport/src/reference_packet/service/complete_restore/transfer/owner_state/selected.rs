//! Decodes only selected outer13/14 capture fields, retaining raw protocol leaves.
//!
//! The actual MAC-verified native Prepare selects the class at its caller. This
//! private DATA decoder repeats the full compiled schema comparison and actual
//! borrowed framing; neither FreshSome nor a wire prefix upgrades old11.

use super::*;
use crate::{
    protocol_snapshot::RestorationMappingClass,
    reference_packet::service::native_snapshot::{
        PacketNativeOwned13SnapshotPlan, PacketNativeOwned14SnapshotPlan,
    },
};

struct CaptureParts<'a> {
    capture: &'a [u8],
    request: &'a [u8],
    control_reference: &'a [u8],
}

fn capture_parts<'a>(
    data: &PacketCompleteRestoreOwnerStateData<'a>,
    class: RestorationMappingClass,
) -> Result<CaptureParts<'a>, ProviderError> {
    let schema = &data.request.prepare.restoration.backend_schema;
    let allocation = &data.request.prepare.allocation;
    let input_maximum =
        usize::try_from(allocation.maximum_input_bytes.get()).map_err(|_| refused())?;
    // The embedded raw-before is part of the signed input object. Its encoded
    // extent is bounded by that complete input extent; a heap-backing budget is
    // not a byte-length limit. Full native reconstruction has separate limits.
    let before_maximum = input_maximum;
    match class {
        RestorationMappingClass::StartupCapture14 => {
            crate::reference_packet::service::native_snapshot::authenticate_native_owned13_snapshot_schema_data(schema)?;
            let plan = PacketNativeOwned13SnapshotPlan::validate(
                data.owner_state_bytes,
                input_maximum,
                before_maximum,
            )?;
            if plan.control_bytes() != data.control_bytes {
                return Err(refused());
            }
            Ok(CaptureParts {
                capture: plan.capture_arguments_bytes(),
                request: plan.capture_request_bytes(),
                control_reference: plan.control_reference_bytes(),
            })
        }
        RestorationMappingClass::InvocationCapture15 => {
            crate::reference_packet::service::native_snapshot::authenticate_native_owned14_snapshot_schema_data(schema)?;
            let plan = PacketNativeOwned14SnapshotPlan::validate(
                data.owner_state_bytes,
                input_maximum,
                before_maximum,
            )?;
            if plan.control_bytes() != data.control_bytes {
                return Err(refused());
            }
            Ok(CaptureParts {
                capture: plan.capture_arguments_bytes(),
                request: plan.capture_request_bytes(),
                control_reference: plan.control_reference_bytes(),
            })
        }
        RestorationMappingClass::Legacy11 => Err(refused()),
    }
}

pub(crate) fn selected_owner_validation_storage_data(
    data: &PacketCompleteRestoreOwnerStateData<'_>,
    class: RestorationMappingClass,
) -> Result<PacketCompleteRestoreOwnerValidationStorage, ProviderError> {
    data.request.validate_data()?;
    capture_parts(data, class)?;
    let allocation = &data.request.prepare.allocation;
    let inputs = PacketCompleteRestoreSelectedOwnerInputs {
        owner_state: data.owner_state_bytes,
        journal: data.journal_bytes,
        control: data.control_bytes,
        anchor: data.anchor_bytes,
        maximum_input_bytes: usize::try_from(allocation.maximum_input_bytes.get())
            .map_err(|_| refused())?,
        maximum_before_bytes: usize::try_from(allocation.maximum_input_bytes.get())
            .map_err(|_| refused())?,
        maximum_requested_bytes: usize::try_from(allocation.maximum_model_bytes.get())
            .map_err(|_| refused())?,
    };
    match class {
        RestorationMappingClass::StartupCapture14 => {
            complete_restore_selected_owner_construction_storage_data(&inputs)
        }
        RestorationMappingClass::InvocationCapture15 => {
            complete_restore_invocation_owner_construction_storage_data(&inputs)
        }
        RestorationMappingClass::Legacy11 => Err(refused()),
    }
}

pub(crate) fn selected_owner_counter_scratch_data() -> usize {
    std::mem::size_of::<CaptureParts<'static>>()
        + std::mem::size_of::<Result<CaptureParts<'static>, ProviderError>>()
        + std::mem::size_of::<PacketCompleteRestoreOwnerStateData<'static>>()
        + std::mem::size_of::<Result<PacketCompleteRestoreOwnerProjection, ProviderError>>()
        + std::mem::size_of::<Result<PacketCompleteRestoreOwnerValidationStorage, ProviderError>>()
        + std::mem::size_of::<Result<Envelope, crucible_node_format::ContractError>>()
        + std::mem::size_of::<Result<CaptureArguments, crucible_node_format::ContractError>>()
        + std::mem::size_of::<Result<ContentRef, crucible_node_format::ContractError>>()
        + std::mem::size_of::<crate::bodies::RequestBody>()
        + std::mem::size_of::<crate::bodies::BeginRequest>()
        + std::mem::size_of::<crate::bodies::BeginArguments>()
        + std::mem::size_of::<Result<crate::bodies::RequestBody, ProviderError>>()
        + std::mem::size_of::<
            Result<crate::bodies::BeginArguments, crucible_node_format::ContractError>,
        >()
        + std::mem::size_of::<PacketNativeOwned13SnapshotPlan<'static>>()
        + std::mem::size_of::<PacketNativeOwned14SnapshotPlan<'static>>()
        + std::mem::size_of::<Result<PacketNativeOwned13SnapshotPlan<'static>, ProviderError>>()
        + std::mem::size_of::<Result<PacketNativeOwned14SnapshotPlan<'static>, ProviderError>>()
}

// Each selected subobject gets the same independent DOM/typed/roundtrip phases
// named by the prospective selected-construction row. Raw-before is never a DOM.
fn decode_part<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, ProviderError> {
    let value = canonical::parse_json(bytes, maximum)?;
    if bounded_canonical(&value, maximum)? != bytes {
        return Err(refused());
    }
    let decoded = T::deserialize(&value).map_err(crucible_node_format::ContractError::from)?;
    if serde_json::to_value(&decoded).map_err(crucible_node_format::ContractError::from)? != value {
        return Err(refused());
    }
    Ok(decoded)
}

pub(crate) fn authenticate_selected_owner_state_data(
    data: PacketCompleteRestoreOwnerStateData<'_>,
    class: RestorationMappingClass,
) -> Result<PacketCompleteRestoreOwnerProjection, ProviderError> {
    selected_owner_validation_storage_data(&data, class)?;
    let prepare = &data.request.prepare;
    let restoration = &prepare.restoration;
    let input_maximum =
        usize::try_from(prepare.allocation.maximum_input_bytes.get()).map_err(|_| refused())?;
    let layouts = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    let model_budget =
        usize::try_from(prepare.allocation.maximum_model_bytes.get()).map_err(|_| refused())?;
    let model_maximum = model_budget.min(layouts.maximum_model_bytes);
    let control_maximum = model_budget.min(layouts.maximum_control_bytes);
    restoration.owner_state.verify(data.owner_state_bytes)?;
    let parts = capture_parts(&data, class)?;
    let capture_request: Envelope = decode_part(parts.request, input_maximum)?;
    let snapshot_capture: CaptureArguments = decode_part(parts.capture, input_maximum)?;
    let control_reference: ContentRef = decode_part(parts.control_reference, input_maximum)?;
    let journal_value = exact_json(&restoration.journal, data.journal_bytes, input_maximum)?;
    let journal = decode_settled_journal_data(&journal_value)?;
    journal.require_complete_registry_data()?;
    if serde_json::to_value(&journal).map_err(crucible_node_format::ContractError::from)?
        != journal_value
    {
        return Err(refused());
    }
    prepare.native_control.verify(data.control_bytes)?;
    prepare.native_anchor.verify(data.anchor_bytes)?;
    journal.confirmation.validate_data()?;
    journal.participants.validate()?;
    journal.cut.validate()?;
    let confirmation = &journal.confirmation.capture;
    let request = &capture_request;
    request.validate()?;
    request.matches_response(&data.request.capture_terminal)?;

    if journal.owner != restoration.target_owner
        || journal.runtime != restoration.source_runtime
        || journal.backend_implementation != restoration.backend_implementation
        || journal.cut != restoration.archived_cut
        || journal.ordinal != restoration.archived_ordinal
        || journal.native_snapshot != restoration.owner_state
        || journal.native_snapshot != confirmation.native_snapshot_ref
        || journal.native_control != prepare.native_control
        || journal.native_control != confirmation.native_control_ref
        || journal.native_anchor != prepare.native_anchor
        || journal.native_anchor != confirmation.native_anchor_ref
        || journal.native_after_protocol != prepare.native_protocol
        || journal.native_after_protocol != journal.confirmation.native_after_ref
        || journal.host_protocol != prepare.host_protocol
        || journal.confirmation_request == confirmation.capture_request_id
        || control_reference != prepare.native_control
        || request.method != Method::Begin
        || request.message != MessageKind::Request
        || request.request_id.0.as_ref() != Some(&confirmation.capture_request_id)
        || request.operation_id.0.as_ref() != Some(&confirmation.capture_operation_id)
        || request.capture_owner_id.0.as_ref() != Some(&journal.owner)
        || request.request_hash(RequestOrigin::Controller)? != confirmation.capture_request_hash
        || data.request.capture_terminal.sequence != confirmation.capture_terminal_sequence
    {
        return Err(refused());
    }
    // All reference-bearing source roles are closed and syntactically checked;
    // their complete bodies are verified by the signed archive factory, not by
    // a recursive generic ContentRef walk in the native process.
    for reference in [&journal.semantic, &journal.ancestry] {
        reference.validate()?;
    }
    let RequestBody::Begin(begin) = decode_request(request.method, &request.body)? else {
        return Err(refused());
    };
    let BeginArguments::Capture(capture) = begin.decoded_arguments()? else {
        return Err(refused());
    };
    if capture.cut != journal.cut
        || capture.event_ordinal != journal.ordinal
        || capture.participant_ids != journal.participants
        || bounded_canonical(&capture, input_maximum)?
            != bounded_canonical(&snapshot_capture, input_maximum)?
        || canonical::hash(
            "source-owned.packet-native-capture-terminal/5",
            &bounded_canonical(&data.request.capture_terminal, input_maximum)?,
        )? != confirmation.capture_terminal_hash
    {
        return Err(refused());
    }
    // The exact compact original protocol and endpoint framing were checked by
    // the borrowed selected plan; a generic Value array is not that predicate.
    let control = decode_packet_control_snapshot(
        data.control_bytes,
        &prepare.native_control,
        control_maximum,
    )?;
    control.authenticate_original_capture_transition_data(PacketOriginalCaptureTransitionData {
        capture_request: request,
        terminal: &data.request.capture_terminal,
        manifest_ref: &restoration.owner_state,
        control_ref: &prepare.native_control,
        anchor_ref: &prepare.native_anchor,
        anchor_bytes: data.anchor_bytes,
        maximum_model_bytes: model_maximum,
    })?;
    Ok(PacketCompleteRestoreOwnerProjection {
        capture_request,
        control,
    })
}
