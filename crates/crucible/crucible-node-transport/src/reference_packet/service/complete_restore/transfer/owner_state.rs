//! Checks full owner-state provenance before any retained model adoption.
//!
//! The current private restore verifier supplies the actual received input banks.
//! This bounded data check creates no native token, socket or installed owner.

use super::*;

#[path = "owner_decode.rs"]
mod owner_decode;
use crate::{
    bodies::{BeginArguments, CaptureArguments, RequestBody, decode_request},
    envelope::{MessageKind, Method, RequestOrigin},
    reference_packet::{
        control::{
            PacketDecodedControlSnapshot, PacketOriginalCaptureTransitionData,
            decode_packet_control_snapshot,
        },
        service::confirmation::PacketNativeAfterConfirmationReceipt,
    },
};
use crucible_node_format::IdSet;
pub use owner_decode::{
    PacketCompleteRestoreModelOutputPopulationData, PacketCompleteRestoreOwnerValidationStorage,
    PacketCompleteRestoreSelectedOwnerInputs,
    complete_restore_invocation_owner_construction_storage_data,
    complete_restore_owner_validation_storage_data,
    complete_restore_selected_model_output_population_counter_scratch_data,
    complete_restore_selected_model_output_population_data,
    complete_restore_selected_owner_construction_counter_scratch_data,
    complete_restore_selected_owner_construction_storage_data,
};
pub(crate) use owner_decode::{
    selected_issuer_decode_counter_scratch_data, selected_issuer_decode_storage_data,
    selected_native_dto_decode_storage_data, selected_value_decode_storage_data,
};
use serde_json::Value;

/// Borrows the exact signed request and separately retained full input bodies.
pub struct PacketCompleteRestoreOwnerStateData<'a> {
    /// Borrows the actual MAC-authenticated commit extension.
    pub request: &'a PacketCompleteRestoreCommitRequest,
    /// Borrows the full native snapshot named by the archived owner state.
    pub owner_state_bytes: &'a [u8],
    /// Borrows the full source journal named by the same signed request.
    pub journal_bytes: &'a [u8],
    /// Borrows the separately transferred pending Control/model body.
    pub control_bytes: &'a [u8],
    /// Borrows the separately transferred unchanged-cut anchor body.
    pub anchor_bytes: &'a [u8],
}

/// Retains checked historical model/Control data without native authority.
///
/// Its only constructor verifies full input references, the exact source journal
/// roles, embedded pending Control and actual Capture request/terminal pair.
/// Actual SDK installation and the private one-shot native restore token remain
/// mandatory before either producer or reactive model adopts a socket.
pub struct PacketCompleteRestoreOwnerProjection {
    capture_request: Envelope,
    control: PacketDecodedControlSnapshot,
}

impl PacketCompleteRestoreOwnerProjection {
    /// Borrows the unchanged historical Capture request including its sequence.
    pub fn capture_request(&self) -> &Envelope {
        &self.capture_request
    }

    /// Moves both validated historical data owners without cloning or installation.
    ///
    /// The native attempt stores these fields before any fallible reconstruction
    /// or displacement. The unchanged Capture original remains independent of
    /// the pending Control/model data. An actual native one-shot token and SDK
    /// installation acknowledgement still gate adoption and effects.
    pub fn into_data_parts(self) -> (Envelope, PacketDecodedControlSnapshot) {
        (self.capture_request, self.control)
    }

    /// Borrows the checked pending model/Control state without installation rights.
    pub fn control(&self) -> &PacketDecodedControlSnapshot {
        &self.control
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeSnapshotData {
    schema: String,
    capture_request: Envelope,
    capture: CaptureArguments,
    control_reference: ContentRef,
    control: Value,
    protocol: Value,
    endpoint: Value,
}

// This repeats the complete portable Source journal grammar so the provider can
// validate its role projection without depending on the host's Core types.
// Source independently validates runtime/semantic/ancestry and every SDK leaf.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SettledJournalData {
    schema: String,
    owner: Id,
    participants: IdSet,
    cut: Position,
    ordinal: U64,
    runtime: ContentRef,
    backend_implementation: ContentRef,
    semantic: ContentRef,
    ancestry: ContentRef,
    native_snapshot: ContentRef,
    native_control: ContentRef,
    native_anchor: ContentRef,
    native_after_protocol: ContentRef,
    host_protocol: ContentRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_extension_registry: Option<ContentRef>,
    confirmation_request: Id,
    confirmation: PacketNativeAfterConfirmationReceipt,
}

const SETTLED_JOURNAL_11: &str = "source-owned.packet-native-settled-journal/11";
const SETTLED_JOURNAL_12: &str = "source-owned.packet-native-settled-journal/12";
const SETTLED_REGISTRY_MEDIA: &str =
    "application/vnd.source-owned.packet-host-extension-registry.v12+json";

// Edition discrimination precedes typed ownership. In particular, serde's
// Option representation must never make an explicit null equivalent to an
// omitted historical field, or let edition11 carry a registry attachment.
fn decode_settled_journal_data(value: &Value) -> Result<SettledJournalData, ProviderError> {
    match (
        value.get("schema").and_then(Value::as_str),
        value.get("host_extension_registry"),
    ) {
        (Some(SETTLED_JOURNAL_11), None) => {}
        (Some(SETTLED_JOURNAL_12), Some(reference)) if !reference.is_null() => {}
        _ => return Err(refused()),
    }
    let journal: SettledJournalData = serde::Deserialize::deserialize(value)
        .map_err(crucible_node_format::ContractError::from)?;
    if let Some(reference) = &journal.host_extension_registry {
        reference.validate()?;
        if reference.media_type != SETTLED_REGISTRY_MEDIA {
            return Err(refused());
        }
    }
    Ok(journal)
}

impl SettledJournalData {
    fn require_complete_registry_data(&self) -> Result<&ContentRef, ProviderError> {
        if self.schema != SETTLED_JOURNAL_12 {
            return Err(refused());
        }
        let reference = self.host_extension_registry.as_ref().ok_or_else(refused)?;
        reference.validate()?;
        if reference.media_type != SETTLED_REGISTRY_MEDIA {
            return Err(refused());
        }
        Ok(reference)
    }
}

/// Checks full snapshot/journal/control/anchor identities and captured transition.
///
/// The caller must pre-admit raw input, JSON/typed, canonical comparison and
/// retained model scratch from the signed allocation plan before calling. Raw
/// input banks remain in the caller's owning slots on refusal. This helper does
/// not authenticate a Core ticket, accept an upload or issue a native token.
///
/// # Errors
/// Refuses changed full references, unknown fields, noncanonical bodies, another
/// owner/cut/backend, altered capture request or terminal, inconsistent embedded
/// Control, or a failed exact pending-Control/model transition.
pub fn authenticate_complete_restore_owner_state_data(
    data: PacketCompleteRestoreOwnerStateData<'_>,
) -> Result<PacketCompleteRestoreOwnerProjection, ProviderError> {
    // Count every retained/temporary decoding phase before the first owned
    // JSON value, typed model or canonical comparison bank is constructed.
    complete_restore_owner_validation_storage_data(&data)?;
    data.request.validate_data()?;
    let prepare = &data.request.prepare;
    let restoration = &prepare.restoration;
    let input_maximum =
        usize::try_from(prepare.allocation.maximum_input_bytes.get()).map_err(|_| refused())?;
    let layouts = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    let model_budget =
        usize::try_from(prepare.allocation.maximum_model_bytes.get()).map_err(|_| refused())?;
    let model_maximum = model_budget.min(layouts.maximum_model_bytes);
    let control_maximum = model_budget.min(layouts.maximum_control_bytes);

    // Framing and exact original before bytes are checked without reparsing or
    // canonicalizing that protocol leaf. Full native predecessor decoding is a
    // separate mandatory source/archive predicate under the same input budget.
    let snapshot_plan = crate::reference_packet::service::native_snapshot::PacketNativeOwned11SnapshotPlan::validate(
        data.owner_state_bytes,
        input_maximum,
        usize::try_from(prepare.allocation.maximum_owned_backing_bytes.get()).map_err(|_| refused())?,
    )?;
    if snapshot_plan.control_bytes() != data.control_bytes {
        return Err(refused());
    }

    let snapshot_value = exact_json(
        &restoration.owner_state,
        data.owner_state_bytes,
        input_maximum,
    )?;
    let journal_value = exact_json(&restoration.journal, data.journal_bytes, input_maximum)?;
    prepare.native_control.verify(data.control_bytes)?;
    prepare.native_anchor.verify(data.anchor_bytes)?;
    let snapshot: NativeSnapshotData = serde::Deserialize::deserialize(&snapshot_value)
        .map_err(crucible_node_format::ContractError::from)?;
    let journal = decode_settled_journal_data(&journal_value)?;
    // Only the selected complete edition closes the fourth historical owner.
    // Its full reference is MAC/index-bound; native model restoration never
    // recreates or invokes the historical host registrar behind that reference.
    journal.require_complete_registry_data()?;
    if serde_json::to_value(&snapshot).map_err(crucible_node_format::ContractError::from)?
        != snapshot_value
        || serde_json::to_value(&journal).map_err(crucible_node_format::ContractError::from)?
            != journal_value
    {
        return Err(refused());
    }
    journal.confirmation.validate_data()?;
    journal.participants.validate()?;
    journal.cut.validate()?;
    let confirmation = &journal.confirmation.capture;
    let request = &snapshot.capture_request;
    request.validate()?;
    request.matches_response(&data.request.capture_terminal)?;

    if snapshot.schema != "source-owned.packet-native-continuation/11"
        || journal.owner != restoration.target_owner
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
        || snapshot.control_reference != prepare.native_control
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
            != bounded_canonical(&snapshot.capture, input_maximum)?
        || bounded_canonical(&snapshot.control, model_maximum)? != data.control_bytes
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
        capture_request: snapshot.capture_request,
        control,
    })
}

fn exact_json(
    reference: &ContentRef,
    bytes: &[u8],
    maximum: usize,
) -> Result<Value, ProviderError> {
    reference.verify(bytes)?;
    if canonical::content_ref(bytes, "application/json")? != *reference {
        return Err(refused());
    }
    let value = canonical::parse_json(bytes, maximum)?;
    if bounded_canonical(&value, maximum)? != bytes {
        return Err(refused());
    }
    Ok(value)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("complete restore owner state provenance")
}

#[cfg(test)]
#[path = "owner_journal_tests.rs"]
mod journal_tests;

mod selected;
pub(crate) use selected::{
    authenticate_selected_owner_state_data, selected_owner_counter_scratch_data,
    selected_owner_validation_storage_data,
};
