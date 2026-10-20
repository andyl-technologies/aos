//! Joins actual before/after Capture17 graphs to the same completed SDK attempt.
//!
//! The before graph owns Capture signing/registration data. The after graph's
//! current action is the fourth-object Poll; the completed Capture is an earlier
//! retained occurrence. No future native Poll terminal is required at that cut.

pub(super) mod construction;

use super::*;
use crate::{
    bodies::{BeginRequest, CaptureArguments},
    envelope::{Envelope, MessageKind, Method, RequestOrigin},
    protocol_snapshot::{
        native_wholegraph17::NativeCurrentGraph17Data,
        owned11::typed::{Fields, plain_string, unsigned},
    },
    reference_packet::{
        continuation_models::PacketModelCaptureBoundaryData,
        service::{
            native_snapshot::PacketNativeRestoredSettled17SnapshotPlan,
            restored_settled_capture::*, restored_settled_confirmation::*,
        },
    },
};
use crucible_node_format::{HashRef, Position, U64, Validate};
use serde::Serialize;
use std::io::Write;

/// Borrows exact fields from an actual independently checked live or cold SDK.
///
/// Only sibling orchestration constructs this adapter, directly from its real
/// SDK lender. It is DATA, has no public constructor and grants no native right.
pub(super) struct OutputPairSdk17Data<'a> {
    pub(super) capture_original: &'a Envelope,
    pub(super) capture_terminal: &'a Envelope,
    pub(super) confirmation_original: &'a Envelope,
    pub(super) request: &'a PacketRestoredSettledCaptureRequest,
    pub(super) confirmation_request: &'a PacketRestoredSettledAfterConfirmationRequest,
    pub(super) receipt: &'a PacketRestoredSettledAfterConfirmationReceipt,
}

/// Checks the concrete native Capture/confirmation conjunction without effects.
///
/// Canonical model/proof scratch is separately Source-funded and sequential.
/// Both complete graph owners and original SDK custody exist before this call.
/// The enclosing reader separately authenticates signed archive ancestry and the
/// actual Source restoration association; this comparison cannot replace them.
///
/// # Errors
/// Refuses another SDK occurrence, Source MAC/context/scope, registration,
/// modeled state, anchor, earlier native Capture publication or current Poll.
pub(super) fn authenticate_output_pair17_data(
    before: &NativeCurrentGraph17Data,
    after: &NativeCurrentGraph17Data,
    sdk: OutputPairSdk17Data<'_>,
    snapshot: &PacketNativeRestoredSettled17SnapshotPlan<'_>,
    anchor_raw: &[u8],
    maximum_model_bytes: usize,
    maximum_frame_bytes: usize,
) -> Result<(), ProviderError> {
    before.validate_data()?;
    after.validate_data()?;
    sdk.request.validate_data()?;
    sdk.confirmation_request.validate_data()?;
    sdk.receipt.validate_data()?;
    sdk.capture_original
        .matches_response(sdk.capture_terminal)?;
    if sdk.receipt.capture != *sdk.confirmation_request
        || before.creator_data() != after.creator_data()
        || before.historical_private_key17_data()? != after.historical_private_key17_data()?
        || before.current_action_original17_data()? != sdk.capture_original
        || after.current_action_original17_data()? != sdk.confirmation_original
        || after.current_capture_confirmation17_data()? != sdk.confirmation_request
        || sdk.capture_original.message != MessageKind::Request
        || sdk.capture_original.method != Method::Begin
        || sdk.confirmation_original.message != MessageKind::Request
        || sdk.confirmation_original.method != Method::Poll
        || sdk.confirmation_original.sequence <= sdk.capture_terminal.sequence
        || sdk.confirmation_original.operation_id != sdk.capture_original.operation_id
        || sdk.confirmation_original.session_id != sdk.capture_original.session_id
        || sdk.confirmation_original.incarnation_id != sdk.capture_original.incarnation_id
        || sdk.confirmation_original.node_id != sdk.capture_original.node_id
        || sdk.confirmation_original.capture_owner_id != sdk.capture_original.capture_owner_id
        || sdk.confirmation_original.execution_owner_id.0.is_some()
    {
        return Err(invalid());
    }

    let before_occurrence = before
        .current_lineage17_data()
        .current_action
        .ok_or_else(invalid)?;
    let after_occurrence = after
        .current_lineage17_data()
        .current_action
        .ok_or_else(invalid)?;
    if !before_occurrence.3
        || before_occurrence.4
        || !after_occurrence.3
        || after_occurrence.4
        || before_occurrence.0 >= after_occurrence.0
        || before_occurrence.2 >= after_occurrence.2
    {
        return Err(invalid());
    }

    let artifact = before.current_capture_artifact17_data()?;
    let context = before.current_capture_context17_data()?;
    artifact.validate_data()?;
    context.validate_data()?;
    let before_stages = before.restoration_stages17_data()?;
    let after_stages = after.restoration_stages17_data()?;
    let before_scope = &before_stages
        .world
        .artifact
        .as_ref()
        .ok_or_else(invalid)?
        .request
        .scope;
    let after_scope = &after_stages
        .world
        .artifact
        .as_ref()
        .ok_or_else(invalid)?
        .request
        .scope;
    if artifact.request != *sdk.request
        || context.request != artifact.request
        || &artifact.request.scope != before_scope
        || before_scope != after_scope
        || artifact.request.scope.target.native_pid != U64::new(u64::from(before.creator_data()))
    {
        return Err(invalid());
    }

    let extension =
        serde_json::to_value(artifact).map_err(crucible_node_format::ContractError::from)?;
    if sdk.capture_original.extensions.len() != 1
        || sdk
            .capture_original
            .extensions
            .get(RESTORED_SETTLED_CAPTURE_FEATURE)
            != Some(&extension)
    {
        return Err(invalid());
    }
    drop(extension);

    let assigned = restored_settled_capture_assigned_request_digest_data(
        sdk.capture_original,
        maximum_frame_bytes,
    )?;
    if context.assigned_request.as_slice() != assigned.as_slice() {
        return Err(invalid());
    }
    verify_restored_settled_capture_proof_data(
        before.historical_private_key17_data()?,
        context,
        &artifact.proof,
    )?;

    let (registered, arguments, begin) = before.current_capture_registration17_data()?;
    let registration_identity = before
        .current_lineage17_data()
        .current_capture_registration_identity_group17_data()?;
    if registered != sdk.capture_original || arguments != &sdk.request.capture {
        return Err(invalid());
    }
    before
        .current_control_data()
        .authenticate_capture_settlement17_data(
            after.current_control_data(),
            registered,
            arguments,
            begin,
            sdk.capture_terminal,
            registration_identity,
        )?;

    let before_roots = before.raw_root_spans_data()?;
    let after_roots = after.raw_root_spans_data()?;
    if field(before_roots.control_data(), "program")?
        != field(after_roots.control_data(), "program")?
    {
        return Err(invalid());
    }

    let model = before.current_model17_data()?;
    let boundary = model.capture_boundary17_data(maximum_model_bytes)?;
    if boundary.gate_closed
        || boundary.retained_outputs != 0
        || boundary.local_cursor != model.current_position_data()
        || boundary.local_cursor > arguments.cut
        || boundary
            .earliest_pending_completion
            .is_some_and(|completion| completion < arguments.cut)
    {
        return Err(invalid());
    }

    let confirmation = sdk.confirmation_request;
    if sdk.capture_original.request_id.0.as_ref() != Some(&confirmation.capture_request_id)
        || sdk.capture_original.operation_id.0.as_ref() != Some(&confirmation.capture_operation_id)
        || sdk.capture_terminal.sequence != confirmation.capture_terminal_sequence
        || sdk
            .capture_original
            .request_hash(RequestOrigin::Controller)?
            != confirmation.capture_request_hash
    {
        return Err(invalid());
    }
    hash_matches(
        &confirmation.capture_terminal_hash,
        PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
        sdk.capture_terminal,
        maximum_frame_bytes,
    )?;
    snapshot
        .before()
        .authenticate_original_bytes(before.raw_current_graph17_data()?)?;
    crate::protocol_snapshot::owned11::correspondence::envelope(
        sdk.capture_original,
        snapshot.capture_request_bytes(),
    )?;
    verify_role_body_data(
        &confirmation.settled_capture_request,
        snapshot.capture_request_bytes(),
    )?;
    anchor::capture(arguments, snapshot.capture_arguments_bytes())?;
    restored_settled_native17_reference_matches_data(
        &confirmation.native_control_ref,
        snapshot.control_reference_bytes(),
    )?;
    if snapshot.control_bytes() != before_roots.control_data() {
        return Err(invalid());
    }
    verify_role_body_data(&confirmation.native_control_ref, snapshot.control_bytes())?;
    verify_role_body_data(&confirmation.native_anchor_ref, anchor_raw)?;
    verify_role_body_data(
        &sdk.receipt.native_after_ref,
        after.raw_current_graph17_data()?,
    )?;
    anchor::authenticate(
        anchor_raw,
        before,
        sdk.capture_original,
        arguments,
        begin,
        &boundary,
        &confirmation.native_control_ref,
    )?;
    earlier::authenticate(
        after,
        before_occurrence.0,
        artifact,
        context,
        registered,
        arguments,
        begin,
        sdk.capture_terminal,
        confirmation,
        snapshot,
        anchor_raw,
        before.raw_current_graph17_data()?,
    )?;
    crate::reference_packet::endpoint::authenticate_native17_retained_terminal_data(
        after,
        sdk.capture_original,
        sdk.capture_terminal,
    )?;
    authenticate_current_confirmation(
        after_roots.boot_data(),
        after_occurrence.0,
        sdk.confirmation_original,
        confirmation,
    )
}

fn authenticate_current_confirmation(
    boot: &[u8],
    index: usize,
    original: &Envelope,
    request: &PacketRestoredSettledAfterConfirmationRequest,
) -> Result<(), ProviderError> {
    let action = action(boot, index)?;
    let selected = field(action, "selected")?;
    if plain_string(field(selected, "family")?)? != "capture" {
        return Err(invalid());
    }
    let data = field(selected, "data")?;
    if plain_string(field(field(data, "body")?, "kind")?)? != "confirmation"
        || field(data, "capture")? != b"null"
        || field(data, "capture_context")? != b"null"
        || field(data, "registration")? != b"null"
        || field(data, "terminal")? != b"null"
        || field(data, "prepared_reply")? != b"null"
        || field(data, "confirmation_receipt")? != b"null"
        || plain_string(field(data, "stage")?)? != "typed"
    {
        return Err(invalid());
    }
    emitted(field(data, "original")?, original)?;
    emitted(field(data, "confirmation")?, request)?;
    let body = field(field(data, "body")?, "data")?;
    let mut body_fields = Fields::object(body)?;
    if unsigned(plain_string(body_fields.named("after_observation_sequence")?)?.as_bytes())? != 0 {
        return Err(invalid());
    }
    let extensions = body_fields.named("extensions")?;
    body_fields.finish()?;
    Fields::object(extensions)?.finish()?;
    // The actual SDK puts the confirmation in the Envelope extension. The
    // baseline Poll body keeps its independently empty method extensions.
    if original.body.len() != 2
        || original
            .body
            .get("after_observation_sequence")
            .and_then(serde_json::Value::as_str)
            != Some("0")
        || original
            .body
            .get("extensions")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|extensions| !extensions.is_empty())
    {
        return Err(invalid());
    }
    let request_value =
        serde_json::to_value(request).map_err(crucible_node_format::ContractError::from)?;
    if original.extensions.len() != 1
        || original
            .extensions
            .get(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE)
            != Some(&request_value)
    {
        return Err(invalid());
    }

    Ok(())
}

fn field<'a>(input: &'a [u8], name: &str) -> Result<&'a [u8], ProviderError> {
    let mut f = Fields::object(input)?;
    while let Some((key, value)) = f.pair()? {
        if plain_string(key)? == name {
            return Ok(value);
        }
    }
    Err(invalid())
}

fn action(boot: &[u8], index: usize) -> Result<&[u8], ProviderError> {
    let mut f = Fields::array(field(field(boot, "settled_reserve")?, "attempts")?)?;
    for ordinal in 0..=index {
        let value = f.next()?.ok_or_else(invalid)?;
        if ordinal == index {
            return Ok(value);
        }
    }
    Err(invalid())
}

fn hash_matches(
    reference: &HashRef,
    domain: &str,
    value: &impl Serialize,
    maximum: usize,
) -> Result<(), ProviderError> {
    reference.validate()?;
    crate::connection::serialized_credit(value, maximum)?;
    let value = serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?;
    let bytes = crucible_node_format::canonical::canonical_json(&value)?;
    if bytes.len() > maximum || crucible_node_format::canonical::hash(domain, &bytes)? != *reference
    {
        return Err(invalid());
    }
    Ok(())
}

fn emitted(raw: &[u8], value: &impl Serialize) -> Result<(), ProviderError> {
    let mut sink = Exact { remaining: raw };
    serde_json::to_writer(&mut sink, value).map_err(|_| invalid())?;
    if !sink.remaining.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

struct Exact<'a> {
    remaining: &'a [u8],
}

impl Write for Exact<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if !self.remaining.starts_with(bytes) {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        self.remaining = &self.remaining[bytes.len()..];
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Counts defining fixed borrowed/parser/hash layouts; dynamic Source scratch is separate.
pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<OutputPairSdk17Data<'static>>()
        + size_of::<PacketModelCaptureBoundaryData>()
        + size_of::<Result<PacketModelCaptureBoundaryData, ProviderError>>()
        + size_of::<Exact<'static>>()
        + size_of::<serde_json::Serializer<&mut Exact<'static>>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 1024]>()
        + size_of::<Fields<'static>>() * 12
        + size_of::<serde_json::Value>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<(), ProviderError>>()
        + crate::protocol_snapshot::owned11::correspondence::envelope_comparison_scratch_data()
        + construction::counter_scratch_data()
}

mod anchor;
mod earlier;
