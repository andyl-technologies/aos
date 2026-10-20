//! Retains the separate new17 Input/Reactive family before any native effect.
//!
//! Raw custody is installed before shape checks. Typed partials are installed
//! before validation. Reentry and every failure poison the attempt permanently;
//! the owning live native scope alone can close complete ACK publication.

use super::*;
use crate::bodies::{
    BeginRequest, BlobBeginRequest, BlobChunkRequest, BlobFinishRequest, ExactRunArguments,
    InputRequest, ObserveRequest, PollRequest, RetireRequest,
};
use crate::envelope::{Envelope, MessageKind, Method};
use crate::reference_packet::input::PacketInputContext;
use crate::reference_packet::service::restored_input_reactive17::{
    PacketRestoredInputReactive17Artifact, PacketRestoredInputReactive17Context,
    PacketRestoredInputReactive17Request, RESTORED_INPUT_REACTIVE17_FEATURE,
    restored_input_reactive17_assigned_request_digest_data,
    restored_input_reactive17_context_schema_data,
    restored_input_reactive17_contract_counter_scratch_data,
    verify_restored_input_reactive17_proof_data,
};
use crate::retained_metadata::serialization_storage::{
    original_json_value_storage_extent_data, original_serialization_tree_node_requested_bytes_data,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crucible_node_format::{ContentRef, Id, Validate};
use serde_json::{Map, Value};
use std::mem::size_of;

#[derive(Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Receiving,
    Raw,
    Typed,
    Authenticated,
    Dispatched,
    Published,
    Failed,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
enum Body {
    Input(InputRequest),
    Begin(BeginRequest),
    Poll(PollRequest),
    Retire(RetireRequest),
    Observe(ObserveRequest),
    BlobBegin(BlobBeginRequest),
    BlobChunk(BlobChunkRequest),
    BlobFinish(BlobFinishRequest),
}

/// Owns one spent raw/typed original and every completed or failed partial.
#[derive(serde::Serialize)]
pub(crate) struct NativeRestoredInputReactive17Attempt {
    ordinal: u64,
    original: Option<Envelope>,
    body: Option<Body>,
    arguments: Option<ExactRunArguments>,
    artifact: Option<PacketRestoredInputReactive17Artifact>,
    context: Option<PacketRestoredInputReactive17Context>,
    checkpoint: Option<crate::reference_packet::control::NativeInputReactive17CheckpointAttempt>,
    terminal: Option<Envelope>,
    prepared_reply: Option<Map<String, Value>>,
    stage: Stage,
    observation: Option<observation17::NativeObservation17ActionAttempt>,
}

impl NativeRestoredInputReactive17Attempt {
    pub(crate) fn new_data(ordinal: u64) -> Self {
        Self {
            ordinal,
            original: None,
            body: None,
            arguments: None,
            artifact: None,
            context: None,
            checkpoint: None,
            terminal: None,
            prepared_reply: None,
            stage: Stage::Receiving,
            observation: None,
        }
    }

    pub(crate) fn retain_original_data(&mut self, original: Envelope) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Receiving || self.original.is_some() {
            return Err(invalid());
        }
        self.original = Some(original);
        let original = self.original.as_ref().ok_or_else(invalid)?;
        original.validate()?;
        raw_shape(original)?;
        self.stage = Stage::Raw;
        Ok(())
    }

    pub(crate) fn decode_body_data(&mut self, frame: usize) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Raw || self.body.is_some() {
            return Err(invalid());
        }
        let original = self.original.as_ref().ok_or_else(invalid)?;
        macro_rules! decode {
            ($variant:ident, $type:ty) => {
                Body::$variant(
                    serde_json::from_value::<$type>(Value::Object(original.body.clone()))
                        .map_err(crucible_node_format::ContractError::from)?,
                )
            };
        }
        self.body = Some(match original.method {
            Method::Input => decode!(Input, InputRequest),
            Method::Begin => decode!(Begin, BeginRequest),
            Method::Poll => decode!(Poll, PollRequest),
            Method::Retire => decode!(Retire, RetireRequest),
            Method::Observe => decode!(Observe, ObserveRequest),
            Method::BlobBegin => decode!(BlobBegin, BlobBeginRequest),
            Method::BlobChunk => decode!(BlobChunk, BlobChunkRequest),
            Method::BlobFinish => decode!(BlobFinish, BlobFinishRequest),
            _ => return Err(invalid()),
        });
        // Keep the actual whole typed artifact before its closed request,
        // cut, domain and source-proof checks. This remains DATA until the
        // genuine Boot scope supplies its actual private key and row debit.
        self.artifact = Some(
            serde::Deserialize::deserialize(
                original
                    .extensions
                    .get(RESTORED_INPUT_REACTIVE17_FEATURE)
                    .ok_or_else(invalid)?,
            )
            .map_err(crucible_node_format::ContractError::from)?,
        );
        let artifact = self.artifact.as_ref().ok_or_else(invalid)?;
        artifact.validate_data()?;
        artifact.request.authenticate_assigned_data(original)?;
        match self.body.as_ref().ok_or_else(invalid)? {
            Body::Input(value) => {
                value.validate()?;
                if value
                    .events
                    .iter()
                    .any(|event| event.payload.length.get() > 32)
                {
                    return Err(invalid());
                }
            }
            Body::Begin(value) => {
                // Preserve independently decoded argument children before their
                // validator or same-owner control checks can refuse.
                self.arguments = Some(
                    serde_json::from_value(Value::Object(value.arguments.clone()))
                        .map_err(crucible_node_format::ContractError::from)?,
                );
                value.validate()?;
                self.arguments.as_ref().ok_or_else(invalid)?.validate()?;
            }
            Body::Poll(value) => value.validate()?,
            Body::Retire(value) => value.validate()?,
            Body::Observe(value) => value.validate()?,
            Body::BlobBegin(value) => value.validate()?,
            Body::BlobChunk(value) => {
                value.validate()?;
                if value.bytes.as_slice().len() > frame {
                    return Err(invalid());
                }
            }
            Body::BlobFinish(value) => value.validate()?,
        }
        self.stage = Stage::Typed;
        Ok(())
    }

    pub(crate) fn original_data(&self) -> Result<&Envelope, ProviderError> {
        // Custody inspection must keep a failed/raw partial visible. Dispatch
        // authenticates its separate monotone stage and same live native scope.
        self.original.as_ref().ok_or_else(invalid)
    }

    pub(crate) fn method_data(&self) -> Result<Method, ProviderError> {
        if !matches!(
            self.stage,
            Stage::Typed | Stage::Authenticated | Stage::Dispatched | Stage::Published
        ) {
            return Err(invalid());
        }
        Ok(self.original_data()?.method)
    }

    /// Borrows the complete retained signed request as DATA, including failures.
    pub(crate) fn request_data(
        &self,
    ) -> Result<&PacketRestoredInputReactive17Request, ProviderError> {
        Ok(&self.artifact.as_ref().ok_or_else(invalid)?.request)
    }

    /// Retains the actual context before checking the genuine Source MAC.
    ///
    /// This is called only beneath the same Boot/index/Rc receive scope. A
    /// successful DATA check alone cannot spend that scope's native action row.
    pub(crate) fn authenticate_source_proof_data(
        &mut self,
        key: &[u8; 32],
        frame: usize,
    ) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Typed || self.context.is_some() {
            return Err(invalid());
        }
        let original = self.original.as_ref().ok_or_else(invalid)?;
        let artifact = self.artifact.as_ref().ok_or_else(invalid)?;
        self.context = Some(PacketRestoredInputReactive17Context {
            schema: restored_input_reactive17_context_schema_data().into(),
            request: artifact.request.clone(),
            assigned_request: crucible_node_format::Bytes::new(
                restored_input_reactive17_assigned_request_digest_data(original, frame)?.to_vec(),
            ),
        });
        verify_restored_input_reactive17_proof_data(
            key,
            self.context.as_ref().ok_or_else(invalid)?,
            &artifact.proof,
        )?;
        self.stage = Stage::Authenticated;
        Ok(())
    }

    pub(crate) fn begin_dispatch_data(&mut self) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Authenticated || self.body.is_none() || self.context.is_none() {
            return Err(invalid());
        }
        self.stage = Stage::Dispatched;
        Ok(())
    }

    pub(crate) fn authenticate_dispatched_data(&self) -> Result<(), ProviderError> {
        if self.stage != Stage::Dispatched {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn retain_prepared_reply_data(
        &mut self,
        reply: &crate::reference_packet::control::PacketControlReply,
    ) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Dispatched || self.prepared_reply.is_some() {
            return Err(invalid());
        }
        self.prepared_reply = Some(reply.body.clone());
        self.stage = Stage::Dispatched;
        Ok(())
    }

    pub(crate) fn retain_terminal_data(
        &mut self,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Dispatched || self.terminal.is_some() {
            return Err(invalid());
        }
        self.terminal = Some(terminal.clone());
        if self.prepared_reply.as_ref() != Some(&terminal.body) {
            return Err(invalid());
        }
        self.original
            .as_ref()
            .ok_or_else(invalid)?
            .matches_response(self.terminal.as_ref().ok_or_else(invalid)?)?;
        self.stage = Stage::Dispatched;
        Ok(())
    }

    pub(crate) fn complete_publication_data(&mut self) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Dispatched || self.terminal.is_none() || self.observation.is_some() {
            return Err(invalid());
        }
        self.stage = Stage::Published;
        Ok(())
    }

    pub(crate) fn interrupt_data(&mut self) {
        self.stage = Stage::Failed;
    }

    pub(crate) fn published_upload_extent_data(
        &self,
        transfer: &str,
    ) -> Result<Option<usize>, ProviderError> {
        if self.stage != Stage::Published {
            return Ok(None);
        }
        let Some(Body::BlobBegin(begin)) = self.body.as_ref() else {
            return Ok(None);
        };
        if begin.transfer_id.as_str() != transfer {
            return Ok(None);
        }
        Ok(Some(
            usize::try_from(begin.content.length.get()).map_err(|_| invalid())?,
        ))
    }

    pub(crate) fn observe_retained_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            ordinal: _,
            original,
            body,
            arguments,
            artifact,
            context,
            checkpoint,
            terminal,
            prepared_reply,
            stage: _,
            observation,
        } = self;
        observer.observe(original)?;
        observer.observe(terminal)?;
        observer.observe(prepared_reply)?;
        if let Some(body) = body {
            match body {
                Body::Input(value) => observer.observe(value)?,
                Body::Begin(value) => observer.observe(value)?,
                Body::Poll(value) => observer.observe(&value.extensions)?,
                Body::Retire(value) => {
                    observer.observe(&value.request_ids)?;
                    observer.observe(&value.operation_ids)?;
                    observer.observe(&value.custody_receipt)?;
                    observer.observe(&value.extensions)?;
                }
                Body::Observe(value) => {
                    observer.observe(&value.binding_hash)?;
                    observer.observe(&value.extensions)?;
                }
                Body::BlobBegin(value) => {
                    observer.observe(&value.transfer_id)?;
                    observer.observe(&value.content)?;
                    observer.observe(&value.extensions)?;
                }
                Body::BlobChunk(value) => {
                    observer.observe(&value.transfer_id)?;
                    observer.observe(&value.bytes)?;
                    observer.observe(&value.extensions)?;
                }
                Body::BlobFinish(value) => {
                    observer.observe(&value.transfer_id)?;
                    observer.observe(&value.extensions)?;
                }
            }
        }
        observer.observe(artifact)?;
        observer.observe(context)?;
        if let Some(checkpoint) = checkpoint {
            checkpoint.observe_retained_data(observer)?;
        }
        if let Some(value) = arguments {
            let ExactRunArguments {
                grant_id,
                participant_ids,
                realization_id,
                activation_id,
                world_generation: _,
                owner_generation: _,
                input_epoch,
                mode: _,
                ordering_profile,
                start: _,
                limit: _,
                boundary_policy: _,
                input_authorization,
                input_watermark: _,
            } = value;
            observer.observe(grant_id)?;
            observer.observe(participant_ids)?;
            observer.observe(realization_id)?;
            observer.observe(activation_id)?;
            observer.observe(input_epoch)?;
            observer.observe(ordering_profile)?;
            observer.observe(input_authorization)?;
        }
        if let Some(observation) = observation {
            observation.observe_retained_data(observer)?;
        }
        Ok(())
    }
}

fn fields(body: &Map<String, Value>, expected: &[&str]) -> Result<(), ProviderError> {
    if body.len() != expected.len() || expected.iter().any(|name| !body.contains_key(*name)) {
        return Err(invalid());
    }
    Ok(())
}

fn object<'a>(value: &'a Value) -> Result<&'a Map<String, Value>, ProviderError> {
    value.as_object().ok_or_else(invalid)
}

fn text(value: &Value, limit: usize) -> Result<&str, ProviderError> {
    value
        .as_str()
        .filter(|value| value.len() <= limit)
        .ok_or_else(invalid)
}

fn raw_shape(original: &Envelope) -> Result<(), ProviderError> {
    if original.message != MessageKind::Request || original.capture_owner_id.0.is_some() {
        return Err(invalid());
    }
    if original.extensions.len() != 1
        || !original
            .extensions
            .contains_key(RESTORED_INPUT_REACTIVE17_FEATURE)
    {
        return Err(invalid());
    }
    let artifact = object(
        original
            .extensions
            .get(RESTORED_INPUT_REACTIVE17_FEATURE)
            .ok_or_else(invalid)?,
    )?;
    fields(artifact, &["request", "proof"])?;
    let body = &original.body;
    let empty = body
        .get("extensions")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty);
    if !empty {
        return Err(invalid());
    }
    match original.method {
        Method::Input => {
            fields(
                body,
                &[
                    "binding_hash",
                    "owner_generation",
                    "batch_id",
                    "batch_sequence",
                    "input_epoch",
                    "batch_hash",
                    "events",
                    "extensions",
                ],
            )?;
            let events = body
                .get("events")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?;
            if events.len() > 4 || original.operation_id.0.is_some() {
                return Err(invalid());
            }
        }
        Method::Begin => {
            fields(
                body,
                &[
                    "kind",
                    "binding_hash",
                    "owner_generation",
                    "activation_id",
                    "world_generation",
                    "arguments",
                    "extensions",
                ],
            )?;
            if !matches!(
                body.get("kind").and_then(Value::as_str),
                Some("exact_run" | "boundary_settle")
            ) || original.operation_id.0.is_none()
            {
                return Err(invalid());
            }
            let arguments = object(body.get("arguments").ok_or_else(invalid)?)?;
            fields(
                arguments,
                &[
                    "grant_id",
                    "participant_ids",
                    "realization_id",
                    "activation_id",
                    "world_generation",
                    "owner_generation",
                    "input_epoch",
                    "mode",
                    "ordering_profile",
                    "start",
                    "limit",
                    "boundary_policy",
                    "input_authorization",
                    "input_watermark",
                ],
            )?;
            let participants = arguments
                .get("participant_ids")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?;
            if participants.len() != 1 {
                return Err(invalid());
            }
            text(&participants[0], 128)?;
            for name in [
                "grant_id",
                "realization_id",
                "activation_id",
                "input_epoch",
                "ordering_profile",
            ] {
                text(arguments.get(name).ok_or_else(invalid)?, 128)?;
            }
            // The actual admitted connected grant later authenticates the
            // real committed input watermark. This grammar does not invent 0.
        }
        Method::Poll => {
            fields(body, &["after_observation_sequence", "extensions"])?;
            if body
                .get("after_observation_sequence")
                .and_then(Value::as_str)
                != Some("0")
                || original.operation_id.0.is_none()
            {
                return Err(invalid());
            }
        }
        Method::Retire => {
            fields(
                body,
                &[
                    "request_ids",
                    "operation_ids",
                    "disposition",
                    "custody_receipt",
                    "extensions",
                ],
            )?;
            if body.get("disposition").and_then(Value::as_str) != Some("consumed")
                || original.operation_id.0.is_some()
            {
                return Err(invalid());
            }
            for name in ["request_ids", "operation_ids"] {
                let values = body
                    .get(name)
                    .and_then(Value::as_array)
                    .ok_or_else(invalid)?;
                if values.len() != 1 {
                    return Err(invalid());
                }
                text(&values[0], 128)?;
            }
        }
        Method::Observe => {
            fields(
                body,
                &[
                    "binding_hash",
                    "owner_generation",
                    "after_observation_sequence",
                    "maximum_items",
                    "extensions",
                ],
            )?;
            if body
                .get("after_observation_sequence")
                .and_then(Value::as_str)
                != Some("0")
                || body.get("maximum_items").and_then(Value::as_str) != Some("1")
                || original.operation_id.0.is_some()
            {
                return Err(invalid());
            }
        }
        Method::BlobBegin => {
            fields(body, &["transfer_id", "content", "extensions"])?;
            text(body.get("transfer_id").ok_or_else(invalid)?, 128)?;
        }
        Method::BlobChunk => {
            fields(body, &["transfer_id", "offset", "bytes", "extensions"])?;
            text(body.get("transfer_id").ok_or_else(invalid)?, 128)?;
            text(body.get("bytes").ok_or_else(invalid)?, 1_398_102)?;
        }
        Method::BlobFinish => {
            fields(body, &["transfer_id", "extensions"])?;
            text(body.get("transfer_id").ok_or_else(invalid)?, 128)?;
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

/// Prices every malformed raw prefix and closed typed partial before receive.
pub(crate) fn original_restored_input_reactive17_ingress_row_data(
    frame: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let raw = original_json_value_storage_extent_data(frame)?;
    // BeginRequest owns an arguments DOM independently of the retained original.
    // Typed argument scalars/IDs and the sole participant have fixed layouts;
    // BlobChunk owns an independent decoded Bytes buffer bounded by raw frame.
    let typed = sum(&[
        size_of::<Body>(),
        size_of::<ExactRunArguments>(),
        mul(12, 128)?,
        frame,
        mul(2, size_of::<Id>())?,
        size_of::<PacketInputContext>(),
        size_of::<PacketRestoredInputReactive17Artifact>(),
        size_of::<PacketRestoredInputReactive17Context>(),
        // The artifact and independently cloned context own separate string,
        // Bytes, ID and reference backing, bounded by this retained raw frame.
        // No alias discount is taken between those two typed owners.
        mul(2, frame)?,
        mul(4, size_of::<crucible_node_format::Event>())?,
        frame,
        raw.value_dom_requested_bytes,
        original_serialization_tree_node_requested_bytes_data::<String, Value>()?,
        original_serialization_tree_node_requested_bytes_data::<String, Value>()?,
        raw.value_dom_requested_bytes,
    ])?;
    let slots = sum(&[
        mul(2, size_of::<NativeRestoredInputReactive17Attempt>())?,
        size_of::<std::cell::RefCell<NativeRestoredInputReactive17Attempt>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            std::mem::align_of::<std::cell::RefCell<NativeRestoredInputReactive17Attempt>>(),
        )?,
    ])?;
    let retained = sum(&[
        mul(6, raw.value_dom_requested_bytes)?,
        mul(2, frame)?,
        typed,
        slots,
        mul(9, size_of::<Envelope>())?,
        size_of::<crate::connection::ConnectionIncident>(),
        size_of::<Option<crate::connection::ConnectionIncident>>(),
    ])?;
    let transient = sum(&[
        mul(2, raw.canonical_pass_requested_bytes()?)?,
        raw.value_dom_requested_bytes,
        mul(2, typed)?,
        mul(2, frame)?,
    ])?;
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(counter_scratch_data())?,
    })
}

pub(super) fn counter_scratch_data() -> usize {
    restored_input_reactive17_contract_counter_scratch_data()
        // The real native17 constructor spends this ingress before its first
        // completed-ancestry/literal loan. Its fixed work is charged here,
        // independently of the later separately debited model/action phase.
        + crate::reference_packet::service::ack_emitter::native_observation17_scope_counter_scratch_data()
        + size_of::<NativeRestoredInputReactive17Attempt>()
        + size_of::<Option<NativeRestoredInputReactive17Attempt>>()
        + size_of::<Body>()
        + size_of::<Option<Body>>()
        + size_of::<ExactRunArguments>()
        + size_of::<Option<ExactRunArguments>>()
        + size_of::<PacketInputContext>()
        + size_of::<Option<PacketInputContext>>()
        + size_of::<Result<PacketInputContext, serde_json::Error>>()
        + size_of::<InputRequest>()
        + size_of::<Result<InputRequest, serde_json::Error>>()
        + size_of::<Result<ExactRunArguments, serde_json::Error>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<&NativeRestoredInputReactive17Attempt>()
        + size_of::<&mut NativeRestoredInputReactive17Attempt>()
        + size_of::<Option<&Envelope>>()
        + size_of::<Result<&Envelope, ProviderError>>()
        + size_of::<Option<&Body>>()
        + size_of::<Result<&Body, ProviderError>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<OriginalRestoredSuffixBudget>()
        + size_of::<&[&str]>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<
            crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
        >()
        + size_of::<
            Result<
                crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
                ProviderError,
            >,
        >()
        + size_of::<&Map<String, Value>>()
        + size_of::<Option<&Map<String, Value>>>()
        + size_of::<Result<&Map<String, Value>, ProviderError>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<std::rc::Rc<std::cell::RefCell<NativeRestoredInputReactive17Attempt>>>()
        + size_of::<std::cell::Ref<'static, NativeRestoredInputReactive17Attempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredInputReactive17Attempt>>()
        + size_of::<
            Result<std::cell::Ref<'static, NativeRestoredInputReactive17Attempt>, ProviderError>,
        >()
        + size_of::<
            Result<std::cell::RefMut<'static, NativeRestoredInputReactive17Attempt>, ProviderError>,
        >()
        + size_of::<ContentRef>()
        + size_of::<Stage>() * 2
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("closed new17 Input/Reactive original differs")
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms
        .iter()
        .try_fold(0usize, |n, v| n.checked_add(*v).ok_or_else(invalid))
}

fn mul(n: usize, bytes: usize) -> Result<usize, ProviderError> {
    n.checked_mul(bytes).ok_or_else(invalid)
}

fn quantity(bytes: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(bytes).map_err(|_| invalid())?))
}

// crucible-lint: allow panic-shortcut -- actual retained DATA partials and poison are the observations.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::service::restored_input_reactive17::tests::sealed_fixture;

    #[test]
    fn input17_keeps_raw_typed_context_and_failure_when_source_mac_refuses() {
        let original = sealed_fixture(&[31; 32]).unwrap();
        let mut attempt = NativeRestoredInputReactive17Attempt::new_data(1);
        attempt.retain_original_data(original.clone()).unwrap();
        attempt.decode_body_data(65_536).unwrap();
        assert!(matches!(attempt.body, Some(Body::Input(_))));
        assert!(attempt.artifact.is_some());
        assert!(attempt.context.is_none());
        assert!(
            attempt
                .authenticate_source_proof_data(&[32; 32], 65_536)
                .is_err()
        );
        assert!(attempt.context.is_some());
        assert_eq!(attempt.original_data().unwrap(), &original);
        assert!(
            attempt
                .authenticate_source_proof_data(&[31; 32], 65_536)
                .is_err()
        );
        assert!(attempt.begin_dispatch_data().is_err());
        let mut observer = MetadataObserver::new();
        attempt.observe_retained_data(&mut observer).unwrap();
        assert!(observer.finish().string_capacity_bytes > 0);
    }

    #[test]
    fn input17_valid_mac_data_still_cannot_close_or_publish_without_actual_dispatch() {
        let original = sealed_fixture(&[31; 32]).unwrap();
        let mut attempt = NativeRestoredInputReactive17Attempt::new_data(1);
        attempt.retain_original_data(original).unwrap();
        attempt.decode_body_data(65_536).unwrap();
        attempt
            .authenticate_source_proof_data(&[31; 32], 65_536)
            .unwrap();
        // No native Boot, Window, row or once scope is created by this DATA test.
        assert!(attempt.complete_publication_data().is_err());
        assert!(attempt.begin_dispatch_data().is_err());
        assert!(attempt.context.is_some());
    }

    #[test]
    fn input17_invalid_nested_cut_retains_actual_artifact_before_validation() {
        let mut original = sealed_fixture(&[31; 32]).unwrap();
        original
            .extensions
            .get_mut(RESTORED_INPUT_REACTIVE17_FEATURE)
            .unwrap()["request"]["command"]["context"]["cut"]["owner_generation"] =
            Value::String("0".into());
        let mut attempt = NativeRestoredInputReactive17Attempt::new_data(1);
        attempt.retain_original_data(original.clone()).unwrap();
        assert!(attempt.decode_body_data(65_536).is_err());
        assert!(matches!(attempt.body, Some(Body::Input(_))));
        assert!(attempt.artifact.is_some());
        assert_eq!(attempt.original_data().unwrap(), &original);
        assert!(attempt.decode_body_data(65_536).is_err());
    }

    #[test]
    fn input4_and_unsigned_originals_stay_in_spent_raw_slot_and_refuse() {
        let (_, mut original) =
            crate::reference_packet::service::restored_input_reactive17::tests::fixture().unwrap();
        let mut attempt = NativeRestoredInputReactive17Attempt::new_data(1);
        // An unsigned original fails the closed raw shape, after raw custody.
        assert!(attempt.retain_original_data(original.clone()).is_err());
        assert!(attempt.decode_body_data(65_536).is_err());
        assert_eq!(attempt.original_data().unwrap(), &original);
        assert!(attempt.body.is_none());
        assert!(attempt.artifact.is_none());
        assert!(attempt.retain_original_data(original.clone()).is_err());
        assert_eq!(attempt.original_data().unwrap(), &original);

        original.extensions.clear();
        original.extensions.insert(
            crate::reference_packet::input::PACKET_INPUT_FEATURE.into(),
            serde_json::json!({"action":"stage"}),
        );
        let mut old = NativeRestoredInputReactive17Attempt::new_data(2);
        assert!(old.retain_original_data(original.clone()).is_err());
        assert_eq!(old.original_data().unwrap(), &original);
    }
}

#[path = "restored_input_reactive17_ingress/observation17.rs"]
mod observation17;
pub(crate) use observation17::{
    NativeObservation17ActionAttempt, NativePublishedInputReactive17CheckpointData,
    original_native_observation17_retained_counter_scratch_data,
};
