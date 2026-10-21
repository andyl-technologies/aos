//! Retains closed Producer lifecycle ingress before any selected native effect.
//!
//! Raw custody is installed before shape checks. Typed partials are installed
//! before validation. Reentry and every failure poison the attempt permanently;
//! the owning live native scope alone can close complete ACK publication.

use super::*;
use crate::bodies::{
    BeginRequest, BlobBeginRequest, BlobChunkRequest, BlobFinishRequest, ExactRunArguments,
    ObserveRequest, PollRequest, RetireRequest,
};
use crate::envelope::{Envelope, MessageKind, Method};
use crate::retained_metadata::serialization_storage::{
    original_json_value_storage_extent_data, original_serialization_tree_node_requested_bytes_data,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crucible_node_format::{ContentRef, Id, Validate};
use serde_json::{Map, Value};
use std::mem::size_of;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Receiving,
    Raw,
    Typed,
    Dispatched,
    Published,
    Failed,
}

enum Body {
    Begin(BeginRequest),
    Poll(PollRequest),
    Retire(RetireRequest),
    Observe(ObserveRequest),
    BlobBegin(BlobBeginRequest),
    BlobChunk(BlobChunkRequest),
    BlobFinish(BlobFinishRequest),
}

/// Owns one spent raw/typed original and every completed or failed partial.
pub(crate) struct NativeRestoredProducerAttempt {
    ordinal: u64,
    original: Option<Envelope>,
    body: Option<Body>,
    arguments: Option<ExactRunArguments>,
    terminal: Option<Envelope>,
    prepared_reply: Option<Map<String, Value>>,
    stage: Stage,
}

impl NativeRestoredProducerAttempt {
    pub(crate) fn new_data(ordinal: u64) -> Self {
        Self {
            ordinal,
            original: None,
            body: None,
            arguments: None,
            terminal: None,
            prepared_reply: None,
            stage: Stage::Receiving,
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
            Method::Begin => decode!(Begin, BeginRequest),
            Method::Poll => decode!(Poll, PollRequest),
            Method::Retire => decode!(Retire, RetireRequest),
            Method::Observe => decode!(Observe, ObserveRequest),
            Method::BlobBegin => decode!(BlobBegin, BlobBeginRequest),
            Method::BlobChunk => decode!(BlobChunk, BlobChunkRequest),
            Method::BlobFinish => decode!(BlobFinish, BlobFinishRequest),
            _ => return Err(invalid()),
        });
        match self.body.as_ref().ok_or_else(invalid)? {
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
                if value.bytes.as_slice().len()
                    > super::producer_lifecycle::projection::chunk_bytes(frame)?
                {
                    return Err(invalid());
                }
            }
            Body::BlobFinish(value) => value.validate()?,
        }
        self.stage = Stage::Typed;
        Ok(())
    }

    pub(crate) fn original_data(&self) -> Result<&Envelope, ProviderError> {
        if !matches!(
            self.stage,
            Stage::Raw | Stage::Typed | Stage::Dispatched | Stage::Published
        ) {
            return Err(invalid());
        }
        self.original.as_ref().ok_or_else(invalid)
    }

    pub(crate) fn method_data(&self) -> Result<Method, ProviderError> {
        if !matches!(
            self.stage,
            Stage::Typed | Stage::Dispatched | Stage::Published
        ) {
            return Err(invalid());
        }
        Ok(self.original_data()?.method)
    }

    pub(crate) fn begin_dispatch_data(&mut self) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Typed || self.body.is_none() {
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
        if previous != Stage::Dispatched || self.terminal.is_none() {
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
            terminal,
            prepared_reply,
            stage: _,
        } = self;
        observer.observe(original)?;
        observer.observe(terminal)?;
        observer.observe(prepared_reply)?;
        if let Some(body) = body {
            match body {
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
        Ok(())
    }
}

fn fields(body: &Map<String, Value>, expected: &[&str]) -> Result<(), ProviderError> {
    if body.len() != expected.len() || expected.iter().any(|name| !body.contains_key(*name)) {
        return Err(invalid());
    }
    Ok(())
}

fn object(value: &Value) -> Result<&Map<String, Value>, ProviderError> {
    value.as_object().ok_or_else(invalid)
}

fn text(value: &Value, limit: usize) -> Result<&str, ProviderError> {
    value
        .as_str()
        .filter(|value| value.len() <= limit)
        .ok_or_else(invalid)
}

fn raw_shape(original: &Envelope) -> Result<(), ProviderError> {
    if original.message != MessageKind::Request
        || !original.extensions.is_empty()
        || original.capture_owner_id.0.is_some()
    {
        return Err(invalid());
    }
    let body = &original.body;
    let empty = body
        .get("extensions")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty);
    if !empty {
        return Err(invalid());
    }
    match original.method {
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
            if arguments.get("input_watermark").and_then(Value::as_str) != Some("0") {
                return Err(invalid());
            }
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
pub(crate) fn original_restored_producer_ingress_row_data(
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
        original_serialization_tree_node_requested_bytes_data::<String, Value>()?,
        original_serialization_tree_node_requested_bytes_data::<String, Value>()?,
        raw.value_dom_requested_bytes,
    ])?;
    let slots = sum(&[
        mul(2, size_of::<NativeRestoredProducerAttempt>())?,
        size_of::<std::cell::RefCell<NativeRestoredProducerAttempt>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            std::mem::align_of::<std::cell::RefCell<NativeRestoredProducerAttempt>>(),
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
    size_of::<NativeRestoredProducerAttempt>()
        + size_of::<Option<NativeRestoredProducerAttempt>>()
        + size_of::<Body>()
        + size_of::<Option<Body>>()
        + size_of::<ExactRunArguments>()
        + size_of::<Option<ExactRunArguments>>()
        + size_of::<Result<ExactRunArguments, serde_json::Error>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<&NativeRestoredProducerAttempt>()
        + size_of::<&mut NativeRestoredProducerAttempt>()
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
        + size_of::<std::rc::Rc<std::cell::RefCell<NativeRestoredProducerAttempt>>>()
        + size_of::<std::cell::Ref<'static, NativeRestoredProducerAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredProducerAttempt>>()
        + size_of::<Result<std::cell::Ref<'static, NativeRestoredProducerAttempt>, ProviderError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeRestoredProducerAttempt>, ProviderError>>(
        )
        + size_of::<ContentRef>()
        + size_of::<Stage>() * 2
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: Method, body: Value) -> Envelope {
        let mut original = crate::envelope::tests::request();
        original.method = method;
        original.capture_owner_id = crate::envelope::Nullable(None);
        original.operation_id = crate::envelope::Nullable(None);
        original.body = body.as_object().unwrap().clone();
        original.extensions.clear();
        original
    }

    #[test]
    fn rejected_raw_method_keeps_its_original_and_poison_cannot_be_reopened() {
        let original = request(Method::Input, serde_json::json!({"extensions":{}}));
        let mut attempt = NativeRestoredProducerAttempt::new_data(1);
        assert!(attempt.retain_original_data(original.clone()).is_err());
        assert_eq!(attempt.original.as_ref(), Some(&original));
        assert!(attempt.retain_original_data(original).is_err());
        assert!(attempt.body.is_none());
        let mut observer = MetadataObserver::new();
        attempt.observe_retained_data(&mut observer).unwrap();
        assert!(observer.finish().tree_containers > 0);
    }

    #[test]
    fn decoded_invalid_chunk_keeps_typed_partial_and_independent_raw_bank() {
        let original = request(
            Method::BlobChunk,
            serde_json::json!({
                "transfer_id":"real-partial", "offset":"0", "bytes":"", "extensions":{}
            }),
        );
        let mut attempt = NativeRestoredProducerAttempt::new_data(1);
        attempt.retain_original_data(original.clone()).unwrap();
        assert!(attempt.decode_body_data(65_536).is_err());
        assert!(matches!(attempt.body, Some(Body::BlobChunk(_))));
        assert_eq!(attempt.original.as_ref(), Some(&original));
        assert!(attempt.begin_dispatch_data().is_err());
        let mut observer = MetadataObserver::new();
        attempt.observe_retained_data(&mut observer).unwrap();
        assert!(observer.finish().vector_banks > 0);
    }

    #[test]
    fn actual_spent_ledger_keeps_two_lifecycles_and_refuses_at_funded_count() {
        use crate::reference_packet::{PacketEvent, PacketProgram};
        use crucible_node_format::{Bytes, Phase, Position};
        use std::os::unix::net::UnixDatagram;

        fn position(time: u64, phase: Phase) -> Position {
            Position::new(U64::new(time), U64::new(0), phase)
        }
        fn spend(
            ledger: &mut OriginalRestoredSuffixBudget,
            row: PacketNativeStartupAllocationRow,
            ordinal: u64,
        ) {
            assert_eq!(ledger.begin_ingress_data(row).unwrap(), ordinal);
            ledger.begin_action_data(row).unwrap();
        }

        let row = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(2),
            maximum_simultaneous_transient_bytes: U64::new(3),
            declared_counter_scratch_bytes: U64::new(5),
        };
        let admitted = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(16),
            ..row
        };
        let mut ledger =
            OriginalRestoredSuffixBudget::new_data(PacketRestoredSuffixReservationData {
                maximum_originals: U64::new(8),
                ingress: admitted,
                actions: admitted,
            })
            .unwrap();
        let (native, oracle) = UnixDatagram::pair().unwrap();
        oracle.set_nonblocking(true).unwrap();
        let mut program = PacketProgram::new(
            vec![
                PacketEvent {
                    id: Id::new("private").unwrap(),
                    evaluation: position(2, Phase::Reaction),
                    completion: position(3, Phase::Reaction),
                    payload: None,
                },
                PacketEvent {
                    id: Id::new("packet").unwrap(),
                    evaluation: position(5, Phase::Reaction),
                    completion: position(6, Phase::Publication),
                    payload: Some(Bytes::new(vec![7, 11, 13])),
                },
            ],
            native,
        )
        .unwrap();
        program.open_gate().unwrap();
        let operations = [Id::new("first").unwrap(), Id::new("second").unwrap()];
        let limits = [
            position(5, Phase::BoundaryControl),
            position(8, Phase::BoundaryControl),
        ];
        let mut checkpoint = program.inventory();
        let mut completed = Vec::new();

        for (index, (operation, limit)) in operations.iter().zip(limits).enumerate() {
            let first_ordinal = u64::try_from(index).unwrap() * 4 + 1;
            // The real ledger debits precede each corresponding model action.
            // No Source grant, SDK exchange or publication authority is forged.
            spend(&mut ledger, row, first_ordinal);
            let preview = program
                .preview(operation, checkpoint.reached, limit)
                .unwrap();
            let actual = program
                .execute(operation.clone(), checkpoint.reached, limit)
                .unwrap()
                .clone();
            assert_eq!(actual, preview);
            assert!(actual.complete);
            ledger.complete_publication_data().unwrap();

            spend(&mut ledger, row, first_ordinal + 1);
            assert_eq!(program.original(operation), Some(&actual));
            ledger.complete_publication_data().unwrap();

            spend(&mut ledger, row, first_ordinal + 2);
            let outputs = actual
                .newborn
                .iter()
                .map(|output| output.event.clone())
                .collect::<Vec<_>>();
            program.retire(operation, &outputs).unwrap();
            ledger.complete_publication_data().unwrap();

            spend(&mut ledger, row, first_ordinal + 3);
            checkpoint = program.inventory();
            assert_eq!(checkpoint.reached, limit);
            assert!(checkpoint.retained_outputs.is_empty());
            assert_eq!(checkpoint.private_mutations.get(), 1);
            assert_eq!(
                checkpoint.packet_effects.get(),
                u64::try_from(index).unwrap()
            );
            ledger.complete_publication_data().unwrap();
            completed.push(actual);
        }

        let mut trace = [0u8; 16];
        assert_eq!(oracle.recv(&mut trace).unwrap(), 1);
        assert_eq!(&trace[..1], &[0]);
        assert_eq!(oracle.recv(&mut trace).unwrap(), 4);
        assert_eq!(&trace[..4], &[1, 7, 11, 13]);
        assert!(checkpoint.pending.is_empty());
        assert!(ledger.begin_ingress_data(row).is_err());
        assert!(ledger.begin_ingress_data(row).is_err());
        // Refusal occurs before a third execute; both actual originals and the
        // final retired checkpoint remain, with no additional native callback.
        assert_eq!(program.inventory(), checkpoint);
        for (operation, grant) in operations.iter().zip(&completed) {
            assert_eq!(program.original(operation), Some(grant));
        }
        assert!(
            program
                .original(&Id::new("unfunded-third").unwrap())
                .is_none()
        );
        assert_eq!(
            oracle.recv(&mut trace).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[path = "producer_ingress/settled.rs"]
mod settled;
