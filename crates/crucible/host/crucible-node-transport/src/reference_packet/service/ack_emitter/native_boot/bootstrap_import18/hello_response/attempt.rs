//! Retains actual Hello serialization outputs and the initial response envelope.
//!
//! Each completed serializer output enters a physical slot before another
//! fallible step. Maps move into the real Completed response and then into the
//! real Envelope; no original request/body clone supplies a fabricated reply.

use crate::ProviderError;
use crate::bodies::{OperationState, ResponseShape};
use crate::envelope::{Envelope, MessageKind, Method, Nullable};
use crate::handshake::{EXTENSION_NEGOTIATION_V1, ExtensionSelectionV1, HelloResult};
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crucible_node_format::{Extensions, U64};
use serde::Serialize;
use serde_json::{Map, Value};
use std::mem::size_of;

/// Retains every actual initialized output until original bootstrap retirement.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    stage: Stage,
    cut: Option<OperationalDeadline>,
    row: Option<[usize; 3]>,
    result_value: Option<Value>,
    completed: Option<ResponseShape>,
    body_value: Option<Value>,
    selection_value: Option<Value>,
    envelope: Option<Envelope>,
    failure: Option<Failure>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Empty,
    Inspecting,
    Quoted,
    Constructed,
    Complete,
    Failed,
}

#[derive(Clone, Copy)]
enum SerializationPhase {
    Result,
    Completed,
    Selection,
}

struct Failure {
    phase: SerializationPhase,
    category: serde_json::error::Category,
    line: usize,
    column: usize,
}

const _: fn(&Attempt) = |value| {
    let Attempt {
        owner: _,
        stage: _,
        cut: _,
        row: _,
        result_value: _,
        completed: _,
        body_value: _,
        selection_value: _,
        envelope: _,
        failure: _,
    } = value;
};

impl Attempt {
    /// Initializes physical output and failure slots without serialization.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            stage: Stage::Empty,
            cut: None,
            row: None,
            result_value: None,
            completed: None,
            body_value: None,
            selection_value: None,
            envelope: None,
            failure: None,
        }
    }

    /// Spends this occurrence before original guards or admission callbacks.
    ///
    /// # Errors
    /// Refuses foreign creator custody or an already spent attempt.
    pub(super) fn start_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }
        self.stage = Stage::Inspecting;
        self.cut = Some(cut);
        Ok(())
    }

    /// Stores the independent row before any serializer or clone allocation.
    ///
    /// # Errors
    /// Refuses another stage, foreign custody or an occupied quote slot.
    pub(super) fn quote_data(&mut self, row: [usize; 3]) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Inspecting || self.row.is_some() {
            return Err(refused());
        }
        self.row = Some(row);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Constructs actual result/body Values and the initial response envelope.
    ///
    /// The caller holds the original complete request/result loans. Each actual
    /// to_value output is stored before the next cut check or constructor.
    /// Serialization errors leave fixed coordinates after their admitted
    /// temporary diagnostics and internal partials have been released.
    ///
    /// # Errors
    /// Refuses stale/substituted custody, re-entry, unexpected initial input,
    /// serialization, a nonobject output or final envelope validation.
    pub(super) fn construct_data(
        &mut self,
        request: &Envelope,
        result: &HelloResult,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        let outcome = self.construct_current_data(request, result, cut);
        let terminal = self.guard(cut);
        if let Err(error) = outcome.and(terminal) {
            self.stage = Stage::Failed;
            return Err(error);
        }
        Ok(())
    }

    fn construct_current_data(
        &mut self,
        request: &Envelope,
        result: &HelloResult,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Quoted
            || self.row.is_none()
            || self.result_value.is_some()
            || self.completed.is_some()
            || self.body_value.is_some()
            || self.selection_value.is_some()
            || self.envelope.is_some()
            || self.failure.is_some()
            || request.message != MessageKind::Request
            || request.method != Method::Hello
            || request.sequence.get() != 1
            || request.protocol != "CNP/1"
            || request.session_id.0.is_some()
            || request.incarnation_id.0.is_some()
            || request.node_id.0.is_some()
            || request.execution_owner_id.0.is_some()
            || request.capture_owner_id.0.is_some()
            || request.operation_id.0.is_some()
            || request.request_id.0.is_none()
            || result.version != "CNP/1"
            || result.controller_nonce.as_slice().len() != 32
            || result.provider_nonce.as_slice().len() != 32
            || result.resume_token.0.is_some()
            || !result.resumed_operations.is_empty()
        {
            return Err(refused());
        }
        serialize_data(
            &mut self.result_value,
            &mut self.failure,
            result,
            SerializationPhase::Result,
            cut,
        )?;
        self.completed = Some(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: take_object_data(&mut self.result_value)?,
            extensions: Extensions::new(),
        });
        self.guard(cut)?;
        serialize_data(
            &mut self.body_value,
            &mut self.failure,
            self.completed.as_ref().ok_or_else(refused)?,
            SerializationPhase::Completed,
            cut,
        )?;
        serialize_data(
            &mut self.selection_value,
            &mut self.failure,
            &ExtensionSelectionV1 {
                format: U64::new(1),
                selected: Vec::new(),
            },
            SerializationPhase::Selection,
            cut,
        )?;
        self.guard(cut)?;
        // Install the actual header owner before either fallible map move.
        // Empty body/extension roots are included in the prospective census;
        // every cloned header then survives an unexpected nonobject output.
        self.envelope = Some(Envelope {
            protocol: request.protocol.clone(),
            message: MessageKind::Response,
            session_id: Nullable(None),
            incarnation_id: Nullable(Some(result.incarnation_id.clone())),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: request.request_id.clone(),
            operation_id: Nullable(None),
            sequence: request.sequence,
            method: Method::Hello,
            body: Map::new(),
            extensions: Extensions::new(),
        });
        let envelope = self.envelope.as_mut().ok_or_else(refused)?;
        envelope.body = take_object_data(&mut self.body_value)?;
        let selected = self.selection_value.take().ok_or_else(refused)?;
        envelope
            .extensions
            .insert(EXTENSION_NEGOTIATION_V1.into(), selected);
        self.stage = Stage::Constructed;
        self.envelope.as_ref().ok_or_else(refused)?.validate()
    }

    /// Completes only after original terminal admission and guards.
    ///
    /// # Errors
    /// Refuses stale custody or incomplete/refused construction.
    pub(super) fn complete_data(&mut self) -> Result<(), ProviderError> {
        self.guard(self.cut.ok_or_else(refused)?)?;
        if self.stage != Stage::Constructed || self.envelope.is_none() || self.failure.is_some() {
            return Err(refused());
        }
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Closes this occurrence while retaining all initialized output slots.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Lends the same completed response without publication or connection admission.
    ///
    /// # Errors
    /// Refuses stale/substituted custody or incomplete/refused construction.
    pub(super) fn data(&self, cut: OperationalDeadline) -> Result<&Envelope, ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Complete || self.failure.is_some() {
            return Err(refused());
        }
        self.envelope.as_ref().ok_or_else(refused)
    }

    /// Counts the complete actual output population, including surviving partials.
    ///
    /// # Errors
    /// Refuses foreign custody, a foreign response branch or census overflow.
    pub(in super::super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        self.owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.observe(&self.result_value)?;
        observer.observe(&self.body_value)?;
        observer.observe(&self.selection_value)?;
        if let Some(response) = &self.completed {
            match response {
                ResponseShape::Completed {
                    operation_state,
                    result,
                    extensions,
                } if *operation_state == OperationState::Completed => {
                    observer.observe(result)?;
                    observer.observe(extensions)?;
                }
                _ => return Err(refused()),
            }
        }
        if let Some(envelope) = &self.envelope {
            let Envelope {
                protocol,
                message,
                session_id,
                incarnation_id,
                node_id,
                execution_owner_id,
                capture_owner_id,
                request_id,
                operation_id,
                sequence,
                method,
                body,
                extensions,
            } = envelope;
            if *message != MessageKind::Response || *method != Method::Hello {
                return Err(refused());
            }
            observer.observe(protocol)?;
            observer.observe(session_id)?;
            observer.observe(incarnation_id)?;
            observer.observe(node_id)?;
            observer.observe(execution_owner_id)?;
            observer.observe(capture_owner_id)?;
            observer.observe(request_id)?;
            observer.observe(operation_id)?;
            observer.observe(sequence)?;
            observer.observe(body)?;
            observer.observe(extensions)?;
        }
        requested_metadata_backing_storage_data(&observer.finish())
    }

    fn guard(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.cut != Some(cut) || cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    #[cfg(test)]
    pub(in super::super) fn envelope_fixture_data(&self) -> Option<&Envelope> {
        self.envelope.as_ref()
    }

    /// Names physical constructor, serializer output and census controls.
    pub(super) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&Envelope>()
            + size_of::<&HelloResult>()
            + size_of::<OperationalDeadline>()
            + size_of::<Option<OperationalDeadline>>()
            + size_of::<ExtensionSelectionV1>()
            + size_of::<Option<Envelope>>()
            + size_of::<ResponseShape>()
            + size_of::<Nullable<crucible_node_format::Id>>() * 2
            + size_of::<String>()
            + size_of::<Extensions>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Result<(), ProviderError>>() * 4
            + size_of::<Result<usize, ProviderError>>() * 2
            + serialization_counter_scratch_data()
    }
}

fn serialize_data<T: Serialize>(
    slot: &mut Option<Value>,
    failure: &mut Option<Failure>,
    input: &T,
    phase: SerializationPhase,
    cut: OperationalDeadline,
) -> Result<(), ProviderError> {
    if cut.is_expired() || slot.is_some() || failure.is_some() {
        return Err(refused());
    }
    match serde_json::to_value(input) {
        Ok(value) => *slot = Some(value),
        Err(error) => {
            *failure = Some(Failure {
                phase,
                category: error.classify(),
                line: error.line(),
                column: error.column(),
            });
            return Err(refused());
        }
    }
    if cut.is_expired() {
        return Err(refused());
    }
    Ok(())
}

fn take_object_data(slot: &mut Option<Value>) -> Result<Map<String, Value>, ProviderError> {
    match slot.take() {
        Some(Value::Object(map)) => Ok(map),
        other => {
            *slot = other;
            Err(refused())
        }
    }
}

fn serialization_counter_scratch_data() -> usize {
    size_of::<&mut Option<Value>>()
        + size_of::<&mut Option<Failure>>()
        + size_of::<SerializationPhase>()
        + size_of::<Failure>()
        + size_of::<OperationalDeadline>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Value>()
        + size_of::<Option<Value>>()
        + size_of::<Map<String, Value>>()
        + size_of::<Result<Map<String, Value>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 2
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 Hello response construction refused")
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
