//! Authenticated adapters over the established public watch reducer.
//!
//! This module adds public/audit projection selection and read-model response
//! authentication. Bootstrap chunking, watermark `W`, monotone resume,
//! deduplication, capacity stops, and resynchronization remain owned by
//! [`crate::client_state::watch`].

use aos_proto::aos::sandbox::v1::{EventKind, WatchCursor, WatchRequest};

use crate::client_state::{
    MAXIMUM_RETAINED_WATCH_BYTES, MAXIMUM_RETAINED_WATCH_EVENTS, MAXIMUM_WATCH_BOOTSTRAP_BYTES,
    MAXIMUM_WATCH_BOOTSTRAP_ITEMS, ServerResyncReasonV1, StreamSequenceContractV1,
    WatchApplyOutcomeV1, WatchError, WatchInputV1, WatchReducerV1, WatchResumePointV1,
    WatchSnapshotChunkV1, WatchTerminationV1,
};

use super::audit_event::CheckedAuditWatchEventV1;
use super::event::CheckedWatchEventV1;
use super::model::{QueryBindingV1, WatchRequestCommitmentV1};
use super::portable::CheckedFeatureSetV1;
use super::watch_resource::CheckedWatchSnapshotResourceV1;

/// Maximum authenticated semantic inputs accepted from one read-model call.
pub const MAXIMUM_AUTHENTICATED_WATCH_INPUTS: usize = 4_096;
const MAXIMUM_WATCH_RESOURCE_TYPES: usize = 128;
const MAXIMUM_WATCH_RESOURCE_TYPE_BYTES: usize = 128;

/// Selects the separately authorized watch projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchSurfaceV1 {
    /// Accepts public resource events and snapshot chunks.
    Public,
    /// Accepts strict audit events and the snapshot-complete control event.
    Audit,
}

/// Reports malformed or substituted watch adapter state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObservationWatchError {
    /// The normalized request or its typed resume point is invalid.
    #[error("authenticated watch request is invalid")]
    InvalidRequest,
    /// A read-model batch exceeds the compiled semantic-input bound.
    #[error("authenticated watch response exceeds its bounded input count")]
    InvalidBatch,
    /// The established reducer rejected construction or input.
    #[error("public watch reducer rejected the request or response")]
    Reducer(WatchError),
}

impl From<WatchError> for ObservationWatchError {
    fn from(error: WatchError) -> Self {
        Self::Reducer(error)
    }
}

/// Stores one normalized watch request with authenticated continuation state.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedWatchRequestV1 {
    wire: WatchRequest,
    binding: QueryBindingV1,
    commitment: WatchRequestCommitmentV1,
    surface: WatchSurfaceV1,
    resume: Option<WatchResumePointV1>,
}

impl CheckedWatchRequestV1 {
    /// Checks request bounds and exact agreement with a typed resume point.
    ///
    /// The caller supplies a commitment to normalized request semantics with
    /// continuation bytes excluded and authenticated separately. Raw cursor
    /// bytes are compared to a typed resume point; they are never relabeled.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationWatchError::InvalidRequest`] for malformed filters,
    /// an unbound raw cursor, or any cursor/binding substitution.
    pub fn new(
        wire: WatchRequest,
        binding: QueryBindingV1,
        commitment: WatchRequestCommitmentV1,
        resume: Option<WatchResumePointV1>,
    ) -> Result<Self, ObservationWatchError> {
        validate_request_shape(&wire)?;
        let raw_resume = wire
            .resume_after
            .as_option()
            .map(|cursor| cursor.opaque_cursor.as_slice());
        let typed_resume = resume.as_ref().map(|point| point.cursor().as_bytes());
        if raw_resume != typed_resume
            || resume
                .as_ref()
                .is_some_and(|point| point.binding() != binding)
        {
            return Err(ObservationWatchError::InvalidRequest);
        }
        let surface = if wire.audit_only {
            WatchSurfaceV1::Audit
        } else {
            WatchSurfaceV1::Public
        };

        Ok(Self {
            wire,
            binding,
            commitment,
            surface,
            resume,
        })
    }

    /// Returns the normalized protobuf request.
    #[must_use]
    pub const fn as_proto(&self) -> &WatchRequest {
        &self.wire
    }

    /// Returns the complete authenticated query binding.
    #[must_use]
    pub const fn binding(&self) -> QueryBindingV1 {
        self.binding
    }

    /// Returns the exact normalized-request commitment.
    #[must_use]
    pub const fn commitment(&self) -> WatchRequestCommitmentV1 {
        self.commitment
    }

    /// Returns the selected authorized projection.
    #[must_use]
    pub const fn surface(&self) -> WatchSurfaceV1 {
        self.surface
    }
}

/// Carries the exact request presented to an authenticated read model.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedWatchReadRequestV1 {
    wire: WatchRequest,
    binding: QueryBindingV1,
    commitment: WatchRequestCommitmentV1,
    resume: Option<WatchResumePointV1>,
}

impl AuthenticatedWatchReadRequestV1 {
    /// Returns the protobuf request projected from typed continuation state.
    #[must_use]
    pub const fn as_proto(&self) -> &WatchRequest {
        &self.wire
    }

    /// Returns the authenticated query/principal/visibility/policy/schema binding.
    #[must_use]
    pub const fn binding(&self) -> QueryBindingV1 {
        self.binding
    }

    /// Returns the exact normalized-request commitment.
    #[must_use]
    pub const fn commitment(&self) -> WatchRequestCommitmentV1 {
        self.commitment
    }

    /// Returns the typed last fully applied cursor and sequence.
    #[must_use]
    pub const fn resume(&self) -> Option<&WatchResumePointV1> {
        self.resume.as_ref()
    }
}

/// Carries one already checked input from an authenticated read model.
#[derive(Clone, Debug, PartialEq)]
pub enum CheckedObservationWatchInputV1 {
    /// Supplies one bounded, indexed public snapshot chunk.
    SnapshotChunk(WatchSnapshotChunkV1<CheckedWatchSnapshotResourceV1>),
    /// Supplies one checked public event or snapshot-complete marker.
    PublicEvent(CheckedWatchEventV1),
    /// Supplies one strict separately authorized audit event.
    AuditEvent(CheckedAuditWatchEventV1),
    /// Reports a closed server resynchronization reason.
    ResyncRequired(ServerResyncReasonV1),
    /// Reports non-disclosing authorization narrowing.
    AuthorizationChanged,
}

/// Returns one authenticated bounded batch for an exact continuation request.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedWatchReadBatchV1 {
    binding: QueryBindingV1,
    commitment: WatchRequestCommitmentV1,
    requested_resume: Option<WatchResumePointV1>,
    inputs: Vec<CheckedObservationWatchInputV1>,
}

impl AuthenticatedWatchReadBatchV1 {
    /// Constructs a response carrying authenticated request correlation.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationWatchError::InvalidBatch`] when the semantic input
    /// count exceeds its compiled bound.
    pub fn new(
        binding: QueryBindingV1,
        commitment: WatchRequestCommitmentV1,
        requested_resume: Option<WatchResumePointV1>,
        inputs: Vec<CheckedObservationWatchInputV1>,
    ) -> Result<Self, ObservationWatchError> {
        if inputs.len() > MAXIMUM_AUTHENTICATED_WATCH_INPUTS {
            return Err(ObservationWatchError::InvalidBatch);
        }
        Ok(Self {
            binding,
            commitment,
            requested_resume,
            inputs,
        })
    }
}

/// Reports one result produced by the established watch reducer adapter.
#[derive(Clone, Debug, PartialEq)]
pub enum ObservationWatchAdvanceV1 {
    /// Carries an ordinary reducer outcome, including bootstrap completion.
    Public(WatchApplyOutcomeV1<CheckedWatchSnapshotResourceV1>),
    /// Carries a fresh audit event after the reducer accepted its base event.
    AuditEventApplied(CheckedAuditWatchEventV1),
}

/// Retains the established reducer across bootstrap chunks and live pages.
#[derive(Clone, Debug, PartialEq)]
pub struct ObservationWatchContinuationV1 {
    request: CheckedWatchRequestV1,
    reducer: WatchReducerV1<CheckedWatchSnapshotResourceV1>,
}

impl ObservationWatchContinuationV1 {
    /// Starts an established bounded bootstrap or typed-cursor resume reducer.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationWatchError`] when reducer bounds or resume state are
    /// invalid.
    pub fn new(request: CheckedWatchRequestV1) -> Result<Self, ObservationWatchError> {
        let reducer = match request.resume.clone() {
            Some(resume) => WatchReducerV1::resume(
                request.binding,
                StreamSequenceContractV1::Monotone,
                resume,
                MAXIMUM_RETAINED_WATCH_EVENTS,
                MAXIMUM_RETAINED_WATCH_BYTES,
            )?,
            None => WatchReducerV1::bootstrap(
                request.binding,
                StreamSequenceContractV1::Monotone,
                MAXIMUM_WATCH_BOOTSTRAP_ITEMS,
                MAXIMUM_WATCH_BOOTSTRAP_BYTES,
                MAXIMUM_RETAINED_WATCH_EVENTS,
                MAXIMUM_RETAINED_WATCH_BYTES,
            )?,
        };
        Ok(Self { request, reducer })
    }

    /// Projects the next read request from the reducer's typed continuation.
    #[must_use]
    pub fn read_request(&self) -> AuthenticatedWatchReadRequestV1 {
        let resume = self.reducer.resume_point().cloned();
        let mut wire = self.request.wire.clone();
        wire.resume_after = resume
            .as_ref()
            .map(|point| WatchCursor {
                opaque_cursor: point.cursor().as_bytes().to_vec(),
                ..Default::default()
            })
            .into();
        AuthenticatedWatchReadRequestV1 {
            wire,
            binding: self.request.binding,
            commitment: self.request.commitment,
            resume,
        }
    }

    /// Returns the underlying reducer's current typed resume point.
    #[must_use]
    pub const fn resume_point(&self) -> Option<&WatchResumePointV1> {
        self.reducer.resume_point()
    }

    /// Returns the underlying terminal state, if any.
    #[must_use]
    pub const fn termination(&self) -> Option<&WatchTerminationV1> {
        self.reducer.termination()
    }

    /// Applies one authenticated batch through the established reducer.
    ///
    /// A mismatched binding, commitment, or typed request cursor is converted
    /// to the reducer's closed relist-required state.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationWatchError`] only when the established reducer is
    /// already terminal or rejects a pre-reduction input.
    pub fn apply_authenticated_batch(
        &mut self,
        batch: AuthenticatedWatchReadBatchV1,
    ) -> Result<Vec<ObservationWatchAdvanceV1>, ObservationWatchError> {
        let expected_resume = self.reducer.resume_point();
        if batch.binding != self.request.binding
            || batch.commitment != self.request.commitment
            || batch.requested_resume.as_ref() != expected_resume
        {
            let outcome = self.reducer.apply(WatchInputV1::ResyncRequired(
                ServerResyncReasonV1::BindingChanged,
            ))?;
            return Ok(vec![ObservationWatchAdvanceV1::Public(outcome)]);
        }

        let mut advances = Vec::with_capacity(batch.inputs.len());
        for input in batch.inputs {
            let advance = self.apply_input(input)?;
            let terminal = matches!(
                &advance,
                ObservationWatchAdvanceV1::Public(WatchApplyOutcomeV1::Terminated(_))
            );
            advances.push(advance);
            if terminal {
                break;
            }
        }
        Ok(advances)
    }

    fn apply_input(
        &mut self,
        input: CheckedObservationWatchInputV1,
    ) -> Result<ObservationWatchAdvanceV1, ObservationWatchError> {
        match input {
            CheckedObservationWatchInputV1::SnapshotChunk(chunk)
                if self.request.surface == WatchSurfaceV1::Public =>
            {
                self.reducer
                    .apply(WatchInputV1::SnapshotChunk(chunk))
                    .map(ObservationWatchAdvanceV1::Public)
                    .map_err(Into::into)
            }
            CheckedObservationWatchInputV1::PublicEvent(event)
                if self.request.surface == WatchSurfaceV1::Public
                    && event.kind() != EventKind::EVENT_KIND_AUDIT =>
            {
                self.reducer
                    .apply(WatchInputV1::Event(event))
                    .map(ObservationWatchAdvanceV1::Public)
                    .map_err(Into::into)
            }
            CheckedObservationWatchInputV1::PublicEvent(event)
                if self.request.surface == WatchSurfaceV1::Audit
                    && event.kind() == EventKind::EVENT_KIND_SNAPSHOT_COMPLETE =>
            {
                self.reducer
                    .apply(WatchInputV1::Event(event))
                    .map(ObservationWatchAdvanceV1::Public)
                    .map_err(Into::into)
            }
            CheckedObservationWatchInputV1::AuditEvent(event)
                if self.request.surface == WatchSurfaceV1::Audit =>
            {
                let outcome = self
                    .reducer
                    .apply(WatchInputV1::Event(event.event().clone()))?;
                match outcome {
                    WatchApplyOutcomeV1::EventApplied(_) => {
                        Ok(ObservationWatchAdvanceV1::AuditEventApplied(event))
                    }
                    other => Ok(ObservationWatchAdvanceV1::Public(other)),
                }
            }
            CheckedObservationWatchInputV1::ResyncRequired(reason) => self
                .reducer
                .apply(WatchInputV1::ResyncRequired(reason))
                .map(ObservationWatchAdvanceV1::Public)
                .map_err(Into::into),
            CheckedObservationWatchInputV1::AuthorizationChanged => self
                .reducer
                .apply(WatchInputV1::AuthorizationChanged)
                .map(ObservationWatchAdvanceV1::Public)
                .map_err(Into::into),
            CheckedObservationWatchInputV1::SnapshotChunk(_)
            | CheckedObservationWatchInputV1::PublicEvent(_)
            | CheckedObservationWatchInputV1::AuditEvent(_) => self
                .reducer
                .apply(WatchInputV1::ResyncRequired(
                    ServerResyncReasonV1::BindingChanged,
                ))
                .map(ObservationWatchAdvanceV1::Public)
                .map_err(Into::into),
        }
    }
}

fn validate_request_shape(wire: &WatchRequest) -> Result<(), ObservationWatchError> {
    if exact_nonzero_id(&wire.project_id).is_none()
        || (!wire.resource_id.is_empty() && exact_nonzero_id(&wire.resource_id).is_none())
        || wire.resource_types.len() > MAXIMUM_WATCH_RESOURCE_TYPES
        || !wire.resource_types.windows(2).all(|pair| pair[0] < pair[1])
        || wire.resource_types.iter().any(|resource_type| {
            resource_type.is_empty()
                || resource_type.len() > MAXIMUM_WATCH_RESOURCE_TYPE_BYTES
                || resource_type.chars().any(char::is_control)
        })
        || (wire.audit_only && (!wire.resource_types.is_empty() || !wire.resource_id.is_empty()))
        || CheckedFeatureSetV1::try_from(wire.observation_features.clone()).is_err()
    {
        Err(ObservationWatchError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn exact_nonzero_id(value: &[u8]) -> Option<[u8; 16]> {
    let identifier: [u8; 16] = value.try_into().ok()?;
    (identifier != [0; 16]).then_some(identifier)
}
