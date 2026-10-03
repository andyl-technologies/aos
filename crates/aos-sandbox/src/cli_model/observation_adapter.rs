//! Pure CLI client adapters for portable observation requests and responses.
//!
//! The adapters construct established protobuf messages and validate complete
//! responses. They do not parse command lines, create clients, or perform I/O.

use aos_proto::aos::sandbox::v1::{
    Event, GetAttachmentRequest, GetAttachmentResponse, GetExecutionRequest, GetExecutionResponse,
    GetOperationRequest, GetOperationResponse, GetSandboxRequest, GetSandboxResponse,
    GetSnapshotRequest, GetSnapshotResponse, GetViewRequest, GetViewResponse,
    OperatorRecoveryRequest, WatchCursor, WatchRequest,
};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::provenance::RequestProvenanceV1;
use crate::client_state::WatchResumePointV1;
use crate::controller_query::{
    BoundWatchCursorV1, CheckedAttachmentResourceV1, CheckedAuditWatchEventV1,
    CheckedExecutionResourceV1, CheckedFilesystemViewResourceV1, CheckedOperationObservationV1,
    CheckedSandboxObservationV1, CheckedSnapshotResourceV1, CheckedWatchRequestV1,
    InvalidAuditWatchEvent, InvalidObservationMetadata, ObservationWatchContinuationV1,
    ObservationWatchError, QueryBindingV1, WatchRequestCommitmentV1,
};

/// Reports a malformed observation client request or response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidObservationClientAdapter {
    /// A stable resource identity is malformed or uses the zero sentinel.
    #[error("observation client identity is invalid")]
    InvalidIdentity,
    /// A response omitted its resource or returned another identity.
    #[error("observation response does not match its request")]
    ResponseMismatch,
    /// A sandbox response failed complete portable observation validation.
    #[error("sandbox observation response is invalid")]
    InvalidSandboxObservation,
    /// An operation response failed complete portable observation validation.
    #[error("operation observation response is invalid")]
    InvalidOperationObservation,
    /// An execution response failed complete portable observation validation.
    #[error("execution observation response is invalid")]
    InvalidExecutionObservation,
    /// A filesystem-view response failed complete portable validation.
    #[error("filesystem-view observation response is invalid")]
    InvalidFilesystemViewObservation,
    /// An attachment response failed complete portable validation.
    #[error("attachment observation response is invalid")]
    InvalidAttachmentObservation,
    /// A snapshot response failed complete portable observation validation.
    #[error("snapshot observation response is invalid")]
    InvalidSnapshotObservation,
    /// An audit event failed complete watch and provenance validation.
    #[error("audit event response is invalid")]
    InvalidAuditEvent,
    /// A sandbox audit cursor cannot be bound to the requested audit stream.
    #[error("sandbox audit cursor does not match the audit watch request")]
    InvalidAuditCursor,
    /// An operator recovery request or result violates its exact closed binding.
    #[error("operator recovery request or result is invalid")]
    InvalidOperatorRecovery,
}

/// Retains an exact dormant operator-recovery action and concurrency fence.
#[derive(Clone, Debug, PartialEq)]
pub struct OperatorRecoveryRequestV1 {
    resource_id: [u8; 16],
    expected_resource_version: Vec<u8>,
    action: i32,
    idempotency_key: Vec<u8>,
    evidence: aos_proto::aos::sandbox::v1::ObjectDescriptor,
}

impl Eq for OperatorRecoveryRequestV1 {}

impl TryFrom<OperatorRecoveryRequest> for OperatorRecoveryRequestV1 {
    type Error = InvalidObservationClientAdapter;

    fn try_from(value: OperatorRecoveryRequest) -> Result<Self, Self::Error> {
        let resource_id: [u8; 16] = value
            .resource_id
            .as_slice()
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let evidence = value
            .evidence
            .as_option()
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?
            .clone();
        crate::controller_query::portable::CheckedObjectDescriptorV1::try_from(evidence.clone())
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if resource_id == [0; 16]
            || value.expected_resource_version.is_empty()
            || value.expected_resource_version.len() > super::grammar::MAXIMUM_CLI_OPAQUE_BYTES
            || !(1..=4).contains(&value.action.to_i32())
            || value.idempotency_key.is_empty()
            || value.idempotency_key.len() > super::grammar::MAXIMUM_IDEMPOTENCY_KEY_BYTES
        {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        Ok(Self {
            resource_id,
            expected_resource_version: value.expected_resource_version,
            action: value.action.to_i32(),
            idempotency_key: value.idempotency_key,
            evidence,
        })
    }
}

impl OperatorRecoveryRequestV1 {
    /// Returns the exact checked recovery request without dispatching it.
    #[must_use]
    pub fn to_proto(&self) -> OperatorRecoveryRequest {
        OperatorRecoveryRequest {
            resource_id: self.resource_id.to_vec(),
            expected_resource_version: self.expected_resource_version.clone(),
            action: self.action.into(),
            idempotency_key: self.idempotency_key.clone(),
            evidence: self.evidence.clone().into(),
            ..Default::default()
        }
    }

    /// Returns the exact request commitment used by authenticated authorization.
    #[must_use]
    pub fn authority_binding(&self) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.operator-recovery-request.v1\0");
        digest.update(self.resource_id);
        hash_recovery_bytes(&mut digest, &self.expected_resource_version);
        digest.update(self.action.to_be_bytes());
        hash_recovery_bytes(&mut digest, &self.idempotency_key);
        hash_recovery_bytes(&mut digest, self.evidence.media_type.as_bytes());
        hash_recovery_bytes(&mut digest, &self.evidence.sha256);
        digest.update(self.evidence.encoded_size.to_be_bytes());
        ObjectDigest::from_bytes(digest.finalize().into())
    }

    pub(crate) const fn resource_id(&self) -> [u8; 16] {
        self.resource_id
    }

    pub(crate) fn expected_resource_version(&self) -> &[u8] {
        &self.expected_resource_version
    }

    pub(crate) const fn action(&self) -> i32 {
        self.action
    }

    pub(crate) fn idempotency_key(&self) -> &[u8] {
        &self.idempotency_key
    }

    pub(crate) const fn evidence(&self) -> &aos_proto::aos::sandbox::v1::ObjectDescriptor {
        &self.evidence
    }
}

fn hash_recovery_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// Carries one recovery request authorized from exact authenticated semantics.
#[must_use = "operator-recovery authority must be consumed by its protected owner"]
pub(crate) struct AuthorizedOperatorRecoveryV1 {
    request: OperatorRecoveryRequestV1,
    provenance: RequestProvenanceV1,
}

impl AuthorizedOperatorRecoveryV1 {
    pub(crate) const fn from_authenticated(
        request: OperatorRecoveryRequestV1,
        provenance: RequestProvenanceV1,
    ) -> Self {
        Self {
            request,
            provenance,
        }
    }

    pub(crate) fn into_parts(self) -> (OperatorRecoveryRequestV1, RequestProvenanceV1) {
        (self.request, self.provenance)
    }
}

/// Retains an exact operation identity around a pure get request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationObservationRequestV1 {
    operation_id: [u8; 16],
}

impl OperationObservationRequestV1 {
    /// Checks a stable operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter::InvalidIdentity`] for zero.
    pub fn new(operation_id: [u8; 16]) -> Result<Self, InvalidObservationClientAdapter> {
        if operation_id == [0; 16] {
            Err(InvalidObservationClientAdapter::InvalidIdentity)
        } else {
            Ok(Self { operation_id })
        }
    }

    /// Returns the established protobuf request without sending it.
    #[must_use]
    pub fn to_proto(self) -> GetOperationRequest {
        GetOperationRequest {
            operation_id: self.operation_id.to_vec(),
            ..Default::default()
        }
    }

    /// Checks the complete response and its request identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for omission, substitution,
    /// malformed status, incomplete condition metadata, or bad bounds.
    pub fn check_response(
        self,
        response: GetOperationResponse,
    ) -> Result<CheckedOperationObservationV1, InvalidObservationClientAdapter> {
        let wire = response
            .operation
            .as_option()
            .ok_or(InvalidObservationClientAdapter::ResponseMismatch)?
            .clone();
        let checked = CheckedOperationObservationV1::try_from(wire)
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperationObservation)?;
        if checked.resource().operation_id() != self.operation_id {
            Err(InvalidObservationClientAdapter::ResponseMismatch)
        } else {
            Ok(checked)
        }
    }
}

impl From<InvalidObservationMetadata> for InvalidObservationClientAdapter {
    fn from(_: InvalidObservationMetadata) -> Self {
        Self::InvalidSandboxObservation
    }
}

impl From<InvalidAuditWatchEvent> for InvalidObservationClientAdapter {
    fn from(_: InvalidAuditWatchEvent) -> Self {
        Self::InvalidAuditEvent
    }
}

impl From<ObservationWatchError> for InvalidObservationClientAdapter {
    fn from(_: ObservationWatchError) -> Self {
        Self::InvalidAuditEvent
    }
}

/// Retains an exact execution identity around a pure get request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionObservationRequestV1 {
    execution_id: [u8; 16],
}

impl ExecutionObservationRequestV1 {
    /// Checks a stable execution identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter::InvalidIdentity`] for zero.
    pub fn new(execution_id: [u8; 16]) -> Result<Self, InvalidObservationClientAdapter> {
        if execution_id == [0; 16] {
            Err(InvalidObservationClientAdapter::InvalidIdentity)
        } else {
            Ok(Self { execution_id })
        }
    }

    /// Returns the established request without sending it.
    #[must_use]
    pub fn to_proto(self) -> GetExecutionRequest {
        GetExecutionRequest {
            execution_id: self.execution_id.to_vec(),
            ..Default::default()
        }
    }

    /// Checks a complete response and exact execution identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for omission, substitution,
    /// malformed status, incomplete conditions, or bad bounds.
    pub fn check_response(
        self,
        response: GetExecutionResponse,
    ) -> Result<CheckedExecutionResourceV1, InvalidObservationClientAdapter> {
        let wire = response
            .execution
            .as_option()
            .ok_or(InvalidObservationClientAdapter::ResponseMismatch)?
            .clone();
        let checked = CheckedExecutionResourceV1::try_from(wire)
            .map_err(|_| InvalidObservationClientAdapter::InvalidExecutionObservation)?;
        if checked.as_proto().execution_id.as_slice() != self.execution_id {
            Err(InvalidObservationClientAdapter::ResponseMismatch)
        } else {
            Ok(checked)
        }
    }
}

/// Retains an exact filesystem-view identity around a pure get request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemViewObservationRequestV1 {
    view_id: [u8; 16],
}

impl FilesystemViewObservationRequestV1 {
    /// Checks a stable filesystem-view identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter::InvalidIdentity`] for zero.
    pub fn new(view_id: [u8; 16]) -> Result<Self, InvalidObservationClientAdapter> {
        if view_id == [0; 16] {
            Err(InvalidObservationClientAdapter::InvalidIdentity)
        } else {
            Ok(Self { view_id })
        }
    }

    /// Returns the established request without sending it.
    #[must_use]
    pub fn to_proto(self) -> GetViewRequest {
        GetViewRequest {
            view_id: self.view_id.to_vec(),
            ..Default::default()
        }
    }

    /// Checks a complete response and exact filesystem-view identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for omission, substitution,
    /// malformed status, incomplete conditions, or bad bounds.
    pub fn check_response(
        self,
        response: GetViewResponse,
    ) -> Result<CheckedFilesystemViewResourceV1, InvalidObservationClientAdapter> {
        let wire = response
            .view
            .as_option()
            .ok_or(InvalidObservationClientAdapter::ResponseMismatch)?
            .clone();
        let checked = CheckedFilesystemViewResourceV1::try_from(wire)
            .map_err(|_| InvalidObservationClientAdapter::InvalidFilesystemViewObservation)?;
        if checked.as_proto().view_id.as_slice() != self.view_id {
            Err(InvalidObservationClientAdapter::ResponseMismatch)
        } else {
            Ok(checked)
        }
    }
}

/// Retains an exact attachment identity around a dormant pure get request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentObservationRequestV1 {
    attachment_id: [u8; 16],
}

impl AttachmentObservationRequestV1 {
    /// Checks a stable attachment identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter::InvalidIdentity`] for zero.
    pub fn new(attachment_id: [u8; 16]) -> Result<Self, InvalidObservationClientAdapter> {
        if attachment_id == [0; 16] {
            Err(InvalidObservationClientAdapter::InvalidIdentity)
        } else {
            Ok(Self { attachment_id })
        }
    }

    /// Returns the dormant additive request without sending it.
    #[must_use]
    pub fn to_proto(self) -> GetAttachmentRequest {
        GetAttachmentRequest {
            attachment_id: self.attachment_id.to_vec(),
            ..Default::default()
        }
    }

    /// Checks a complete response and exact attachment identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for omission, substitution,
    /// malformed status, incomplete conditions, or bad bounds.
    pub fn check_response(
        self,
        response: GetAttachmentResponse,
    ) -> Result<CheckedAttachmentResourceV1, InvalidObservationClientAdapter> {
        let wire = response
            .attachment
            .as_option()
            .ok_or(InvalidObservationClientAdapter::ResponseMismatch)?
            .clone();
        let checked = CheckedAttachmentResourceV1::try_from(wire)
            .map_err(|_| InvalidObservationClientAdapter::InvalidAttachmentObservation)?;
        if checked.as_proto().attachment_id.as_slice() != self.attachment_id {
            Err(InvalidObservationClientAdapter::ResponseMismatch)
        } else {
            Ok(checked)
        }
    }
}

/// Retains an exact snapshot identity around a pure get request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotObservationRequestV1 {
    snapshot_id: [u8; 16],
}

impl SnapshotObservationRequestV1 {
    /// Checks a stable snapshot identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter::InvalidIdentity`] for zero.
    pub fn new(snapshot_id: [u8; 16]) -> Result<Self, InvalidObservationClientAdapter> {
        if snapshot_id == [0; 16] {
            Err(InvalidObservationClientAdapter::InvalidIdentity)
        } else {
            Ok(Self { snapshot_id })
        }
    }

    /// Returns the established request without sending it.
    #[must_use]
    pub fn to_proto(self) -> GetSnapshotRequest {
        GetSnapshotRequest {
            snapshot_id: self.snapshot_id.to_vec(),
            ..Default::default()
        }
    }

    /// Checks a complete response and exact snapshot identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for omission, substitution,
    /// malformed status, incomplete conditions, or bad bounds.
    pub fn check_response(
        self,
        response: GetSnapshotResponse,
    ) -> Result<CheckedSnapshotResourceV1, InvalidObservationClientAdapter> {
        let wire = response
            .snapshot
            .as_option()
            .ok_or(InvalidObservationClientAdapter::ResponseMismatch)?
            .clone();
        let checked = CheckedSnapshotResourceV1::try_from(wire)
            .map_err(|_| InvalidObservationClientAdapter::InvalidSnapshotObservation)?;
        if checked.as_proto().snapshot_id.as_slice() != self.snapshot_id {
            Err(InvalidObservationClientAdapter::ResponseMismatch)
        } else {
            Ok(checked)
        }
    }
}

/// Retains an exact sandbox identity around a pure get request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxObservationRequestV1 {
    sandbox_id: [u8; 16],
}

impl SandboxObservationRequestV1 {
    /// Checks a stable sandbox identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter::InvalidIdentity`] for zero.
    pub fn new(sandbox_id: [u8; 16]) -> Result<Self, InvalidObservationClientAdapter> {
        if sandbox_id == [0; 16] {
            Err(InvalidObservationClientAdapter::InvalidIdentity)
        } else {
            Ok(Self { sandbox_id })
        }
    }

    /// Returns the established protobuf request without sending it.
    #[must_use]
    pub fn to_proto(self) -> GetSandboxRequest {
        GetSandboxRequest {
            sandbox_id: self.sandbox_id.to_vec(),
            ..Default::default()
        }
    }

    /// Checks the complete response and its request identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for omission, substitution,
    /// malformed status, incomplete authority correlation, or bad bounds.
    pub fn check_response(
        self,
        response: GetSandboxResponse,
    ) -> Result<CheckedSandboxObservationV1, InvalidObservationClientAdapter> {
        let wire = response
            .sandbox
            .as_option()
            .ok_or(InvalidObservationClientAdapter::ResponseMismatch)?
            .clone();
        let checked = CheckedSandboxObservationV1::try_from(wire)?;
        if checked.resource().sandbox_id() != self.sandbox_id {
            Err(InvalidObservationClientAdapter::ResponseMismatch)
        } else {
            Ok(checked)
        }
    }

    /// Checks a response and binds its audit cursor to an exact audit request.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for an invalid sandbox,
    /// project mismatch, malformed cursor, or query-binding mismatch.
    pub fn check_response_for_audit(
        self,
        response: GetSandboxResponse,
        audit_request: &AuditWatchRequestV1,
    ) -> Result<BoundSandboxObservationV1, InvalidObservationClientAdapter> {
        let observation = self.check_response(response)?;
        if observation.resource().as_proto().project_id.as_slice()
            != audit_request.project_id.as_slice()
        {
            return Err(InvalidObservationClientAdapter::InvalidAuditCursor);
        }
        let observed_cursor = observation.additive().audit_event_cursor();
        let authenticated_cursor = audit_request
            .resume_after
            .as_ref()
            .map(WatchResumePointV1::cursor);
        let cursor_matches = match (observed_cursor, authenticated_cursor) {
            (None, None) => true,
            (Some(observed), Some(authenticated)) => {
                authenticated.binding() == audit_request.binding
                    && observed.as_bytes() == authenticated.as_bytes()
            }
            (None, Some(_)) | (Some(_), None) => false,
        };
        if !cursor_matches {
            return Err(InvalidObservationClientAdapter::InvalidAuditCursor);
        }

        Ok(BoundSandboxObservationV1 {
            observation,
            audit_cursor: authenticated_cursor.cloned(),
        })
    }
}

/// Stores a sandbox observation whose audit cursor carries a full query binding.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundSandboxObservationV1 {
    observation: CheckedSandboxObservationV1,
    audit_cursor: Option<BoundWatchCursorV1>,
}

impl BoundSandboxObservationV1 {
    /// Returns the checked sandbox observation.
    #[must_use]
    pub const fn observation(&self) -> &CheckedSandboxObservationV1 {
        &self.observation
    }

    /// Returns the audit cursor bound to the exact audit request semantics.
    #[must_use]
    pub const fn audit_cursor(&self) -> Option<&BoundWatchCursorV1> {
        self.audit_cursor.as_ref()
    }
}

/// Retains a complete query binding around a project audit watch request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditWatchRequestV1 {
    project_id: [u8; 16],
    binding: QueryBindingV1,
    commitment: WatchRequestCommitmentV1,
    resume_after: Option<WatchResumePointV1>,
}

impl AuditWatchRequestV1 {
    /// Checks one project audit watch request and an optional bound cursor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for a zero project or a
    /// cursor created under different query, principal, policy, or schema.
    pub fn new(
        project_id: [u8; 16],
        binding: QueryBindingV1,
        commitment: WatchRequestCommitmentV1,
        resume_after: Option<WatchResumePointV1>,
    ) -> Result<Self, InvalidObservationClientAdapter> {
        if project_id == [0; 16]
            || resume_after
                .as_ref()
                .is_some_and(|cursor| cursor.binding() != binding)
        {
            Err(InvalidObservationClientAdapter::InvalidIdentity)
        } else {
            Ok(Self {
                project_id,
                binding,
                commitment,
                resume_after,
            })
        }
    }

    /// Returns the established protobuf watch request without opening a stream.
    #[must_use]
    pub fn to_proto(&self) -> WatchRequest {
        WatchRequest {
            project_id: self.project_id.to_vec(),
            audit_only: true,
            resume_after: self
                .resume_after
                .as_ref()
                .map(|resume| WatchCursor {
                    opaque_cursor: resume.cursor().as_bytes().to_vec(),
                    ..Default::default()
                })
                .into(),
            ..Default::default()
        }
    }

    /// Checks one streamed event under the exact request binding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter::InvalidAuditEvent`] for an
    /// authentication mismatch, invalid audit identity, decision, policy
    /// revision, or cursor.
    pub fn check_event(
        &self,
        event: Event,
        authenticated_binding: QueryBindingV1,
        authenticated_commitment: WatchRequestCommitmentV1,
    ) -> Result<CheckedAuditWatchEventV1, InvalidObservationClientAdapter> {
        if authenticated_binding != self.binding || authenticated_commitment != self.commitment {
            return Err(InvalidObservationClientAdapter::InvalidAuditEvent);
        }
        CheckedAuditWatchEventV1::from_response(self.binding, event).map_err(Into::into)
    }

    /// Constructs the pure monotone continuation for this request.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter::InvalidAuditEvent`] if the
    /// retained cursor no longer matches the complete request binding.
    pub fn continuation(
        &self,
    ) -> Result<ObservationWatchContinuationV1, InvalidObservationClientAdapter> {
        let request = CheckedWatchRequestV1::new(
            self.to_proto(),
            self.binding,
            self.commitment,
            self.resume_after.clone(),
        )?;
        ObservationWatchContinuationV1::new(request).map_err(Into::into)
    }

    /// Returns the complete local query binding.
    #[must_use]
    pub const fn binding(&self) -> QueryBindingV1 {
        self.binding
    }

    /// Returns the normalized watch-semantic commitment.
    #[must_use]
    pub const fn commitment(&self) -> WatchRequestCommitmentV1 {
        self.commitment
    }

    /// Returns the typed strictly-after resume point, if requested.
    #[must_use]
    pub const fn resume_after(&self) -> Option<&WatchResumePointV1> {
        self.resume_after.as_ref()
    }
}
