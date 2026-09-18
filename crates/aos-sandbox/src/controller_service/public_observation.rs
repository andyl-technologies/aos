//! Dormant pure handler for checked portable resource observations.
//!
//! This module is deliberately not registered with the production Connect
//! router. It defines only the read-model boundary and request/response
//! projection needed for later activation.

use std::fmt;

use aos_proto::aos::sandbox::v1::{
    Attachment, Execution, FilesystemView, GetAttachmentRequest, GetAttachmentResponse,
    GetExecutionRequest, GetExecutionResponse, GetOperationRequest, GetOperationResponse,
    GetSandboxRequest, GetSandboxResponse, GetSnapshotRequest, GetSnapshotResponse, GetViewRequest,
    GetViewResponse, Operation, Sandbox, Snapshot,
};

use crate::controller_query::{
    AuthenticatedWatchReadBatchV1, AuthenticatedWatchReadRequestV1, CheckedAttachmentResourceV1,
    CheckedExecutionResourceV1, CheckedFilesystemViewResourceV1, CheckedOperationObservationV1,
    CheckedSandboxObservationV1, CheckedSnapshotResourceV1, CheckedWatchRequestV1,
    InvalidObservationMetadata, InvalidPublicResource, ObservationWatchAdvanceV1,
    ObservationWatchContinuationV1, ObservationWatchError,
};

/// Supplies portable sandbox wire resources without granting effect authority.
pub trait PublicObservationReadModelV1 {
    /// Reports the backing read-model failure.
    type Error;

    /// Loads one portable sandbox observation by stable identity.
    ///
    /// The returned resource remains untrusted until the pure handler checks
    /// every public field and correlation.
    ///
    /// # Errors
    ///
    /// Returns the implementation-defined read-model error.
    fn load_sandbox(&self, sandbox_id: [u8; 16]) -> Result<Option<Sandbox>, Self::Error>;

    /// Loads one portable operation observation by stable identity.
    ///
    /// The returned resource remains untrusted until the pure handler checks
    /// its operation state and complete condition metadata.
    ///
    /// # Errors
    ///
    /// Returns the implementation-defined read-model error.
    fn load_operation(&self, operation_id: [u8; 16]) -> Result<Option<Operation>, Self::Error>;

    /// Loads one portable execution observation by stable identity.
    ///
    /// # Errors
    ///
    /// Returns the implementation-defined read-model error.
    fn load_execution(&self, execution_id: [u8; 16]) -> Result<Option<Execution>, Self::Error>;

    /// Loads one portable filesystem-view observation by stable identity.
    ///
    /// # Errors
    ///
    /// Returns the implementation-defined read-model error.
    fn load_filesystem_view(
        &self,
        view_id: [u8; 16],
    ) -> Result<Option<FilesystemView>, Self::Error>;

    /// Loads one portable attachment observation by stable identity.
    ///
    /// # Errors
    ///
    /// Returns the implementation-defined read-model error.
    fn load_attachment(&self, attachment_id: [u8; 16]) -> Result<Option<Attachment>, Self::Error>;

    /// Loads one portable snapshot observation by stable identity.
    ///
    /// # Errors
    ///
    /// Returns the implementation-defined read-model error.
    fn load_snapshot(&self, snapshot_id: [u8; 16]) -> Result<Option<Snapshot>, Self::Error>;

    /// Loads one bounded watch page without opening a transport stream.
    ///
    /// # Errors
    ///
    /// Returns the implementation-defined read-model error.
    fn load_watch(
        &self,
        request: &AuthenticatedWatchReadRequestV1,
    ) -> Result<AuthenticatedWatchReadBatchV1, Self::Error>;
}

/// Stores a fully checked pure watch page and its resumable consumer state.
#[derive(Clone, Debug)]
pub struct CheckedWatchPageV1 {
    advances: Vec<ObservationWatchAdvanceV1>,
    continuation: ObservationWatchContinuationV1,
}

impl CheckedWatchPageV1 {
    /// Returns event applications, exact duplicates, and bootstrap `W`.
    #[must_use]
    pub fn advances(&self) -> &[ObservationWatchAdvanceV1] {
        &self.advances
    }

    /// Returns the state that must authenticate and consume the next page.
    #[must_use]
    pub const fn continuation(&self) -> &ObservationWatchContinuationV1 {
        &self.continuation
    }

    /// Consumes the page and returns the authenticated continuation state.
    #[must_use]
    pub fn into_continuation(self) -> ObservationWatchContinuationV1 {
        self.continuation
    }
}

/// Reports a rejected dormant public-observation request.
#[derive(Debug)]
pub enum PublicObservationServiceError<ReadError> {
    /// The request carries no exact nonzero sandbox identity.
    InvalidRequest,
    /// No resource exists under the requested identity.
    NotFound,
    /// The read model returned an invalid or mismatched public observation.
    InvalidObservation(InvalidObservationMetadata),
    /// The read model returned another invalid or mismatched portable resource.
    InvalidResource(InvalidPublicResource),
    /// A watch request, event page, cursor, or ordering relation is invalid.
    InvalidWatch(ObservationWatchError),
    /// The backing read model failed without exposing diagnostics publicly.
    ReadModel(ReadError),
}

impl<ReadError> fmt::Display for PublicObservationServiceError<ReadError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("public observation request is invalid"),
            Self::NotFound => formatter.write_str("public observation was not found"),
            Self::InvalidObservation(_) => {
                formatter.write_str("stored public observation is invalid")
            }
            Self::InvalidResource(_) => formatter.write_str("stored public resource is invalid"),
            Self::InvalidWatch(_) => formatter.write_str("public watch observation is invalid"),
            Self::ReadModel(_) => formatter.write_str("public observation read model failed"),
        }
    }
}

impl<ReadError> std::error::Error for PublicObservationServiceError<ReadError> where
    ReadError: fmt::Debug
{
}

/// Checks requests and read-model responses without transport side effects.
pub struct PurePublicObservationHandlerV1<ReadModel> {
    read_model: ReadModel,
}

impl<ReadModel> PurePublicObservationHandlerV1<ReadModel> {
    /// Wraps a portable read model without registering any RPC route.
    #[must_use]
    pub const fn new(read_model: ReadModel) -> Self {
        Self { read_model }
    }

    /// Returns the wrapped read model.
    #[must_use]
    pub const fn read_model(&self) -> &ReadModel {
        &self.read_model
    }

    /// Consumes the handler and returns the wrapped read model.
    #[must_use]
    pub fn into_read_model(self) -> ReadModel {
        self.read_model
    }
}

impl<ReadModel> PurePublicObservationHandlerV1<ReadModel>
where
    ReadModel: PublicObservationReadModelV1,
{
    /// Projects one checked sandbox response without performing network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`PublicObservationServiceError`] for malformed identity,
    /// absence, read-model failure, invalid status, or identity substitution.
    pub fn get_sandbox(
        &self,
        request: GetSandboxRequest,
    ) -> Result<GetSandboxResponse, PublicObservationServiceError<ReadModel::Error>> {
        let sandbox_id = exact_nonzero_id(&request.sandbox_id)
            .ok_or(PublicObservationServiceError::InvalidRequest)?;
        let wire = self
            .read_model
            .load_sandbox(sandbox_id)
            .map_err(PublicObservationServiceError::ReadModel)?
            .ok_or(PublicObservationServiceError::NotFound)?;
        let checked = CheckedSandboxObservationV1::try_from(wire)
            .map_err(PublicObservationServiceError::InvalidObservation)?;
        if checked.resource().sandbox_id() != sandbox_id {
            return Err(PublicObservationServiceError::InvalidObservation(
                InvalidObservationMetadata::InvalidStatus,
            ));
        }

        Ok(GetSandboxResponse {
            sandbox: Some(checked.resource().as_proto().clone()).into(),
            ..Default::default()
        })
    }

    /// Projects one checked operation response without performing network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`PublicObservationServiceError`] for malformed identity,
    /// absence, read-model failure, invalid status, or identity substitution.
    pub fn get_operation(
        &self,
        request: GetOperationRequest,
    ) -> Result<GetOperationResponse, PublicObservationServiceError<ReadModel::Error>> {
        let operation_id = exact_nonzero_id(&request.operation_id)
            .ok_or(PublicObservationServiceError::InvalidRequest)?;
        let wire = self
            .read_model
            .load_operation(operation_id)
            .map_err(PublicObservationServiceError::ReadModel)?
            .ok_or(PublicObservationServiceError::NotFound)?;
        let checked = CheckedOperationObservationV1::try_from(wire)
            .map_err(PublicObservationServiceError::InvalidObservation)?;
        if checked.resource().operation_id() != operation_id {
            return Err(PublicObservationServiceError::InvalidObservation(
                InvalidObservationMetadata::InvalidStatus,
            ));
        }

        Ok(GetOperationResponse {
            operation: Some(checked.resource().as_proto().clone()).into(),
            ..Default::default()
        })
    }

    /// Projects one checked execution response without performing network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`PublicObservationServiceError`] for malformed identity,
    /// absence, read-model failure, invalid status, or identity substitution.
    pub fn get_execution(
        &self,
        request: GetExecutionRequest,
    ) -> Result<GetExecutionResponse, PublicObservationServiceError<ReadModel::Error>> {
        let execution_id = exact_nonzero_id(&request.execution_id)
            .ok_or(PublicObservationServiceError::InvalidRequest)?;
        let wire = self
            .read_model
            .load_execution(execution_id)
            .map_err(PublicObservationServiceError::ReadModel)?
            .ok_or(PublicObservationServiceError::NotFound)?;
        let checked = CheckedExecutionResourceV1::try_from(wire)
            .map_err(PublicObservationServiceError::InvalidResource)?;
        if checked.as_proto().execution_id.as_slice() != execution_id {
            return Err(PublicObservationServiceError::InvalidResource(
                InvalidPublicResource::InvalidPlacement,
            ));
        }

        Ok(GetExecutionResponse {
            execution: Some(checked.into_proto()).into(),
            ..Default::default()
        })
    }

    /// Projects one checked filesystem-view response without network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`PublicObservationServiceError`] for malformed identity,
    /// absence, read-model failure, invalid status, or identity substitution.
    pub fn get_filesystem_view(
        &self,
        request: GetViewRequest,
    ) -> Result<GetViewResponse, PublicObservationServiceError<ReadModel::Error>> {
        let view_id = exact_nonzero_id(&request.view_id)
            .ok_or(PublicObservationServiceError::InvalidRequest)?;
        let wire = self
            .read_model
            .load_filesystem_view(view_id)
            .map_err(PublicObservationServiceError::ReadModel)?
            .ok_or(PublicObservationServiceError::NotFound)?;
        let checked = CheckedFilesystemViewResourceV1::try_from(wire)
            .map_err(PublicObservationServiceError::InvalidResource)?;
        if checked.as_proto().view_id.as_slice() != view_id {
            return Err(PublicObservationServiceError::InvalidResource(
                InvalidPublicResource::InvalidPlacement,
            ));
        }

        Ok(GetViewResponse {
            view: Some(checked.into_proto()).into(),
            ..Default::default()
        })
    }

    /// Projects one checked dormant attachment response without network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`PublicObservationServiceError`] for malformed identity,
    /// absence, read-model failure, invalid status, or identity substitution.
    pub fn get_attachment(
        &self,
        request: GetAttachmentRequest,
    ) -> Result<GetAttachmentResponse, PublicObservationServiceError<ReadModel::Error>> {
        let attachment_id = exact_nonzero_id(&request.attachment_id)
            .ok_or(PublicObservationServiceError::InvalidRequest)?;
        let wire = self
            .read_model
            .load_attachment(attachment_id)
            .map_err(PublicObservationServiceError::ReadModel)?
            .ok_or(PublicObservationServiceError::NotFound)?;
        let checked = CheckedAttachmentResourceV1::try_from(wire)
            .map_err(PublicObservationServiceError::InvalidResource)?;
        if checked.as_proto().attachment_id.as_slice() != attachment_id {
            return Err(PublicObservationServiceError::InvalidResource(
                InvalidPublicResource::InvalidPlacement,
            ));
        }

        Ok(GetAttachmentResponse {
            attachment: Some(checked.into_proto()).into(),
            ..Default::default()
        })
    }

    /// Projects one checked snapshot response without performing network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`PublicObservationServiceError`] for malformed identity,
    /// absence, read-model failure, invalid status, or identity substitution.
    pub fn get_snapshot(
        &self,
        request: GetSnapshotRequest,
    ) -> Result<GetSnapshotResponse, PublicObservationServiceError<ReadModel::Error>> {
        let snapshot_id = exact_nonzero_id(&request.snapshot_id)
            .ok_or(PublicObservationServiceError::InvalidRequest)?;
        let wire = self
            .read_model
            .load_snapshot(snapshot_id)
            .map_err(PublicObservationServiceError::ReadModel)?
            .ok_or(PublicObservationServiceError::NotFound)?;
        let checked = CheckedSnapshotResourceV1::try_from(wire)
            .map_err(PublicObservationServiceError::InvalidResource)?;
        if checked.as_proto().snapshot_id.as_slice() != snapshot_id {
            return Err(PublicObservationServiceError::InvalidResource(
                InvalidPublicResource::InvalidPlacement,
            ));
        }

        Ok(GetSnapshotResponse {
            snapshot: Some(checked.into_proto()).into(),
            ..Default::default()
        })
    }

    /// Constructs continuation state without contacting the read model.
    ///
    /// # Errors
    ///
    /// Returns [`PublicObservationServiceError::InvalidWatch`] when the
    /// established reducer rejects the bounded request state.
    pub fn start_watch(
        &self,
        request: CheckedWatchRequestV1,
    ) -> Result<ObservationWatchContinuationV1, PublicObservationServiceError<ReadModel::Error>>
    {
        ObservationWatchContinuationV1::new(request)
            .map_err(PublicObservationServiceError::InvalidWatch)
    }

    /// Applies one authenticated read-model page and retains continuation state.
    ///
    /// # Errors
    ///
    /// Returns [`PublicObservationServiceError`] for read-model failure or a
    /// pre-reduction adapter error. Binding, commitment, cursor, sequence, and
    /// watermark conflicts become the reducer's closed relist-required result.
    pub fn watch(
        &self,
        mut continuation: ObservationWatchContinuationV1,
    ) -> Result<CheckedWatchPageV1, PublicObservationServiceError<ReadModel::Error>> {
        let request = continuation.read_request();
        let batch = self
            .read_model
            .load_watch(&request)
            .map_err(PublicObservationServiceError::ReadModel)?;
        let advances = continuation
            .apply_authenticated_batch(batch)
            .map_err(PublicObservationServiceError::InvalidWatch)?;

        Ok(CheckedWatchPageV1 {
            advances,
            continuation,
        })
    }
}

fn exact_nonzero_id(value: &[u8]) -> Option<[u8; 16]> {
    let identifier: [u8; 16] = value.try_into().ok()?;
    (identifier != [0; 16]).then_some(identifier)
}
