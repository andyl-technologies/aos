//! Executor service traits and the checked coordinator client.
//!
//! The traits compose the operation-specific messages owned by the sibling
//! modules. The client applies request-bound response validation uniformly to
//! direct implementations and transport adapters.

use super::*;

/// Implementor-facing transport-neutral executor assignment interface.
///
/// A loopback RPC adapter must strictly decode the same
/// [`SubmitAttemptRequest`] bytes and return the same [`SubmitAttemptResponse`]
/// vocabulary. Implementations own local placement and execution but receive no
/// mutable campaign-ref capability. Coordinators call services only through
/// [`ExecutorClient`], which applies the same exact-response validation to
/// direct and RPC implementations.
pub trait ExecutorService {
    /// Implementation-specific transport or local service failure.
    type Error;

    /// Submits one idempotent local attempt assignment.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when the service could not
    /// produce a protocol response. Ordinary incompatibility, backpressure,
    /// unavailable input, and authorization failures are successful protocol
    /// responses in [`SubmitAttemptDisposition::Rejected`].
    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error>;
}

/// Read-only status extension implemented by direct and RPC executors.
pub trait ExecutorStatusService: ExecutorService {
    /// Returns the current state of one exact execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when operational state cannot
    /// be read or a protocol response cannot be constructed.
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error>;
}

/// Idempotent cancellation extension implemented by direct and RPC executors.
pub trait ExecutorControlService: ExecutorStatusService {
    /// Requests a durable exact checkpoint of one execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when operational state cannot
    /// be changed or a protocol response cannot be constructed.
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error>;

    /// Requests cancellation of one exact execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when operational state cannot
    /// be changed or a protocol response cannot be constructed.
    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error>;
}

/// Exact-checkpoint resume extension implemented by direct and RPC executors.
pub trait ExecutorResumeService: ExecutorStatusService {
    /// Admits one fresh execution incarnation from a durable paused root.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when operational state cannot
    /// be authenticated or changed, or a protocol response cannot be built.
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error>;
}

/// Coordinator-facing checked client over one direct or RPC executor service.
pub struct ExecutorClient<S> {
    service: S,
}

impl<S> ExecutorClient<S> {
    /// Wraps one implementor-facing executor service.
    #[must_use]
    pub const fn new(service: S) -> Self {
        Self { service }
    }

    /// Returns the wrapped service after coordinator ownership ends.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.service
    }
}

impl<S: ExecutorService> ExecutorClient<S> {
    /// Submits an assignment and validates the exact response basis.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] when the implementation cannot
    /// produce a protocol response, or [`ExecutorClientError::InvalidResponse`]
    /// when it returns a response for any other canonical request.
    pub fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .submit_attempt(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }
}

impl<S: ExecutorStatusService> ExecutorClient<S> {
    /// Reads and validates one exact local execution status response.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] for service failure or
    /// [`ExecutorClientError::InvalidResponse`] for a cross-request response.
    pub fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .get_attempt_execution(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }
}

impl<S: ExecutorControlService> ExecutorClient<S> {
    /// Requests and validates one exact local checkpoint operation.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] for service failure or
    /// [`ExecutorClientError::InvalidResponse`] for a cross-request response.
    pub fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .checkpoint_attempt_execution(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }

    /// Cancels and validates one exact local execution incarnation.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] for service failure or
    /// [`ExecutorClientError::InvalidResponse`] for a cross-request response.
    pub fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .cancel_attempt_execution(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }
}

impl<S: ExecutorResumeService> ExecutorClient<S> {
    /// Resumes and validates one exact durable paused execution.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] for service failure or
    /// [`ExecutorClientError::InvalidResponse`] for a cross-request response.
    pub fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, ExecutorClientError<S::Error>> {
        let response = self
            .service
            .resume_attempt_execution(request)
            .map_err(ExecutorClientError::Service)?;
        response
            .validate_for(request)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(response)
    }
}

impl<S: crate::executor_capability::ExecutorCapabilityService> ExecutorClient<S> {
    /// Fetches immutable capabilities and the current daemon epoch.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] when the implementation cannot
    /// produce a description.
    pub fn describe_executor(
        &mut self,
    ) -> Result<crate::ExecutorDescription, ExecutorClientError<S::Error>> {
        self.service
            .describe_executor()
            .map_err(ExecutorClientError::Service)
    }

    /// Fetches and validates the next volatile capacity report.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorClientError::Service`] when the implementation cannot
    /// produce a report, or [`ExecutorClientError::InvalidResponse`] when the
    /// report belongs to another daemon/capability set, fails to advance the
    /// cursor, exceeds immutable ceilings, or advertises unsupported locality.
    pub fn watch_capacity(
        &mut self,
        description: &crate::ExecutorDescription,
        after_sequence: Option<u64>,
    ) -> Result<crate::ExecutorCapacityReport, ExecutorClientError<S::Error>> {
        let request = crate::WatchExecutorCapacityRequest::new(description, after_sequence)
            .map_err(ExecutorClientError::InvalidResponse)?;
        let report = self
            .service
            .watch_capacity(&request)
            .map_err(ExecutorClientError::Service)?;
        report
            .validate_for(description, after_sequence)
            .map_err(ExecutorClientError::InvalidResponse)?;
        Ok(report)
    }
}

/// Failure from the coordinator-facing checked executor client.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecutorClientError<E> {
    /// The direct or RPC implementation failed to produce a response.
    #[error("executor service failed: {0}")]
    Service(#[source] E),
    /// The implementation returned a malformed cross-request response.
    #[error(transparent)]
    InvalidResponse(CampaignCodecError),
}
