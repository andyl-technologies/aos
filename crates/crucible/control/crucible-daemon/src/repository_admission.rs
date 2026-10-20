//! Read-only campaign repository adapter for local executor admission.
//!
//! The adapter deliberately exposes no campaign mutation or mutable-ref
//! capability to the executor. It translates repository validation into the
//! stable executor rejection vocabulary while retaining the repository as the
//! sole authority for immutable attempt, lineage, and observation semantics.

use std::sync::Arc;

use crucible_campaign::{
    AttemptId, CampaignLineageId, CampaignRepository, ExecutorCompatibilityProfile,
    ExecutorRejection, FindingCandidateBundleId, ObservationId, SubmitAttemptRequest,
};

use crate::{AttemptAdmissionValidator, CompletionValidationFailure};

/// Production read-only admission boundary backed by a campaign repository.
#[derive(Clone)]
pub struct RepositoryAttemptAdmission {
    repository: Arc<CampaignRepository>,
    profile: ExecutorCompatibilityProfile,
}

impl RepositoryAttemptAdmission {
    /// Wraps one repository without granting executor mutation authority.
    #[must_use]
    pub const fn new(
        repository: Arc<CampaignRepository>,
        profile: ExecutorCompatibilityProfile,
    ) -> Self {
        Self {
            repository,
            profile,
        }
    }
}

impl AttemptAdmissionValidator for RepositoryAttemptAdmission {
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        self.repository
            .validate_executor_request_with_profile(request, &self.profile)
            .map_err(|error| error.executor_rejection())
    }

    fn validate_execution_scope(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<(), ExecutorRejection> {
        self.repository
            .validate_executor_execution_scope_with_profile(request, &self.profile)
            .map_err(|error| error.executor_rejection())
    }

    fn selected_savepoint_source_attempt(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<Option<AttemptId>, ExecutorRejection> {
        self.repository
            .executor_selected_savepoint_source_attempt(request)
            .map_err(|error| error.executor_rejection())
    }

    fn validate_completion(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
    ) -> Result<(), CompletionValidationFailure> {
        self.repository
            .validate_executor_completion_with_profile(request, observation, &self.profile)
            .map_err(|error| match error.executor_rejection() {
                ExecutorRejection::UnavailableInput => {
                    CompletionValidationFailure::UnavailableInput
                }
                ExecutorRejection::Unauthorized => CompletionValidationFailure::Unauthorized,
                ExecutorRejection::Incompatible
                | ExecutorRejection::Backpressure
                | ExecutorRejection::ConflictingAssignment
                | ExecutorRejection::TerminalFailure => CompletionValidationFailure::Incompatible,
            })
    }

    fn validate_completion_artifacts(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        self.repository
            .validate_executor_completion_artifacts_with_profile(
                request,
                observation,
                finding_candidate,
                &self.profile,
            )
            .map_err(map_completion_validation_failure)
    }

    fn validate_retained_completion(
        &self,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        self.repository
            .validate_retained_executor_completion_with_profile(
                lineage,
                attempt,
                observation,
                finding_candidate,
                &self.profile,
            )
            .map_err(map_completion_validation_failure)
    }
}

fn map_completion_validation_failure(
    error: crucible_campaign::CampaignRepositoryError,
) -> CompletionValidationFailure {
    match error.executor_rejection() {
        ExecutorRejection::UnavailableInput => CompletionValidationFailure::UnavailableInput,
        ExecutorRejection::Unauthorized => CompletionValidationFailure::Unauthorized,
        ExecutorRejection::Incompatible
        | ExecutorRejection::Backpressure
        | ExecutorRejection::ConflictingAssignment
        | ExecutorRejection::TerminalFailure => CompletionValidationFailure::Incompatible,
    }
}
