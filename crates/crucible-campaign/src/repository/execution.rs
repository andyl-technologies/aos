//! Repository-backed validation for local executor protocol responses.
//!
//! Component-message validation proves an exact request/response exchange.
//! This owner layer additionally authenticates the named campaign records and
//! prevents an executor from treating an observation from another attempt or
//! lineage as completion.

use super::*;

impl CampaignRepository {
    /// Authenticates one executor request against immutable campaign semantics.
    ///
    /// This read-only boundary is suitable for a local executor admission
    /// adapter: it authenticates the lineage and attempt closure and requires
    /// the attempt's start artifact to belong to the lineage's exact scenario
    /// artifact. It does not expose or mutate campaign refs.
    ///
    /// # Errors
    ///
    /// Returns an error when the lineage or attempt closure is missing or
    /// invalid, or when the attempt is incompatible with the named lineage.
    pub fn validate_executor_request(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_executor_request_lineage(request).map(drop)
    }

    /// Authenticates a request and requires the executor's exact local profile.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::validate_executor_request`], or an
    /// integrity error when any Crucible, QEMU, protocol, scenario-schema, or
    /// exact-closure-schema compatibility field differs.
    pub fn validate_executor_request_with_profile(
        &self,
        request: &SubmitAttemptRequest,
        profile: &ExecutorCompatibilityProfile,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.validate_executor_request_lineage(request)?;
        if !profile.admits(&lineage) {
            return Err(integrity("executor-compatibility-profile-mismatch"));
        }
        Ok(())
    }

    fn validate_executor_request_lineage(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<CampaignLineage, CampaignRepositoryError> {
        let lineage = self.read_lineage(request.lineage().content_id())?;
        self.verify_campaign_closure(request.lineage().content_id())?;
        let attempt = self.load_attempt(request.attempt())?;
        let start = match attempt.start() {
            AttemptStart::Discover { configuration } => configuration,
            AttemptStart::Branch { parent, .. } => parent,
        };
        let start = self.read_configuration_artifact(start.content_id())?;
        if start.scenario() != lineage.scenario()
            || start.scenario_artifact() != lineage.scenario_content()
        {
            return Err(integrity("executor-attempt-lineage-mismatch"));
        }
        Ok(lineage)
    }

    /// Validates one exact executor response against stored campaign semantics.
    ///
    /// Direct and RPC coordinator adapters call this after the checked
    /// [`crate::ExecutorClient`] exchange and before treating any outcome as an
    /// accepted execution or completion.
    ///
    /// # Errors
    ///
    /// Returns an error when the response belongs to another request, the
    /// lineage or attempt closure is missing or invalid, the attempt is not
    /// compatible with the named lineage, or an already-completed observation
    /// does not authenticate the exact attempt and lineage.
    pub fn validate_executor_response(
        &self,
        request: &SubmitAttemptRequest,
        response: &SubmitAttemptResponse,
    ) -> Result<(), CampaignRepositoryError> {
        response.validate_for(request)?;
        if let SubmitAttemptDisposition::AlreadyCompleted { observation } = response.disposition() {
            return self.validate_executor_completion(request, observation);
        }
        self.validate_executor_request(request)
    }

    /// Authenticates one completed observation against an exact executor request.
    ///
    /// This read-only entry point is used both before a worker publishes durable
    /// completion state and when a restarted executor considers reusing its
    /// operational completion acceleration.
    ///
    /// # Errors
    ///
    /// Returns an error when request input is unavailable or incompatible, the
    /// observation closure is missing or invalid, or its attempt/child does not
    /// belong to the exact request lineage and scenario artifact.
    pub fn validate_executor_completion(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.validate_executor_request_lineage(request)?;
        self.validate_executor_completion_for_lineage(request, observation, &lineage)
    }

    /// Authenticates completion against both campaign semantics and local profile.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::validate_executor_completion`], or an
    /// integrity error when the executor compatibility profile differs from the
    /// request lineage.
    pub fn validate_executor_completion_with_profile(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
        profile: &ExecutorCompatibilityProfile,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.validate_executor_request_lineage(request)?;
        if !profile.admits(&lineage) {
            return Err(integrity("executor-compatibility-profile-mismatch"));
        }
        self.validate_executor_completion_for_lineage(request, observation, &lineage)
    }

    fn validate_executor_completion_for_lineage(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
        lineage: &CampaignLineage,
    ) -> Result<(), CampaignRepositoryError> {
        let observation = self.load_observation(observation)?;
        if observation.attempt() != request.attempt() {
            return Err(integrity("executor-completion-attempt-mismatch"));
        }
        let child = self.read_configuration_artifact(observation.child_content().content_id())?;
        if child.scenario() != lineage.scenario()
            || child.scenario_artifact() != lineage.scenario_content()
        {
            return Err(integrity("executor-completion-lineage-mismatch"));
        }
        Ok(())
    }
}
