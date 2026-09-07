//! Repository-backed validation for local executor protocol responses.
//!
//! Component-message validation proves an exact request/response exchange.
//! This owner layer additionally authenticates the named campaign records and
//! prevents an executor from treating an observation from another attempt or
//! lineage as completion.

use super::*;

impl CampaignRepository {
    /// Authenticates the operational scope of one executor request.
    ///
    /// Semantic requests need no authority beyond ordinary immutable attempt
    /// admission. A savepoint capture must name an exact persisted capture
    /// request whose parent snapshot, lineage, configuration, attempt, and stop
    /// boundary all reconstruct consistently.
    ///
    /// # Errors
    ///
    /// Returns an error when a scoped owner fact or its parent closure is
    /// unavailable, corrupt, incompatible with the request, or outside the
    /// supplied executor profile.
    pub fn validate_executor_execution_scope_with_profile(
        &self,
        request: &SubmitAttemptRequest,
        profile: &ExecutorCompatibilityProfile,
    ) -> Result<(), CampaignRepositoryError> {
        let AttemptStartMode::SavepointCapture {
            request: capture_id,
            configuration,
        } = request.start_mode()
        else {
            return Ok(());
        };

        let CampaignFact::SavepointCaptureRequested(capture) =
            self.read_fact(capture_id.content_id())?
        else {
            return Err(integrity(
                "executor-savepoint-capture-scope-is-not-capture-request",
            ));
        };
        if capture.configuration != configuration || capture.attempt != request.attempt() {
            return Err(integrity(
                "executor-savepoint-capture-scope-request-basis-mismatch",
            ));
        }

        let parent = self.read_snapshot(capture.expected_snapshot.content_id())?;
        self.validate_complete_head(capture.expected_snapshot.content_id())?;
        if parent.snapshot.lineage() != request.lineage() {
            return Err(integrity(
                "executor-savepoint-capture-scope-lineage-mismatch",
            ));
        }
        let attempt = self.savepoint_capture_basis(&parent, &capture)?;
        if attempt.id()? != request.attempt() {
            return Err(integrity(
                "executor-savepoint-capture-scope-attempt-mismatch",
            ));
        }

        let lineage = self.read_lineage(parent.snapshot.lineage().content_id())?;
        if !profile.admits(&lineage) {
            return Err(integrity("executor-compatibility-profile-mismatch"));
        }
        Ok(())
    }

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
            AttemptStart::Branch {
                parent, selection, ..
            } => {
                let selection = self.resolve_selection(selection)?;
                if selection.opportunity().scenario() != lineage.scenario() {
                    return Err(integrity("executor-attempt-opportunity-scenario-mismatch"));
                }
                parent
            }
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
            self.validate_executor_completion(request, observation)?;
            return self
                .validate_executor_finding_candidate(observation, response.finding_candidate());
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
        self.validate_executor_completion_for_lineage(request.attempt(), observation, &lineage)
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
        self.validate_executor_completion_for_lineage(request.attempt(), observation, &lineage)
    }

    /// Authenticates every immutable root reported for one completion.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`Self::validate_executor_completion_with_profile`], or a closure and
    /// basis error when the optional candidate is incomplete or names another
    /// observation.
    pub fn validate_executor_completion_artifacts_with_profile(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
        profile: &ExecutorCompatibilityProfile,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_executor_completion_with_profile(request, observation, profile)?;
        self.validate_executor_finding_candidate(observation, finding_candidate)
    }

    /// Authenticates a retained completion without reconstructing an assignment.
    ///
    /// Status and control requests retain the lineage, attempt, and execution
    /// basis but deliberately omit assignment-local resource fields. This check
    /// authenticates the semantic lineage and attempt directly, requires the
    /// local compatibility profile, and validates every reported completion
    /// root.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the lineage, attempt, observation, or
    /// optional candidate closure is unavailable, corrupt, or incompatible.
    pub fn validate_retained_executor_completion_with_profile(
        &self,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
        profile: &ExecutorCompatibilityProfile,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage_record = self.read_lineage(lineage.content_id())?;
        self.verify_campaign_closure(lineage.content_id())?;
        self.load_attempt(attempt)?;
        if !profile.admits(&lineage_record) {
            return Err(integrity("executor-compatibility-profile-mismatch"));
        }
        self.validate_executor_completion_for_lineage(attempt, observation, &lineage_record)?;
        self.validate_executor_finding_candidate(observation, finding_candidate)
    }

    fn validate_executor_completion_for_lineage(
        &self,
        attempt: AttemptId,
        observation: ObservationId,
        lineage: &CampaignLineage,
    ) -> Result<(), CampaignRepositoryError> {
        let observation = self.load_observation(observation)?;
        if observation.attempt() != attempt {
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

    fn validate_executor_finding_candidate(
        &self,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(candidate) = finding_candidate else {
            return Ok(());
        };
        let bundle = self.load_finding_candidate_bundle(candidate)?;
        if bundle.observation() != observation {
            return Err(integrity("executor-completion-finding-candidate-mismatch"));
        }
        Ok(())
    }
}
