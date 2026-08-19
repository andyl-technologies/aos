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
        Ok(())
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
        self.validate_executor_request(request)?;

        if let SubmitAttemptDisposition::AlreadyCompleted { observation } = response.disposition() {
            let lineage = self.read_lineage(request.lineage().content_id())?;
            let observation = self.load_observation(observation)?;
            if observation.attempt() != request.attempt() {
                return Err(integrity("executor-completion-attempt-mismatch"));
            }
            let child =
                self.read_configuration_artifact(observation.child_content().content_id())?;
            if child.scenario() != lineage.scenario()
                || child.scenario_artifact() != lineage.scenario_content()
            {
                return Err(integrity("executor-completion-lineage-mismatch"));
            }
        }

        Ok(())
    }
}
