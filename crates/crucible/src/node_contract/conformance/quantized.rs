//! Authenticated internal input staging and original quantized collection grants.

use crucible_node_contract::{Id, Position};

use super::*;

impl ConformanceRuntime {
    /// Owns a separately authorized internal-input quantized collection lifecycle.
    ///
    /// Exact producers may share this world, but every input-bearing owner must
    /// select Quantized. External-input topology is unchanged. Installed plan
    /// authorization and each native input/operation callback default to refusal.
    ///
    /// # Errors
    /// Retains every supplied original on changed policy, unsupported input mode,
    /// missing actual source custody or ordinary runtime admission failure.
    pub fn from_prepared_quantized(
        graph: ConformanceGraph,
        prepared: PreparedRealization,
    ) -> Result<Self, ConformanceRuntimeFailure> {
        Self::from_prepared_scope(graph, prepared, true)
    }

    /// Stages the scheduler's same complete original input cut and commits its ACK.
    ///
    /// The scheduler requires the cutoff immediately after the quantized start.
    /// Staging transfers custody only. Begin consumes this exact batch later;
    /// failed or uncertain native staging never creates a replacement batch.
    ///
    /// # Errors
    /// Refuses unavailable quantized authorization, incomplete producer closure,
    /// changed input bodies/cut, reused identities, finite-credit exhaustion or
    /// uncertain native Stage/ACK. Original obligations remain retained.
    pub fn stage_quantized_inputs(
        &mut self,
        node: &Id,
        stage_operation: Id,
        batch: Id,
        cutoff: Position,
    ) -> Result<(), RuntimePollFailure> {
        self.current().map_err(RuntimePollFailure::Admission)?;
        if !self.quantized {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        self.graph
            .authenticate_quantized()
            .map_err(policy_failure)?;
        let activation = self
            .activation
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?;
        let original = self
            .runtime
            .scheduler(&self.graph.graph, activation)
            .map_err(RuntimePollFailure::Admission)?
            .prepare_input_batch(node, stage_operation, batch, cutoff)
            .map_err(scheduler_failure)?;
        let authenticated = self
            .graph
            .authenticate_inputs(&original)
            .map_err(policy_failure);
        let authenticated = authenticated
            .and_then(|()| self.native_current().map_err(RuntimePollFailure::Admission));
        if let Err(error) = authenticated {
            // No Stage has occurred. Reconcile only this authentic reservation,
            // preserving the scheduler's original used-identity history.
            self.runtime
                .scheduler(
                    &self.graph.graph,
                    self.activation
                        .as_ref()
                        .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?,
                )
                .map_err(RuntimePollFailure::Admission)?
                .reconcile_input_no_effect(&original)
                .map_err(scheduler_failure)?;
            return Err(error);
        }

        let acknowledgement = self.runtime.stage_inputs(original)?;
        self.current().map_err(RuntimePollFailure::Admission)?;
        let commit = self.runtime.commit_input_acknowledgement(acknowledgement)?;
        self.current().map_err(RuntimePollFailure::Admission)?;
        self.runtime.commit_input_staging(&commit)
    }

    /// Begins a single original window using its already staged and ACKed batch.
    ///
    /// # Errors
    /// Refuses missing original Stage/ACK, changed complete plan or grant,
    /// unsafe boundary closure, duplicate identity or exhausted native credits.
    pub fn begin_quantized(
        &mut self,
        node: &Id,
        operation: Id,
        window: Id,
        input_batch: Id,
    ) -> Result<BeginResult, RuntimeError> {
        self.current()?;
        if !self.quantized {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.graph
            .authenticate_quantized()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        let activation = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        let original = self
            .runtime
            .scheduler(&self.graph.graph, activation)?
            .admit_quantum(node, operation, window, input_batch)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        let authenticated = self
            .graph
            .authenticate_operation(node, original.operation(), &original.request())
            .map_err(|error| RuntimeError::SchedulerRefused(error.message));
        let authenticated = authenticated.and_then(|()| self.native_current());
        if let Err(error) = authenticated {
            self.runtime
                .scheduler(
                    &self.graph.graph,
                    self.activation.as_ref().ok_or(RuntimeError::NotActivated)?,
                )?
                .reconcile_no_effect(&original)
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
            return Err(error);
        }
        self.runtime.begin_admitted(original)
    }

    /// Closes the same retained quantized window without another Begin.
    ///
    /// # Errors
    /// Refuses changed current plan/source/grant, foreign token or unsupported
    /// mode. Uncertain native close retains the same original window and owners.
    pub fn close_quantum(&mut self, token: &OperationToken) -> Result<Submission, RuntimeError> {
        self.current_operation(token)?;
        if !self.quantized {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.graph
            .authenticate_quantized()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        self.native_current()?;
        self.runtime.close_quantum(token)
    }
}

fn policy_failure(error: crate::node_admission::EvidenceError) -> RuntimePollFailure {
    RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.message))
}

fn scheduler_failure(error: crate::node_scheduling::SchedulingError) -> RuntimePollFailure {
    RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.to_string()))
}
