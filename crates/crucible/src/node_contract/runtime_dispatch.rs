//! No-effect preflight, opaque dispatch and original submission reconciliation.

use super::*;

impl NodeRuntime {
    // Model fixtures exercise owner/lifecycle mechanics independently of a
    // causal scheduler. Production dispatch always consumes an opaque grant.
    #[cfg(test)]
    pub(crate) fn begin(
        &mut self,
        activation: &WorldActivation,
        node: &NodeId,
        operation: OperationId,
        request: OperationRequest,
    ) -> Result<BeginResult, RuntimeError> {
        self.begin_with_inputs(activation, node, operation, request, None)
    }

    fn begin_with_inputs(
        &mut self,
        activation: &WorldActivation,
        node: &NodeId,
        operation: OperationId,
        request: OperationRequest,
        inputs: Option<Rc<crate::node_scheduling::RuntimeInputBatch>>,
    ) -> Result<BeginResult, RuntimeError> {
        self.validate_activation(activation)?;
        if self.operations.contains_key(&operation) || self.input_batches.contains_key(&operation) {
            return Err(RuntimeError::DuplicateOperation);
        }
        if self
            .operations
            .len()
            .saturating_add(self.input_batches.len())
            >= self.limits.maximum_operations
        {
            return Err(RuntimeError::ResourceLimit);
        }

        let route = self.checked_route(node)?;
        let handle = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        validate_request(handle.as_ref(), &request)?;
        self.validate_owners_available(&route)?;
        if let Some(kind) = request.required_facet() {
            let _ = self.facet(node, kind)?;
        }

        let token = OperationToken {
            authority: Rc::clone(&self.authority),
            operation: operation.clone(),
            route,
        };
        let admission = OperationAdmission {
            token: token.clone(),
            request,
            activation: activation.clone(),
            inputs,
        };
        self.reserve(&token);
        self.operations.insert(
            operation.clone(),
            RetainedOperation {
                admission: admission.clone(),
                result: RetainedResult::Pending,
                close_submission: None,
                submission_effects: None,
                scheduling_commit: None,
            },
        );

        let submission = match self.nodes.get_mut(node) {
            Some(handle) => handle.begin_operation(&admission),
            None => return Err(RuntimeError::UnknownNode),
        };
        match submission {
            Submission::Refused(refusal) => {
                self.release_reservation(&token);
                // Retain the used identity: a retry must not become a fresh mutation.
                if let Some(operation) = self.operations.get_mut(&operation) {
                    operation.result = RetainedResult::Failed(OperationFailure {
                        effects: EffectKnowledge::None,
                        reason: refusal.reason.clone(),
                    });
                }
                Ok(BeginResult::Refused(refusal))
            }
            Submission::Accepted => Ok(BeginResult::Accepted(token)),
            Submission::Uncertain(effects) => {
                if let Some(entry) = self.operations.get_mut(&operation) {
                    entry.submission_effects = Some(effects.clone());
                }
                self.contain_roster(token.route());
                Ok(BeginResult::Uncertain { token, effects })
            }
        }
    }

    /// Recovers the original token without resubmitting native work.
    ///
    /// # Errors
    /// Returns an unknown-operation error when no original ledger entry exists.
    pub fn recover(&self, operation: &OperationId) -> Result<OperationToken, RuntimeError> {
        self.operations
            .get(operation)
            .map(|entry| entry.admission.token.clone())
            .ok_or(RuntimeError::ForeignAuthority)
    }

    /// Recovers the original committed publication authority without republishing.
    ///
    /// The runtime retains this evidence after the caller drops its token or a
    /// native acknowledgement fails. Recovered handles only retry the original
    /// idempotent native acknowledgement; they cannot add or reorder outputs.
    ///
    /// # Errors
    /// Refuses foreign tokens and operations whose canonical publication has
    /// not yet committed through the retained scheduler.
    pub fn recover_scheduling_commit(
        &self,
        token: &OperationToken,
    ) -> Result<crate::node_scheduling::SchedulingCommit, RuntimeError> {
        self.validate_token(token)?;
        self.operations
            .get(token.operation())
            .and_then(|entry| entry.scheduling_commit.as_ref())
            .map(crate::node_scheduling::SchedulingCommit::retained_copy)
            .ok_or(RuntimeError::OutstandingObligations)
    }

    /// Begins one opaque scheduler-authorized exact or quantized operation.
    ///
    /// # Errors
    /// Refuses invalid activation, owner custody, selected modes or original
    /// operation identities before native effects begin.
    pub fn begin_admitted(
        &mut self,
        admission: crate::node_scheduling::ExecutionAdmission,
    ) -> Result<BeginResult, RuntimeError> {
        let inputs = self.execution_inputs(&admission);
        let result = inputs.and_then(|inputs| {
            self.begin_with_inputs(
                admission.activation(),
                admission.node(),
                admission.operation().clone(),
                admission.request(),
                inputs,
            )
        });
        if matches!(result, Err(_) | Ok(BeginResult::Refused(_))) {
            if let Some(scheduler) = &mut self.scheduler {
                scheduler
                    .reconcile_no_effect(&admission)
                    .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
            }
        }
        result
    }

    /// Validates a complete disjoint dispatch round before any native effects.
    ///
    /// Returned routes are immutable observations, not independent mutation
    /// authority. Every dispatch still consumes its original opaque admission.
    /// Shared capture owners participate in exclusivity as well as execution
    /// owners, including aliases exposed through different public components.
    ///
    /// # Errors
    /// Refuses foreign worlds, stale bindings, reused identities, conflicting
    /// owners, unsupported facets and resource ceilings before dispatch begins.
    pub fn validate_admitted_batch(
        &mut self,
        admissions: &[crate::node_scheduling::ExecutionAdmission],
    ) -> Result<Vec<NodeRoute>, RuntimeError> {
        if self
            .operations
            .len()
            .checked_add(self.input_batches.len())
            .and_then(|count| count.checked_add(admissions.len()))
            .is_none_or(|count| count > self.limits.maximum_operations)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut operations = std::collections::BTreeSet::new();
        let mut owners = std::collections::BTreeSet::new();
        let mut domains = std::collections::BTreeSet::new();
        let mut routes = Vec::with_capacity(admissions.len());
        for admission in admissions {
            self.validate_activation(admission.activation())?;
            let _ = self.execution_inputs(admission)?;
            if self.operations.contains_key(admission.operation())
                || self.input_batches.contains_key(admission.operation())
                || !operations.insert(admission.operation().clone())
            {
                return Err(RuntimeError::DuplicateOperation);
            }
            let route = self.checked_route(admission.node())?;
            self.validate_owners_available(&route)?;
            if route
                .owners
                .iter()
                .any(|owner| !owners.insert(owner.owner.clone()))
            {
                return Err(RuntimeError::OwnerBusy);
            }
            let route_domains = self.route_domains(&route);
            if !domains.is_disjoint(&route_domains) {
                return Err(RuntimeError::OwnerBusy);
            }
            domains.extend(route_domains);
            let request = admission.request();
            let node = self
                .nodes
                .get(admission.node())
                .ok_or(RuntimeError::UnknownNode)?;
            validate_request(node.as_ref(), &request)?;
            if let Some(kind) = request.required_facet() {
                let _ = self.facet(admission.node(), kind)?;
            }
            routes.push(route);
        }

        Ok(routes)
    }

    /// Returns opaque scheduling evidence for a validated retained completion.
    ///
    /// # Errors
    /// Refuses foreign tokens, incomplete or failed native evidence, and unknown
    /// world activation. ID-only outputs remain subject to scheduler refusal
    /// until their complete canonical coordinates can be established.
    pub fn scheduling_receipt(
        &self,
        token: &OperationToken,
    ) -> Result<crate::node_scheduling::SchedulingReceipt, RuntimeError> {
        self.validate_token(token)?;
        if !self.activated {
            return Err(RuntimeError::NotActivated);
        }
        let outcome = match self
            .operations
            .get(token.operation())
            .map(|entry| &entry.result)
        {
            Some(RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome)) => {
                outcome
            }
            _ => return Err(RuntimeError::OutstandingObligations),
        };
        let activation = WorldActivation {
            authority: Rc::clone(&self.authority),
            record: self.barrier.record().clone(),
        };
        Ok(crate::node_scheduling::SchedulingReceipt::new(
            activation,
            token.route.node.clone(),
            token.operation.clone(),
            outcome.progress.clone(),
            outcome.retained_outputs.clone(),
            outcome.scheduling.clone(),
        ))
    }

    /// Observes native producer closure while retaining stopped owner custody.
    ///
    /// # Errors
    /// Refuses inactive or foreign worlds, busy domains, changed owner bindings,
    /// unsupported observations and incomplete or unauthenticated native evidence.
    pub fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
        node: &NodeId,
    ) -> Result<crate::node_scheduling::ValidatedSchedulingObservation, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        let route = self
            .checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_owners_available(&route)
            .map_err(RuntimePollFailure::Admission)?;
        let handle = self
            .nodes
            .get_mut(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let observation = handle
            .observe_scheduling(activation)
            .map_err(RuntimePollFailure::Native)?;
        if observation.node != *node
            || observation.owners != route.owners
            || observation.bounds.len() > self.limits.maximum_nodes
            || observation.publications.len() > self.limits.maximum_retained_outputs
            || handle
                .validate_scheduling_observation(activation, &observation)
                .is_err()
        {
            self.contain_roster(&route);
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        Ok(crate::node_scheduling::ValidatedSchedulingObservation::new(
            activation.clone(),
            observation,
        ))
    }

    pub(crate) fn preflight_scheduling_receipts(
        &self,
        tokens: &[&OperationToken],
    ) -> Result<(), RuntimeError> {
        let receipts = tokens
            .iter()
            .map(|token| self.scheduling_receipt(token))
            .collect::<Result<Vec<_>, _>>()?;
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .preflight_receipts(&receipts)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))
    }

    /// Commits validated original native evidence through the retained scheduler.
    ///
    /// # Errors
    /// Refuses foreign activation or receipts, missing original retained evidence,
    /// an absent scheduler, and incomplete canonical publication or input custody.
    pub fn commit_scheduling_receipt(
        &mut self,
        receipt: crate::node_scheduling::SchedulingReceipt,
    ) -> Result<crate::node_scheduling::SchedulingCommit, RuntimeError> {
        self.validate_activation(&receipt.activation)?;
        let original = match self
            .operations
            .get(&receipt.operation)
            .map(|entry| &entry.result)
        {
            Some(RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome)) => {
                outcome
            }
            _ => return Err(RuntimeError::OutstandingObligations),
        };
        if original.node != receipt.node
            || original.progress != receipt.progress
            || original.retained_outputs != receipt.retained_outputs
            || original.scheduling != receipt.observation
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        if let Some(commit) = self
            .operations
            .get(&receipt.operation)
            .and_then(|entry| entry.scheduling_commit.as_ref())
        {
            return Ok(commit.retained_copy());
        }
        let operation = receipt.operation.clone();
        let commit = self
            .scheduler
            .as_mut()
            .ok_or(RuntimeError::NotActivated)?
            .accept_receipt(receipt)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        let entry = self
            .operations
            .get_mut(&operation)
            .ok_or(RuntimeError::ForeignAuthority)?;
        entry.scheduling_commit = Some(commit.retained_copy());
        Ok(commit)
    }
}
