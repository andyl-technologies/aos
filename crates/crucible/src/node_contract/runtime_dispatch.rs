//! No-effect preflight, opaque dispatch and original submission reconciliation.

use super::*;
use crate::node_contract::ProgressEvidence;

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

    pub(super) fn begin_with_inputs(
        &mut self,
        activation: &WorldActivation,
        node: &NodeId,
        operation: OperationId,
        request: OperationRequest,
        inputs: Option<Rc<crate::node_scheduling::RuntimeInputBatch>>,
    ) -> Result<BeginResult, RuntimeError> {
        self.begin_with_inputs_and_producer_claim(
            activation, node, operation, request, inputs, None,
        )
    }

    pub(super) fn begin_with_inputs_and_producer_claim(
        &mut self,
        activation: &WorldActivation,
        node: &NodeId,
        operation: OperationId,
        request: OperationRequest,
        inputs: Option<Rc<crate::node_scheduling::RuntimeInputBatch>>,
        producer: Option<&crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>>,
    ) -> Result<BeginResult, RuntimeError> {
        if let Some(claim) = producer {
            if inputs.is_some() {
                return Err(RuntimeError::UnsupportedFacet);
            }
            claim.authenticate_request_data(self, activation, node, &operation, &request)?;
        }
        self.validate_activation(activation)?;
        self.validate_condition_dispatch(node, &operation, &request)?;
        if let Some(terminal) = &self.terminal {
            if !matches!(&request, OperationRequest::FinalizeAssertions { barrier, receipt }
                if barrier.as_ref() == &terminal.saved.record
                    && receipt == &terminal.saved.reference
                    && node == &terminal.saved.record.node
                    && operation == terminal.saved.record.operation)
            {
                return Err(RuntimeError::OutstandingObligations);
            }
        } else if matches!(&request, OperationRequest::FinalizeAssertions { .. }) {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.operations.contains_key(&operation)
            || self.input_batches.contains_key(&operation)
            || self.administrative_operation_used(&operation)
        {
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

        super::final_collection_scope(self.collecting.as_deref())?;
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
        let maximum_publications = producer.map_or(self.limits.maximum_retained_outputs, |claim| {
            claim
                .row_data()
                .provider
                .population_data()
                .newborn_publications_data()
        });
        let maximum_semantic_events = maximum_publications
            .checked_add(
                admission
                    .inputs()
                    .map_or(0, |batch| batch.deliveries().len()),
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        let coordinator_attempt = self.reserve_coordinator_attempt_data(
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentKind17::Begin,
            Some(&operation), Some(node), exact_window(admission.request()).map(|(start, _)| start),
            maximum_semantic_events,
        )?;
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

        // The actual retained entry exists before the callback receives its
        // nonconstructible loan. Recovering a token cannot recreate this scope.
        let retained = self
            .operations
            .get(&operation)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let dispatch = OriginalRuntimeOperationDispatch::from_retained(
            retained,
            &self.authority,
            activation,
            &self.activated,
            &self.barrier,
        )?;
        let submission = match self.nodes.get_mut(node) {
            Some(handle) => match producer {
                Some(claim) => handle.begin_original_restored_producer_operation(&dispatch, claim),
                None => handle.begin_original_retained_operation(&dispatch),
            },
            None => return Err(RuntimeError::UnknownNode),
        };
        let coordinator_state = match &submission {
            Submission::Refused(_) => crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Refused,
            Submission::Accepted => crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Committed,
            Submission::Uncertain(_) => crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Uncertain,
        };
        let result: Result<BeginResult, RuntimeError> = match submission {
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
        };
        // Native disposition is retained in the existing operation owners
        // before a fallible coordinator-currentness recheck can refuse.
        if let Err(error) =
            self.finish_coordinator_attempt_data(coordinator_attempt, coordinator_state)
        {
            self.contain_roster(admission.token.route());
            return Err(error);
        }
        result
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
        if matches!(result, Err(_) | Ok(BeginResult::Refused(_)))
            && let Some(state) = &self.scheduler
            && let Some(mut scheduler) = state.borrow_if_initialized()?
        {
            scheduler
                .reconcile_no_effect(&admission)
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
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
                || self.administrative_operation_used(admission.operation())
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
        self.scheduling_receipt_with_producer_claim(token, None)
    }

    pub(crate) fn scheduling_receipt_with_producer_claim(
        &self,
        token: &OperationToken,
        claim: Option<&crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>>,
    ) -> Result<crate::node_scheduling::SchedulingReceipt, RuntimeError> {
        self.validate_token(token)?;
        self.authenticate_original_restored_producer_runtime_callback_data(
            token,
            claim,
            crate::node_admission::ProducerExecutionPhase::Publication,
        )?;
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .current()?;
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
        let evaluations = self.authenticate_deferred_evaluations(token, outcome)?;
        let activation = self.barrier.activation(&self.authority);
        Ok(crate::node_scheduling::SchedulingReceipt::new(
            activation,
            token.route.node.clone(),
            token.operation.clone(),
            outcome.progress.clone(),
            outcome.retained_outputs.clone(),
            outcome.scheduling.clone(),
        )
        .retain_deferred_evaluations(evaluations))
    }

    fn authenticate_deferred_evaluations(
        &self,
        token: &OperationToken,
        outcome: &OperationOutcome,
    ) -> Result<Vec<crate::node_scheduling::DeferredPublicationAuthorization>, RuntimeError> {
        use crate::node_scheduling::DeferredPublicationAuthorization;
        let current = self
            .operations
            .get(token.operation())
            .ok_or(RuntimeError::ForeignAuthority)?;
        let Some(observation) = outcome.scheduling.as_ref() else {
            return Ok(Vec::new());
        };
        if observation.publications.len() > self.limits.maximum_retained_outputs {
            return Err(RuntimeError::ResourceLimit);
        }
        let Some((start, _)) = exact_window(current.admission.request()) else {
            return Ok(Vec::new());
        };
        let node = self
            .nodes
            .get(&token.route.node)
            .ok_or(RuntimeError::UnknownNode)?;
        let snapshot = self
            .snapshots
            .get(&token.route.node)
            .ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(node.as_ref())?;
        let mut authorized = Vec::new();
        authorized
            .try_reserve_exact(observation.publications.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut remaining_parents = crucible_node_contract::MAX_ARRAY_ELEMENTS;
        for publication in &observation.publications {
            let Some(evaluation) = publication
                .evaluation
                .filter(|evaluation| *evaluation < start)
            else {
                continue;
            };
            remaining_parents = remaining_parents
                .checked_sub(publication.causal_parents.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            let mut original_prior = None;
            for prior in self.operations.values() {
                let RetainedResult::Acknowledged(prior_outcome) = &prior.result else {
                    continue;
                };
                let Some((prior_start, prior_limit)) = exact_window(prior.admission.request())
                else {
                    continue;
                };
                if prior.admission.token().route != token.route
                    || !Rc::ptr_eq(
                        &prior.admission.activation().authority,
                        &current.admission.activation().authority,
                    )
                    || prior.admission.activation().record()
                        != current.admission.activation().record()
                    || prior.scheduling_commit.is_none()
                    || evaluation < prior_start
                    || evaluation >= prior_limit
                    || !matches!(prior_outcome.progress, ProgressEvidence::Exact { reached, .. } if evaluation < reached && reached <= start)
                {
                    continue;
                }
                snapshot.validate_current(node.as_ref())?;
                match node.validate_deferred_original_publication(
                    &current.admission,
                    outcome,
                    publication,
                    &prior.admission,
                    prior_outcome,
                ) {
                    Ok(()) => {
                        if original_prior.is_some() {
                            return Err(RuntimeError::InvalidReceipt);
                        }
                        original_prior = Some(prior.admission.token().operation());
                    }
                    Err(OperationFailure {
                        effects: EffectKnowledge::None,
                        ..
                    }) => {}
                    Err(_) => {
                        // Native uncertainty cannot become a candidate miss or
                        // renewed permission on a later read. Revoke the same
                        // original slot, retaining its queues and all custody.
                        self.scheduler
                            .as_ref()
                            .ok_or(RuntimeError::NotActivated)?
                            .revoke();
                        return Err(RuntimeError::InvalidReceipt);
                    }
                }
                snapshot.validate_current(node.as_ref())?;
            }
            let prior = original_prior.ok_or(RuntimeError::UnsupportedFacet)?;
            authorized.push(DeferredPublicationAuthorization::new(publication, prior));
        }
        snapshot.validate_current(node.as_ref())?;
        Ok(authorized)
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
        let coordinator_attempt = self.reserve_coordinator_attempt_data(
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentKind17::Observe,
            None, Some(node), None, 0,
        ).map_err(RuntimePollFailure::Admission)?;
        let result = (|| {
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
            self.finish_coordinator_attempt_with_evidence_data(
            coordinator_attempt,
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Committed,
            Some(&observation.proof_ref),
        ).map_err(RuntimePollFailure::Admission)?;
            Ok(crate::node_scheduling::ValidatedSchedulingObservation::new(
                activation.clone(),
                observation,
            ))
        })();
        if result.is_err() {
            self.finish_coordinator_runtime_result_data(coordinator_attempt, &result)
                .map_err(RuntimePollFailure::Admission)?;
        }
        result
    }

    pub(crate) fn observe_original_installed_first_scheduling(
        &mut self,
        activation: &WorldActivation,
        node: &NodeId,
    ) -> Result<(), RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        let route = self
            .checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_owners_available(&route)
            .map_err(RuntimePollFailure::Admission)?;
        let coordinator_attempt = self.reserve_coordinator_attempt_data(
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentKind17::Observe,
            None, Some(node), None, 0,
        ).map_err(RuntimePollFailure::Admission)?;
        let result = (|| {
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
                return Err(RuntimePollFailure::Native(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: crate::node_admission::OriginalRestoredSchedulingObservationClaim::RECEIPT_FAILURE.into(),
            }));
            }
            self.finish_coordinator_attempt_with_evidence_data(
            coordinator_attempt,
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Committed,
            Some(&observation.proof_ref),
        ).map_err(RuntimePollFailure::Admission)?;
            Ok(())
        })();
        if result.is_err() {
            self.finish_coordinator_runtime_result_data(coordinator_attempt, &result)
                .map_err(RuntimePollFailure::Admission)?;
        }
        result
    }

    pub(crate) fn observe_scheduling_with_original_claim(
        &mut self,
        activation: &WorldActivation,
        node: &NodeId,
        claim: &crate::node_admission::OriginalRestoredSchedulingObservationClaim<'_>,
    ) -> Result<crate::node_scheduling::ValidatedSchedulingObservation, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        let route = self
            .checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_owners_available(&route)
            .map_err(RuntimePollFailure::Admission)?;
        claim
            .authenticate_runtime_data(self, &route)
            .map_err(RuntimePollFailure::Admission)?;
        if !claim.world_data().same_authority(activation) {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let coordinator_attempt = self.reserve_coordinator_attempt_data(
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentKind17::Observe,
            None, Some(node), None, 0,
        ).map_err(RuntimePollFailure::Admission)?;
        let result = (|| {
            let handle = self
                .nodes
                .get_mut(node)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let observation = handle
                .observe_original_restored_scheduling(claim)
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
                return Err(RuntimePollFailure::Native(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: crate::node_admission::OriginalRestoredSchedulingObservationClaim::RECEIPT_FAILURE.into(),
            }));
            }
            self.finish_coordinator_attempt_with_evidence_data(
            coordinator_attempt,
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Committed,
            Some(&observation.proof_ref),
        ).map_err(RuntimePollFailure::Admission)?;
            Ok(crate::node_scheduling::ValidatedSchedulingObservation::new(
                activation.clone(),
                observation,
            ))
        })();
        if result.is_err() {
            self.finish_coordinator_runtime_result_data(coordinator_attempt, &result)
                .map_err(RuntimePollFailure::Admission)?;
        }
        result
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
            .retained()?
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
        self.commit_scheduling_receipt_with_producer_claim(receipt, None)
    }

    pub(crate) fn commit_scheduling_receipt_with_producer_claim(
        &mut self,
        receipt: crate::node_scheduling::SchedulingReceipt,
        claim: Option<&crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>>,
    ) -> Result<crate::node_scheduling::SchedulingCommit, RuntimeError> {
        self.validate_activation(&receipt.activation)?;
        let entry = self
            .operations
            .get(&receipt.operation)
            .ok_or(RuntimeError::OutstandingObligations)?;
        self.authenticate_original_restored_producer_runtime_callback_data(
            entry.admission.token(),
            claim,
            crate::node_admission::ProducerExecutionPhase::Publication,
        )?;
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
        let scheduling = self.scheduler.as_ref().ok_or(RuntimeError::NotActivated)?;
        let commit = scheduling.with_coordinator17_data(|log| {
            scheduling
                .borrow_mut()?
                .accept_receipt_with_coordinator17_data(receipt, log)
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))
        })?;
        let entry = self
            .operations
            .get_mut(&operation)
            .ok_or(RuntimeError::ForeignAuthority)?;
        entry.scheduling_commit = Some(commit.retained_copy());
        Ok(commit)
    }
}

fn exact_window(
    request: &OperationRequest,
) -> Option<(
    crucible_node_contract::Position,
    crucible_node_contract::Position,
)> {
    match request {
        OperationRequest::ExactRun { start, limit, .. }
        | OperationRequest::BoundarySettle { start, limit } => Some((*start, *limit)),
        _ => None,
    }
}
