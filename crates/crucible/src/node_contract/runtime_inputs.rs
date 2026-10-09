//! Original immutable input staging, authenticated acknowledgement and custody.

use crucible_node_contract::{Id, Validate};

use super::*;
use crate::node_scheduling::{
    NativeInputAcknowledgement, RuntimeInputBatch, ValidatedInputAcknowledgement,
};

pub(super) struct RetainedInput {
    pub(super) batch: RuntimeInputBatch,
    pub(super) acknowledgement: Option<NativeInputAcknowledgement>,
    pub(super) failure: Option<OperationFailure>,
    pub(super) committed: bool,
    pub(super) commit: Option<crate::node_scheduling::InputCustodyCommit>,
}

impl NodeRuntime {
    /// Stages an original opaque complete input cut without semantic execution.
    ///
    /// Native acknowledgement is not modeled delivery. Owner/domain reservations
    /// remain held until the scheduler durably accepts original custody through
    /// [`Self::commit_input_staging`]. A lost result is recovered by observation;
    /// this method never repeats a used staging identity.
    ///
    /// # Errors
    /// Refuses foreign activation, changed routes, reused staging/batch identities,
    /// busy owners or resource ceilings before native effects. Failed native
    /// staging retains the original batch; uncertain effects quarantine owners.
    pub fn stage_inputs(
        &mut self,
        batch: RuntimeInputBatch,
    ) -> Result<ValidatedInputAcknowledgement, RuntimePollFailure> {
        let checked = (|| -> Result<(NodeRoute, OperationToken), RuntimePollFailure> {
            self.validate_activation(batch.activation())
                .map_err(RuntimePollFailure::Admission)?;
            if self.operations.contains_key(batch.stage_operation())
                || self.input_batches.contains_key(batch.stage_operation())
                || self
                    .input_batches
                    .values()
                    .any(|input| input.batch.batch() == batch.batch())
            {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::DuplicateOperation,
                ));
            }
            if self
                .operations
                .len()
                .checked_add(self.input_batches.len())
                .is_none_or(|count| count >= self.limits.maximum_operations)
                || batch.deliveries().len() > self.limits.maximum_retained_outputs
                || batch.payloads().len() > self.limits.maximum_retained_outputs
            {
                return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
            }
            let route = self
                .checked_route(batch.node())
                .map_err(RuntimePollFailure::Admission)?;
            if route.owners != batch.owners() {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidRoute));
            }
            self.validate_owners_available(&route)
                .map_err(RuntimePollFailure::Admission)?;
            let token = OperationToken {
                authority: Rc::clone(&self.authority),
                operation: batch.stage_operation().clone(),
                route: route.clone(),
            };
            Ok((route, token))
        })();
        let (route, token) = match checked {
            Ok(checked) => checked,
            Err(error) => {
                if let Some(scheduler) = &mut self.scheduler {
                    scheduler
                        .reconcile_input_no_effect(&batch)
                        .map_err(|failure| {
                            RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(
                                failure.to_string(),
                            ))
                        })?;
                }
                return Err(error);
            }
        };
        self.reserve(&token);
        let operation = batch.stage_operation().clone();
        self.input_batches.insert(
            operation.clone(),
            RetainedInput {
                batch,
                acknowledgement: None,
                failure: None,
                committed: false,
                commit: None,
            },
        );

        let result = match (
            self.nodes.get_mut(&route.node),
            self.input_batches.get(&operation),
        ) {
            (Some(node), Some(retained)) => node.stage_inputs(&retained.batch),
            _ => Err(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "original staged-input custody disappeared".into(),
            }),
        };
        match result {
            Ok(acknowledgement) => {
                let valid = match (
                    self.nodes.get(&route.node),
                    self.input_batches.get(&operation),
                ) {
                    (Some(node), Some(retained)) => {
                        valid_ack(&retained.batch, &acknowledgement)
                            && node
                                .validate_input_acknowledgement(&retained.batch, &acknowledgement)
                                .is_ok()
                    }
                    _ => false,
                };
                if !valid {
                    let failure = OperationFailure {effects: EffectKnowledge::Unknown,
                        reason: "native acknowledgement does not authenticate the original complete input cut".into()};
                    if let Some(retained) = self.input_batches.get_mut(&operation) {
                        retained.acknowledgement = Some(acknowledgement);
                        retained.failure = Some(failure);
                    }
                    self.contain_roster(&route);
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
                let retained =
                    self.input_batches
                        .get_mut(&operation)
                        .ok_or(RuntimePollFailure::Admission(
                            RuntimeError::ForeignAuthority,
                        ))?;
                retained.acknowledgement = Some(acknowledgement.clone());
                Ok(ValidatedInputAcknowledgement::new(
                    retained.batch.activation().clone(),
                    acknowledgement,
                ))
            }
            Err(failure) => {
                if let Some(retained) = self.input_batches.get_mut(&operation) {
                    retained.failure = Some(failure.clone());
                }
                if failure.effects == EffectKnowledge::None {
                    self.release_reservation(&token);
                    if let (Some(scheduler), Some(retained)) =
                        (&mut self.scheduler, self.input_batches.get(&operation))
                    {
                        scheduler
                            .reconcile_input_no_effect(&retained.batch)
                            .map_err(|error| {
                                RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(
                                    error.to_string(),
                                ))
                            })?;
                    }
                } else {
                    self.contain_roster(&route);
                }
                Err(RuntimePollFailure::Native(failure))
            }
        }
    }

    /// Recovers authenticated original native staging evidence without restaging.
    ///
    /// # Errors
    /// Refuses unknown or failed staging, foreign activation, unavailable native
    /// custody, or an acknowledgement that no longer covers the original buffers.
    pub fn recover_input_staging(
        &mut self,
        activation: &WorldActivation,
        stage_operation: &Id,
    ) -> Result<ValidatedInputAcknowledgement, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        let retained =
            self.input_batches
                .get(stage_operation)
                .ok_or(RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                ))?;
        if let Some(failure) = &retained.failure {
            return Err(RuntimePollFailure::Native(failure.clone()));
        }
        let node_id = retained.batch.node().clone();
        let route = self
            .checked_route(&node_id)
            .map_err(RuntimePollFailure::Admission)?;
        if route.owners.iter().any(|owner| {
            self.owners.get(&owner.owner).is_none_or(|custody| {
                custody.lifecycle == Lifecycle::Quarantined
                    || custody.lifecycle == Lifecycle::Released
            })
        }) {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable,
            ));
        }
        let retained =
            self.input_batches
                .get(stage_operation)
                .ok_or(RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                ))?;
        let acknowledgement =
            retained
                .acknowledgement
                .as_ref()
                .ok_or(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ))?;
        let valid = self.nodes.get(&node_id).is_some_and(|node| {
            valid_ack(&retained.batch, acknowledgement)
                && node
                    .validate_input_acknowledgement(&retained.batch, acknowledgement)
                    .is_ok()
        });
        if !valid {
            self.contain_roster(&route);
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        Ok(ValidatedInputAcknowledgement::new(
            activation.clone(),
            acknowledgement.clone(),
        ))
    }

    /// Commits an authenticated original acknowledgement into coordinator custody.
    ///
    /// The runtime retains the opaque commit before returning it, so losing the
    /// reply cannot replace or repeat the original input cut.
    ///
    /// # Errors
    /// Refuses unavailable original native buffers, changed batch scope, foreign
    /// activation or a scheduler that cannot commit the exact staged inventory.
    pub fn commit_input_acknowledgement(
        &mut self,
        acknowledgement: ValidatedInputAcknowledgement,
    ) -> Result<crate::node_scheduling::InputCustodyCommit, RuntimePollFailure> {
        self.validate_activation(&acknowledgement.activation)
            .map_err(RuntimePollFailure::Admission)?;
        let stage = acknowledgement.acknowledgement.stage_operation.clone();
        let retained = self
            .input_batches
            .get(&stage)
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        if retained.failure.is_some()
            || retained.acknowledgement.as_ref() != Some(&acknowledgement.acknowledgement)
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        if let Some(commit) = &retained.commit {
            return Ok(commit.retained_copy());
        }
        self.recover_input_staging(&acknowledgement.activation, &stage)?;
        let scheduler = self
            .scheduler
            .as_mut()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?;
        let commit = scheduler
            .accept_input_acknowledgement(acknowledgement)
            .map_err(|error| {
                RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.to_string()))
            })?;
        let retained = self
            .input_batches
            .get_mut(&stage)
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        retained.commit = Some(commit.retained_copy());
        Ok(commit)
    }

    /// Releases original staging locks after the scheduler accepted native custody.
    ///
    /// This settles buffer transfer only. Native inputs remain retained for a
    /// later causally admitted operation; no modeled input is consumed here.
    ///
    /// # Errors
    /// Refuses foreign or replaced custody commits, changed original buffers,
    /// or owners no longer reserved for this exact staging operation.
    pub fn commit_input_staging(
        &mut self,
        commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), RuntimePollFailure> {
        self.validate_activation(commit.activation())
            .map_err(RuntimePollFailure::Admission)?;
        let retained = self.input_batches.get(commit.stage_operation()).ok_or(
            RuntimePollFailure::Admission(RuntimeError::ForeignAuthority),
        )?;
        let original = retained
            .commit
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ))?;
        if original.node() != commit.node()
            || original.batch() != commit.batch()
            || original.inventory() != commit.inventory()
            || original.cutoff() != commit.cutoff()
            || retained.batch.node() != commit.node()
            || retained.failure.is_some()
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        if retained.committed {
            return Ok(());
        }
        self.recover_input_staging(commit.activation(), commit.stage_operation())?;
        let route = self
            .checked_route(commit.node())
            .map_err(RuntimePollFailure::Admission)?;
        if route.owners.iter().any(|identity| {
            self.owners
                .get(&identity.owner)
                .is_none_or(|owner| owner.operation.as_ref() != Some(commit.stage_operation()))
        }) {
            return Err(RuntimePollFailure::Admission(RuntimeError::OwnerBusy));
        }
        let token = OperationToken {
            authority: Rc::clone(&self.authority),
            operation: commit.stage_operation().clone(),
            route,
        };
        self.release_reservation(&token);
        let retained = self.input_batches.get_mut(commit.stage_operation()).ok_or(
            RuntimePollFailure::Admission(RuntimeError::ForeignAuthority),
        )?;
        retained.committed = true;
        Ok(())
    }

    pub(super) fn execution_inputs(
        &mut self,
        admission: &crate::node_scheduling::ExecutionAdmission,
    ) -> Result<Option<Rc<RuntimeInputBatch>>, RuntimeError> {
        let Some(batch_id) = admission.input_batch() else {
            if matches!(admission.request(), OperationRequest::QuantumBegin { .. })
                || self.input_batches.values().any(|input| {
                    input.committed
                        && input.failure.is_none()
                        && input.batch.node() == admission.node()
                        && !input.batch.deliveries().is_empty()
                        && !self.input_fully_consumed(&input.batch)
                })
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            return Ok(None);
        };
        self.validate_activation(admission.activation())?;
        let retained = self
            .input_batches
            .values()
            .find(|retained| retained.batch.batch() == batch_id)
            .ok_or(RuntimeError::OutstandingObligations)?;
        if !retained.committed
            || retained.failure.is_some()
            || retained.batch.node() != admission.node()
            || retained.batch.activation().record() != admission.activation().record()
            || !Rc::ptr_eq(
                &retained.batch.activation().authority,
                &admission.activation().authority,
            )
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let route = self
            .snapshots
            .get(admission.node())
            .ok_or(RuntimeError::UnknownNode)?
            .route
            .clone();
        if route.owners != retained.batch.owners() {
            return Err(RuntimeError::InvalidRoute);
        }
        let scope_valid = match admission.request() {
            OperationRequest::QuantumBegin {
                start, input_batch, ..
            } => {
                input_batch == *batch_id
                    && start.time_ps.get().checked_add(1)
                        == Some(retained.batch.cutoff().time_ps.get())
                    && retained.batch.cutoff().microstep.get() == 0
                    && retained.batch.cutoff().phase
                        == crucible_node_contract::Phase::BoundaryControl
                    && retained
                        .batch
                        .deliveries()
                        .iter()
                        .all(|delivery| delivery.delivery.time_ps <= start.time_ps)
            }
            // Staging preserves future buffers; it does not grant permission
            // to consume them. Authentic execution receipts enforce the exact
            // grant's half-open range and cumulative consumed prefix.
            OperationRequest::ExactRun { .. } | OperationRequest::BoundarySettle { .. } => true,
            _ => false,
        };
        if !scope_valid {
            return Err(RuntimeError::InvalidTiming);
        }
        let acknowledgement = retained
            .acknowledgement
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?;
        if !self.nodes.get(admission.node()).is_some_and(|node| {
            valid_ack(&retained.batch, acknowledgement)
                && node
                    .validate_input_acknowledgement(&retained.batch, acknowledgement)
                    .is_ok()
        }) {
            self.contain_roster(&route);
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(Some(Rc::new(retained.batch.retained_copy())))
    }

    // Only an authenticated native terminal receipt can discharge the original
    // staged buffers. Coordinator queue removal and staging ACKs prove no such
    // semantic consumption. The bounded operation ledger retains this receipt
    // even when the caller has already acknowledged its outputs.
    fn input_fully_consumed(&self, batch: &RuntimeInputBatch) -> bool {
        self.operations.values().any(|operation| {
            if operation.admission.token.route.node != *batch.node()
                || operation
                    .admission
                    .inputs()
                    .is_none_or(|original| original.batch() != batch.batch())
            {
                return false;
            }
            let outcome = match &operation.result {
                RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) => {
                    outcome
                }
                _ => return false,
            };
            outcome
                .scheduling
                .as_ref()
                .and_then(|observation| observation.input_progress.as_ref())
                .is_some_and(|progress| {
                    progress.batch == *batch.batch()
                        && progress.consumed.len() == batch.deliveries().len()
                        && progress.consumed.iter().zip(batch.deliveries()).all(
                            |(identity, delivery)| {
                                identity.producer == delivery.producer
                                    && identity.source_sequence == delivery.source_sequence
                            },
                        )
                })
        })
    }

    /// Returns original retained input metadata without authorizing delivery.
    ///
    /// # Errors
    /// Refuses a staging identity that has never entered this runtime's ledger.
    pub fn retained_input_batch(
        &self,
        stage_operation: &Id,
    ) -> Result<&RuntimeInputBatch, RuntimeError> {
        self.input_batches
            .get(stage_operation)
            .map(|retained| &retained.batch)
            .ok_or(RuntimeError::ForeignAuthority)
    }
}

fn valid_ack(batch: &RuntimeInputBatch, acknowledgement: &NativeInputAcknowledgement) -> bool {
    acknowledgement.stage_operation == *batch.stage_operation()
        && acknowledgement.batch == *batch.batch()
        && acknowledgement.node == *batch.node()
        && acknowledgement.owners == batch.owners()
        && acknowledgement.cutoff == batch.cutoff()
        && acknowledgement.inventory == *batch.inventory()
        && acknowledgement.proof_ref.validate().is_ok()
        && acknowledgement.proof_ref.length.get() > 0
}

#[cfg(test)]
#[path = "runtime_input_tests.rs"]
mod tests;
