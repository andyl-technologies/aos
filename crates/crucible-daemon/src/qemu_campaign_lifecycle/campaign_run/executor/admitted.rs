//! Accepted assignments and publication through the genuine campaign actor.
//!
//! Worker execution and immutable publication occur outside the short actor
//! lock. The same durable queue token is staged and reconciled after actual
//! lifecycle teardown; neither observations nor captures bypass admission.

use super::*;
use crate::{
    AttemptResultStageOutcome, AttemptWorkerReconcileOutcome, CompletionOutcome,
    publish_prepared_attempt_result, reconcile_published_attempt_result,
};
use crucible_api::host_operational::HostOperationalError;

#[derive(Debug)]
struct GuardedCancellationForwarder(ExecutionCancellation);

impl crate::executor_supervisor::ExecutionCancellationHook for GuardedCancellationForwarder {
    fn signal(&self) {
        self.0.cancel();
    }
}

fn admitted_error<E: Error + 'static>(
    error: impl Error + Send + 'static,
) -> SynchronousCampaignExecutorError<E> {
    SynchronousCampaignExecutorError::Admitted(Box::new(
        crate::packaged_qemu_executor::guarded::RetainedOperationError::new(error),
    ))
}

impl<M> SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + Send + Sync + 'static,
{
    pub(super) fn submit_admitted(
        &mut self,
        owner: &super::super::GuardedCampaignOwner,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, SynchronousCampaignExecutorError<M::Error>> {
        // Immutable repository/closure authentication precedes actor ownership;
        // the sole writer rechecks current assignment identity on reacquisition.
        let validation = owner.validate_submission(request);
        let (response, queued) = owner
            .inner
            .actor
            .with_supervisor(|actor| {
                let response = actor.submit_after_validation(request, validation);
                let queued = match &response {
                    Ok(response)
                        if matches!(
                            response.disposition(),
                            SubmitAttemptDisposition::Accepted { .. }
                        ) =>
                    {
                        actor.next_queued_for(request.request_digest())
                    }
                    _ => None,
                };
                Ok((response, queued))
            })
            .map_err(admitted_error)?;
        let response = response.map_err(admitted_error)?;
        if let SubmitAttemptDisposition::AlreadyCompleted { observation } = response.disposition() {
            return self.reproduce_completed(owner, request, observation);
        }
        if !matches!(
            response.disposition(),
            SubmitAttemptDisposition::Accepted { .. }
        ) {
            return Ok(response);
        }
        let mut queued = queued.ok_or_else(|| admitted_error(HostOperationalError::Unavailable))?;
        if let Some(caller) = &self.caller_supervisor
            && let Err(error) = queued.bind_caller_supervision(caller)
        {
            owner
                .inner
                .actor
                .with_supervisor(|actor| Ok(actor.stage_and_reconcile_terminal_failure(&queued)))
                .map_err(admitted_error)?
                .map_err(admitted_error)?;
            return Err(admitted_error(error));
        }
        let cancellation_forwarder =
            self.cancellation
                .register_hook(Arc::new(GuardedCancellationForwarder(
                    queued.cancellation().clone(),
                )));
        let _cancellation_forwarder = match cancellation_forwarder {
            Ok(forwarder) => forwarder,
            Err(message) => {
                owner
                    .inner
                    .actor
                    .with_supervisor(
                        |actor| Ok(actor.stage_and_reconcile_terminal_failure(&queued)),
                    )
                    .map_err(admitted_error)?
                    .map_err(admitted_error)?;
                return Err(admitted_error(HostOperationalError::InvalidMessage {
                    message: message.to_owned(),
                }));
            }
        };
        owner
            .inner
            .actor
            .install_checkpoint_handoff(&mut queued, owner.inner.checkpoints.clone());
        let work = self.worker.execute(queued);
        let prepared = match prepare_attempt_result(&self.store, &owner.inner.checkpoints, work) {
            Ok(prepared) => prepared,
            Err(error) => {
                let queued = match &error {
                    AttemptResultPreparationError::Worker { queued, .. } => queued.as_ref(),
                    AttemptResultPreparationError::Candidate { pending, .. } => pending.queued(),
                    AttemptResultPreparationError::Checkpoint { pending, .. } => pending.queued(),
                }
                .reconciliation_copy();
                // Guest teardown precedes every attempted accounting release.
                // If teardown or the durable stop cannot prove completion,
                // the original actor retains its reservation for quarantine.
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                owner
                    .inner
                    .actor
                    .with_supervisor(
                        |actor| Ok(actor.stage_and_reconcile_terminal_failure(&queued)),
                    )
                    .map_err(admitted_error)?
                    .map_err(admitted_error)?;
                return Err(admitted_error(error));
            }
        };
        match prepared {
            PreparedAttemptWorkResult::Observation(prepared) => {
                self.publish_admitted_observation(owner, request, *prepared)
            }
            PreparedAttemptWorkResult::ExactCheckpoint(prepared) => {
                self.publish_admitted_checkpoint(owner, request, *prepared)
            }
        }
    }

    fn reproduce_completed(
        &mut self,
        owner: &super::super::GuardedCampaignOwner,
        request: &SubmitAttemptRequest,
        expected: ObservationId,
    ) -> Result<SubmitAttemptResponse, SynchronousCampaignExecutorError<M::Error>> {
        let basis = owner
            .completed_reproduction_basis(request, expected)
            .map_err(SynchronousCampaignExecutorError::Admitted)?;
        let mut services = owner.replay_services().map_err(admitted_error)?;
        if let Some(caller) = &self.caller_supervisor {
            services = services.with_outer_supervisor(caller.clone());
        }
        let service = services
            .start_for_completed_reproduction(&basis, self.cancellation.clone())
            .map_err(admitted_error)?;
        let product = match self
            .worker
            .model_mut()
            .execute(basis.input(), service.context())
        {
            Ok(product) => product,
            Err(failure) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Execution(failure));
            }
        };
        let AttemptExecutionProduct::PreparedSemantic(mut result) = product else {
            reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
            return Err(SynchronousCampaignExecutorError::UnexpectedCheckpoint);
        };
        let publication = match service
            .context()
            .host_operation_supervisor()
            .ok_or(HostOperationalError::Unavailable)
            .map_err(admitted_error)
            .and_then(|supervisor| {
                supervisor
                    .begin(crucible_linux_resource::host_supervision::HostOperationClass::CheckpointPublication)
                    .map_err(admitted_error)
            })
        {
            Ok(publication) => publication,
            Err(error) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(error);
            }
        };
        let fence = match crate::executor_worker::bind_admitted_semantic_replay_captures(
            &self.store,
            &mut result,
            &publication,
        ) {
            Ok(fence) => fence,
            Err(error) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Admitted(Box::new(
                    crate::packaged_qemu_executor::guarded::RetainedOperationError::from_box(error),
                )));
            }
        };
        let published = (|| {
            publication.wait_slice().map_err(admitted_error)?;
            validate_prepared_semantic_attempt_result(
                &self.store,
                AttemptExecutionKey::for_request(request),
                &result,
            )
            .map_err(|error| SynchronousCampaignExecutorError::Preparation(Box::new(error)))?;
            publication.wait_slice().map_err(admitted_error)?;
            let observation = publish_prepared_semantic_attempt_result(
                &self.store,
                self.exact_retention.as_ref(),
                &result,
            )
            .map_err(SynchronousCampaignExecutorError::Publication)?;
            publication.wait_slice().map_err(admitted_error)?;
            Ok(observation)
        })();
        let observation = match published {
            Ok(observation) => observation,
            Err(error) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(error);
            }
        };
        // All new exact replay leaves remain protected through publication of
        // the authentic result closure. The source's completed row is never
        // rewritten to pretend a second assignment was accepted.
        drop(fence);
        reconcile_model(
            self.worker.model_mut(),
            AttemptExecutionDisposition::Observation(observation),
        )?;
        publication.complete().map_err(admitted_error)?;
        service
            .release_after_world_cleanup()
            .map_err(admitted_error)?;
        if observation != expected {
            return Err(admitted_error(HostOperationalError::InvalidMessage {
                message: "fresh reproduction disagrees with its authenticated completed source"
                    .to_owned(),
            }));
        }
        // The service is discharged only after real model/native cleanup. Its
        // guarded Drop retains watchdog and capacity if any borrower remains.
        drop(service);
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::AlreadyCompleted { observation },
        )
        .map_err(SynchronousCampaignExecutorError::Protocol)
    }

    fn publish_admitted_observation(
        &mut self,
        owner: &super::super::GuardedCampaignOwner,
        request: &SubmitAttemptRequest,
        prepared: crate::PreparedAttemptResult,
    ) -> Result<SubmitAttemptResponse, SynchronousCampaignExecutorError<M::Error>> {
        let observation = prepared.observation();
        let journal = crate::PreparedResultJournalNamespace::open(owner.inner.journal_root())
            .map_err(admitted_error)?;
        let staged = crate::executor_worker::stage_admitted_prepared_result(
            &owner.inner.actor,
            &self.store,
            &journal,
            crate::MAX_PREPARED_SEMANTIC_RESULT_BYTES,
            prepared,
        )
        .map_err(admitted_error)?;
        let outcome = match staged {
            AttemptResultStageOutcome::Publish(staged) => {
                let published = publish_prepared_attempt_result(
                    &self.store,
                    self.exact_retention.as_ref(),
                    staged,
                )
                .map_err(admitted_error)?;
                // Teardown and all native borrower cleanup precede releasing
                // the immutable assignment's operational capacity.
                reconcile_model(
                    self.worker.model_mut(),
                    AttemptExecutionDisposition::Observation(observation),
                )?;
                owner
                    .inner
                    .actor
                    .with_supervisor(|actor| {
                        Ok(reconcile_published_attempt_result::<
                            _,
                            _,
                            RepositoryAttemptWorkerError<M::Error>,
                        >(actor, published))
                    })
                    .map_err(admitted_error)?
                    .map_err(admitted_error)?
            }
            AttemptResultStageOutcome::Finished { prepared, outcome } => {
                reconcile_model(
                    self.worker.model_mut(),
                    AttemptExecutionDisposition::Observation(observation),
                )?;
                prepared.remove_journal().map_err(admitted_error)?;
                outcome
            }
        };
        match outcome {
            AttemptWorkerReconcileOutcome::Reconciled {
                completion: CompletionOutcome::Completed | CompletionOutcome::AlreadyCompleted,
                ..
            } => SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::AlreadyCompleted { observation },
            )
            .map_err(SynchronousCampaignExecutorError::Protocol),
            _ => Err(admitted_error(HostOperationalError::Unavailable)),
        }
    }

    fn publish_admitted_checkpoint(
        &mut self,
        owner: &super::super::GuardedCampaignOwner,
        request: &SubmitAttemptRequest,
        prepared: crate::PreparedCheckpointResult,
    ) -> Result<SubmitAttemptResponse, SynchronousCampaignExecutorError<M::Error>> {
        let root = prepared.root();
        let staged = owner
            .inner
            .actor
            .with_supervisor(|actor| Ok(stage_prepared_checkpoint_result(actor, prepared)))
            .map_err(admitted_error)?
            .map_err(admitted_error)?;
        match staged {
            CheckpointResultStageOutcome::Publish(staged) => {
                let published = publish_staged_checkpoint_result(&owner.inner.checkpoints, *staged)
                    .map_err(admitted_error)?;
                reconcile_model(
                    self.worker.model_mut(),
                    AttemptExecutionDisposition::ExactCheckpoint(root),
                )?;
                let outcome = owner
                    .inner
                    .actor
                    .with_supervisor(|actor| {
                        Ok(reconcile_published_checkpoint_result(actor, published))
                    })
                    .map_err(admitted_error)?
                    .map_err(admitted_error)?;
                if !matches!(
                    outcome,
                    CheckpointCompletionOutcome::Paused
                        | CheckpointCompletionOutcome::AlreadyPaused
                ) {
                    return Err(admitted_error(HostOperationalError::Unavailable));
                }
            }
            CheckpointResultStageOutcome::Finished {
                outcome: CheckpointPublicationOutcome::AlreadyPaused,
                ..
            } => {
                reconcile_model(
                    self.worker.model_mut(),
                    AttemptExecutionDisposition::ExactCheckpoint(root),
                )?;
            }
            _ => return Err(admitted_error(HostOperationalError::Unavailable)),
        }
        self.exact_inventory
            .retain_checkpoint(root)
            .map_err(admitted_error)?;
        owner
            .inner
            .actor
            .with_supervisor(|actor| Ok(actor.submit_attempt(request)))
            .map_err(admitted_error)?
            .map_err(admitted_error)
    }
}
