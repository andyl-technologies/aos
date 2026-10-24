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
use crucible_control_api::host_operational::HostOperationalError;
use crucible_host_resources::host_supervision::HostOperationClass;

#[derive(Debug)]
struct GuardedCancellationForwarder(ExecutionCancellation);

impl crate::executor_supervisor::ExecutionCancellationHook for GuardedCancellationForwarder {
    fn signal(&self) {
        self.0.cancel();
    }
}

pub(super) fn admitted_error<E, T>(error: T) -> SynchronousCampaignExecutorError<E>
where
    AdmittedCampaignError<E>: From<T>,
{
    SynchronousCampaignExecutorCause::Admitted(Box::new(error.into())).into()
}

impl<M> SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + Send + Sync + 'static,
{
    /// Prepares the same model-owned factory before the first Service effect.
    pub(super) fn prepare_completed_reproduction(
        &mut self,
    ) -> Result<
        crate::lifecycle_cleanup::ServiceMainHandle,
        SynchronousCampaignExecutorError<M::Error>,
    > {
        use crate::completed_reproduction::CompletedReproductionPreparationError;

        match (self.prepare_reproduction)(self.worker.model_mut()) {
            Ok(handle) => Ok(handle),
            Err(CompletedReproductionPreparationError::Lifecycle(first)) => {
                Err(admitted_error(first))
            }
            #[cfg(any(test, feature = "test-support"))]
            Err(CompletedReproductionPreparationError::OperationOnlyUnsupported) => {
                Err(SynchronousCampaignExecutorError::from(
                    SynchronousCampaignExecutorCause::AuthorityUnavailable,
                ))
            }
        }
    }

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
            .map_err(admitted_error)?;
        let service = self.prepare_completed_reproduction()?;
        let mut services = match owner.replay_services() {
            Ok(services) => services,
            Err(first) => {
                let mut first = Some(first);
                let stored = service.with_start(|start| {
                    if start.first().is_none()
                        && let Some(first) = first.take()
                    {
                        start.record_initial_failure(first);
                    }
                });
                if let Some(first) = first {
                    let mut error = admitted_error(first);
                    if let Err(access) = stored {
                        error.receiver_return = Some(service.failure_with_refusal(
                            "retain completed reproduction Service preflight",
                            access,
                        ));
                    }
                    return Err(error);
                }
                return Err(SynchronousCampaignExecutorCause::Prepared(
                    service.failure("select completed reproduction Service"),
                )
                .into());
            }
        };
        if let Some(caller) = &self.caller_supervisor {
            services = services.with_outer_supervisor(caller.clone());
        }
        match service.with_start(|start| {
            services.start_for_completed_reproduction(start, &basis, self.cancellation.clone())
        }) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(SynchronousCampaignExecutorCause::Prepared(
                    service.failure("start completed reproduction Service"),
                )
                .into());
            }
            Err(first) => {
                return Err(SynchronousCampaignExecutorCause::Prepared(
                    service.failure_with_refusal("borrow completed reproduction Service", first),
                )
                .into());
            }
        }
        let receiver = service.retain_receiver_in_main().map_err(|first| {
            SynchronousCampaignExecutorError::from(SynchronousCampaignExecutorCause::Prepared(
                service.failure_with_refusal("retain completed reproduction context", first),
            ))
        })?;
        let mut reproduced: Result<ObservationId, SynchronousCampaignExecutorError<M::Error>> =
            (|| {
                let context = service
                    .with_ready(|ready| ready.context().clone())
                    .map_err(|first| {
                        SynchronousCampaignExecutorError::from(
                            SynchronousCampaignExecutorCause::Prepared(
                                service.failure_with_refusal(
                                    "project completed reproduction context",
                                    first,
                                ),
                            ),
                        )
                    })?;
                let product = match self.worker.model_mut().execute(basis.input(), &context) {
                    Ok(product) => product,
                    Err(failure) => {
                        reconcile_model(
                            self.worker.model_mut(),
                            AttemptExecutionDisposition::Failed,
                        )?;
                        return Err(SynchronousCampaignExecutorError::from(
                            SynchronousCampaignExecutorCause::Execution(failure),
                        ));
                    }
                };
                let AttemptExecutionProduct::PreparedSemantic(mut result) = product else {
                    reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                    return Err(SynchronousCampaignExecutorError::from(
                        SynchronousCampaignExecutorCause::UnexpectedCheckpoint,
                    ));
                };
                let publication_result = context
                    .host_operation_supervisor()
                    .ok_or(HostOperationalError::Unavailable)
                    .map_err(admitted_error)
                    .and_then(|supervisor| {
                        supervisor
                            .begin(HostOperationClass::CheckpointPublication)
                            .map_err(|first| {
                                let _phase_observation = service
                                    .with_start(|start| start.record_external_supervision(first));
                                admitted_error(first)
                            })
                    });
                let publication = match publication_result {
                    Ok(publication) => publication,
                    Err(error) => {
                        reconcile_model(
                            self.worker.model_mut(),
                            AttemptExecutionDisposition::Failed,
                        )?;
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
                        reconcile_model(
                            self.worker.model_mut(),
                            AttemptExecutionDisposition::Failed,
                        )?;
                        return Err(admitted_error(error));
                    }
                };
                let published = (|| {
                    publication.wait_slice().map_err(|first| {
                        let _phase_observation =
                            service.with_start(|start| start.record_external_supervision(first));
                        admitted_error(first)
                    })?;
                    validate_prepared_semantic_attempt_result(
                        &self.store,
                        AttemptExecutionKey::for_request(request),
                        &result,
                    )
                    .map_err(|error| {
                        SynchronousCampaignExecutorError::from(
                            SynchronousCampaignExecutorCause::Preparation(Box::new(error)),
                        )
                    })?;
                    publication.wait_slice().map_err(|first| {
                        let _phase_observation =
                            service.with_start(|start| start.record_external_supervision(first));
                        admitted_error(first)
                    })?;
                    let observation = publish_prepared_semantic_attempt_result(
                        &self.store,
                        self.exact_retention.as_ref(),
                        &result,
                    )
                    .map_err(SynchronousCampaignExecutorCause::Publication)?;
                    publication.wait_slice().map_err(|first| {
                        let _phase_observation =
                            service.with_start(|start| start.record_external_supervision(first));
                        admitted_error(first)
                    })?;
                    Ok(observation)
                })();
                let observation = match published {
                    Ok(observation) => observation,
                    Err(error) => {
                        reconcile_model(
                            self.worker.model_mut(),
                            AttemptExecutionDisposition::Failed,
                        )?;
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
                publication.complete().map_err(|first| {
                    let _phase_observation =
                        service.with_start(|start| start.record_external_supervision(first));
                    admitted_error(first)
                })?;
                Ok(observation)
            })();
        // The projected context, publication Original, fence and result have
        // all left their real scope. Actual model/World aliases have separate
        // canonical body/loan obligations; reconciliation alone proves none.
        if let Err(first) = receiver.return_after_alias_destruction() {
            let returned =
                service.failure_with_refusal("return completed reproduction aliases", first);
            match &mut reproduced {
                Err(error) => error.receiver_return = Some(returned),
                Ok(_) => {
                    reproduced = Err(SynchronousCampaignExecutorCause::Prepared(returned).into())
                }
            }
        }
        let observation = match reproduced {
            Ok(observation) => observation,
            Err(error) => {
                let _retained = service.failure("retire failed completed reproduction");
                return Err(error);
            }
        };
        let mut retirement = service
            .prepared_selector()
            .service_main_handle()
            .into_retirement();
        match retirement.retry() {
            Ok(true) => {}
            Ok(false) => {
                return Err(SynchronousCampaignExecutorCause::Prepared(
                    service.failure("completed reproduction physical return pending"),
                )
                .into());
            }
            Err(first) => {
                let _retained = service.failure("completed reproduction cleanup refused");
                return Err(SynchronousCampaignExecutorCause::Retirement(first).into());
            }
        }
        match retirement.finish() {
            Ok(terminal) if terminal.first_failure().is_some() => {
                return Err(
                    SynchronousCampaignExecutorCause::Terminal(std::sync::Mutex::new(terminal))
                        .into(),
                );
            }
            Ok(terminal) => drop(terminal),
            Err(_retirement) => {
                return Err(SynchronousCampaignExecutorCause::Prepared(
                    service.failure("completed reproduction terminal disposal pending"),
                )
                .into());
            }
        }
        if observation != expected {
            return Err(admitted_error(HostOperationalError::InvalidMessage {
                message: "fresh reproduction disagrees with its authenticated completed source"
                    .to_owned(),
            }));
        }
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::AlreadyCompleted { observation },
        )
        .map_err(|first| SynchronousCampaignExecutorCause::Protocol(first).into())
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
            .map_err(SynchronousCampaignExecutorCause::Protocol)
            .map_err(SynchronousCampaignExecutorError::from),
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
