//! Shared transport custody for exact controller broker exchanges.
//!
//! Callers prepare and validate their own requests. This owner retains the
//! prepared request through session recovery, socket backpressure, and outcome
//! commit ambiguity, then revalidates currentness before releasing custody.

use aos_sandbox::EffectFailure;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorRequestPreparationV1,
    DormantBrokerDescriptorRequestSendProgressV1, DormantBrokerDescriptorRequestSendRecoveryV1,
    DormantBrokerRequestPreparationV1, DormantBrokerRequestSendProgressV1,
    DormantBrokerResponseProgressV1, DormantOutstandingBrokerRequestV1,
    DormantPreparedBrokerDescriptorRequestV1, DormantPreparedBrokerRequestV1,
    DormantUnconfirmedBrokerDescriptorRequestV1, DormantUnconfirmedBrokerRequestV1,
    ProtectedBrokerOutcomeCommitRecoveryV1, ProtectedBrokerOutcomeCommitResultV1,
    ProtectedBrokerRequestCommitRecoveryV1, ProtectedBrokerSessionInitializationRecoveryV1,
};

/// Caller-specific diagnostics for a retained exchange.
pub(crate) struct RetainedExchangeErrorsV1 {
    pub(crate) absent: &'static str,
    pub(crate) retained: &'static str,
    pub(crate) unusable: &'static str,
}

enum ExchangeStageV1 {
    Initialization {
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Successor {
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    DescriptorInitialization {
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    },
    DescriptorSuccessor {
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    },
    Send(DormantPreparedBrokerRequestV1),
    DescriptorSend(DormantPreparedBrokerDescriptorRequestV1),
    DescriptorSendRecovery(DormantBrokerDescriptorRequestSendRecoveryV1),
    Receive(DormantOutstandingBrokerRequestV1),
    Commit(ProtectedBrokerOutcomeCommitRecoveryV1),
}

struct PendingExchangeV1<C> {
    context: Option<C>,
    stage: ExchangeStageV1,
}

#[derive(Clone, Copy)]
enum ExchangeDispositionV1 {
    Legacy,
    Generation,
}

enum GenerationExchangeCauseV1 {
    Session(crate::BrokerSessionSecurityError),
    Wait(crate::DormantBrokerSessionHandshakeErrorV1),
    Response,
}

/// Retains one request and its caller context until authenticated completion.
pub(crate) struct RetainedBrokerExchangeV1<C> {
    pending: Option<PendingExchangeV1<C>>,
    failed: bool,
    original_context: Option<C>,
    original_outcome: Option<AuthenticatedBrokerMethodOutcomeV1>,
    original_cause: Option<GenerationExchangeCauseV1>,
    original_response: Option<Result<DormantBrokerResponseProgressV1, crate::BrokerSessionSecurityError>>,
}

impl<C> Default for RetainedBrokerExchangeV1<C> {
    fn default() -> Self {
        Self {
            pending: None,
            failed: false,
            original_context: None,
            original_outcome: None,
            original_cause: None,
            original_response: None,
        }
    }
}

impl<C> RetainedBrokerExchangeV1<C> {
    /// Reports whether protected custody or an unusable session blocks new work.
    pub(crate) const fn has_pending(&self) -> bool {
        self.pending.is_some() || self.failed
    }

    /// Reports whether an exact request remains retained.
    pub(crate) const fn has_request(&self) -> bool {
        self.pending.is_some()
    }

    /// Reports whether the session must be replaced before further work.
    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.failed
    }

    /// Borrows the exact context retained beside the prepared request.
    pub(crate) fn context(&self) -> Option<&C> {
        self.pending.as_ref().and_then(|pending| pending.context.as_ref())
    }

    /// Updates an unsent request's caller context after a second protected append.
    pub(crate) fn context_mut(&mut self) -> Option<&mut C> {
        self.pending.as_mut().and_then(|pending| pending.context.as_mut())
    }

    /// Retains a caller-validated preparation and its exact context.
    pub(crate) fn start(&mut self, context: C, preparation: DormantBrokerRequestPreparationV1) {
        self.pending = Some(PendingExchangeV1 {
            context: Some(context),
            stage: preparation_stage(preparation),
        });
    }

    /// Retains only a genuinely prepared selected request, never a recovery variant.
    pub(crate) fn start_generation(&mut self, context: C, prepared: DormantPreparedBrokerRequestV1) {
        self.pending = Some(PendingExchangeV1 {
            context: Some(context),
            stage: ExchangeStageV1::Send(prepared),
        });
    }

    /// Retains a descriptor request and every FD across installation and send recovery.
    pub(crate) fn start_descriptor(
        &mut self,
        context: C,
        preparation: DormantBrokerDescriptorRequestPreparationV1,
    ) {
        self.pending = Some(PendingExchangeV1 {
            context: Some(context),
            stage: descriptor_preparation_stage(preparation),
        });
    }

    /// Marks a session unusable after a caller-specific terminal failure.
    pub(crate) fn mark_failed(&mut self) {
        self.failed = true;
    }

    /// Advances retained custody to a signed outcome with currentness checked.
    ///
    /// # Errors
    ///
    /// Returns a retryable error when recovery remains pending or the session
    /// fails. The exact context and stage remain owned across retryable waits.
    pub(crate) fn drive(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        errors: &RetainedExchangeErrorsV1,
    ) -> Result<(C, AuthenticatedBrokerMethodOutcomeV1), EffectFailure> {
        self.drive_with_disposition(session, errors, ExchangeDispositionV1::Legacy)?
            .ok_or_else(|| EffectFailure::Retryable(errors.unusable.to_owned()))
    }

    /// Drives the same transport engine while retaining returned causes and outcome.
    /// A selected failure never grants reconnect or a replacement attempt.
    pub(crate) fn drive_generation(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        errors: &RetainedExchangeErrorsV1,
    ) -> Result<(), EffectFailure> {
        self.drive_with_disposition(session, errors, ExchangeDispositionV1::Generation)
            .map(|_| ())
    }

    pub(crate) fn generation_outcome(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        if self.failed { return None; }
        self.original_outcome.as_ref()
    }

    pub(crate) fn generation_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.original_cause.as_ref()? {
            GenerationExchangeCauseV1::Session(error) => Some(error),
            GenerationExchangeCauseV1::Wait(error) => Some(error),
            GenerationExchangeCauseV1::Response => match self.original_response.as_ref()? {
                Err(error) => Some(error),
                Ok(DormantBrokerResponseProgressV1::Committed(
                    ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. },
                )) => Some(error),
                _ => None,
            },
        }
    }

    fn drive_with_disposition(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        errors: &RetainedExchangeErrorsV1,
        disposition: ExchangeDispositionV1,
    ) -> Result<Option<(C, AuthenticatedBrokerMethodOutcomeV1)>, EffectFailure> {
        if self.failed {
            return Err(EffectFailure::Retryable(errors.unusable.to_owned()));
        }

        let mut attempted_recovery = false;
        loop {
            let pending = self
                .pending
                .take()
                .ok_or_else(|| EffectFailure::Retryable(errors.absent.to_owned()))?;
            // Selected start admits only Prepared; an ambiguous receive remains
            // whole below. It can never authorize a legacy recovery transition.
            if matches!(disposition, ExchangeDispositionV1::Generation)
                && !matches!(&pending.stage, ExchangeStageV1::Send(_) | ExchangeStageV1::Receive(_))
            {
                self.pending = Some(pending);
                return self.fail(errors);
            }
            let mut context = pending.context;
            if matches!(disposition, ExchangeDispositionV1::Generation) {
                if let Some(context) = context.take() {
                    self.original_context = Some(context);
                }
            }
            let stage = match pending.stage {
                ExchangeStageV1::Initialization { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            context,
                            ExchangeStageV1::Initialization { recovery, request },
                            errors,
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_initialization(recovery, request))
                }
                ExchangeStageV1::Successor { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            context,
                            ExchangeStageV1::Successor { recovery, request },
                            errors,
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_successor(recovery, request))
                }
                ExchangeStageV1::DescriptorInitialization { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            context,
                            ExchangeStageV1::DescriptorInitialization { recovery, request },
                            errors,
                        );
                    }
                    attempted_recovery = true;
                    descriptor_preparation_stage(
                        session.recover_prepared_descriptor_initialization(recovery, request),
                    )
                }
                ExchangeStageV1::DescriptorSuccessor { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            context,
                            ExchangeStageV1::DescriptorSuccessor { recovery, request },
                            errors,
                        );
                    }
                    attempted_recovery = true;
                    descriptor_preparation_stage(
                        session.recover_prepared_descriptor_successor(recovery, request),
                    )
                }
                ExchangeStageV1::Send(prepared) => {
                    let deadline = prepared.deadline_boottime_nanoseconds();
                    match session.send_authenticated_request(prepared) {
                        Ok(DormantBrokerRequestSendProgressV1::Sent(outstanding)) => {
                            ExchangeStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerRequestSendProgressV1::Pending(prepared)) => {
                            if self.wait_with_disposition(session, true, deadline, disposition).is_err() {
                                return self.retain(
                                    context,
                                    ExchangeStageV1::Send(prepared),
                                    errors,
                                );
                            }
                            ExchangeStageV1::Send(prepared)
                        }
                        Err(error) => {
                            self.retain_generation_session_error(error, disposition);
                            return self.fail(errors);
                        }
                    }
                }
                ExchangeStageV1::DescriptorSend(prepared) => {
                    let deadline = prepared.deadline_boottime_nanoseconds();
                    match session.send_authenticated_descriptor_request(prepared) {
                        DormantBrokerDescriptorRequestSendProgressV1::Sent(outstanding) => {
                            ExchangeStageV1::Receive(outstanding)
                        }
                        DormantBrokerDescriptorRequestSendProgressV1::Pending(prepared) => {
                            if self.wait_with_disposition(session, true, deadline, disposition).is_err() {
                                return self.retain(
                                    context,
                                    ExchangeStageV1::DescriptorSend(prepared),
                                    errors,
                                );
                            }
                            ExchangeStageV1::DescriptorSend(prepared)
                        }
                        DormantBrokerDescriptorRequestSendProgressV1::RecoveryRequired(
                            recovery,
                        ) => ExchangeStageV1::DescriptorSendRecovery(recovery),
                    }
                }
                ExchangeStageV1::DescriptorSendRecovery(recovery) => {
                    if attempted_recovery {
                        return self.retain(
                            context,
                            ExchangeStageV1::DescriptorSendRecovery(recovery),
                            errors,
                        );
                    }
                    attempted_recovery = true;
                    match session.retry_authenticated_descriptor_request(recovery) {
                        DormantBrokerDescriptorRequestSendProgressV1::Sent(outstanding) => {
                            ExchangeStageV1::Receive(outstanding)
                        }
                        DormantBrokerDescriptorRequestSendProgressV1::Pending(prepared) => {
                            ExchangeStageV1::DescriptorSend(prepared)
                        }
                        DormantBrokerDescriptorRequestSendProgressV1::RecoveryRequired(
                            recovery,
                        ) => ExchangeStageV1::DescriptorSendRecovery(recovery),
                    }
                }
                ExchangeStageV1::Receive(outstanding) => {
                    let deadline = outstanding.deadline_boottime_nanoseconds();
                    let received = if matches!(disposition, ExchangeDispositionV1::Generation) {
                        Ok(self.receive_generation(session, outstanding, errors)?)
                    } else {
                        session.receive_authenticated_response(outstanding)
                    };
                    match received {
                        Ok(DormantBrokerResponseProgressV1::Pending(outstanding)) => {
                            if self.wait_with_disposition(session, false, deadline, disposition).is_err() {
                                return self.retain(
                                    context,
                                    ExchangeStageV1::Receive(outstanding),
                                    errors,
                                );
                            }
                            ExchangeStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
                        )) => return self.complete(session, context, committed, errors, disposition),
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                                recovery, ..
                            },
                        )) => ExchangeStageV1::Commit(recovery),
                        Err(error) => {
                            self.retain_generation_session_error(error, disposition);
                            return self.fail(errors);
                        }
                    }
                }
                ExchangeStageV1::Commit(recovery) => {
                    if attempted_recovery {
                        return self.retain(context, ExchangeStageV1::Commit(recovery), errors);
                    }
                    attempted_recovery = true;
                    match session.recover_broker_outcome_commit(recovery) {
                        ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                            return self.complete(session, context, committed, errors, disposition);
                        }
                        ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                            recovery, ..
                        } => ExchangeStageV1::Commit(recovery),
                    }
                }
            };
            self.pending = Some(PendingExchangeV1 { context, stage });
        }
    }

    fn retain<T>(
        &mut self,
        context: Option<C>,
        stage: ExchangeStageV1,
        errors: &RetainedExchangeErrorsV1,
    ) -> Result<T, EffectFailure> {
        self.pending = Some(PendingExchangeV1 { context, stage });
        Err(EffectFailure::Retryable(errors.retained.to_owned()))
    }

    fn fail<T>(&mut self, errors: &RetainedExchangeErrorsV1) -> Result<T, EffectFailure> {
        self.failed = true;
        Err(EffectFailure::Retryable(errors.unusable.to_owned()))
    }

    fn complete(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        context: Option<C>,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        errors: &RetainedExchangeErrorsV1,
        disposition: ExchangeDispositionV1,
    ) -> Result<Option<(C, AuthenticatedBrokerMethodOutcomeV1)>, EffectFailure> {
        let (outcome, currentness) = committed.into_outcome_and_currentness();
        if matches!(disposition, ExchangeDispositionV1::Generation) {
            self.original_outcome = Some(outcome);
            let checked = (|| {
                let mut current = session.revalidate_broker_outcome(currentness)?;
                current.revalidate()
            })();
            if let Err(error) = checked {
                self.retain_generation_session_error(error, disposition);
                return self.fail(errors);
            }
            return Ok(None);
        }

        let Ok(mut current) = session.revalidate_broker_outcome(currentness) else {
            return self.fail(errors);
        };
        if current.revalidate().is_err() {
            return self.fail(errors);
        }
        match context {
            Some(context) => Ok(Some((context, outcome))),
            None => self.fail(errors),
        }
    }

    fn retain_generation_session_error(
        &mut self,
        error: crate::BrokerSessionSecurityError,
        disposition: ExchangeDispositionV1,
    ) {
        if matches!(disposition, ExchangeDispositionV1::Generation) {
            self.original_cause.get_or_insert(GenerationExchangeCauseV1::Session(error));
            self.failed = true;
        }
    }

    /// Parks the entire returned response before interpreting selected progress.
    /// Recovery owns its actual error and pending advancement without a retry.
    fn receive_generation(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        outstanding: DormantOutstandingBrokerRequestV1,
        errors: &RetainedExchangeErrorsV1,
    ) -> Result<DormantBrokerResponseProgressV1, EffectFailure> {
        self.original_response = Some(session.receive_authenticated_response(outstanding));
        if matches!(
            self.original_response.as_ref(),
            Some(Err(_))
                | Some(Ok(DormantBrokerResponseProgressV1::Committed(
                    ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { .. },
                )))
        ) {
            self.original_cause.get_or_insert(GenerationExchangeCauseV1::Response);
            return self.fail(errors);
        }

        // Only successful Pending/Committed ownership enters the shared engine.
        // No selected error or recovery target is taken from the resident slot.
        match self.original_response.take() {
            Some(Ok(progress)) => Ok(progress),
            retained => {
                self.original_response = retained;
                self.fail(errors)
            }
        }
    }

    fn wait_with_disposition(
        &mut self,
        session: &DormantAuthenticatedBrokerSessionV1,
        wants_write: bool,
        deadline: u64,
        disposition: ExchangeDispositionV1,
    ) -> Result<(), ()> {
        if matches!(disposition, ExchangeDispositionV1::Legacy) {
            return wait(session, wants_write, deadline);
        }
        let result = session.as_fd().and_then(|descriptor| {
            crate::dormant_handshake::wait_for_handshake_readiness(
                descriptor, wants_write, deadline,
            )
        });
        if let Err(error) = result {
            self.original_cause.get_or_insert(GenerationExchangeCauseV1::Wait(error));
            self.failed = true;
            return Err(());
        }
        Ok(())
    }
}

fn preparation_stage(preparation: DormantBrokerRequestPreparationV1) -> ExchangeStageV1 {
    match preparation {
        DormantBrokerRequestPreparationV1::Prepared(prepared) => ExchangeStageV1::Send(prepared),
        DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
            recovery,
            request,
            ..
        } => ExchangeStageV1::Initialization { recovery, request },
        DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
            recovery, request, ..
        } => ExchangeStageV1::Successor { recovery, request },
    }
}

fn descriptor_preparation_stage(
    preparation: DormantBrokerDescriptorRequestPreparationV1,
) -> ExchangeStageV1 {
    match preparation {
        DormantBrokerDescriptorRequestPreparationV1::Prepared(prepared) => {
            ExchangeStageV1::DescriptorSend(prepared)
        }
        DormantBrokerDescriptorRequestPreparationV1::InitializationRecoveryRequired {
            recovery,
            request,
            ..
        } => ExchangeStageV1::DescriptorInitialization { recovery, request },
        DormantBrokerDescriptorRequestPreparationV1::SuccessorRecoveryRequired {
            recovery,
            request,
            ..
        } => ExchangeStageV1::DescriptorSuccessor { recovery, request },
    }
}

fn wait(
    session: &DormantAuthenticatedBrokerSessionV1,
    wants_write: bool,
    deadline_boottime_nanoseconds: u64,
) -> Result<(), ()> {
    let descriptor = session.as_fd().map_err(|_| ())?;
    crate::dormant_handshake::wait_for_handshake_readiness(
        descriptor,
        wants_write,
        deadline_boottime_nanoseconds,
    )
    .map_err(|_| ())
}
