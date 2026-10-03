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
    context: C,
    stage: ExchangeStageV1,
}

/// Retains one request and its caller context until authenticated completion.
pub(crate) struct RetainedBrokerExchangeV1<C> {
    pending: Option<PendingExchangeV1<C>>,
    failed: bool,
}

impl<C> Default for RetainedBrokerExchangeV1<C> {
    fn default() -> Self {
        Self {
            pending: None,
            failed: false,
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
        self.pending.as_ref().map(|pending| &pending.context)
    }

    /// Updates an unsent request's caller context after a second protected append.
    pub(crate) fn context_mut(&mut self) -> Option<&mut C> {
        self.pending.as_mut().map(|pending| &mut pending.context)
    }

    /// Retains a caller-validated preparation and its exact context.
    pub(crate) fn start(&mut self, context: C, preparation: DormantBrokerRequestPreparationV1) {
        self.pending = Some(PendingExchangeV1 {
            context,
            stage: preparation_stage(preparation),
        });
    }

    /// Retains a descriptor request and every FD across installation and send recovery.
    pub(crate) fn start_descriptor(
        &mut self,
        context: C,
        preparation: DormantBrokerDescriptorRequestPreparationV1,
    ) {
        self.pending = Some(PendingExchangeV1 {
            context,
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
        if self.failed {
            return Err(EffectFailure::Retryable(errors.unusable.to_owned()));
        }

        let mut attempted_recovery = false;
        loop {
            let pending = self
                .pending
                .take()
                .ok_or_else(|| EffectFailure::Retryable(errors.absent.to_owned()))?;
            let context = pending.context;
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
                            if wait(session, true, deadline).is_err() {
                                return self.retain(
                                    context,
                                    ExchangeStageV1::Send(prepared),
                                    errors,
                                );
                            }
                            ExchangeStageV1::Send(prepared)
                        }
                        Err(_) => return self.fail(errors),
                    }
                }
                ExchangeStageV1::DescriptorSend(prepared) => {
                    let deadline = prepared.deadline_boottime_nanoseconds();
                    match session.send_authenticated_descriptor_request(prepared) {
                        DormantBrokerDescriptorRequestSendProgressV1::Sent(outstanding) => {
                            ExchangeStageV1::Receive(outstanding)
                        }
                        DormantBrokerDescriptorRequestSendProgressV1::Pending(prepared) => {
                            if wait(session, true, deadline).is_err() {
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
                    match session.receive_authenticated_response(outstanding) {
                        Ok(DormantBrokerResponseProgressV1::Pending(outstanding)) => {
                            if wait(session, false, deadline).is_err() {
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
                        )) => return self.complete(session, context, committed, errors),
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                                recovery, ..
                            },
                        )) => ExchangeStageV1::Commit(recovery),
                        Err(_) => return self.fail(errors),
                    }
                }
                ExchangeStageV1::Commit(recovery) => {
                    if attempted_recovery {
                        return self.retain(context, ExchangeStageV1::Commit(recovery), errors);
                    }
                    attempted_recovery = true;
                    match session.recover_broker_outcome_commit(recovery) {
                        ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                            return self.complete(session, context, committed, errors);
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
        context: C,
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
        context: C,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        errors: &RetainedExchangeErrorsV1,
    ) -> Result<(C, AuthenticatedBrokerMethodOutcomeV1), EffectFailure> {
        let (outcome, currentness) = committed.into_outcome_and_currentness();
        let Ok(mut current) = session.revalidate_broker_outcome(currentness) else {
            return self.fail(errors);
        };
        if current.revalidate().is_err() {
            return self.fail(errors);
        }
        Ok((context, outcome))
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
