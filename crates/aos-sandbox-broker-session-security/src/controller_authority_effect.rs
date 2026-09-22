//! Controller-owned execution of durable authority-bound broker effects.
//!
//! The exchange preserves one reconciler-prepared request across protected
//! initialization, successor commit, socket backpressure, response admission,
//! and outcome-commit ambiguity. It never rebuilds or substitutes the durable
//! request identity.

use aos_sandbox::lifecycle::{
    CurrentLifecycleEffectV1, LifecycleAtomicDatasetSnapshotPlanV1, LiveRuntimeFenceV1,
};
use aos_sandbox::{
    AuthorityEffectObservationV1, EffectFailure, PreparedAuthorityEffectV1,
    ValidatedAuthorityEffectReceiptV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestPreparationV1,
    DormantBrokerRequestSendProgressV1, DormantBrokerResponseProgressV1,
    DormantOutstandingBrokerRequestV1, DormantPreparedBrokerRequestV1,
    DormantUnconfirmedBrokerRequestV1, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerRequestCommitRecoveryV1,
    ProtectedBrokerSessionInitializationRecoveryV1,
};

const RETAINED_RECOVERY: &str = "authority effect retains protected recovery custody";
const SESSION_UNUSABLE: &str = "authority effect authenticated session is unusable";

/// Retains one authority effect exchange beside its authenticated session owner.
#[derive(Default)]
pub(crate) struct ControllerAuthorityEffectExchangeV1 {
    pending: Option<PendingAuthorityEffectV1>,
    failed: bool,
}

struct PendingAuthorityEffectV1 {
    effect: PreparedAuthorityEffectV1,
    kind: AuthorityEffectExchangeKindV1,
    stage: AuthorityEffectStageV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityEffectExchangeKindV1 {
    Apply,
    HostQuery,
    AtomicStorage,
}

enum AuthorityEffectStageV1 {
    Initialization {
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Successor {
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Send(DormantPreparedBrokerRequestV1),
    Receive(DormantOutstandingBrokerRequestV1),
    Commit(ProtectedBrokerOutcomeCommitRecoveryV1),
}

impl ControllerAuthorityEffectExchangeV1 {
    /// Reports whether an exact effect still owns this session's next action.
    pub(crate) const fn has_pending(&self) -> bool {
        self.pending.is_some() || self.failed
    }

    /// Reports that only a fresh authenticated session can make progress.
    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.failed
    }

    /// Resumes matching retained custody without issuing a previously absent Apply.
    pub(crate) fn resume(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        effect: &PreparedAuthorityEffectV1,
    ) -> Option<Result<ValidatedAuthorityEffectReceiptV1, EffectFailure>> {
        if self.failed {
            return Some(Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned())));
        }
        let pending = self.pending.as_ref()?;
        if pending.effect != *effect || pending.kind != AuthorityEffectExchangeKindV1::Apply {
            return Some(Err(EffectFailure::Permanent(
                "authority effect differs from retained recovery custody".to_owned(),
            )));
        }
        Some(
            self.drive(session)
                .and_then(|outcome| validate_apply_terminal(effect, &outcome)),
        )
    }

    /// Drives or resumes one exact durable Apply through terminal authentication.
    pub(crate) fn apply(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        effect.broker_request().map_err(|_| {
            EffectFailure::Permanent("durable authority effect is malformed".to_owned())
        })?;
        if self.failed {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self.pending.as_ref().is_some_and(|pending| {
            pending.effect != *effect || pending.kind != AuthorityEffectExchangeKindV1::Apply
        }) {
            return Err(EffectFailure::Permanent(
                "authority effect differs from retained recovery custody".to_owned(),
            ));
        }
        if self.pending.is_none() {
            let preparation = session
                .prepare_authenticated_authority_effect(effect)
                .map_err(|_| {
                    EffectFailure::Retryable(
                        "authority effect could not enter protected session custody".to_owned(),
                    )
                })?;
            let stage = preparation_stage(preparation);
            self.pending = Some(PendingAuthorityEffectV1 {
                effect: effect.clone(),
                kind: AuthorityEffectExchangeKindV1::Apply,
                stage,
            });
        }

        let outcome = self.drive(session)?;
        validate_apply_terminal(effect, &outcome)
    }

    /// Drives the exact signed Storage group while retaining ambiguous session custody.
    pub(crate) fn atomic_storage(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        lifecycle: &CurrentLifecycleEffectV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        fence: LiveRuntimeFenceV1,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        effect.broker_request().map_err(|_| {
            EffectFailure::Permanent("durable Storage group effect is malformed".to_owned())
        })?;
        if self.failed {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self.pending.as_ref().is_some_and(|pending| {
            pending.effect != *effect
                || pending.kind != AuthorityEffectExchangeKindV1::AtomicStorage
        }) {
            return Err(EffectFailure::Permanent(
                "Storage group differs from retained recovery custody".to_owned(),
            ));
        }
        if self.pending.is_none() {
            let preparation = session
                .prepare_authenticated_authority_effect_checked(effect, |request| {
                    lifecycle
                        .validate_authenticated_atomic_storage_snapshot_request(
                            request, plan, fence,
                        )
                        .is_ok()
                })
                .map_err(|_| {
                    EffectFailure::Retryable(
                        "Storage group could not enter protected session custody".to_owned(),
                    )
                })?;
            self.pending = Some(PendingAuthorityEffectV1 {
                effect: effect.clone(),
                kind: AuthorityEffectExchangeKindV1::AtomicStorage,
                stage: preparation_stage(preparation),
            });
        }

        let outcome = self.drive(session)?;
        validate_apply_terminal(effect, &outcome)?;
        Ok(outcome)
    }

    /// Queries Host for the durable status of one exact prior-process Apply.
    pub(crate) fn query_host(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
        effect.broker_request().map_err(|_| {
            EffectFailure::Permanent("durable Host authority effect is malformed".to_owned())
        })?;
        if self.failed {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self.pending.as_ref().is_some_and(|pending| {
            pending.effect != *effect || pending.kind != AuthorityEffectExchangeKindV1::HostQuery
        }) {
            return Err(EffectFailure::Permanent(
                "Host effect query differs from retained recovery custody".to_owned(),
            ));
        }
        if self.pending.is_none() {
            let preparation = session
                .prepare_authenticated_host_effect_query(effect)
                .map_err(|_| {
                    EffectFailure::Retryable(
                        "Host effect query could not enter protected session custody".to_owned(),
                    )
                })?;
            self.pending = Some(PendingAuthorityEffectV1 {
                effect: effect.clone(),
                kind: AuthorityEffectExchangeKindV1::HostQuery,
                stage: preparation_stage(preparation),
            });
        }

        let outcome = self.drive(session)?;
        let observation = validate_host_query_terminal(effect, &outcome)?;
        if observation == AuthorityEffectObservationV1::Pending {
            // Host queries reuse the original Apply ID. A second query must use
            // a new authenticated session after this terminal query outcome.
            self.failed = true;
        }
        Ok(observation)
    }

    fn drive(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        let mut attempted_recovery = false;
        loop {
            let pending = self.pending.take().ok_or_else(|| {
                EffectFailure::Retryable("authority effect custody is absent".to_owned())
            })?;
            let effect = pending.effect;
            let kind = pending.kind;
            let stage = match pending.stage {
                AuthorityEffectStageV1::Initialization { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            effect,
                            kind,
                            AuthorityEffectStageV1::Initialization { recovery, request },
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_initialization(recovery, request))
                }
                AuthorityEffectStageV1::Successor { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            effect,
                            kind,
                            AuthorityEffectStageV1::Successor { recovery, request },
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_successor(recovery, request))
                }
                AuthorityEffectStageV1::Send(prepared) => {
                    let deadline = prepared.deadline_boottime_nanoseconds();
                    match session.send_authenticated_request(prepared) {
                        Ok(DormantBrokerRequestSendProgressV1::Sent(outstanding)) => {
                            AuthorityEffectStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerRequestSendProgressV1::Pending(prepared)) => {
                            if wait(session, true, deadline).is_err() {
                                return self.retain(
                                    effect,
                                    kind,
                                    AuthorityEffectStageV1::Send(prepared),
                                );
                            }
                            AuthorityEffectStageV1::Send(prepared)
                        }
                        Err(_) => return self.fail(),
                    }
                }
                AuthorityEffectStageV1::Receive(outstanding) => {
                    let deadline = outstanding.deadline_boottime_nanoseconds();
                    match session.receive_authenticated_response(outstanding) {
                        Ok(DormantBrokerResponseProgressV1::Pending(outstanding)) => {
                            if wait(session, false, deadline).is_err() {
                                return self.retain(
                                    effect,
                                    kind,
                                    AuthorityEffectStageV1::Receive(outstanding),
                                );
                            }
                            AuthorityEffectStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
                        )) => return self.complete(session, committed),
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                                recovery, ..
                            },
                        )) => AuthorityEffectStageV1::Commit(recovery),
                        Err(_) => return self.fail(),
                    }
                }
                AuthorityEffectStageV1::Commit(recovery) => {
                    if attempted_recovery {
                        return self.retain(effect, kind, AuthorityEffectStageV1::Commit(recovery));
                    }
                    attempted_recovery = true;
                    match session.recover_broker_outcome_commit(recovery) {
                        ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                            return self.complete(session, committed);
                        }
                        ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                            recovery, ..
                        } => AuthorityEffectStageV1::Commit(recovery),
                    }
                }
            };
            self.pending = Some(PendingAuthorityEffectV1 {
                effect,
                kind,
                stage,
            });
        }
    }

    fn retain<T>(
        &mut self,
        effect: PreparedAuthorityEffectV1,
        kind: AuthorityEffectExchangeKindV1,
        stage: AuthorityEffectStageV1,
    ) -> Result<T, EffectFailure> {
        self.pending = Some(PendingAuthorityEffectV1 {
            effect,
            kind,
            stage,
        });
        Err(EffectFailure::Retryable(RETAINED_RECOVERY.to_owned()))
    }

    fn fail<T>(&mut self) -> Result<T, EffectFailure> {
        self.failed = true;
        Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()))
    }

    fn complete(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        let (outcome, currentness) = committed.into_outcome_and_currentness();
        let Ok(mut current) = session.revalidate_broker_outcome(currentness) else {
            return self.fail();
        };
        if current.revalidate().is_err() {
            return self.fail();
        }

        Ok(outcome)
    }
}

fn preparation_stage(preparation: DormantBrokerRequestPreparationV1) -> AuthorityEffectStageV1 {
    match preparation {
        DormantBrokerRequestPreparationV1::Prepared(prepared) => {
            AuthorityEffectStageV1::Send(prepared)
        }
        DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
            recovery,
            request,
            ..
        } => AuthorityEffectStageV1::Initialization { recovery, request },
        DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
            recovery, request, ..
        } => AuthorityEffectStageV1::Successor { recovery, request },
    }
}

fn validate_apply_terminal(
    effect: &PreparedAuthorityEffectV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
    if let AuthenticatedBrokerMethodResultV1::Error(error) = outcome.result() {
        let diagnostic = if error.safe_message().is_empty() {
            "broker rejected the durable authority effect".to_owned()
        } else {
            format!(
                "broker rejected the durable authority effect: {}",
                error.safe_message()
            )
        };
        return Err(EffectFailure::Permanent(diagnostic));
    }
    effect.validate_authenticated_outcome(outcome).map_err(|_| {
        EffectFailure::Permanent("broker returned a contradictory authority receipt".to_owned())
    })
}

fn validate_host_query_terminal(
    effect: &PreparedAuthorityEffectV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<AuthorityEffectObservationV1, EffectFailure> {
    if let AuthenticatedBrokerMethodResultV1::Error(error) = outcome.result() {
        let diagnostic = if error.safe_message().is_empty() {
            "Host rejected the durable authority-effect query".to_owned()
        } else {
            format!(
                "Host rejected the durable authority-effect query: {}",
                error.safe_message()
            )
        };
        return Err(EffectFailure::Permanent(diagnostic));
    }
    effect
        .validate_authenticated_host_observation(outcome)
        .map_err(|_| {
            EffectFailure::Permanent(
                "Host returned a contradictory authority-effect observation".to_owned(),
            )
        })
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
