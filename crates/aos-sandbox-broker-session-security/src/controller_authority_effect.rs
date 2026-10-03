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
use aos_sandbox_protocol::semantics::{
    CanonicalStoragePreparationSemanticsV1, ProtectedStorageCreatePreparationV1,
};

use crate::DormantAuthenticatedBrokerSessionV1;
use crate::controller_retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};

const RETAINED_RECOVERY: &str = "authority effect retains protected recovery custody";
const SESSION_UNUSABLE: &str = "authority effect authenticated session is unusable";
const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "authority effect custody is absent",
    retained: RETAINED_RECOVERY,
    unusable: SESSION_UNUSABLE,
};

/// Retains one authority effect exchange beside its authenticated session owner.
#[derive(Default)]
pub(crate) struct ControllerAuthorityEffectExchangeV1 {
    exchange: RetainedBrokerExchangeV1<AuthorityEffectContextV1>,
}

struct AuthorityEffectContextV1 {
    effect: PreparedAuthorityEffectV1,
    kind: AuthorityEffectExchangeKindV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityEffectExchangeKindV1 {
    Apply,
    HostQuery,
    AtomicStorage,
    StoragePrepare,
}

impl ControllerAuthorityEffectExchangeV1 {
    /// Reports whether an exact effect still owns this session's next action.
    pub(crate) const fn has_pending(&self) -> bool {
        self.exchange.has_pending()
    }

    /// Reports that only a fresh authenticated session can make progress.
    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.exchange.requires_reconnect()
    }

    /// Resumes matching retained custody without issuing a previously absent Apply.
    pub(crate) fn resume(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        effect: &PreparedAuthorityEffectV1,
    ) -> Option<Result<ValidatedAuthorityEffectReceiptV1, EffectFailure>> {
        if self.requires_reconnect() {
            return Some(Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned())));
        }
        let pending = self.exchange.context()?;
        if pending.effect != *effect || pending.kind != AuthorityEffectExchangeKindV1::Apply {
            return Some(Err(EffectFailure::Permanent(
                "authority effect differs from retained recovery custody".to_owned(),
            )));
        }
        Some(
            self.exchange
                .drive(session, &ERRORS)
                .map(|(_, outcome)| outcome)
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
        if self.requires_reconnect() {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self.exchange.context().is_some_and(|pending| {
            pending.effect != *effect || pending.kind != AuthorityEffectExchangeKindV1::Apply
        }) {
            return Err(EffectFailure::Permanent(
                "authority effect differs from retained recovery custody".to_owned(),
            ));
        }
        if self.exchange.context().is_none() {
            let preparation = session
                .prepare_authenticated_authority_effect(effect)
                .map_err(|_| {
                    EffectFailure::Retryable(
                        "authority effect could not enter protected session custody".to_owned(),
                    )
                })?;
            self.exchange.start(
                AuthorityEffectContextV1 {
                    effect: effect.clone(),
                    kind: AuthorityEffectExchangeKindV1::Apply,
                },
                preparation,
            );
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
        if self.requires_reconnect() {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self.exchange.context().is_some_and(|pending| {
            pending.effect != *effect
                || pending.kind != AuthorityEffectExchangeKindV1::AtomicStorage
        }) {
            return Err(EffectFailure::Permanent(
                "Storage group differs from retained recovery custody".to_owned(),
            ));
        }
        if self.exchange.context().is_none() {
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
            self.exchange.start(
                AuthorityEffectContextV1 {
                    effect: effect.clone(),
                    kind: AuthorityEffectExchangeKindV1::AtomicStorage,
                },
                preparation,
            );
        }

        let outcome = self.drive(session)?;
        validate_apply_terminal(effect, &outcome)?;
        Ok(outcome)
    }

    /// Retains one exact signed Create catalog preparation through completion.
    pub(crate) fn storage_create_prepare(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        protected: &ProtectedStorageCreatePreparationV1,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        effect.broker_request().map_err(|_| {
            EffectFailure::Permanent("Storage Create preparation is malformed".to_owned())
        })?;
        if self.requires_reconnect() {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self.exchange.context().is_some_and(|pending| {
            pending.effect != *effect
                || pending.kind != AuthorityEffectExchangeKindV1::StoragePrepare
        }) {
            return Err(EffectFailure::Permanent(
                "Storage preparation differs from retained recovery custody".to_owned(),
            ));
        }
        if self.exchange.context().is_none() {
            let preparation = session
                .prepare_authenticated_authority_effect_checked(effect, |request| {
                    let Ok(now) = crate::handshake::protected_boottime_nanoseconds() else {
                        return false;
                    };
                    request.method()
                        == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                        && request.authorization().is_some()
                        && CanonicalStoragePreparationSemanticsV1::decode(
                            request.exact_body(),
                            request.peer(),
                            request.peer_policy(),
                            now,
                        )
                        .is_ok_and(|decoded| protected.matches_decoded(&decoded))
                })
                .map_err(|_| {
                    EffectFailure::Retryable(
                        "Storage Create preparation could not enter protected session custody"
                            .to_owned(),
                    )
                })?;
            self.exchange.start(
                AuthorityEffectContextV1 {
                    effect: effect.clone(),
                    kind: AuthorityEffectExchangeKindV1::StoragePrepare,
                },
                preparation,
            );
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
        if self.requires_reconnect() {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self.exchange.context().is_some_and(|pending| {
            pending.effect != *effect || pending.kind != AuthorityEffectExchangeKindV1::HostQuery
        }) {
            return Err(EffectFailure::Permanent(
                "Host effect query differs from retained recovery custody".to_owned(),
            ));
        }
        if self.exchange.context().is_none() {
            let preparation = session
                .prepare_authenticated_host_effect_query(effect)
                .map_err(|_| {
                    EffectFailure::Retryable(
                        "Host effect query could not enter protected session custody".to_owned(),
                    )
                })?;
            self.exchange.start(
                AuthorityEffectContextV1 {
                    effect: effect.clone(),
                    kind: AuthorityEffectExchangeKindV1::HostQuery,
                },
                preparation,
            );
        }

        let outcome = self.drive(session)?;
        let observation = validate_host_query_terminal(effect, &outcome)?;
        if observation == AuthorityEffectObservationV1::Pending {
            // Host queries reuse the original Apply ID. A second query must use
            // a new authenticated session after this terminal query outcome.
            self.exchange.mark_failed();
        }
        Ok(observation)
    }

    fn drive(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        self.exchange
            .drive(session, &ERRORS)
            .map(|(_, outcome)| outcome)
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
