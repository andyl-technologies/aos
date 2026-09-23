//! Exact controller custody shared by public Cache pin and unpin effects.
//!
//! Both operations retain the same protected and physical ambiguity tokens.
//! The caller supplies the transaction identity and operation-specific errors.

use aos_sandbox::cache_residency::{
    CacheOwnerErrorV1, CacheOwnerOutcomeUnknownV1, CacheOwnerPinSettlementErrorV1,
    CacheOwnerPinSettlementV1, CacheResidencyCommitOutcomeV1, CacheResidencyOutcomeUnknownV1,
    CacheResidencyProtectedOwnerRecoveryV1, CacheResidencyProtectedOwnerV1,
    CacheResidencyRecoveryV1, DormantCacheOwnerV1,
};

use super::{EffectFailure, OperationId};

pub(in crate::controller_service) struct PendingControllerCacheCustodyV1<Payload> {
    pub(in crate::controller_service) operation_id: OperationId,
    pub(in crate::controller_service) payload: Payload,
    pub(in crate::controller_service) custody: CacheCustodyV1,
}

pub(in crate::controller_service) enum CacheCustodyV1 {
    Protected(CacheResidencyOutcomeUnknownV1),
    Physical(CacheOwnerOutcomeUnknownV1),
}

pub(in crate::controller_service) struct CacheCustodyMessages {
    pub(in crate::controller_service) owners_unavailable: &'static str,
    pub(in crate::controller_service) another_operation: &'static str,
    pub(in crate::controller_service) physical_unresolved: &'static str,
    pub(in crate::controller_service) protected_pending: &'static str,
    pub(in crate::controller_service) protected_indeterminate: &'static str,
    pub(in crate::controller_service) protected_diverged: &'static str,
    pub(in crate::controller_service) physical_unknown: &'static str,
}

/// Selects only an ambiguous protected commit or physical settlement token.
pub(in crate::controller_service) fn cache_custody_from_commit(
    outcome: CacheResidencyCommitOutcomeV1,
    settlement: Option<Result<CacheOwnerPinSettlementV1, CacheOwnerPinSettlementErrorV1>>,
) -> Option<CacheCustodyV1> {
    match outcome {
        CacheResidencyCommitOutcomeV1::OutcomeUnknown { pending, .. }
        | CacheResidencyCommitOutcomeV1::ValidationUnknown { pending, .. } => {
            Some(CacheCustodyV1::Protected(pending))
        }
        CacheResidencyCommitOutcomeV1::Applied(_) => match settlement {
            Some(Err(CacheOwnerPinSettlementErrorV1::Owner(
                CacheOwnerErrorV1::OutcomeUnknown(pending),
            ))) => Some(CacheCustodyV1::Physical(pending)),
            _ => None,
        },
    }
}

/// Recovers retained custody before either operation can make more progress.
pub(in crate::controller_service) fn recover_pending_cache_custody<Payload>(
    pending: &mut Option<PendingControllerCacheCustodyV1<Payload>>,
    protected: &mut Option<CacheResidencyProtectedOwnerV1>,
    physical: &mut Option<DormantCacheOwnerV1>,
    operation_id: OperationId,
    transaction_id: impl FnOnce(&Payload) -> [u8; 16],
    messages: &CacheCustodyMessages,
) -> Result<(), EffectFailure> {
    if pending.is_some() && (protected.is_none() || physical.is_none()) {
        return Err(EffectFailure::Retryable(
            messages.owners_unavailable.to_owned(),
        ));
    }
    let Some(retained) = pending.take() else {
        return Ok(());
    };
    if retained.operation_id != operation_id {
        *pending = Some(retained);
        return Err(EffectFailure::Retryable(
            messages.another_operation.to_owned(),
        ));
    }

    let PendingControllerCacheCustodyV1 {
        operation_id,
        payload,
        custody,
    } = retained;
    match custody {
        CacheCustodyV1::Physical(token) => {
            let owner = physical.as_mut().ok_or_else(|| {
                EffectFailure::Permanent("physical Cache owner is unavailable".to_owned())
            })?;
            match owner.recover_outcome_unknown(token) {
                Ok(_) => Ok(()),
                Err(failure) => {
                    let (token, cause) = failure.into_parts();
                    *pending = Some(PendingControllerCacheCustodyV1 {
                        operation_id,
                        payload,
                        custody: CacheCustodyV1::Physical(token),
                    });
                    Err(EffectFailure::Retryable(format!(
                        "{}: {cause}",
                        messages.physical_unresolved
                    )))
                }
            }
        }
        CacheCustodyV1::Protected(token) => {
            let owner = protected.as_mut().ok_or_else(|| {
                EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
            })?;
            let physical = physical.as_mut().ok_or_else(|| {
                EffectFailure::Permanent("physical Cache owner is unavailable".to_owned())
            })?;
            let recovery = owner.recover(transaction_id(&payload), token, |postcommit| {
                postcommit.settle_cache_owner_pin_change(physical)
            });
            let (next_custody, failure) = match recovery {
                CacheResidencyProtectedOwnerRecoveryV1::Pending {
                    pending: token,
                    cause,
                    ..
                } => (
                    CacheCustodyV1::Protected(token),
                    EffectFailure::Retryable(format!("{}: {cause}", messages.protected_pending)),
                ),
                CacheResidencyProtectedOwnerRecoveryV1::Classified {
                    recovery:
                        CacheResidencyRecoveryV1::Indeterminate {
                            pending: token,
                            cause,
                        },
                    ..
                } => (
                    CacheCustodyV1::Protected(token),
                    EffectFailure::Retryable(format!(
                        "{}: {cause}",
                        messages.protected_indeterminate
                    )),
                ),
                CacheResidencyProtectedOwnerRecoveryV1::Classified {
                    recovery: CacheResidencyRecoveryV1::Diverged(token),
                    ..
                } => (
                    CacheCustodyV1::Protected(token),
                    EffectFailure::Permanent(messages.protected_diverged.to_owned()),
                ),
                CacheResidencyProtectedOwnerRecoveryV1::Classified {
                    recovery: CacheResidencyRecoveryV1::Applied(_),
                    handoff:
                        Some(Err(CacheOwnerPinSettlementErrorV1::Owner(
                            CacheOwnerErrorV1::OutcomeUnknown(token),
                        ))),
                    ..
                } => (
                    CacheCustodyV1::Physical(token),
                    EffectFailure::Retryable(messages.physical_unknown.to_owned()),
                ),
                CacheResidencyProtectedOwnerRecoveryV1::Classified { .. }
                | CacheResidencyProtectedOwnerRecoveryV1::ColdLookupRequired { .. } => {
                    // The caller's next pass rechecks the transaction and physical owner.
                    return Ok(());
                }
            };
            *pending = Some(PendingControllerCacheCustodyV1 {
                operation_id,
                payload,
                custody: next_custody,
            });
            Err(failure)
        }
    }
}
