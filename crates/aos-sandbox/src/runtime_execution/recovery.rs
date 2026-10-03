//! Applicative protected-journal recovery for runtime execution effects.
//!
//! Recovery first resolves durable exact replay. Nonterminal effects require
//! one opaque complete inventory minted by an authenticated loader. Every
//! closed portable recovery decision is then committed or returned with the
//! exact prior state and opaque ambiguity token needed for protected reopen.

use aos_sandbox_core::runtime_backend::{
    BackendExecutionInventoryV1, DurableExecutionEffectV1, ExecutionEffectTransitionV1,
    ExecutionRecoveryActionV1, ExecutionRecoveryPreflightV1, preflight_execution_recovery,
    reconcile_execution_effect, reserve_effect_issue,
};

use super::evidence::{
    JournalExecutionCompletionV1, completion_from_authenticated_absence_v1,
    completion_from_authenticated_quarantine_v1, completion_from_backend_observation_v1,
};
use super::store::{
    AuthenticatedJournalExecutionRecoveryV1, ExecutionJournalRecoveryTokenV1,
    JournalRuntimeExecutionError, JournalRuntimeExecutionStoreV1,
};

/// Reports the durable result of applying one closed recovery decision.
#[must_use = "recovery ambiguity and the exact prior state must be retained"]
pub enum AppliedExecutionRecoveryV1 {
    /// The original Complete record is the retained exact replay response.
    ExactReplay(DurableExecutionEffectV1),
    /// Recovery durably committed the selected successor state.
    Committed(DurableExecutionEffectV1),
    /// Commit durability is ambiguous and requires protected reopen.
    RecoveryRequired {
        /// Exact durable state from before the ambiguous transition.
        prior: DurableExecutionEffectV1,
        /// Completion evidence that must be reused, when completing recovery.
        completion: Option<JournalExecutionCompletionV1>,
        /// Store-owned authority for resolving only this transaction.
        token: ExecutionJournalRecoveryTokenV1,
    },
    /// Protected reopen proved the selected transition absent.
    NotCommitted {
        /// Exact durable state that remains current.
        prior: DurableExecutionEffectV1,
        /// Completion evidence retained for an explicit later decision.
        completion: Option<JournalExecutionCompletionV1>,
    },
}

/// Reconciles and durably applies one execution recovery decision.
///
/// Callers pass no inventory for a Complete snapshot. This preserves the
/// required durable-replay-before-live-inventory ordering. Every other phase
/// requires an opaque complete inventory obtained through the portable
/// authenticated loader boundary.
///
/// # Errors
///
/// Returns [`JournalRuntimeExecutionError`] for absent required inventory,
/// stale or conflicting bindings, invalid completion evidence, or a protected
/// journal transition failure.
pub(crate) fn apply_execution_recovery_v1(
    store: &mut JournalRuntimeExecutionStoreV1<'_>,
    snapshot: AuthenticatedJournalExecutionRecoveryV1,
    inventory: Option<BackendExecutionInventoryV1>,
) -> Result<AppliedExecutionRecoveryV1, JournalRuntimeExecutionError> {
    if preflight_execution_recovery(snapshot.effect())
        == ExecutionRecoveryPreflightV1::ReturnExactReplay
    {
        return Ok(AppliedExecutionRecoveryV1::ExactReplay(
            snapshot.effect().clone(),
        ));
    }
    let inventory = inventory.ok_or(JournalRuntimeExecutionError::MissingInventory)?;
    let action = reconcile_execution_effect(snapshot.effect(), &inventory)?;
    let prior = snapshot.effect().clone();

    match action {
        ExecutionRecoveryActionV1::ReturnExactReplay => {
            Ok(AppliedExecutionRecoveryV1::ExactReplay(prior))
        }
        ExecutionRecoveryActionV1::ReserveInitialIssue => {
            map_transition(prior.clone(), None, reserve_effect_issue(store, &prior)?)
        }
        ExecutionRecoveryActionV1::CommitObserved(observation) => {
            let completion = completion_from_backend_observation_v1(&prior, observation)?;
            commit_completion(store, prior, completion)
        }
        ExecutionRecoveryActionV1::CommitLost {
            inventory_commitment,
            provenance_commitment,
            inventory_generation,
            sequence_floor,
        } => {
            if inventory_commitment != inventory.inventory_commitment()
                || provenance_commitment != inventory.provenance_commitment()
                || inventory_generation != inventory.inventory_generation()
                || sequence_floor != inventory.sequence_floor()
            {
                return Err(JournalRuntimeExecutionError::RecordConflict);
            }
            let completion = completion_from_authenticated_absence_v1(&prior, &inventory)?;
            commit_completion(store, prior, completion)
        }
        ExecutionRecoveryActionV1::Quarantine => {
            if prior.phase() == aos_sandbox_core::runtime_backend::EffectPhaseV1::Pending {
                match reserve_effect_issue(store, &prior)? {
                    ExecutionEffectTransitionV1::Committed(issued) => {
                        store.disarm_recovery_issue(&issued);
                        let completion =
                            completion_from_authenticated_quarantine_v1(&issued, &inventory)?;
                        commit_completion(store, issued, completion)
                    }
                    ExecutionEffectTransitionV1::RecoveryRequired(token) => {
                        Ok(AppliedExecutionRecoveryV1::RecoveryRequired {
                            prior,
                            completion: None,
                            token,
                        })
                    }
                    ExecutionEffectTransitionV1::NotCommitted => {
                        Ok(AppliedExecutionRecoveryV1::NotCommitted {
                            prior,
                            completion: None,
                        })
                    }
                }
            } else {
                let completion = completion_from_authenticated_quarantine_v1(&prior, &inventory)?;
                commit_completion(store, prior, completion)
            }
        }
    }
}

fn commit_completion(
    store: &mut JournalRuntimeExecutionStoreV1<'_>,
    prior: DurableExecutionEffectV1,
    completion: JournalExecutionCompletionV1,
) -> Result<AppliedExecutionRecoveryV1, JournalRuntimeExecutionError> {
    let transition = store.commit_verified_completion(&prior, &completion)?;
    map_transition(prior, Some(completion), transition)
}

fn map_transition(
    prior: DurableExecutionEffectV1,
    completion: Option<JournalExecutionCompletionV1>,
    transition: ExecutionEffectTransitionV1<ExecutionJournalRecoveryTokenV1>,
) -> Result<AppliedExecutionRecoveryV1, JournalRuntimeExecutionError> {
    Ok(match transition {
        ExecutionEffectTransitionV1::Committed(effect) => {
            AppliedExecutionRecoveryV1::Committed(effect)
        }
        ExecutionEffectTransitionV1::RecoveryRequired(token) => {
            AppliedExecutionRecoveryV1::RecoveryRequired {
                prior,
                completion,
                token,
            }
        }
        ExecutionEffectTransitionV1::NotCommitted => {
            AppliedExecutionRecoveryV1::NotCommitted { prior, completion }
        }
    })
}
