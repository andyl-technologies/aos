//! Same-peer completion and More ancestry retained in the original capsule.
//!
//! Only a callback token from this exact journal can authorize completion. The
//! original parent remains retained after each child transition. Every uncertain
//! operation prevents a new descendant; native recovery addresses that original
//! before its per-CPU last-operation result can be replaced.

use super::*;
use crate::qmp::{
    QmpKvmCompletionSummary, QmpKvmCompletionTransaction, QmpKvmMoreResponseState,
    QmpKvmMoreResponseTransaction, QmpKvmResponseBytesOperation, QmpKvmResponseBytesRequest,
    QmpKvmResponseBytesState,
};

pub(super) const MAXIMUM_RETAINED_BYTE_CREDIT: usize = 64 * 1024 * 1024;
// Covers the native 4096-byte payload, canonical encoding, identity strings and
// bounded scalar record. No credit is reclaimed while an original is retained.
const RETAINED_STATE_CREDIT: usize = 16 * 1024;

impl<S: QmpTimeoutStream> Journal<S> {
    /// Refuses fresh effects while an original native reply is still unknown.
    ///
    /// Reconciliation bypasses this check and retains the original request. A
    /// successful retry keeps historical uncertainty, so this component stays
    /// conservatively closed rather than guessing that a new cache is safe.
    pub(super) fn require_known_response_originals(&self) -> Result<(), KvmComponentError> {
        for entry in &self.entries {
            let unresolved = match &entry.original {
                Original::Initial(transaction) => {
                    transaction.uncertain_effects()
                        || transaction
                            .latest()
                            .is_none_or(|reply| !reply.observed().result_known)
                }
                Original::Completion { transaction, .. } => {
                    transaction.uncertain_effects() || transaction.accepted().is_none()
                }
                Original::More { transaction, .. } => {
                    transaction.uncertain_effects()
                        || transaction
                            .latest()
                            .is_none_or(|reply| !reply.observed().result_known)
                }
                Original::Window(_) | Original::Ack(_) => false,
            };
            if unresolved {
                return Err(KvmComponentError::Transition(
                    "original response reconciliation remains outstanding",
                ));
            }
        }
        Ok(())
    }

    /// Holds every original callback chain until its genuine terminal result.
    pub(super) fn require_settled_response_chains(&self) -> Result<(), KvmComponentError> {
        self.require_known_response_originals()?;
        for (index, entry) in self.entries.iter().enumerate() {
            if matches!(entry.original, Original::Initial(_)) && !self.response_chain_done(index) {
                return Err(KvmComponentError::Transition(
                    "original native response chain remains unfinished",
                ));
            }
        }
        Ok(())
    }

    fn response_chain_done(&self, mut current: usize) -> bool {
        // Each edge refers to an earlier retained token in this same journal.
        // The finite walk still bounds an invalid cycle without allocating.
        for _ in 0..self.entries.len() {
            let Some(entry) = self.entries.get(current) else {
                return false;
            };
            let next = match &entry.original {
                Original::Initial(_) | Original::More { .. } => {
                    self.entries.iter().position(|child| {
                        matches!(&child.original, Original::Completion { handler, .. }
                            if *handler == current)
                    })
                }
                Original::Completion { transaction, .. } => {
                    let Some(result) = transaction.accepted() else {
                        return false;
                    };
                    if transaction.uncertain_effects() || !result.observed().result_known {
                        return false;
                    }
                    match result.observed().native_phase {
                        3 => return true,
                        2 => self.entries.iter().position(|child| {
                            matches!(&child.original, Original::More { completion, .. }
                                if *completion == current)
                        }),
                        _ => return false,
                    }
                }
                Original::Window(_) | Original::Ack(_) => return false,
            };
            let Some(next) = next else {
                return false;
            };
            if next <= current {
                return false;
            }
            current = next;
        }
        false
    }

    pub(in crate::kvm_profile::owned_components) fn submit_completion(
        &mut self,
        handler: &KvmComponentToken,
    ) -> Result<(KvmComponentToken, Result<QmpKvmCompletionSummary, QmpError>), KvmComponentError>
    {
        self.require_known_response_originals()?;
        self.reserve_entry()?;
        let handler_index = self.original_handler(handler)?;
        if self.entries.iter().any(|entry| {
            matches!(entry.original,
            Original::Completion { handler, .. } if handler == handler_index)
        }) {
            return Err(KvmComponentError::Transition(
                "original handler completion already retained",
            ));
        }
        let credit = self.payload_credit(
            self.maximum_attempts
                .checked_add(2)
                .ok_or(KvmComponentError::ResourceLimit)?,
        )?;

        // The Query is observational and comes from this same authenticated
        // peer. Raw caller-provided byte facts never authorize this transition.
        let query = match &self.entries[handler_index].original {
            Original::Initial(original) => {
                if original.uncertain_effects()
                    || original
                        .latest()
                        .is_none_or(|state| !state.observed().result_known)
                {
                    return Err(KvmComponentError::Transition(
                        "original initial callback is uncertain",
                    ));
                }
                let retained = original.original();
                QmpKvmResponseBytesRequest {
                    operation: QmpKvmResponseBytesOperation::Query,
                    record_index: retained.record_index,
                    generation: retained.generation,
                    expected_invocation: retained.expected_invocation,
                    operation_id: 0,
                    expected_sequence: 0,
                }
            }
            Original::More { transaction, .. } => {
                if transaction.uncertain_effects()
                    || transaction
                        .latest()
                        .is_none_or(|state| !state.observed().result_known)
                {
                    return Err(KvmComponentError::Transition(
                        "original More callback is uncertain",
                    ));
                }
                let retained = transaction.birth().observed();
                QmpKvmResponseBytesRequest {
                    operation: QmpKvmResponseBytesOperation::Query,
                    record_index: retained.record_index,
                    generation: retained.generation,
                    expected_invocation: retained.invocation,
                    operation_id: 0,
                    expected_sequence: 0,
                }
            }
            _ => return Err(KvmComponentError::ForeignToken),
        };
        let baseline = self.qmp.control_native_kvm_response_bytes(&query)?;
        let transaction = match &self.entries[handler_index].original {
            Original::Initial(original) => {
                let predecessor = self.entries.iter().rev().find_map(|entry| {
                    let Original::Completion { transaction, .. } = &entry.original else {
                        return None;
                    };
                    (transaction.baseline().observed().vcpu_index == baseline.observed().vcpu_index)
                        .then_some(transaction)
                });
                if predecessor.is_some_and(|original| {
                    original.uncertain_effects() || original.accepted().is_none()
                }) {
                    return Err(KvmComponentError::Transition(
                        "original CPU predecessor is uncertain or unknown",
                    ));
                }
                QmpKvmCompletionTransaction::prepare_initial(
                    baseline,
                    original.latest().ok_or(KvmComponentError::Transition(
                        "original initial result is unknown",
                    ))?,
                    predecessor.and_then(QmpKvmCompletionTransaction::accepted),
                    self.maximum_attempts,
                )?
            }
            Original::More {
                transaction,
                completion,
            } => {
                let Original::Completion {
                    transaction: previous,
                    ..
                } = &self.entries[*completion].original
                else {
                    return Err(KvmComponentError::ForeignToken);
                };
                if previous.uncertain_effects() {
                    return Err(KvmComponentError::Transition(
                        "original preceding completion is uncertain",
                    ));
                }
                QmpKvmCompletionTransaction::prepare_more(
                    baseline,
                    previous.accepted().ok_or(KvmComponentError::Transition(
                        "original More birth is unknown",
                    ))?,
                    transaction.latest().ok_or(KvmComponentError::Transition(
                        "original More result is unknown",
                    ))?,
                    self.maximum_attempts,
                )?
            }
            _ => return Err(KvmComponentError::ForeignToken),
        };
        self.retained_byte_credit = credit;
        let token = self.retain(Original::Completion {
            handler: handler_index,
            transaction,
        });
        let Original::Completion { transaction, .. } = &mut self.entries[token.index].original
        else {
            return Err(KvmComponentError::ForeignToken);
        };
        let exchange = transaction.dispatch_once(&mut self.qmp);
        self.observations.push((
            token.index,
            Observation::Completion {
                state: transaction.latest_summary(),
                uncertain: transaction.uncertain_effects(),
            },
        ));
        Ok((token, exchange))
    }

    pub(in crate::kvm_profile::owned_components) fn reconcile_completion(
        &mut self,
        token: &KvmComponentToken,
    ) -> Result<QmpKvmCompletionSummary, KvmComponentError> {
        let index = self.admit_attempt(token, CommandClass::Completion)?;
        let Original::Completion { transaction, .. } = &mut self.entries[index].original else {
            return Err(KvmComponentError::ForeignToken);
        };
        let exchange = transaction.reconcile(&mut self.qmp);
        self.observations.push((
            index,
            Observation::Completion {
                state: transaction.latest_summary(),
                uncertain: transaction.uncertain_effects(),
            },
        ));
        Ok(exchange?)
    }

    pub(in crate::kvm_profile::owned_components) fn submit_more(
        &mut self,
        completion: &KvmComponentToken,
    ) -> Result<(KvmComponentToken, Result<QmpKvmMoreResponseState, QmpError>), KvmComponentError>
    {
        self.require_known_response_originals()?;
        self.reserve_entry()?;
        let index = self.original_index(completion, CommandClass::Completion)?;
        if self.entries.iter().any(|entry| {
            matches!(entry.original,
            Original::More { completion, .. } if completion == index)
        }) {
            return Err(KvmComponentError::Transition(
                "original More callback already retained",
            ));
        }
        let credit = self.payload_credit(1)?;
        let Original::Completion { transaction, .. } = &self.entries[index].original else {
            return Err(KvmComponentError::ForeignToken);
        };
        if transaction.uncertain_effects() {
            return Err(KvmComponentError::Transition(
                "original More completion is uncertain",
            ));
        }
        let birth = transaction
            .accepted()
            .ok_or(KvmComponentError::Transition(
                "original More completion is unknown",
            ))?
            .try_copy()?;
        let transaction = QmpKvmMoreResponseTransaction::prepare(birth)?;
        self.retained_byte_credit = credit;
        let token = self.retain(Original::More {
            completion: index,
            transaction,
        });
        let Original::More { transaction, .. } = &mut self.entries[token.index].original else {
            return Err(KvmComponentError::ForeignToken);
        };
        let exchange = transaction.dispatch_once(&mut self.qmp);
        self.observations.push((
            token.index,
            Observation::More {
                state: transaction.latest().copied(),
                uncertain: transaction.uncertain_effects(),
            },
        ));
        Ok((token, exchange))
    }

    pub(in crate::kvm_profile::owned_components) fn reconcile_more(
        &mut self,
        token: &KvmComponentToken,
    ) -> Result<QmpKvmMoreResponseState, KvmComponentError> {
        let index = self.admit_attempt(token, CommandClass::More)?;
        let Original::More { transaction, .. } = &mut self.entries[index].original else {
            return Err(KvmComponentError::ForeignToken);
        };
        let exchange = transaction.reconcile(&mut self.qmp);
        self.observations.push((
            index,
            Observation::More {
                state: transaction.latest().copied(),
                uncertain: transaction.uncertain_effects(),
            },
        ));
        Ok(exchange?)
    }

    pub(in crate::kvm_profile::owned_components) fn completion_reply(
        &self,
        token: &KvmComponentToken,
        reply: usize,
    ) -> Result<QmpKvmResponseBytesState, KvmComponentError> {
        let index = self.original_index(token, CommandClass::Completion)?;
        let Original::Completion { transaction, .. } = &self.entries[index].original else {
            return Err(KvmComponentError::ForeignToken);
        };
        Ok(transaction
            .replies()
            .get(reply)
            .ok_or(KvmComponentError::Transition(
                "retained original reply is absent",
            ))?
            .try_copy()?)
    }

    fn payload_credit(&self, states: usize) -> Result<usize, KvmComponentError> {
        let credit = states
            .checked_mul(RETAINED_STATE_CREDIT)
            .and_then(|required| self.retained_byte_credit.checked_add(required))
            .filter(|total| *total <= MAXIMUM_RETAINED_BYTE_CREDIT)
            .ok_or(KvmComponentError::ResourceLimit)?;
        Ok(credit)
    }

    fn original_handler(&self, token: &KvmComponentToken) -> Result<usize, KvmComponentError> {
        if !Rc::ptr_eq(&self.identity, &token.identity) {
            return Err(KvmComponentError::ForeignToken);
        }
        let entry = self
            .entries
            .get(token.index)
            .ok_or(KvmComponentError::ForeignToken)?;
        if !matches!(entry.original, Original::Initial(_) | Original::More { .. }) {
            return Err(KvmComponentError::ForeignToken);
        }
        Ok(token.index)
    }
}
