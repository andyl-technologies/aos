//! Rejoins one earned Root member with its same native journal and real Input.
//!
//! Capacity forecasts have a separate readonly type. This gate exists only
//! inside the actual Flight's disjoint mutable journal scope and cannot be
//! constructed by a caller, a passive suffix or a successful advisory result.

use std::collections::BTreeMap;

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use super::RootAuthorityErrorV1;
use super::append_context::RootAuthorityQ04AppendContextV1;
use super::binding_history::RootAuthorityQ04HistoryV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::journal::RootPolicyJournalV1;
use crate::native::target::RootOriginalInputLoanV1;

/// Identifies the actual resident cause of a refused native Root append.
///
/// This diagnostic grants no authority and owns no replacement error. The
/// same genuine Input and Authority history keep their original typed cause.
#[derive(Clone, Copy)]
pub enum RootAuthorityQ04AppendFailureV1 {
    /// The actual Authority currentness, preflight or native result refused.
    AuthorityHeld,
    /// The genuine Input retained its actual Work/Target/Origin refusal first.
    PolicyHeld,
}

impl RootAuthorityQ04AppendFailureV1 {
    fn from_original_v1(original: &RootOriginalInputLoanV1<'_, '_, '_>) -> Self {
        if original.has_retained_failure_v1() {
            Self::PolicyHeld
        } else {
            Self::AuthorityHeld
        }
    }
}

pub(in crate::native) struct AuthorityAppendGateV1<'gate, 'cut, 'origin, 'startup> {
    context: RootAuthorityQ04AppendContextV1<'gate, 'origin, 'startup>,
    history: &'gate RootAuthorityQ04HistoryV1,
    stage: &'gate crate::q04_data::Q04RootStageRecipeV1,
    index: usize,
    original: &'gate RootOriginalInputLoanV1<'cut, 'origin, 'startup>,
}

impl AuthorityAppendGateV1<'_, '_, '_, '_> {
    pub(in crate::native) fn preflight_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), NativeError> {
        self.retain_v1((|| {
            if !self.history.may_append(self.index)
                || self.history.transactions().get(self.index..) != Some(transactions)
            {
                return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
            }
            self.require_history_stage_v1(journal)?;
            Ok(())
        })())?;
        self.original
            .require_same_origin_v1(&self.context.original_transport_v1())
            .map_err(|()| NativeError::boundary())
    }

    pub(in crate::native) fn require_q04_transition_v1(
        &self,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
        prospective_index: usize,
    ) -> Result<(), NativeError> {
        let index = self
            .index
            .checked_add(prospective_index)
            .ok_or_else(NativeError::geometry)?;
        self.history.require_transition(state, transaction, index)
    }

    fn before_native_commit_v1(
        &self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), NativeError> {
        // The inner old Journal helper repeated these observations after its
        // whole suffix preflight, before entering native commit preparation.
        self.retain_v1(self.history.require_fixed_original(journal))?;
        self.original
            .recheck_cut_v1(self.history.identity())
            .map(|_| ())
            .map_err(|()| NativeError::boundary())
    }

    pub(in crate::native) fn final_crossing_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), NativeError> {
        self.retain_v1((|| {
            if !self.history.may_append(self.index)
                || self.history.transactions().get(self.index) != Some(transaction)
            {
                return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
            }
            self.require_history_stage_v1(journal)?;
            Ok(())
        })())?;
        // Input retains its own actual Target/Origin cause before returning
        // this marker. Neither error enum owns the other role recursively.
        self.original
            .require_same_origin_v1(&self.context.original_transport_v1())
            .map_err(|()| NativeError::boundary())?;
        self.original
            .recheck_cut_v1(self.history.identity())
            .map_err(|()| NativeError::boundary())?;
        // Slow semantic/encoder work has ended. The same original pins,
        // complete Authority history and Source ACK are checked again here.
        self.retain_v1(self.context.require_current_v1(journal))
    }

    fn require_history_stage_v1(
        &self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.history.require_fixed_original(journal)?;
        self.context
            .require_stage_cut_v1(self.history.identity(), self.stage)?;
        self.history
            .require_original_stage_row_v1(journal, self.stage, self.index)?;
        Ok(())
    }

    fn retain_v1(&self, outcome: Result<(), RootAuthorityErrorV1>) -> Result<(), NativeError> {
        match outcome {
            Ok(()) => Ok(()),
            Err(error) => {
                self.history.retain_gate_failure_v1(error);
                Err(NativeError::boundary())
            }
        }
    }
}

impl<'authority, 'origin, 'startup>
    super::RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>
{
    /// Appends the one next earned Root member and parks its complete outcome.
    ///
    /// # Errors
    /// Returns a marker after retaining real preflight/native or current-cut
    /// failure. No later member becomes eligible from a forecast or failed IO.
    pub fn append_next_q04_history_v1(
        &mut self,
        stage: &crate::q04_data::Q04RootStageRecipeV1,
        source_packet: &[u8],
        original: &RootOriginalInputLoanV1<'_, 'origin, 'startup>,
    ) -> Result<(), RootAuthorityQ04AppendFailureV1> {
        let demand = match super::append_context::append_entry_receiving_demand_v1() {
            Ok(demand) => demand,
            Err(error) => {
                self.history_admission = Some(Err(error));
                return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
            }
        };
        let admission = self.authority.journal.admit_role_observation_v1(demand);
        if let Err(error) = admission {
            self.history_admission = Some(Err(RootAuthorityErrorV1::Journal(error)));
            return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
        }
        let returned = self.q04_append_scope_v1(source_packet);
        let (journal, context, history) = match returned {
            Ok(scope) => scope,
            Err(error) => {
                self.history_admission = Some(Err(error));
                return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
            }
        };
        let index = history.committed();
        if history.failure_v1().is_some()
            || !history.may_append(index)
            || history.commits.get(index).is_none_or(Option::is_some)
        {
            if history.failure_v1().is_none() && !original.has_retained_failure_v1() {
                history.retain_gate_failure_v1(
                    crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into(),
                );
            }
            return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
        }
        // The old owner checked the actual Stage, native prefix and Input
        // before entering Journal preflight. The later final crossing cannot
        // replace this earlier observation or its first-failure position.
        let entry = (|| {
            context.require_stage_cut_v1(history.identity(), stage)?;
            history.require_fixed_original(journal)?;
            history.require_original_stage_row_v1(journal, stage, index)?;
            Ok(())
        })();
        if let Err(error) = entry {
            history.retain_gate_failure_v1(error);
            return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
        }
        if original.recheck_cut_v1(history.identity()).is_err() {
            return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
        }
        let mut gate =
            crate::native::append::PolicyMutationGateV1::Authority(AuthorityAppendGateV1 {
                context,
                history,
                stage,
                index,
                original,
            });
        let preflight = gate.preflight(journal, &history.transactions()[index..]);
        if let Err(error) = preflight {
            drop(gate);
            history.preflight = Some(Err(error.into()));
            return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
        }
        let before_commit = match &gate {
            crate::native::append::PolicyMutationGateV1::Authority(authority) => {
                authority.before_native_commit_v1(journal)
            }
            // This exact local was constructed from the genuine Authority
            // above. A different variant cannot supply its history checks.
            _ => Err(NativeError::boundary()),
        };
        if let Err(error) = before_commit {
            drop(gate);
            history.preflight = Some(Err(error.into()));
            return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
        }
        let returned = gate.commit(journal, &history.transactions()[index]);
        // The actual native Result is resident before caller-owned original
        // clock, gen1, held-cache or later transport posts can fail.
        history.preflight = Some(Ok(()));
        history.commits[index] = Some(returned);
        if matches!(history.commits[index], Some(Err(_))) {
            return Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original));
        }
        match history.advance_parked_commit() {
            Ok(()) => Ok(()),
            Err(error) => {
                history.retain_gate_failure_v1(error);
                Err(RootAuthorityQ04AppendFailureV1::from_original_v1(original))
            }
        }
    }
}
