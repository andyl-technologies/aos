//! Composes the sole prospective and native schedules with genuine Policy gates.
//!
//! Ordinary storage and selected Root storage retain their different disposal
//! policies. The private context never owns a financial/native invocation guard
//! across a role's final currentness debit or its independent owed post.

mod context;
mod delete;
mod gate;
mod genesis;
mod policy;
mod preflight;

pub(in crate::native) use context::PolicyAppendContextV1;
pub(in crate::native) use gate::PolicyMutationGateV1;

use crate::native::PolicyNativeJournalErrorV1 as ErrorV1;
use crate::native::journal::RootPolicyJournalV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1 as Mechanical, CommitResult,
};
use aos_sandbox_ledger_replay::replay::root_original_inventory;
use aos_sandbox_protocol::domain_ledger::{
    readonly,
    transaction::{JournalTransaction, validate_transaction},
};

impl RootPolicyJournalV1 {
    pub(in crate::native) fn commit_with_role_gate_v1(
        &mut self,
        transaction: &JournalTransaction,
        mut gate: PolicyMutationGateV1<'_, '_, '_, '_, '_>,
    ) -> Result<CommitResult, ErrorV1> {
        self.ensure_healthy()?;
        self.admit_append_semantics_v1(transaction, &gate)?;
        let capacity = policy::require_live_v1(self, transaction, &mut gate)?;
        validate_transaction(transaction, self.limits()).map_err(Mechanical::from)?;
        delete::validate(
            self.read_view().state(),
            transaction,
            self.next_sequence(),
            self.limits(),
        )?;
        capacity.require_presence_v1(transaction)?;
        if self
            .read_view()
            .transaction_ids()
            .contains(transaction.id())
        {
            return Err(Mechanical::DuplicateTransaction.into());
        }
        if self.read_view().committed_transactions() >= self.limits().maximum_transactions {
            return Err(Mechanical::LimitExceeded("committed transaction count").into());
        }
        readonly::validate_idempotency_changes(
            self.read_view().idempotency_index(),
            transaction.records(),
        )
        .map_err(Mechanical::from)?;

        // Startup's Initial still holds the same L borrow. Its genuine private
        // gate lends that borrow at the original post prepayment frontier.
        let borrowed_financial = match &gate {
            PolicyMutationGateV1::StartupCredential(original) =>
                Some(original.borrowed_financial_v1()),
            _ => None,
        };
        self.begin_native_append_interval_v1(transaction, borrowed_financial)?;
        let mut context = PolicyAppendContextV1::new(self);
        aos_sandbox_broker::run_canonical_semantic_append_v1! {
            context: context,
            transaction: transaction,
            gate: gate,
            boundary: ErrorV1::boundary(),
            coordinates: (materialized_bytes, commit_sequence, following_sequence, durable_bytes),
            preflight: {
                root_original_inventory::require_append_sequence_headroom(
                    context.journal.read_view().state(), transaction, following_sequence,
                )?;
                let expected_length = context.expected_length()?;
                preflight::require_capacity_v1(context.journal, context.journal.read_view().state(),
                    transaction, materialized_bytes, expected_length,
                    context.journal.read_view().committed_transactions().checked_add(1)
                        .ok_or_else(ErrorV1::geometry)?, &capacity)?;
                if gate.has_successor_v1() {
                    aos_sandbox_ledger_replay::replay::source_tree_successor::require_sequence_headroom(
                        &root_original_inventory::materialize(context.journal.read_view().state(), transaction),
                        following_sequence,
                    )?;
                }
            },
            final_crossing: {
                // Native prepare returned after releasing its own N guard.
                // The real role may now debit/recheck its same Authority.
                gate.final_crossing_v1(context.journal, transaction)?;
            },
            durable_check: {},
            published: {
                context.journal.captured_native_bytes = durable_bytes;
            },
            completed: { Ok(CommitResult { commit_sequence, durable_bytes }) },
        }
    }
}
