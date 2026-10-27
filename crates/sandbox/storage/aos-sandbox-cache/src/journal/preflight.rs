//! Forecasts the same ordinary Cache bounds under the real original interlock.
//!
//! Prospective maps and encoded frames remain advisory DATA. The actual owner
//! still requires its intrinsic snapshot, original target/gate and native
//! crossing before effect; no forecast is adopted as a writer or live permit.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::domain_transaction_custody::pressure::{
    CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
};
use aos_sandbox_ledger_replay::{ordinary_mutation as ordinary, replay::root_original_inventory};

use super::{CacheMutationGateV1, HeldCacheMutationGateV1, Journal, JournalError, JournalTransaction, RecordNamespace, delete_batch, policy};

// One finite DATA selection feeds the same bound/map/frame engine. It cannot
// append or supply the genuine Root loan required by the native Q04 entry.
enum CachePreflightRecipeV1<'recipe, 'cut> {
    Ordinary,
    ReadOnlyBase { hold: &'recipe Journal },
    Q04 { recipes: &'recipe super::q04::CacheQ04TransactionRecipesV1<'cut>, first: usize },
}

impl CachePreflightRecipeV1<'_, '_> {
    fn transaction_recipe(&self, offset: usize) -> policy::CacheTransactionRecipeV1<'_, '_> {
        match self {
            Self::Ordinary | Self::ReadOnlyBase { .. } => policy::CacheTransactionRecipeV1::Ordinary,
            Self::Q04 { recipes, first } => policy::CacheTransactionRecipeV1::Q04 {
                recipes, index: first + offset,
            },
        }
    }
}

impl Journal {
    pub(crate) fn preflight_transactions(&self, transactions: &[JournalTransaction]) -> Result<(), JournalError> {
        self.preflight_with_original_cache_gate_v1(transactions, CacheMutationGateV1::Ordinary)
    }

    pub(crate) fn preflight_with_retained_cache_gate_v1(
        &self,
        transactions: &[JournalTransaction],
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<(), JournalError> {
        self.preflight_with_original_cache_gate_v1(transactions, CacheMutationGateV1::Retained(gate))
    }

    pub(crate) fn preflight_with_original_cache_gate_v1(
        &self,
        transactions: &[JournalTransaction],
        gate: CacheMutationGateV1<'_>,
    ) -> Result<(), JournalError> {
        self.preflight_in_recipe_v1(transactions, gate, CachePreflightRecipeV1::Ordinary)
    }

    pub(crate) fn preflight_q04_cache_read_only_base_v1(
        &self,
        hold: &Journal,
    ) -> Result<(), crate::error::CacheQ04ErrorV1> {
        self.preflight_in_recipe_v1(
            &[], CacheMutationGateV1::Ordinary, CachePreflightRecipeV1::ReadOnlyBase { hold },
        )?;
        Ok(())
    }

    pub(super) fn preflight_cache_q04_data_v1(
        &self,
        recipes: &super::q04::CacheQ04TransactionRecipesV1<'_>,
        first: usize,
    ) -> Result<(), JournalError> {
        let transactions = recipes.transactions().get(first..).ok_or(JournalError::boundary())?;
        self.preflight_in_recipe_v1(
            transactions, CacheMutationGateV1::Ordinary,
            CachePreflightRecipeV1::Q04 { recipes, first },
        )
    }

    fn preflight_in_recipe_v1(
        &self,
        transactions: &[JournalTransaction],
        mut gate: CacheMutationGateV1<'_>,
        recipe: CachePreflightRecipeV1<'_, '_>,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        let native = self.read_view();
        for transaction in transactions {
            ordinary::require_no_create_storage_mutation(native.state(), transaction)?;
        }
        aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(native, native.state())?;
        match &recipe {
            CachePreflightRecipeV1::ReadOnlyBase { hold } => self.require_q04_cache_read_only_base_v1(hold)?,
            _ => gate.check(self)?,
        }
        aos_sandbox_broker::canonical_prospective_preflight_data_v1! {
            error JournalError;
            transactions transactions;
            count transactions.len();
            transaction(index) &transactions[index];
            models models = aos_sandbox_broker::canonical_journal::preflight::schedule::CanonicalPreflightWorkingModelsDataV1 {
                state: native.state().clone(),
                idempotency: native.idempotency_index().clone(),
                transaction_ids: native.transaction_ids().clone(),
                materialized_bytes: native.materialized_bytes(),
                next_sequence: native.next_sequence(),
                committed_transactions: native.committed_transactions(),
            };
            limits native.limits();
            retained None;
            preview {
                delete_batch::bound_preview_view(
                    native.state(), &delete_batch::PreflightTransactionViewV1::Ordinary(transactions),
                    native.limits(),
                )?;
            }
            metadata native.metadata();
            before_transaction(transaction) {
                let settling = policy::successor_settling(&models.state, transaction)?;
                aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(native, &models.state)?;
                ordinary::require_no_nix_native_mutation_v1(&models.state, transaction)?;
                policy::require_ordinary_owner(self, &models.state, transaction)?;
                ordinary::require_common_no_selected_boundaries_v1(&models.state, transaction)?;
                policy::require_holds_and_git(self, &models.state, transaction, recipe.transaction_recipe(index))?;
                ordinary::require_no_consumer_resource_transition_v1(native.state(), transaction, false)?;
                if transaction.records().iter().any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation) {
                    return Err(JournalError::boundary());
                }
            }
            delete {
                delete_batch::validate(&models.state, transaction, models.next_sequence, native.limits())?;
            }
            after_frames(frame_count) {
                root_original_inventory::require_append_sequence_headroom(
                    &models.state, transaction,
                    models.next_sequence.checked_add(frame_count).ok_or(Mechanical::SequenceExhausted)?,
                )?;
            }
            reserved(expected_length) {
                validate_reserved_capacity_data_v1(
                    &models.state, models.materialized_bytes, transaction.records(),
                    CapacityDeletionSelectorDataV1::Reservation(settling), expected_length,
                    models.committed_transactions.checked_add(1)
                        .ok_or(JournalError::limit_exceeded("committed transaction count"))?,
                    native.limits(),
                ).map_err(Mechanical::from)?;
            }
        }
    }
}
