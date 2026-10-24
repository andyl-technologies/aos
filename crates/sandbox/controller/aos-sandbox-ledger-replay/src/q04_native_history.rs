//! Compares complete Q04 native-history DATA beside the full Cold recipe.
//!
//! The owner borrows exact recipes and optional canonical bank/stopped models.
//! It opens nothing and issues no role, currentness or financial completion.
//! Native callers retain the actual held replay, full map/idempotency equality,
//! physical names sampled after replay and every independent native bookend.

mod recipe;

#[cfg(test)]
mod tests;

use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalJournalMechanicalErrorV1, CanonicalReplayPrefixReadViewV1,
};
use aos_sandbox_model::{ResourceDimension, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    effect_history::{CreateStoppedNativeObservationDataV2, CreateStoppedNativeObservationErrorV2},
    protected_names::ProtectedJournalNamesV1,
    resource_bank::{PhysicalHistory, ResourceBankDataError},
    transaction::JournalTransaction,
};
use std::collections::BTreeSet;

/// Preserves the original physical-history or exact suffix comparison cause.
#[derive(Debug, thiserror::Error)]
pub enum Q04NativeHistoryDataErrorV1 {
    /// Preserves native-coordinate, recipe or canonical encoding refusal.
    #[error(transparent)]
    Mechanical(#[from] CanonicalJournalMechanicalErrorV1),
    /// Preserves the canonical bank chronology, including allocation refusal.
    #[error(transparent)]
    Bank(#[from] ResourceBankDataError),
    /// Preserves the strict stopped/pre-ACK/terminal comparison cause.
    #[error(transparent)]
    Stopped(#[from] CreateStoppedNativeObservationErrorV2),
}

struct Q04RecipeSliceDataV1<'recipes>(&'recipes [JournalTransaction]);

impl Q04RecipeSliceDataV1<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn transaction(&self, index: usize) -> &JournalTransaction {
        &self.0[index]
    }
}

crate::define_q04_native_history_data_v1!(
    Q04NativeHistoryCoreV1<'recipes>,
    Q04RecipeSliceDataV1<'recipes>
);

/// Retains one complete recipe-prefix comparison without native authority.
///
/// A successful Cold entry alone does not finish this comparison. The real
/// caller subsequently supplies its actual completed replay IDs and names,
/// runs [`Self::finish_after_replay_v1`], and compares its whole held native
/// state and Cold remainder before any positive role operation.
pub struct Q04NativeRecipeAuditDataV1<'recipes> {
    core: Q04NativeHistoryCoreV1<'recipes>,
    eof: Option<(u64, u64, u64)>,
    complete: bool,
    failure: Option<Q04NativeHistoryDataErrorV1>,
}

impl<'recipes> Q04NativeRecipeAuditDataV1<'recipes> {
    /// Constructs the exact borrowed recipe and optional-history comparison.
    ///
    /// # Errors
    /// Refuses a selection exceeding the actual configured transaction limit
    /// or containing repeated recipe UUIDs. This selects no native limit/grant.
    pub fn new(
        recipes: &'recipes [JournalTransaction],
        maximum_transactions: usize,
        original_next: Option<u64>,
        bank: Option<PhysicalHistory<'recipes>>,
        stopped: Option<CreateStoppedNativeObservationDataV2<'recipes>>,
    ) -> Result<Self, Q04NativeHistoryDataErrorV1> {
        let recipes = Q04RecipeSliceDataV1(recipes);
        Q04NativeHistoryCoreV1::validate_recipes_v1(&recipes, maximum_transactions)?;
        Ok(Self {
            core: Q04NativeHistoryCoreV1::from_validated_recipe_data_v1(
                recipes,
                original_next,
                bank,
                stopped,
            ),
            eof: None,
            complete: false,
            failure: None,
        })
    }

    /// Describes the actual inline owner and construction allowance as DATA.
    ///
    /// # Errors
    /// Refuses overflow. Canonical cursor/semantic scratch and the actual bank
    /// use-history backing remain separately admitted before their growth.
    pub fn fixed_demand_v1() -> Result<ResourceVector, CanonicalJournalMechanicalErrorV1> {
        // Resident and construction payloads are already the two owner
        // planes. Charge only the constructor Result's additional layout.
        let constructor_control = std::mem::size_of::<Result<Self, Q04NativeHistoryDataErrorV1>>()
            .checked_sub(std::mem::size_of::<Self>());

        // Keep the core/closure return, local result and retain argument
        // independently represented across their actual forwarding calls.
        let comparison_controls = std::mem::size_of::<Result<(), Q04NativeHistoryDataErrorV1>>()
            .checked_mul(3);
        let retained_controls = std::mem::size_of::<(
            Q04NativeHistoryDataErrorV1,
            Result<(), ()>,
        )>();
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(constructor_control?))
            .and_then(|bytes| bytes.checked_add(comparison_controls?))
            .and_then(|bytes| bytes.checked_add(retained_controls))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(CanonicalJournalMechanicalErrorV1::LimitExceeded(
                "Q04 history DATA geometry",
            ))?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
    }

    /// Observes the actual canonical COMMIT at the original history hook.
    ///
    /// # Errors
    /// Retains the exact bank, stopped-terminal, coordinate or suffix refusal.
    pub fn observe_commit_v1(&mut self, commit: CanonicalCommitReadViewV1<'_>) -> Result<(), ()> {
        if self.failure.is_some() {
            return Err(());
        }
        let (begin, offset) = commit.begin_position();
        let result = if self.eof.is_some() || self.complete {
            Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary.into())
        } else {
            self.core.observe_v1(
                commit.transaction(),
                begin,
                commit.commit_sequence(),
                offset,
                commit.coordinates().offset,
            )
        };
        self.retain_v1(result)
    }

    pub(crate) fn observe_prefix_v1(
        &mut self,
        prefix: CanonicalReplayPrefixReadViewV1<'_>,
        captured_end: u64,
    ) -> Result<(), ()> {
        if self.failure.is_some() {
            return Err(());
        }
        if self.eof.is_some() || self.complete {
            return self.retain_v1(Err(
                CanonicalJournalMechanicalErrorV1::ProtectedBoundary.into()
            ));
        }
        let coordinates = prefix.coordinates();
        self.eof = Some((
            coordinates.durable_end,
            coordinates.durable_next_sequence,
            captured_end,
        ));
        Ok(())
    }

    /// Reports whether the canonical bank hook needs actual post-replay names.
    #[must_use]
    pub fn requires_names_v1(&self) -> bool {
        self.core.requires_names_v1()
    }

    /// Finishes bank, stopped and exact suffix checks after the real replay.
    ///
    /// Actual IDs and names are historical DATA from the continuously held
    /// native owner. They grant no authority and cannot replace its full
    /// native/index/map equality or independently owed final bookend.
    ///
    /// # Errors
    /// Retains missing EOF, bank/terminal failure, wrong membership, changed
    /// native coordinates, incomplete suffix, reentry or any prior refusal.
    pub fn finish_after_replay_v1(
        &mut self,
        transaction_ids: &BTreeSet<[u8; 16]>,
        names: Option<ProtectedJournalNamesV1>,
        physical_end: u64,
        next_sequence: u64,
    ) -> Result<(), ()> {
        if self.failure.is_some() {
            return Err(());
        }
        let result = (|| {
            if self.complete {
                return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary.into());
            }
            self.core
                .finish_v1(transaction_ids, names, physical_end, next_sequence)?;
            if self.eof != Some((physical_end, next_sequence, physical_end)) {
                return Err(CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot.into());
            }
            self.complete = true;
            Ok(())
        })();
        self.retain_v1(result)
    }

    fn retain_v1(&mut self, result: Result<(), Q04NativeHistoryDataErrorV1>) -> Result<(), ()> {
        match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.failure.get_or_insert(cause);
                Err(())
            }
        }
    }

    /// Reports only this owner's completed historical DATA comparison.
    #[must_use]
    pub fn completed_data_v1(&self) -> bool {
        self.complete && self.failure.is_none()
    }

    /// Borrows the exact first comparison cause without moving its owner.
    #[must_use]
    pub fn failure(&self) -> Option<&Q04NativeHistoryDataErrorV1> {
        self.failure.as_ref()
    }

    /// Moves the actual ordinary error after the same cursor has been dropped.
    #[must_use]
    pub fn into_ordinary_failure_v1(self) -> Option<Q04NativeHistoryDataErrorV1> {
        self.failure
    }
}
