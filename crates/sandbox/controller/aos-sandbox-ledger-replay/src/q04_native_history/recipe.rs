//! Binds one canonical Q04 history comparison to a private finite recipe view.
//!
//! The lexical view supplies only borrowed transaction DATA. Actual callers
//! keep their native parser, role constructors, financial originals and posts.

/// Defines the sole Q04 history comparison around a private transaction view.
///
/// The view has the existing `len` and `transaction` DATA methods. It selects
/// no native operation, parser, role or permission. The concrete public slice
/// owner and Domain's private finite recipe enum share this exact body.
#[macro_export]
macro_rules! define_q04_native_history_data_v1 {
    ($visibility:vis $name:ident<$recipes_lifetime:lifetime>, $recipes:ty) => {
        $visibility struct $name<$recipes_lifetime> {
            recipes: $recipes,
            matched: usize,
            previous_end: u64,
            previous_next: u64,
            original_next: Option<u64>,
            bank_history: Option<aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory<$recipes_lifetime>>,
            stopped_terminal: Option<aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedNativeObservationDataV2<$recipes_lifetime>>,
        }

        impl<$recipes_lifetime> $name<$recipes_lifetime> {
            pub(crate) fn validate_recipes_v1(recipes: &$recipes, maximum_transactions: usize)
                -> Result<(), $crate::q04_native_history::Q04NativeHistoryDataErrorV1>
            {
                use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
                if recipes.len() > maximum_transactions
                    || (0..recipes.len()).any(|index| (0..index).any(|prior|
                        recipes.transaction(prior).id() == recipes.transaction(index).id()))
                {
                    return Err(Mechanical::ProtectedBoundary.into());
                }
                Ok(())
            }

            // Both concrete bindings call the same validation above before
            // selecting their optional pure model hooks. This constructor
            // makes no native, semantic or financial completion claim.
            pub(crate) fn from_validated_recipe_data_v1(
                recipes: $recipes,
                original_next: Option<u64>,
                bank_history: Option<aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory<$recipes_lifetime>>,
                stopped_terminal: Option<aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedNativeObservationDataV2<$recipes_lifetime>>,
            ) -> Self {
                Self { recipes, matched: 0, previous_end: 0, previous_next: 1,
                    original_next, bank_history, stopped_terminal }
            }

            pub(crate) fn observe_v1(&mut self,
                transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
                begin_sequence: u64, commit_sequence: u64, begin_offset: u64, end_offset: u64,
            ) -> Result<(), $crate::q04_native_history::Q04NativeHistoryDataErrorV1> {
                use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
                use aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes;

                if let Some(history) = self.bank_history.as_mut() {
                    history.observe(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)?;
                }
                if let Some(terminal) = self.stopped_terminal.as_mut() {
                    terminal.observe_v2(transaction)?;
                }
                let next = commit_sequence.checked_add(1).ok_or(Mechanical::SequenceExhausted)?;
                let frames = u64::try_from(transaction.records().len())
                    .map_err(|_| Mechanical::LimitExceeded("Q04 native record count"))?
                    .checked_add(2).ok_or(Mechanical::SequenceExhausted)?;
                if begin_sequence != self.previous_next
                    || next.checked_sub(begin_sequence) != Some(frames)
                    || begin_offset != self.previous_end
                    || end_offset.checked_sub(begin_offset)
                        != Some(encoded_transaction_append_bytes(transaction).map_err(Mechanical::from)?)
                {
                    return Err(Mechanical::ProtectedBoundary.into());
                }
                self.previous_end = end_offset;
                self.previous_next = next;

                if let Some(original_next) = self.original_next {
                    if begin_sequence < original_next {
                        if next > original_next || (0..self.recipes.len()).any(|index|
                            self.recipes.transaction(index).id() == transaction.id())
                        {
                            return Err(Mechanical::ProtectedBoundary.into());
                        }
                        return Ok(());
                    }
                    if self.matched >= self.recipes.len()
                        || (self.matched == 0 && begin_sequence != original_next)
                        || transaction != self.recipes.transaction(self.matched)
                    {
                        return Err(Mechanical::ProtectedBoundary.into());
                    }
                    self.matched += 1;
                    return Ok(());
                }
                if self.matched < self.recipes.len() {
                    let expected = self.recipes.transaction(self.matched);
                    if transaction.id() == expected.id() {
                        if transaction != expected {
                            return Err(Mechanical::ProtectedBoundary.into());
                        }
                        self.matched += 1;
                    } else if (0..self.recipes.len()).any(|index|
                        self.recipes.transaction(index).id() == transaction.id())
                    {
                        return Err(Mechanical::ProtectedBoundary.into());
                    }
                } else if (0..self.recipes.len()).any(|index|
                    self.recipes.transaction(index).id() == transaction.id())
                {
                    return Err(Mechanical::ProtectedBoundary.into());
                }
                Ok(())
            }

            pub(crate) fn requires_names_v1(&self) -> bool { self.bank_history.is_some() }

            pub(crate) fn finish_v1(&self,
                transaction_ids: &std::collections::BTreeSet<[u8; 16]>,
                names: Option<aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1>,
                physical_end: u64, next_sequence: u64,
            ) -> Result<(), $crate::q04_native_history::Q04NativeHistoryDataErrorV1> {
                use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
                if let Some(history) = self.bank_history.as_ref() {
                    history.finish(transaction_ids, names.ok_or(Mechanical::ProtectedBoundary)?)?;
                }
                if let Some(terminal) = self.stopped_terminal.as_ref() {
                    terminal.require_observed_v2()?;
                }
                if self.matched != self.recipes.len()
                    || (self.recipes.len() == 0
                        && self.original_next.is_some_and(|next| next != next_sequence))
                    || self.previous_end != physical_end || self.previous_next != next_sequence
                {
                    return Err(Mechanical::StaleAuthoritySnapshot.into());
                }
                Ok(())
            }
        }
    };
}
