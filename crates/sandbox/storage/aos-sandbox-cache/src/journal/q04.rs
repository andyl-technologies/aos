//! Retains Cache's fixed Q04 recipe beside its actual original Hold writer.
//!
//! Canonical Protocol owns the inert records and digests. The genuine upper
//! Controller owner checks its identity immediately before capture; this
//! module does not claim Controller custody. Appending additionally requires
//! the original Root flight at the final native crossing.

use std::path::Path;

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::{
    cache_state::hold_state::q04_recipes::{
        CacheQ04TransactionRecipesDataV1, Q04CacheTerminalPhaseV1,
    },
    domain_ledger::{
        cache_policy_hold::CachePolicyHoldV1,
        create_q04_history::{Q04CutIdentityV1, recipes::lower_release_capacity_shape_data_v1},
        protected_names::ProtectedJournalNamesV1,
    },
};

use super::{Journal, JournalError, JournalTransaction, gate, policy};
use crate::error::CacheQ04ErrorV1;

/// Retains the canonical three-phase suffix of the same original Hold writer.
///
/// No constructor accepts supplied parts. Mutation still requires the actual
/// Root flight and the private same-writer prefix/currentness gates.
pub struct CacheQ04TransactionRecipesV1<'cut> {
    identity: &'cut Q04CutIdentityV1,
    uid: u32,
    names: ProtectedJournalNamesV1,
    original_next: u64,
    data: CacheQ04TransactionRecipesDataV1,
}

impl<'cut> CacheQ04TransactionRecipesV1<'cut> {
    // The sole actual upper capture calls ledger.require_identity(identity)
    // immediately before this method. A decoded identity is never described
    // as a Controller original, Root phase or permission to append here.
    pub(crate) fn capture_after_controller_identity_v1(
        journal: &mut Journal,
        identity: &'cut Q04CutIdentityV1,
        selected: crate::CurrentProjectPhysicalCacheHeadV1,
    ) -> Result<Self, CacheQ04ErrorV1> {
        let uid = journal.protected_owner_uid()?;
        journal.require_protected_named_location(
            Path::new(crate::PROTECTED_CACHE_ROOT), gate::NAME, uid, gate::hold_limits(),
        )?;
        let before = gate::state::current_state(journal)?;
        if before.hold.is_some_and(CachePolicyHoldV1::is_held)
            || before.v8_pending.is_some()
            || selected.project() != identity.project()
        {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        let names = journal.protected_writer_physical_names_v1()?;
        let original_next = journal.snapshot_sequence();
        let held = CachePolicyHoldV1::new(
            selected.project(), selected.partition().digest(), selected.head(),
            identity.binding(), identity.epoch(),
        ).map_err(JournalError::from)?;
        let data = CacheQ04TransactionRecipesDataV1::new(
            identity, names, before.hold, held, lower_release_capacity_shape_data_v1(identity),
        )?;
        let recipes = Self { identity, uid, names, original_next, data };
        recipes.require_fixed_journal(journal)?;
        recipes.require_prefix(journal.read_view().state(), 0)?;
        Ok(recipes)
    }

    /// Borrows the three canonical transactions without granting append authority.
    #[must_use]
    pub fn transactions(&self) -> &[JournalTransaction; 3] {
        self.data.transactions()
    }

    /// Borrows the exact original cut identity used by the native capture.
    #[must_use]
    pub fn identity(&self) -> &Q04CutIdentityV1 {
        self.identity
    }

    /// Returns the observed prehold physical sequence coordinate.
    #[must_use]
    pub fn original_next(&self) -> u64 {
        self.original_next
    }

    /// Returns the release digest observed on the genuine original Root flight.
    #[must_use]
    pub fn release_authorization(&self) -> Option<ObjectDigest> {
        self.data.release_authorization()
    }

    // The genuine same-wire Root loan supplies authenticated phase DATA here.
    // Its complete upper release/transition checks surround this native body
    // at the exact original slots; this pure accessor adds no samples or grant.
    pub(crate) fn bind_observed_release_data_after_root_v1(
        &mut self,
        journal: &mut Journal,
        root: &aos_sandbox_broker::controller_receiving::profile::root_flight::ControllerRootQ04CacheLoanV1<'_, '_, '_>,
    ) -> Result<(), CacheQ04ErrorV1> {
        if self.release_authorization().is_some() || !std::ptr::eq(self.identity, root.identity()) {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        let release = root.release_phase()
            .map_err(|cause| JournalError::RootOriginal(Box::new(cause)))?.digest();
        self.require_fixed_journal(journal)?;
        self.require_prefix(journal.read_view().state(), 1)?;
        journal.require_q04_native_recipe_prefix_v1(&self.transactions()[..1], self.original_next)?;
        self.data.bind_release_data_v1(self.identity, self.names, release)?;
        journal.preflight_cache_q04_remaining_v1(self, 1)?;
        self.require_fixed_journal(journal)?;
        Ok(())
    }

    /// Computes the canonical clearance transaction digest from this actual suffix.
    ///
    /// # Errors
    /// Refuses missing observed release or unrepresentable canonical coordinates.
    pub fn clear_recipe_digest(&self) -> Result<ObjectDigest, CacheQ04ErrorV1> {
        self.data.clear_recipe_digest(self.identity, self.names, self.original_next)
            .map_err(Into::into)
    }

    /// Returns the canonical hold DATA for the selected fixed phase.
    #[must_use]
    pub fn terminal_hold(&self, phase: Q04CacheTerminalPhaseV1) -> CachePolicyHoldV1 {
        self.data.terminal_hold(phase)
    }

    pub(crate) fn require_fixed_journal(&self, journal: &Journal) -> Result<(), JournalError> {
        journal.require_protected_named_location(
            Path::new(crate::PROTECTED_CACHE_ROOT), gate::NAME, self.uid, gate::hold_limits(),
        )?;
        if journal.protected_writer_physical_names_v1()? != self.names {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    pub(crate) fn require_prefix(&self, state: &policy::State, committed: usize) -> Result<(), JournalError> {
        self.data.require_prefix(state, committed).map_err(Into::into)
    }

    pub(super) fn require_transition(
        &self,
        state: &policy::State,
        transaction: &JournalTransaction,
        index: usize,
    ) -> Result<(), JournalError> {
        self.data.require_transition(state, transaction, index).map_err(Into::into)
    }
}

impl Journal {
    pub(crate) fn preflight_cache_q04_suffix_v1(
        &mut self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
    ) -> Result<(), CacheQ04ErrorV1> {
        self.preflight_cache_q04_remaining_v1(recipes, 0)
    }

    pub(crate) fn preflight_cache_q04_remaining_v1(
        &mut self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        first: usize,
    ) -> Result<(), CacheQ04ErrorV1> {
        if first >= recipes.transactions().len() {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.read_view().state(), first)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..first], recipes.original_next())?;
        self.preflight_cache_q04_data_v1(recipes, first)?;
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.read_view().state(), first)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..first], recipes.original_next())?;
        Ok(())
    }
}

impl Journal {
    pub(crate) fn require_q04_native_recipe_prefix_v1(
        &self,
        recipes: &[JournalTransaction],
        original_next: u64,
    ) -> Result<(), CacheQ04ErrorV1> {
        if original_next == 0 {
            return Err(JournalError::boundary().into());
        }
        self.require_q04_native_recipe_view_v1(recipes, Some(original_next))
    }

    pub(crate) fn require_q04_native_recipes_v1(
        &self,
        recipes: &[JournalTransaction],
    ) -> Result<(), CacheQ04ErrorV1> {
        self.require_q04_native_recipe_view_v1(recipes, None)
    }

    fn require_q04_native_recipe_view_v1(
        &self,
        recipes: &[JournalTransaction],
        original_next: Option<u64>,
    ) -> Result<(), CacheQ04ErrorV1> {
        self.ensure_protected_authority()?;
        let witness = self.protected_writer_name_witness()?;
        let result = self.audit_cache_q04_native_v1(recipes, original_next, &witness);
        // The name post is owed independently, including a failed whole-file
        // replay. Preserve the primary cause and the later debt separately.
        let bookend = self.validate_protected_writer_name_witness(&witness);
        match (result, bookend) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), final_bookend) => Err(CacheQ04ErrorV1::NativeHistory {
                first, final_bookend: final_bookend.err(),
            }),
            (Ok(()), Err(first)) => Err(CacheQ04ErrorV1::NativeHistory {
                first, final_bookend: None,
            }),
        }
    }

    fn audit_cache_q04_native_v1(
        &self,
        recipes: &[JournalTransaction],
        original_next: Option<u64>,
        witness: &super::ProtectedWriterNameWitness,
    ) -> Result<(), JournalError> {
        use aos_sandbox_ledger_replay::q04_native_history::Q04NativeRecipeAuditDataV1;
        use super::native_audit::{CacheNativeAuditV1, q04_history_error};

        // The old stopped selector first recognizes the current Effect
        // header, then requires the native name controller.journal. Every
        // constructor of this private owner fixes one of Cache's five names,
        // so that exact selected header is the same protected-boundary denial.
        // Deleted foreign history is not newly rejected: the complete replay
        // still compares all namespaces and actual materialized rows below.
        if self.records(super::RecordNamespace::Effect).any(|(_, value)| {
            value.first() == Some(&6) && value.get(2) == Some(&3)
        }) {
            return Err(JournalError::boundary());
        }
        let bank = aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory::new(
            self.read_view().state(),
        );
        let audit = Q04NativeRecipeAuditDataV1::new(
            recipes, self.limits().maximum_transactions, original_next, bank, None,
        ).map_err(q04_history_error)?;
        let (native, semantic, audit) = self.reread_native_audit_v1(
            witness.file().byte_len(), CacheNativeAuditV1::Q04(audit),
        )?;
        let CacheNativeAuditV1::Q04(mut audit) = audit else {
            return Err(JournalError::boundary());
        };
        let names = if audit.requires_names_v1() {
            Some(self.protected_writer_physical_names_v1()?)
        } else {
            None
        };
        if audit.finish_after_replay_v1(
            native.transaction_ids_data_v1(), names, witness.file().byte_len(),
            self.snapshot_sequence(),
        ).is_err() {
            // This explicit post-replay stage owns its own selected cause;
            // Cold's earlier hook latch cannot describe a later refusal.
            return Err(audit.into_ordinary_failure_v1()
                .map(q04_history_error).unwrap_or(JournalError::boundary()));
        }
        let actual = self.read_view();
        let coordinates = native.coordinates_data_v1();
        if coordinates.durable_end != witness.file().byte_len()
            || coordinates.durable_next_sequence != actual.next_sequence()
            || coordinates.committed_transactions != actual.committed_transactions()
            || native.transaction_ids_data_v1() != actual.transaction_ids()
            || native.committed_namespaces_data_v1() != actual.committed_namespaces()
            || native.state_data_v1() != actual.state()
            || native.materialized_bytes_data_v1() != actual.materialized_bytes()
            || native.idempotency_data_v1() != actual.idempotency_index()
            || !semantic.challenge_history.is_empty()
            || !self.remainder.challenge_history.is_empty()
            || semantic.original_replay.has_dependencies()
            || self.remainder.original_replay.has_dependencies()
            || semantic.history_compacted != self.remainder.history_compacted
            || semantic.q04_lower_history_present != self.remainder.q04_lower_history_present
        {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        Ok(())
    }
}

impl Journal {
    pub(crate) fn readback_cache_q04_original_v1(
        &self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        committed: usize,
    ) -> Result<(), CacheQ04ErrorV1> {
        if committed == 0 || committed > 3 {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.read_view().state(), committed)?;
        self.require_q04_native_recipe_prefix_v1(
            &recipes.transactions()[..committed], recipes.original_next(),
        )?;
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.read_view().state(), committed)?;
        Ok(())
    }

    pub(crate) fn require_q04_returned_commit_v1(
        &self,
        result: &super::CommitResult,
    ) -> Result<(), CacheQ04ErrorV1> {
        self.ensure_protected_authority()?;
        self.require_protected_names_current()?;
        let expected = result.commit_sequence.checked_add(1).ok_or(
            JournalError::Mechanical(
                aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::SequenceExhausted,
            ),
        )?;
        if self.read_view().next_sequence() != expected
            || self.read_view().metadata().map_err(JournalError::from)?.len() != result.durable_bytes
        {
            return Err(JournalError::stale_snapshot().into());
        }
        self.ensure_protected_authority()?;
        self.require_protected_names_current()?;
        Ok(())
    }
}
