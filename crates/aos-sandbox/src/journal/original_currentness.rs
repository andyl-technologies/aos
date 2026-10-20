//! Original writer currentness, native history, and postcommit readbacks.
//!
//! This private owner keeps the complete Q04 native suffix audit, fixed Cache
//! loans, Controller signing and refresh bookends, and original owner readbacks.
//! Every check borrows the same Journal and its closed role recipes. Shared
//! replay, advisory preflight and final append crossings remain with their
//! existing owners; callers retain native outcomes and first-cause reservoirs.
//!
//! This grouping changes neither protected custody nor dependency boundaries.

use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;

use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest, Sha256};

use super::{
    CACHE_POLICY_HOLD_JOURNAL,
    CacheQ04TransactionRecipesV1,
    CommitResult,
    ControllerPolicyHoldV1,
    ControllerQ04TransitionV1,
    DeploymentHistoryObserverV1,
    Journal,
    JournalAuthorityInstance,
    JournalError,
    JournalLimits,
    JournalTransaction,
    PreflightTransactionViewV1,
    ProtectedAuthorityScope,
    ProtectedJournalAuthority,
    ProtectedJournalNamesV1,
    ProtectedWriterNameWitness,
    RecordNamespace,
    SourceQ04TransactionRecipesV1,
    controller_policy_hold,
    encode_record_fields,
    replay_coordinator_observed_v1,
    runtime_deployment_history,
};

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Q04ControllerBookendPurposeV1<'recipes> {
    Original,
    HeldSigner(&'recipes [ControllerQ04TransitionV1<'recipes>]),
    Gen1Refresh(&'recipes [ControllerQ04TransitionV1<'recipes>]),
}

#[cfg(target_os = "linux")]
pub(crate) use aos_sandbox_protocol::cache_state::hold_state::q04_recipes::Q04CacheTerminalPhaseV1;

#[cfg(target_os = "linux")]
struct Q04OriginalCacheTargetV1 {
    instance: Arc<JournalAuthorityInstance>,
    sequence: u64,
    limits: JournalLimits,
    name: &'static str,
    uid: u32,
    witness: ProtectedWriterNameWitness,
}

#[cfg(target_os = "linux")]
impl Q04OriginalCacheTargetV1 {
    fn capture(journal: &Journal, name: &'static str, uid: u32) -> Result<Self, JournalError> {
        journal.require_protected_named_location(
            Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT), name, uid, journal.native.limits(),
        )?;
        Ok(Self {
            instance: Arc::clone(&journal.authority_instance),
            sequence: journal.snapshot_sequence(),
            limits: journal.native.limits(),
            name,
            uid,
            witness: journal.protected_writer_name_witness()?,
        })
    }

    fn require(&self, journal: &Journal) -> Result<(), JournalError> {
        if !Arc::ptr_eq(&self.instance, &journal.authority_instance)
            || self.sequence != journal.snapshot_sequence()
            || self.limits != journal.native.limits()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        journal.require_protected_named_location(
            Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT), self.name, self.uid, self.limits,
        )?;
        journal.validate_protected_writer_name_witness(&self.witness)
    }
}

// The actual resident initialization lends this original hold writer. The
// other targets are pinned to their exact allocations, names, limits and
// sequences; neither their Journals nor a mutable gate can escape this loan.
#[cfg(target_os = "linux")]
pub(crate) struct Q04CacheTerminalNativeLoanV1<'hold, 'recipes, 'cut> {
    hold: &'hold mut Journal,
    recipes: &'recipes CacheQ04TransactionRecipesV1<'cut>,
    phase: Q04CacheTerminalPhaseV1,
    targets: [Q04OriginalCacheTargetV1; 2],
}

// This is an existing-only observation before Root is opened. The original
// hold remains mutably borrowed, but no mutable gate or transaction escapes.
#[cfg(target_os = "linux")]
pub(crate) struct Q04CachePrepareNativeLoanV1<'hold> {
    hold: &'hold mut Journal,
    prior: Option<CachePolicyHoldV1>,
    targets: [Q04OriginalCacheTargetV1; 2],
    original_hold: Q04OriginalCacheTargetV1,
}

#[cfg(target_os = "linux")]
impl Q04CachePrepareNativeLoanV1<'_> {
    pub(crate) fn require_current(
        &self,
        state: &Journal,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if authority.namespace != RecordNamespace::DesiredState
            || authority.scope != ProtectedAuthorityScope::SingleNamespace
            || self.hold.require_q04_cache_prepare_v1()? != self.prior
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.original_hold.require(self.hold)?;
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        self.hold.require_q04_native_recipes_v1(&[])?;
        state.preflight_q04_cache_read_only_base_v1(self.hold)?;
        authority.journal.preflight_q04_cache_read_only_base_v1(self.hold)?;
        self.original_hold.require(self.hold)?;
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Q04CacheTerminalNativeLoanV1<'_, '_, '_> {
    pub(crate) fn identity(&self) -> &crate::policy_compiler::create_q04::Q04CutIdentityV1 {
        self.recipes.identity()
    }

    pub(crate) fn hold(&self) -> CachePolicyHoldV1 {
        self.recipes.terminal_hold(self.phase)
    }

    pub(crate) fn require_current(
        &mut self,
        state: &Journal,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if authority.namespace != RecordNamespace::DesiredState
            || authority.scope != ProtectedAuthorityScope::SingleNamespace
        {
            return Err(JournalError::ForeignAuthorityNamespace.into());
        }
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        // Zero selections still run the sole whole native parser and complete
        // replay comparison. Cache state/authority may not append in this cut.
        state.require_q04_native_recipes_v1(&[])?;
        authority.journal.require_q04_native_recipes_v1(&[])?;
        self.recipes.require_fixed_journal(self.hold)?;
        self.recipes.require_prefix(self.hold.native.state(), self.phase.prefix())?;
        self.hold.require_q04_native_recipe_prefix_v1(
            &self.recipes.transactions()[..self.phase.prefix()], self.recipes.original_next(),
        )?;
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        self.recipes.require_fixed_journal(self.hold)?;
        self.recipes.require_prefix(self.hold.native.state(), self.phase.prefix())?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn borrow_q04_cache_prepare_native_v1<'hold>(
        state: &Journal,
        authority: &Journal,
        hold: &'hold mut Journal,
    ) -> Result<Q04CachePrepareNativeLoanV1<'hold>, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        let root = Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT);
        let uid = hold.protected_owner_uid()?;
        if state.cache_policy_gate.as_ref().is_none_or(|(directory, owner)| {
            directory.as_path() != root || *owner != uid
        }) || authority.cache_policy_gate != state.cache_policy_gate
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let prior = hold.require_q04_cache_prepare_v1()?;
        let original_hold = Q04OriginalCacheTargetV1::capture(hold, CACHE_POLICY_HOLD_JOURNAL, uid)?;
        let targets = [
            Q04OriginalCacheTargetV1::capture(state, "state.journal", uid)?,
            Q04OriginalCacheTargetV1::capture(authority, "authority.journal", uid)?,
        ];
        Ok(Q04CachePrepareNativeLoanV1 { hold, prior, targets, original_hold })
    }

    pub(super) fn require_q04_cache_read_only_base_v1(&self, hold: &Journal) -> Result<(), JournalError> {
        let uid = hold.protected_owner_uid()?;
        hold.require_q04_cache_prepare_v1()?;
        let location = self
            .native.protected_view()
            .ok_or(JournalError::ProtectedBoundary)?;
        let fixed_target = match location.name() {
            "clock.journal" => self.cache_policy_gate.is_none(),
            "authority.journal" | "state.journal" => self.cache_policy_gate.as_ref().is_some_and(|(root, owner)| {
                root.as_path() == Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT) && *owner == uid
            }),
            _ => false,
        };
        if !fixed_target
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_protected_named_location(
            Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT),
            &location.name(),
            uid,
            self.native.limits(),
        )?;
        self.require_q04_native_recipes_v1(&[])
            .map_err(|cause| JournalError::Q04RootOriginal(Box::new(cause)))?;
        hold.require_q04_native_recipes_v1(&[])
            .map_err(|cause| JournalError::Q04RootOriginal(Box::new(cause)))?;
        Ok(())
    }

    pub(crate) fn borrow_q04_cache_terminal_native_v1<'hold, 'recipes, 'cut>(
        state: &Journal,
        authority: &Journal,
        hold: &'hold mut Journal,
        recipes: &'recipes CacheQ04TransactionRecipesV1<'cut>,
        phase: Q04CacheTerminalPhaseV1,
    ) -> Result<Q04CacheTerminalNativeLoanV1<'hold, 'recipes, 'cut>, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        let root = Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT);
        let uid = hold.protected_owner_uid()?;
        if state.cache_policy_gate.as_ref().is_none_or(|(directory, owner)| {
            directory.as_path() != root || *owner != uid
        }) || authority.cache_policy_gate != state.cache_policy_gate
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        recipes.require_fixed_journal(hold)?;
        recipes.require_prefix(hold.native.state(), phase.prefix())?;
        let targets = [
            Q04OriginalCacheTargetV1::capture(state, "state.journal", uid)?,
            Q04OriginalCacheTargetV1::capture(authority, "authority.journal", uid)?,
        ];
        Ok(Q04CacheTerminalNativeLoanV1 { hold, recipes, phase, targets })
    }
}

// Preserve the new actual allocation refusal; ordinary semantic categories
// retain their established protected-boundary projection.
#[cfg(target_os = "linux")]
fn resource_bank_history_error(
    error: aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError,
) -> JournalError {
    match error {
        aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError::Representation(cause) =>
            JournalError::Q04RootOriginal(Box::new(
                crate::policy_compiler::create_q04::CreateQ04ErrorV1::ResourceReservation(Box::new(
                    crate::controller_resource_reservation::ResourceReservationErrorV1::Representation(cause),
                )),
            )),
        _ => JournalError::ProtectedBoundary,
    }
}

// Fixed control bytes belong to the actual semantic/native receiving recipe;
// namespace cardinalities remain with the existing map and path suppliers.
pub(super) fn native_audit_fixed_receiving_demand_v1()
    -> Result<aos_sandbox_core::ResourceVector, JournalError>
{
    use aos_sandbox_ledger_replay::q04_native_history::Q04NativeHistoryDataErrorV1;

    // The two existing owner planes include the core's construction. Its
    // returned comparison result and moved projection cause are additional.
    let comparison_controls = std::mem::size_of::<(
        Result<(), Q04NativeHistoryDataErrorV1>,
        Q04NativeHistoryDataErrorV1,
    )>();
    let bytes = std::mem::size_of::<Q04NativeRecipeAuditV1<'static>>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(comparison_controls))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::LimitExceeded("native history observer controls"))?;
    Ok(aos_sandbox_core::ResourceVector::ZERO
        .with(aos_sandbox_core::ResourceDimension::MemoryBytes, bytes))
}

// The same lexical DATA recipe serves this private heterogeneous view and
// the concrete lower ordinary-slice observer. No role/native callback escapes.
#[cfg(target_os = "linux")]
aos_sandbox_ledger_replay::define_q04_native_history_data_v1!(
    Q04NativeRecipeAuditCoreV1<'recipes>, PreflightTransactionViewV1<'recipes>);

#[cfg(target_os = "linux")]
pub(super) struct Q04NativeRecipeAuditV1<'recipes> {
    core: Q04NativeRecipeAuditCoreV1<'recipes>,
}

#[cfg(target_os = "linux")]
impl Q04NativeRecipeAuditV1<'_> {
    pub(super) fn observe(&mut self, transaction: &JournalTransaction,
        begin_sequence: u64, commit_sequence: u64, begin_offset: u64, end_offset: u64,
    ) -> Result<(), JournalError> {
        self.core.observe_v1(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)
            .map_err(q04_history_data_error_v1)
    }
}

#[cfg(target_os = "linux")]
fn q04_history_data_error_v1(
    cause: aos_sandbox_ledger_replay::q04_native_history::Q04NativeHistoryDataErrorV1,
) -> JournalError {
    use aos_sandbox_ledger_replay::q04_native_history::Q04NativeHistoryDataErrorV1;
    match cause {
        Q04NativeHistoryDataErrorV1::Mechanical(cause) => JournalError::from(cause),
        Q04NativeHistoryDataErrorV1::Bank(cause) => resource_bank_history_error(cause),
        Q04NativeHistoryDataErrorV1::Stopped(cause) => super::create_stopped_history::observation_error(cause),
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn require_root_q04_materialized_prefix_v1(
        &self,
        history: &crate::policy_compiler::create_q04::Q04RootAuthorityHistoryV1,
        prefix: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        history.require_prefix_rows(self.native.state().iter().map(|((namespace, key), value)| {
            (*namespace, key.as_slice(), value.as_slice())
        }), prefix)?;
        Ok(())
    }

    // This observes the actual whole Controller ledger/native file under its
    // original mutable borrow. The copied tuple is equality DATA only; every
    // signer calls this again after parking its returned packet or first cause.
    pub(crate) fn q04_controller_signing_bookend_v1(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: Option<&[ControllerQ04TransitionV1<'_>]>,
    ) -> Result<(u64, ProtectedJournalNamesV1, Option<ControllerPolicyHoldV1>), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        let purpose = match transitions {
            None => Q04ControllerBookendPurposeV1::Original,
            Some(transitions) => Q04ControllerBookendPurposeV1::HeldSigner(transitions),
        };
        self.q04_controller_ledger_bookend_v1(ledger, purpose)
    }

    // Released Q04 history is observable for genuine gen1 refresh, not for
    // the held signer. Exact native membership and all original rows remain.
    pub(crate) fn q04_controller_refresh_bookend_v1(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: &[ControllerQ04TransitionV1<'_>],
    ) -> Result<(u64, ProtectedJournalNamesV1, Option<ControllerPolicyHoldV1>), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.q04_controller_ledger_bookend_v1(ledger, Q04ControllerBookendPurposeV1::Gen1Refresh(transitions))
    }

    fn q04_controller_ledger_bookend_v1(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        purpose: Q04ControllerBookendPurposeV1<'_>,
    ) -> Result<(u64, ProtectedJournalNamesV1, Option<ControllerPolicyHoldV1>), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        crate::policy_compiler::validate_current_create_controller_journal_v1(self)?;
        ledger.require_original(self)?;
        match purpose {
            Q04ControllerBookendPurposeV1::Original => {
                controller_policy_hold::require_q04_signing_original(self.native.state())?;
                self.require_q04_native_recipes_v1(&[])?;
                if self.snapshot_sequence() != ledger.original_next() {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
            }
            Q04ControllerBookendPurposeV1::HeldSigner(transitions)
                | Q04ControllerBookendPurposeV1::Gen1Refresh(transitions) => {
                let prefix = if matches!(purpose, Q04ControllerBookendPurposeV1::HeldSigner(_)) {
                    controller_policy_hold::require_q04_signing_prefix(self.native.state(), transitions)?
                } else {
                    controller_policy_hold::require_q04_refresh_prefix(self.native.state(), transitions)?
                };
                if !std::ptr::eq(ledger, transitions[0].ledger()) {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                for transition in transitions {
                    transition.require_fixed_owner(self)?;
                }
                self.require_q04_native_recipe_view_at_original_v1(
                    PreflightTransactionViewV1::ControllerQ04(&transitions[..prefix]),
                    Some(ledger.original_next()),
                )?;
                transitions[prefix - 1].require_current_readback(self)?;
            }
        }
        ledger.require_original(self)?;
        crate::policy_compiler::validate_current_create_controller_journal_v1(self)?;
        Ok((
            self.snapshot_sequence(),
            self.protected_writer_physical_names_v1()?,
            self.controller_policy_hold_v1()?,
        ))
    }

    // A pre-envelope seed uses the complete actual old native row recipe,
    // names and sequence. It excludes every Q04 future transaction/phase/head
    // and provides comparison DATA only, never a floor or writer certificate.
    pub(crate) fn q04_root_before_rows_v1(
        &self,
    ) -> Result<(u64, ProtectedJournalNamesV1, ObjectDigest), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.require_q04_native_recipes_v1(&[])?;
        self.validate_held_protected_names()?;
        let sequence = self.snapshot_sequence();
        let names = self.protected_writer_physical_names_v1()?;
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.create-q04.root-before-rows.v1\0");
        digest.update(names.to_bytes());
        digest.update(sequence.to_be_bytes());
        for (namespace, key, value) in self.all_records() {
            digest.update(encode_record_fields(namespace, key, Some(value))?);
        }
        self.require_q04_native_recipes_v1(&[])?;
        self.validate_held_protected_names()?;
        if self.snapshot_sequence() != sequence || self.protected_writer_physical_names_v1()? != names {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        Ok((sequence, names, ObjectDigest::from_bytes(digest.finalize().into())))
    }

    /// Checks the exact original terminal predecessor without issuing a permit.
    ///
    /// The caller keeps the actual eight native Results borrowed. The passive
    /// terminal comparison cannot substitute copied history for that owner.
    ///
    /// # Errors
    /// Rejects failed or missing Results, changed protected names, additional
    /// history, changed durable extent or differing original commit positions.
    pub(crate) fn require_q04_terminal_preappend_positions_v1(
        &self,
        terminal: aos_sandbox_protocol::domain_ledger::resource_bank::TerminalBinding,
        returned: &[Option<Result<CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 8],
    ) -> Result<(), JournalError> {
        self.validate_held_protected_names()?;
        terminal.require_preappend_positions(
            self.protected_writer_physical_names_v1()?,
            self.snapshot_sequence(),
            self.native.metadata()?.len(),
            returned.iter().map(|result| result.as_ref().and_then(|result| {
                result.as_ref().ok().map(|position| (position.commit_sequence, position.durable_bytes))
            })),
        ).map_err(|cause| JournalError::Q04RootOriginal(Box::new(
            crate::policy_compiler::create_q04::CreateQ04ErrorV1::ResourceReservation(Box::new(cause.into())),
        )))?;
        self.validate_held_protected_names()
    }

    /// Rejoins the actual returned terminal commit before the first J append.
    ///
    /// # Errors
    /// Rejects changed names, an absent terminal transaction, any intervening
    /// native append, changed NEXT or differing durable file extent.
    pub(crate) fn require_create_intake_preappend_position_v1(
        &self,
        names: super::ProtectedJournalNamesV1,
        terminal: &JournalTransaction,
        returned: &CommitResult,
    ) -> Result<(), JournalError> {
        self.validate_held_protected_names()?;
        if self.protected_writer_physical_names_v1()? != names
            || !self.native.transaction_ids().contains(terminal.id())
            || self.native.next_sequence() != returned.commit_sequence.checked_add(1)
                .ok_or(JournalError::SequenceExhausted)?
            || self.native.metadata()?.len() != returned.durable_bytes
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.validate_held_protected_names()
    }

    /// Checks retained Q04 recipe DATA against this same original native file.
    ///
    /// This private observation issues no authority or reusable current token.
    /// Its real owning caller separately validates purpose, exact ledger,
    /// eligible suffix, other owners and the unchanged original cutoff.
    pub(crate) fn require_q04_native_recipes_v1(
        &self,
        recipes: &[JournalTransaction],
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.require_q04_native_recipe_view_v1(PreflightTransactionViewV1::Ordinary(recipes))
    }

    // Closed bank observation reuses the same native parser and complete
    // replay/name bookends. Terminal rows alone cannot prove their origins.
    pub(crate) fn require_controller_resource_history_v1(
        &self,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.require_q04_native_recipes_v1(&[])
    }

    // The actual U receiver borrows its positively returned bank reservation.
    // Charge the SAME physical progression owner before observer Vec growth.
    pub(crate) fn require_controller_resource_history_for_create_storage_use_v1(
        &self,
        original: &mut crate::controller_resource_reservation::CreateStorageUseHistoryReceivingLoanV1<'_>,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        self.ensure_healthy()?;
        original.admit_actual_history_once(self.native.state())?;
        self.require_controller_resource_history_v1()
            .map_err(|cause| crate::controller_resource_reservation::ResourceReservationErrorV1::Terminal(Box::new(cause)))
    }

    pub(crate) fn require_controller_resource_q04_prefix_v1(
        &self,
        recipes: &[ControllerQ04TransitionV1<'_>],
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        let first = recipes.first()
            .ok_or(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut)?;
        self.require_q04_native_recipe_view_at_original_v1(
            PreflightTransactionViewV1::ControllerQ04(recipes),
            Some(first.ledger().original_next()),
        )
    }

    fn require_q04_native_recipe_view_v1(
        &self,
        recipes: PreflightTransactionViewV1<'_>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.require_q04_native_recipe_view_at_original_v1(recipes, None)
    }

    // Original NEXT is comparison DATA captured before the first logical
    // hold. This reads through the sole native parser; it does not establish
    // currentness or authorize a commit from a sequence scalar.
    pub(crate) fn require_q04_native_recipe_prefix_v1(
        &self,
        recipes: &[JournalTransaction],
        original_next: u64,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if original_next == 0 {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.require_q04_native_recipe_view_at_original_v1(
            PreflightTransactionViewV1::Ordinary(recipes), Some(original_next),
        )
    }

    pub(super) fn require_q04_native_recipe_view_at_original_v1(
        &self,
        recipes: PreflightTransactionViewV1<'_>,
        original_next: Option<u64>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        self.ensure_protected_authority()?;
        let witness = self.protected_writer_name_witness()?;
        let result = self.audit_original_native_recipe_view_v1(recipes, original_next, &witness, None);
        let bookend = self.validate_protected_writer_name_witness(&witness);
        match (result, bookend) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), final_bookend) => Err(CreateQ04ErrorV1::NativeHistory {
                first,
                final_bookend: final_bookend.err(),
            }),
            (Ok(()), Err(first)) => Err(CreateQ04ErrorV1::NativeHistory {
                first,
                final_bookend: None,
            }),
        }
    }

    // Shared nonauthorizing readback mechanics: purpose owners retain their
    // distinct entry checks and error/bookend projection around this parser.
    fn audit_original_native_recipe_view_v1(
        &self,
        recipes: PreflightTransactionViewV1<'_>,
        original_next: Option<u64>,
        witness: &ProtectedWriterNameWitness,
        selected_names: Option<ProtectedJournalNamesV1>,
    ) -> Result<(), JournalError> {
        // Before any Q04 selfwrite there are no selected recipes yet.
        // An empty selection still audits the entire original native
        // history and compares its complete replay to this same owner.
        Q04NativeRecipeAuditCoreV1::validate_recipes_v1(
            &recipes, self.native.limits().maximum_transactions,
        ).map_err(q04_history_data_error_v1)?;
        // Select the original strict Controller hook at the same custody
        // boundary and only after the unchanged recipe geometry validation.
        let stopped = super::create_stopped_history::NativeTerminalSelectionV1::from_original_v1(self)?
            .map(super::create_stopped_history::NativeTerminalSelectionV1::into_observation_v1);
        let bank = aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory::new(self.native.state());
        let mut history = Q04NativeRecipeAuditV1 {
            core: Q04NativeRecipeAuditCoreV1::from_validated_recipe_data_v1(
                recipes, original_next, bank, stopped),
        };
        let reader = self.native.captured_reader(witness.file().byte_len());
        let replayed = replay_coordinator_observed_v1(
            reader,
            self.native.limits(),
            None,
            Some(DeploymentHistoryObserverV1::Q04(&mut history)),
        )?;
        let names = if history.core.requires_names_v1() {
            Some(match selected_names {
                Some(names) => names,
                None => self.protected_writer_physical_names_v1()?,
            })
        } else { None };
        history.core.finish_v1(replayed.native.transaction_ids_data_v1(), names,
            witness.file().byte_len(), self.native.next_sequence())
            .map_err(q04_history_data_error_v1)?;
        if replayed.durable_end != witness.file().byte_len()
            || replayed.next_sequence != self.native.next_sequence()
            || replayed.committed_transactions != self.native.committed_transactions()
            || replayed.native.transaction_ids_data_v1() != self.native.transaction_ids()
            || replayed.native.committed_namespaces_data_v1() != self.native.committed_namespaces()
            || replayed.native.state_data_v1() != self.native.state()
            || replayed.native.materialized_bytes_data_v1() != self.native.materialized_bytes()
            || replayed.native.idempotency_data_v1() != self.native.idempotency()
            || !replayed.source_challenge_history.is_empty()
            || !self.source_challenge_history.is_empty()
            || replayed.source_original_replay.has_dependencies()
            || self.source_original_replay.has_dependencies()
            || replayed.source_history_compacted != self.source_history_compacted
            || replayed.q04_lower_history_present != self.q04_lower_history_present
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }



    pub(crate) fn readback_controller_q04_phase_v1(
        &mut self,
        transitions: &[ControllerQ04TransitionV1<'_>],
        index: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let transition = transitions.get(index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if transitions.len() != 8 {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let readback = (|| {
            transition.ledger().require_original(self)?;
            self.require_q04_native_recipe_view_at_original_v1(
                PreflightTransactionViewV1::ControllerQ04(&transitions[..=index]),
                Some(transition.ledger().original_next()),
            )?;
            transition.require_current_readback(self)?;
            Ok(())
        })();
        if let Err(error) = readback {
            self.native.poison();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn readback_source_q04_original_v1(
        &mut self,
        recipes: &SourceQ04TransactionRecipesV1<'_>,
        committed: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if committed == 0 || committed > 3 {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), committed)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..committed], recipes.original_next())?;
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), committed)?;
        Ok(())
    }

    pub(crate) fn readback_cache_q04_original_v1(
        &self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        committed: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if committed == 0 || committed > 3 {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), committed)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..committed], recipes.original_next())?;
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), committed)?;
        Ok(())
    }

    pub(crate) fn require_q04_returned_commit_v1(
        &self,
        result: &CommitResult,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.validate_held_protected_names()?;
        if self.native.next_sequence() != result.commit_sequence.checked_add(1).ok_or(JournalError::SequenceExhausted)?
            || self.native.metadata()?.len() != result.durable_bytes
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        self.validate_held_protected_names()?;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod create_storage_use_history_error_tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError;

    #[test]
    fn actual_progress_allocation_error_survives_native_boundary_projection() {
        let allocation = Vec::<u8>::new().try_reserve(usize::MAX).unwrap_err();
        let original_message = allocation.to_string();

        let projected = resource_bank_history_error(ResourceBankDataError::Representation(allocation));

        let JournalError::Q04RootOriginal(original) = projected else { panic!("native allocation cause lost"); };
        let crate::policy_compiler::create_q04::CreateQ04ErrorV1::ResourceReservation(original) = *original
            else { panic!("resource cause lost"); };
        let crate::controller_resource_reservation::ResourceReservationErrorV1::Representation(original) = *original
            else { panic!("actual allocation error replaced"); };
        assert_eq!(original.to_string(), original_message);
    }

    #[test]
    fn existing_corrupt_history_keeps_its_protected_boundary_category() {
        assert!(matches!(resource_bank_history_error(ResourceBankDataError::CorruptLedger),
            JournalError::ProtectedBoundary));
    }
}
