//! Keeps Controller, Root, Source and protected-signing Q04 orchestration upper.
//!
//! The native Cache owner retains every actual writer, clock, physical guard
//! and reached native result. This wrapper supplies the real Controller ledger
//! and Source/Root semantic checks at their original frontiers. It cannot
//! construct a lower phase from DATA or replace any native custody borrower.

use super::*;
use crate::policy_compiler::create_q04::{CreateQ04ErrorV1, Q04CutIdentityV1};
use aos_sandbox_cache::{CacheQ04TransactionRecipesV1, Q04CacheTerminalPhaseV1};

#[derive(Clone, Copy)]
pub(super) enum FirstSourceV1 {
    Native,
    Upper,
}

#[derive(Default)]
pub(super) struct Q04UpperProgressV1 {
    pub(super) paid_intake:
        Option<Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1>>,
    first: Option<CreateQ04ErrorV1>,
    postcheck: Option<CreateQ04ErrorV1>,
    pub(super) source: Option<FirstSourceV1>,
    pub(super) entered: bool,
}

impl Q04UpperProgressV1 {
    pub(super) fn select_native(&mut self) {
        self.source.get_or_insert(FirstSourceV1::Native);
    }

    pub(super) fn select_upper(&mut self) {
        self.source.get_or_insert(FirstSourceV1::Upper);
    }

    fn native_result(&mut self, returned: Result<(), ()>) -> Result<(), ()> {
        if returned.is_err() {
            self.source.get_or_insert(FirstSourceV1::Native);
        }
        returned
    }

    fn upper_result(&mut self, returned: Result<(), CreateQ04ErrorV1>) -> Result<(), ()> {
        if let Err(cause) = returned {
            self.first.get_or_insert(cause);
            self.source.get_or_insert(FirstSourceV1::Upper);
            return Err(());
        }
        Ok(())
    }

    fn upper_post(&mut self, returned: Result<(), CreateQ04ErrorV1>) {
        if let Err(cause) = returned {
            self.postcheck.get_or_insert(cause);
            self.source.get_or_insert(FirstSourceV1::Upper);
        }
    }

    pub(super) fn failure<'cause>(
        &'cause self,
        native: &'cause aos_sandbox_cache::CacheResidentInitializationV1,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        let upper = || {
            self.first
                .as_ref()
                .or(self.postcheck.as_ref())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| {
                    self.paid_intake
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
        };
        match self.source {
            Some(FirstSourceV1::Native) => native
                .original_q04_failure_v1()
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| native.failure())
                .or_else(upper),
            Some(FirstSourceV1::Upper) => upper(),
            None => upper(),
        }
    }
}

/// Keeps the actual Cache borrower beside the upper semantic first cause.
///
/// Only the actual paid preflight wrapper constructs it. There is no Journal,
/// descriptor, phase or map adopter and no ordinary fallback for a paid Q04.
pub(crate) struct OriginalQ04CacheOwnerCutV1<'original> {
    pub(super) native: aos_sandbox_cache::OriginalQ04CacheOwnerCutV1<'original>,
    pub(super) upper: &'original mut Q04UpperProgressV1,
}

impl<'owner> OriginalQ04CacheOwnerCutV1<'owner> {
    pub(crate) fn capture_prepare_readback(
        &mut self,
        project: aos_sandbox_model::ProjectId,
    ) -> Result<(), ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let returned = self.native.capture_prepare_readback(project);
        self.upper.native_result(returned)
    }

    pub(crate) fn prepare_readback(
        &self,
    ) -> Result<&aos_sandbox_cache::Q04CachePrepareReadbackV1, CreateQ04ErrorV1> {
        if self.upper.source.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.native
            .prepare_readback()
            .map_err(|_| CreateQ04ErrorV1::ChangedCut)
    }

    pub(crate) fn write_prepare_metadata(
        &mut self,
        metadata: &mut [u8; crate::policy_compiler::create_q04::PREHOLD_METADATA_BYTES],
    ) -> Result<(), ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let returned = self.native.write_prepare_metadata(metadata);
        self.upper.native_result(returned)
    }

    pub(crate) fn capture_transaction_recipes<'cut>(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        identity: &'cut Q04CutIdentityV1,
    ) -> Result<CacheQ04TransactionRecipesV1<'cut>, ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let prepared = match self.native.prepare_transaction_recipe_capture_v1(identity) {
            Ok(prepared) => prepared,
            Err(()) => {
                self.upper.source.get_or_insert(FirstSourceV1::Native);
                return Err(());
            }
        };
        // This is the original Controller identity frontier: all Cache prepare
        // checks precede it; the same borrowed Cache capture immediately follows.
        self.upper.upper_result(ledger.require_identity(identity))?;
        match prepared.capture_after_controller_identity_v1() {
            Ok(recipes) => Ok(recipes),
            Err(()) => {
                self.upper.source.get_or_insert(FirstSourceV1::Native);
                Err(())
            }
        }
    }

    pub(crate) fn bind_observed_release<'cut>(
        &mut self,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, 'cut>,
        recipes: &mut CacheQ04TransactionRecipesV1<'cut>,
    ) -> Result<(), ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let mut native = match self
            .native
            .prepare_release_binding_v1(root.native_original_v1(), recipes)
        {
            Ok(native) => native,
            Err(()) => {
                self.upper.select_native();
                return Err(());
            }
        };
        let release = match root.release_phase() {
            Ok(release) => release.digest(),
            Err(cause) => {
                self.upper.upper_result(Err(cause))?;
                return Err(());
            }
        };
        self.upper
            .upper_result(root.require_lower_transition(1, Some(release)))?;
        self.upper
            .native_result(native.bind_recipe_native_once_v1())?;
        self.upper
            .upper_result(root.require_lower_transition(1, Some(release)))?;
        self.upper
            .native_result(native.finish_after_root_check_v1())?;
        self.upper.upper_result(root.recheck())
    }

    pub(crate) fn append_original_phase(
        &mut self,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        index: usize,
    ) -> Result<(), ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let mut prepared = match self.native.prepare_append_original_phase_v1(
            root.native_original_v1(),
            recipes,
            index,
        ) {
            Ok(prepared) => prepared,
            Err(()) => {
                self.upper.source.get_or_insert(FirstSourceV1::Native);
                return Err(());
            }
        };
        self.upper
            .upper_result(root.require_lower_transition(index, recipes.release_authorization()))?;
        let returned = (|| {
            self.upper.native_result(prepared.validate_journal_entry_once_v1())?;
            if self.upper.upper_result(root.require_lower_transition(
                index, recipes.release_authorization(),
            )).is_err() {
                prepared.refuse_journal_entry_after_upper_root_v1();
                return Err(());
            }
            let (transaction, mut context, mut gate) = match prepared.begin_append_context_once_v1() {
                Ok(parts) => parts,
                Err(()) => { self.upper.select_native(); return Err(()); }
            };
            let committed = aos_sandbox_broker::run_canonical_semantic_append_v1! {
                ordinary,
                context: context,
                transaction: transaction,
                gate: gate,
                boundary: aos_sandbox_cache::CacheJournalErrorV1::boundary_data_v1(),
                coordinates: (materialized_bytes, commit_sequence, following_sequence, durable_bytes),
                preflight: {
                    context.preflight_native_once_v1(materialized_bytes, following_sequence)?;
                },
                final_crossing: {
                    // The real ordinary guard and prepared native stage remain
                    // held while the unchanged full upper Root verifier runs.
                    if self.upper.upper_result(root.require_lower_transition(
                        index, recipes.release_authorization(),
                    )).is_err() {
                        return Err(aos_sandbox_cache::CacheJournalErrorV1::boundary_data_v1());
                    }
                    context.finish_final_crossing_once_v1()?;
                },
                durable_check: {},
                published: { context.mark_q04()?; },
                completed: {
                    Ok(aos_sandbox_broker::canonical_journal::CommitResult { commit_sequence, durable_bytes })
                },
            };
            self.upper.native_result(context.retain_result_once_v1(committed))
        })();
        let _ = self.upper.native_result(returned);
        let readback = prepared.finish_native_readback_once_v1();
        self.upper.native_result(readback)?;
        if self.upper.source.is_some() { return Err(()); }
        // The original readback closure reaches Root only after the actual
        // commit, complete native prefix and Cache currentness all passed.
        self.upper
            .upper_post(root.require_lower_transition(index, recipes.release_authorization()));
        if self.upper.source.is_some() {
            return Err(());
        }
        let returned = prepared.finish_after_root_check_v1();
        self.upper.native_result(returned)
    }

    pub(crate) fn capture_terminal_readback(
        &mut self,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        phase: Q04CacheTerminalPhaseV1,
    ) -> Result<(), ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let mut native = match self.native.prepare_terminal_readback_v1(
            root.native_original_v1(), recipes, phase,
        ) {
            Ok(native) => native,
            Err(()) => {
                self.upper.select_native();
                return Err(());
            }
        };
        let returned = (|| {
            if !native.body_ready_v1() {
                self.upper.select_native();
                return Err(());
            }
            // Original outer body Root check; the four provider checks below
            // remain inside the same native provider guard, in their old slots.
            self.upper.upper_result(root.recheck())?;
            self.upper.native_result(native.validate_provider_request_once_v1())?;
            self.upper.upper_result(root.recheck())?;

            let mut guard = match native.begin_provider_readback_once_v1() {
                Ok(guard) => guard,
                Err(()) => { self.upper.select_native(); return Err(()); }
            };
            let mut context = match guard.borrow_context_once_v1() {
                Ok(context) => context,
                Err(()) => { self.upper.select_native(); return Err(()); }
            };
            if self.upper.native_result(context.prepare_reconstruction_once_v1()).is_ok() {
                if self.upper.upper_result(root.recheck()).is_ok() {
                    let _ = self.upper.native_result(context.capture_reconstruction_once_v1());
                } else {
                    let _ = self.upper.native_result(context.refuse_reconstruction_after_upper_root_v1());
                }
            }
            // Native after and its Root tail are one original short-circuit
            // check; the later physical/Clock/Root posts remain independent.
            if self.upper.native_result(context.observe_native_after_once_v1()).is_ok() {
                self.upper.upper_post(root.recheck());
            }
            let _ = self.upper.native_result(context.observe_physical_clock_posts_once_v1());
            self.upper.upper_post(root.recheck());
            self.upper.native_result(context.finish_after_upper_root_post_v1())
        })();
        let _ = self.upper.native_result(returned);
        // Dropping the context then guard closes only their original scopes.
        // It precedes these two original, independently owed outer afters.
        let _ = self.upper.native_result(native.finish_native_posts_v1());
        self.upper.upper_post(root.recheck());
        if self.upper.source.is_some() {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn terminal_readback(
        &self,
        phase: Q04CacheTerminalPhaseV1,
    ) -> Result<&aos_sandbox_cache::CacheResidencyWriterReadbackV2, CreateQ04ErrorV1> {
        if self.upper.source.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.native
            .terminal_readback(phase)
            .map_err(|_| CreateQ04ErrorV1::ChangedCut)
    }

    pub(crate) fn capture_signed_held_readback(
        &mut self,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        staged: crate::policy_compiler::StagedClosedPolicyRootBaseV2,
        proposed: &[u8],
        credentials: &mut crate::public_api_session::ControllerQ04CredentialCustodyV1,
    ) -> Result<(), ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let native = match self
            .native
            .prepare_signed_held_readback_v1(root.native_original_v1(), recipes)
        {
            Ok(native) => native,
            Err(()) => {
                self.upper.select_native();
                return Err(());
            }
        };
        let prepared = (|| {
            if self.upper.source.is_some() {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            credentials
                .recheck()
                .map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
            root.cache_signing_challenge(staged, proposed)
        })();
        let challenge = match prepared {
            Ok(challenge) => challenge,
            Err(cause) => {
                self.upper.upper_result(Err(cause))?;
                return Err(());
            }
        };
        let signing = (|| {
            let (generation, signer) = match credentials.cache_signer() {
                Some(signer) => signer,
                None => {
                    self.upper.upper_result(Err(CreateQ04ErrorV1::ChangedCut))?;
                    return Err(());
                }
            };
            let unsigned = match native.prepare_packet_once_v1(challenge, generation) {
                Ok(unsigned) => unsigned,
                Err(()) => {
                    self.upper.select_native();
                    return Err(());
                }
            };
            self.upper.upper_result(root.require_signing_boundary())?;
            self.upper
                .native_result(unsigned.sign_native_once_v1(signer))
        })();
        let _ = signing;
        if credentials.recheck().is_err() {
            self.upper.upper_post(Err(CreateQ04ErrorV1::ChangedCut));
            return Err(());
        }
        let returned = self.native.finish_signed_held_native_post_v1(recipes);
        self.upper.native_result(returned)?;
        self.upper.upper_post(root.recheck());
        if self.upper.source.is_some() {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn signed_held_readback(
        &self,
    ) -> Result<
        &[u8; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2],
        CreateQ04ErrorV1,
    > {
        if self.upper.source.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.native
            .signed_held_readback()
            .map_err(|_| CreateQ04ErrorV1::ChangedCut)
    }

    pub(crate) fn finish_original_clearance(
        &mut self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        root: &crate::policy_compiler::create_q04::OriginalQ04FinalRootObservationV1<'_, '_, '_>,
    ) -> Result<(), ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let returned = self
            .native
            .prepare_final_clearance_v1(recipes, root.native_original_v1());
        self.upper.native_result(returned)?;
        self.upper.upper_result(root.recheck())?;
        let native = match self
            .native
            .prepare_clearance_completion_v1(recipes, root.native_original_v1())
        {
            Ok(native) => native,
            Err(()) => {
                self.upper.select_native();
                return Err(());
            }
        };
        // This is the original second FULL Controller/Source/semantic Root
        // check, after all Cache native observations and before the only mark.
        self.upper.upper_post(root.recheck());
        if self.upper.source.is_some() {
            return Err(());
        }
        self.upper
            .native_result(native.complete_after_root_check_v1())
    }

    pub(crate) fn clearance_loan<'cache, 'flight, 'profile, 'cut>(
        &'cache mut self,
        root: &'cache crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<
            'flight,
            'profile,
            'cut,
        >,
        recipes: &'cache CacheQ04TransactionRecipesV1<'cut>,
    ) -> Result<OriginalQ04CacheClearanceLoanV1<'cache, 'owner, 'flight, 'profile, 'cut>, ()> {
        if self.upper.source.is_some() {
            return Err(());
        }

        let returned = self
            .native
            .require_source_clearance_native_v1(root.native_original_v1(), recipes);
        if returned.is_err() {
            self.upper.source.get_or_insert(FirstSourceV1::Native);
            return Err(());
        }
        self.upper
            .upper_result(root.require_lower_transition(2, recipes.release_authorization()))?;
        Ok(OriginalQ04CacheClearanceLoanV1 {
            cache: self,
            recipes,
            root,
        })
    }
}

/// Keeps the actual native Cache borrower through the upper Source clear.
pub(crate) struct OriginalQ04CacheClearanceLoanV1<'cache, 'owner, 'flight, 'profile, 'cut> {
    cache: &'cache mut OriginalQ04CacheOwnerCutV1<'owner>,
    recipes: &'cache CacheQ04TransactionRecipesV1<'cut>,
    root: &'cache crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<
        'flight,
        'profile,
        'cut,
    >,
}

impl OriginalQ04CacheClearanceLoanV1<'_, '_, '_, '_, '_> {
    pub(crate) fn recheck_at_append(
        &self,
        identity: &Q04CutIdentityV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        if !std::ptr::eq(identity, self.recipes.identity())
            || !std::ptr::eq(identity, self.root.identity())
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.cache
            .native
            .recheck_source_clearance_at_append_v1(self.root.native_original_v1(), self.recipes)
            .map_err(CreateQ04ErrorV1::from)?;
        self.root
            .require_lower_transition(2, self.recipes.release_authorization())
    }

    pub(crate) fn capture_source_clear(
        mut self,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        recipes: &crate::journal::SourceQ04TransactionRecipesV1<'_>,
        destination: &mut Option<Result<crate::journal::CommitResult, CreateQ04ErrorV1>>,
        first: &mut Option<CreateQ04ErrorV1>,
        postcheck: &mut Option<CreateQ04ErrorV1>,
    ) -> Result<(), ()> {
        let prepared = (|| {
            if destination.is_some() || first.is_some() || postcheck.is_some() {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.cache
                .native
                .recheck_original_owned_v1()
                .map_err(CreateQ04ErrorV1::from)?;
            self.recheck_at_append(recipes.identity())?;
            recipes.require_named_owner(source)?;
            source
                .journal()
                .preflight_source_q04_remaining_v1(recipes, 2)
        })();
        if let Err(cause) = prepared {
            first.get_or_insert(cause);
            return Err(());
        }
        *destination = Some(source.journal().commit_source_q04_original_v1(
            recipes,
            2,
            self.root,
            Some(&self),
        ));
        if matches!(destination, Some(Err(_))) {
            match destination.take() {
                Some(Err(cause)) => {
                    *first = Some(cause);
                }
                returned => {
                    *destination = returned;
                }
            }
        }
        let readback = (|| {
            let result = destination
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            source
                .journal()
                .readback_source_q04_original_v1(recipes, 3)?;
            source.journal().require_q04_returned_commit_v1(result)?;
            recipes.require_named_owner(source)?;
            self.cache
                .native
                .recheck_original_owned_v1()
                .map_err(CreateQ04ErrorV1::from)?;
            self.recheck_at_append(recipes.identity())
        })();
        if let Err(cause) = readback {
            postcheck.get_or_insert(cause);
        }
        if first.is_some() || postcheck.is_some() || !matches!(destination, Some(Ok(_))) {
            return Err(());
        }
        Ok(())
    }
}

// The finite provider driver adds one body closure/status forwarding plane and
// the upper Result projections at each native suspension boundary. Native
// guard/context construction and all dynamic replay backing are priced by the
// native supplier; this term names only the actual new upper controls.
pub(super) fn terminal_provider_control_receiving_bytes_v1() -> Option<usize> {
    // The immediate terminal-body closure captures the distinct native token,
    // actual upper Root reference and mutable upper progress. Its constructor
    // and FnOnce receiver are separate from the returned status planes.
    let capture = std::mem::size_of::<(
        &mut aos_sandbox_cache::CacheQ04TerminalBorrowV1<'_, '_, '_, '_, '_>,
        &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        &mut Q04UpperProgressV1,
    )>();
    std::mem::size_of::<Result<(), ()>>()
        .checked_mul(3)?
        .checked_add(std::mem::size_of::<Result<(), CreateQ04ErrorV1>>().checked_mul(2)?)?
        .checked_add(capture.checked_mul(2)?)
}

// The actual upper append invocation owns its closure status and the shared
// macro's primary result while the native context parks that same outcome.
pub(super) fn append_driver_control_receiving_bytes_v1() -> Option<usize> {
    // The enclosing body keeps these five captures while the macro's distinct
    // primary closure keeps its own eight captures. Both exist at the true
    // full upper final-crossing suspension; neither is token/header padding.
    let body = std::mem::size_of::<(
        &mut aos_sandbox_cache::CacheQ04AppendOriginalBorrowV1<'_, '_, '_, '_, '_>,
        &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        &mut Q04UpperProgressV1,
        &aos_sandbox_cache::CacheQ04TransactionRecipesV1<'_>,
        &usize,
    )>();
    let primary = std::mem::size_of::<(
        &mut aos_sandbox_cache::CacheQ04AppendContextV1<'_, '_, '_, '_>,
        &mut aos_sandbox_cache::CacheQ04AppendGateV1,
        &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
        &mut Option<aos_sandbox_cache::CacheQ04AppendGuardV1>,
        &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        &mut Q04UpperProgressV1,
        &aos_sandbox_cache::CacheQ04TransactionRecipesV1<'_>,
        &usize,
    )>();
    std::mem::size_of::<Result<(), ()>>()
        .checked_mul(2)?
        .checked_add(std::mem::size_of::<Result<aos_sandbox_broker::canonical_journal::CommitResult, aos_sandbox_cache::CacheJournalErrorV1>>())?
        .checked_add(body.checked_mul(2)?)?
        .checked_add(primary.checked_mul(2)?)
}
