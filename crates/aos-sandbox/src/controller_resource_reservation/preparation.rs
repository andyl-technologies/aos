//! Pays the original generation-one preparation interval before Q04 capture.
//!
//! The original Root Anchored reply and current Controller/Source borrowers
//! select a reservation against an already-paid Project. Only the later real
//! Completed reply admits its use by Q04. Every result remains resident when
//! completion fails; neither expiry nor ordinary disposal refunds the claim.

use std::sync::{Arc, Mutex};

use aos_sandbox_core::{OperationId, RawPairedClockSample, ResourceDimension, ResourceVector};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::normal_root::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use crate::policy_compiler::create_q04::{
    OriginalQ04CompletedPreparationLoanV1, OriginalQ04ProjectPreparationLoanV1,
};
use crate::Journal;

use super::{
    AccountKind, AccountTransition, Claim, ClaimCut, ClaimPurpose, ClaimState,
    ControllerResourceBankOpeningV1, EnrollmentIdentity, ResourceReservationErrorV1,
    ReturnedAppend, replay,
};

// Fixed original association DATA is never an allocation permit. Only the
// borrower-taking prepare entry and same native CAS can pay its amount.
pub(crate) struct OriginalPreparationData {
    pub(crate) project: [u8; 16],
    pub(crate) authorization: [u8; 32],
    pub(crate) tree: [u8; 32],
    pub(crate) instance: [u8; 32],
    pub(crate) operation: [u8; 16],
    pub(crate) amount: ResourceVector,
    pub(crate) original: RawPairedClockSample,
    pub(crate) deadline: u64,
    pub(crate) nonce: [u8; 16],
    pub(crate) controller_names: crate::journal::ProtectedJournalNamesV1,
    pub(crate) source_names: crate::journal::ProtectedJournalNamesV1,
    pub(crate) source_sequence: u64,
    pub(crate) floor: [u8; 32],
    pub(crate) tree_head: [u8; 32],
    pub(crate) lineage_head: [u8; 32],
}

/// Retains one native Project reservation and its original preparation debt.
///
/// An empty instance supplies no capacity. Only the private original-Q04
/// borrower can enter it, and only a returned durable CAS followed by genuine
/// Completed ancestry permits preparation. The parent keeps this owner across
/// later Q04/Birth outcomes; dropping it never releases native accounting.
pub struct ProjectPreparationReservationAttemptV1 {
    prepared: Option<Result<OriginalPreparationData, ResourceReservationErrorV1>>,
    bank: Option<Result<(), ResourceReservationErrorV1>>,
    append: ReturnedAppend,
    posts: [Option<Result<(), SourceGenesisErrorV1>>; 3],
    profile: Option<Result<(), NormalRootStartupErrorV1>>,
    clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    completed: Option<Result<(), ResourceReservationErrorV1>>,
    child: Option<RetainedQ04Child>,
    terminal_preparation: Option<Result<(), ResourceReservationErrorV1>>,
    terminal_borrows: [Option<Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 2],
    terminal_bank: Option<Result<(), ResourceReservationErrorV1>>,
    terminal: ReturnedAppend,
    terminal_posts: [Option<Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 5],
    terminal_profile: Option<Result<(), NormalRootStartupErrorV1>>,
    terminal_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
}

struct RetainedQ04Child {
    original: super::Q04ResourceTransferV1,
    native: [Option<Result<crate::journal::CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 8],
    posts: [Option<Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 7],
    disposition: Option<Result<super::Q04TerminalDispositionV1, crate::policy_compiler::create_q04::CreateQ04ErrorV1>>,
}

impl ProjectPreparationReservationAttemptV1 {
    pub(crate) const fn new() -> Self {
        Self {
            prepared: None,
            bank: None,
            append: ReturnedAppend::new(),
            posts: [None, None, None],
            profile: None,
            clock: None,
            completed: None,
            child: None,
            terminal_preparation: None,
            terminal_borrows: [None, None],
            terminal_bank: None,
            terminal: ReturnedAppend::new(),
            terminal_posts: [None, None, None, None, None],
            terminal_profile: None,
            terminal_clock: None,
        }
    }

    pub(crate) fn prepare(
        &mut self,
        original: &OriginalQ04ProjectPreparationLoanV1<'_, '_, '_, '_>,
        operation: OperationId,
    ) -> Result<(), ()> {
        if self.prepared.is_some() {
            return Err(());
        }
        self.prepared = Some((|| {
            original.recheck()?;
            let mut data = original.data()?;
            data.operation = operation.into_bytes();
            // This is an explicit conservative signed envelope, not a mapping
            // that fills missing portable resource dimensions with zero.
            if data.operation == [0; 16]
                || data.amount.get(ResourceDimension::MemoryBytes) == 0
                || data.amount.get(ResourceDimension::OpenFiles) == 0
                || data.amount.get(ResourceDimension::ConcurrentOperations) == 0
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(data)
        })());
        if matches!(self.prepared, Some(Ok(_))) { Ok(()) } else { Err(()) }
    }

    // The Controller RefCell borrower has ended before this method. No bank
    // mutex spans a reentrant Root/Source call or any independent owner post.
    pub(crate) fn append(
        &mut self,
        journal: &mut Journal,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        if self.bank.is_some() { return; }
        match bank.lock() {
            Ok(bank) => {
                self.bank = Some(Ok(()));
                let transition = self.prepared.as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)
                    .and_then(|original| {
                        let enrollment = bank.require_enrolled(journal, profile)?;
                        original.transition(journal, enrollment)
                    });
                self.append.append_into(journal, transition);
            }
            Err(_) => self.bank = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable)),
        }
    }

    pub(crate) fn post(
        &mut self,
        original: &OriginalQ04ProjectPreparationLoanV1<'_, '_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ()> {
        original.observe_posts(&mut self.posts);
        self.finish_posts(profile)
    }

    pub(crate) fn post_unavailable_controller(
        &mut self,
        error: SourceGenesisErrorV1,
        source: Result<(), SourceGenesisErrorV1>,
        root: Result<(), SourceGenesisErrorV1>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ()> {
        self.posts = [Some(Err(error)), Some(source), Some(root)];
        self.finish_posts(profile)
    }

    fn finish_posts(&mut self, profile: &ProductionControllerNormalRootProfileV1) -> Result<(), ()> {
        self.profile = Some(profile.recheck());
        // This raw observation remains independent even when an earlier RPC
        // poisoned the Root owner. It always compares the initial same cut.
        self.clock = Some(match self.prepared.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(original) => crate::policy_compiler::observe_root_first_source_successor_clock_v2(
                Some(original.original),
            ).and_then(|sample| {
                if sample.boottime_nanoseconds() >= original.deadline {
                    Err(SourceGenesisErrorV1::Stale)
                } else { Ok(sample) }
            }),
            None => Err(SourceGenesisErrorV1::Stale),
        });
        if self.failure().is_some() || self.append.require_committed().is_err() {
            Err(())
        } else { Ok(()) }
    }

    pub(crate) fn confirm_completed(
        &mut self,
        original: &OriginalQ04CompletedPreparationLoanV1<'_, '_, '_, '_, '_>,
    ) -> Result<(), ()> {
        if self.completed.is_some() || self.failure().is_some() {
            return Err(());
        }
        self.completed = Some(original.recheck().map_err(Into::into));
        if matches!(self.completed, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    pub(crate) fn require_preparation(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() || !matches!(self.completed, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.append.require_committed().map(|_| ())
    }

    pub(super) fn original_binding(&self) -> Result<super::PreparationBinding, ResourceReservationErrorV1> {
        self.require_preparation()?;
        self.append.require_committed()?.preparation
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn original_clock(&self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.prepared.as_ref().and_then(|result| result.as_ref().ok())
            .map(|data| data.original).ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn retain_cleared_child(
        &mut self,
        original: super::Q04ResourceTransferV1,
        native: [Option<Result<crate::journal::CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 8],
        posts: [Option<Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 7],
        disposition: Result<super::Q04TerminalDispositionV1, crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.child.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        // Move the actual co-issuance result and its originals before any
        // projection. This historical charged owner does not renew a cut or
        // mint a fresh Birth/Storage/cleanup operation permission.
        self.child = Some(RetainedQ04Child { original, native, posts, disposition: Some(disposition) });
        let child = self.child.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if child.original.crossing_failure().is_some()
            || child.native.iter().any(|result| !matches!(result, Some(Ok(_))))
            || !matches!(child.disposition, Some(Ok(_)))
            || child.posts.iter().any(|post| !matches!(post, Some(Ok(()))))
            || child.original.require_last_clock().is_err()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Retains the whole child check before any terminal outcome projection.
    ///
    /// The disposition's authentic error stays in the child and precedes this
    /// coarse conflict in failure selection.
    ///
    /// # Errors
    /// Refuses an occupied prearmed slot without replacing its original result.
    pub(crate) fn terminal_preparation(
        &mut self,
        result: Result<(), ResourceReservationErrorV1>,
    ) -> Result<(), ()> {
        if self.terminal_preparation.is_some() { return Err(()); }
        self.terminal_preparation = Some(result);
        Ok(())
    }

    /// Retains one original borrower observation before independent posts.
    ///
    /// An unavailable borrower remains a typed error, not a fabricated loan.
    ///
    /// # Errors
    /// Refuses an unknown index or occupied slot without replacing its result.
    pub(crate) fn terminal_borrow(
        &mut self,
        index: usize,
        result: Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    ) -> Result<(), ()> {
        let slot = self.terminal_borrows.get_mut(index).ok_or(())?;
        if slot.is_some() { return Err(()); }
        *slot = Some(result);
        Ok(())
    }

    // This called phase changes accounting category only. The same parent
    // retains full Spec/native/uncertain owners; no amount is refunded.
    pub(crate) fn append_terminal(
        &mut self,
        journal: &mut Journal,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        if self.terminal_bank.is_some()
            || !matches!(self.terminal_preparation, Some(Ok(())))
            || self.terminal_borrows.iter().any(|result| !matches!(result, Some(Ok(()))))
        {
            return;
        }
        match bank.lock() {
            Ok(bank) => {
                self.terminal_bank = Some(bank.require_enrolled(journal, profile).map(|_| ()));
                if !matches!(self.terminal_bank, Some(Ok(()))) { return; }
                let original = self.child.as_mut()
                    .and_then(|child| child.disposition.take())
                    .ok_or(ResourceReservationErrorV1::Conflict)
                    .and_then(|result| result
                        .map(|disposition| disposition.transition)
                        .map_err(|error| ResourceReservationErrorV1::Terminal(Box::new(error))));
                self.terminal.append_into(journal, original);
            }
            Err(_) => self.terminal_bank = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable)),
        }
    }

    pub(crate) fn terminal_post(
        &mut self,
        index: usize,
        result: Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    ) -> Result<(), ()> {
        let slot = self.terminal_posts.get_mut(index).ok_or(())?;
        if slot.is_some() { return Err(()); }
        *slot = Some(result);
        Ok(())
    }

    pub(crate) fn finish_terminal_posts(
        &mut self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ()> {
        if self.terminal_profile.is_some() || self.terminal_clock.is_some() { return Err(()); }
        self.terminal_profile = Some(profile.recheck());
        // This LAST observation is raw and independent of poisoned RPC/native
        // owners. It compares the original paired sample and exclusive D.
        self.terminal_clock = Some(match self.prepared.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(original) => crate::policy_compiler::observe_root_first_source_successor_clock_v2(
                Some(original.original),
            ).and_then(|sample| {
                if sample.boottime_nanoseconds() >= original.deadline {
                    Err(SourceGenesisErrorV1::Stale)
                } else { Ok(sample) }
            }),
            None => Err(SourceGenesisErrorV1::Stale),
        });
        self.require_terminal_retention().map_err(|_| ())
    }

    /// Checks the retained native terminal outcome without issuing new capacity.
    ///
    /// Every dimension remains charged at its original amount. This result is
    /// not a Birth, Storage, cleanup or Snapshot allocation permit.
    ///
    /// # Errors
    /// Refuses absent/uncertain native outcomes, changed original owners or an
    /// expired original cut. All whole results remain in this parent.
    pub fn require_terminal_retention(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some()
            || !matches!(self.terminal_preparation, Some(Ok(())))
            || self.terminal_borrows.iter().any(|result| !matches!(result, Some(Ok(()))))
            || !matches!(self.terminal_bank, Some(Ok(())))
            || self.terminal_posts.iter().any(|post| !matches!(post, Some(Ok(()))))
            || !matches!(self.terminal_profile, Some(Ok(())))
            || !matches!(self.terminal_clock, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.terminal.require_committed().map(|_| ())
    }

    /// Borrows the first original failure without replacing native uncertainty.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.prepared.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.bank.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.append.failure())
            .or_else(|| self.posts.iter().find_map(|result| result.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static))))
            .or_else(|| self.profile.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.clock.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.completed.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.child.as_ref().and_then(|child| {
                child.original.crossing_failure().map(|error| error as &(dyn std::error::Error + 'static))
                    .or_else(|| child.native.iter().find_map(|result| result.as_ref()
                        .and_then(|result| result.as_ref().err())
                        .map(|error| error as &(dyn std::error::Error + 'static))))
                    .or_else(|| child.posts.iter().find_map(|post| post.as_ref()
                        .and_then(|post| post.as_ref().err())
                        .map(|error| error as &(dyn std::error::Error + 'static))))
                    .or_else(|| child.original.last_clock_failure()
                        .map(|error| error as &(dyn std::error::Error + 'static)))
                    .or_else(|| child.disposition.as_ref().and_then(|result| result.as_ref().err())
                        .map(|error| error as &(dyn std::error::Error + 'static)))
            }))
            .or_else(|| self.terminal_preparation.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.terminal_borrows.iter().find_map(|result| result.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static))))
            .or_else(|| self.terminal_bank.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.terminal.failure())
            .or_else(|| self.terminal_posts.iter().find_map(|result| result.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static))))
            .or_else(|| self.terminal_profile.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.terminal_clock.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }
}

impl OriginalPreparationData {
    fn transition(
        &self,
        journal: &Journal,
        enrollment: EnrollmentIdentity,
    ) -> Result<AccountTransition, ResourceReservationErrorV1> {
        let state = journal.controller_resource_state_v1()?;
        let mut projects = state.iter().filter_map(|((namespace, key), value)| {
            (*namespace == crate::RecordNamespace::ControllerResourceReservation
                && key.first() == Some(&replay::HEAD_PREFIX))
                .then(|| super::codec::decode_head(value))
        });
        let mut selected = None;
        for head in &mut projects {
            let head = head?;
            if head.kind == AccountKind::Project && head.project == self.project {
                if selected.replace(head).is_some() {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
        }
        let before = selected.ok_or(ResourceReservationErrorV1::Conflict)?;
        if before.enrollment != enrollment || enrollment.boot != self.original.host_boot_id()
            || before.tree_revision != self.tree || replay::finite_ceilings(before)? != self.amount
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let claim = Claim {
            enrollment,
            id: self.operation,
            account: before.id,
            child: [0; 16],
            owner: self.authorization,
            purpose: ClaimPurpose::ProjectPreparation,
            operation: self.operation,
            project: self.project,
            sandbox: [0; 16],
            tree_revision: self.tree,
            genesis_instance: self.instance,
            cut: ClaimCut::Operation {
                original_wall_seconds: self.original.wall_seconds(),
                original_boottime_nanoseconds: self.original.boottime_nanoseconds(),
                deadline_boottime_nanoseconds: self.deadline,
            },
            amount: self.amount,
            state: ClaimState::Reserved,
        };
        let mut transition = AccountTransition::reserve(before, claim)?;
        transition.original_clock = Some(self.original);
        transition.preparation = Some(super::PreparationBinding {
            claim,
            nonce: self.nonce,
            controller_names: self.controller_names,
            source_names: self.source_names,
            source_sequence: self.source_sequence,
            floor: self.floor,
            tree_head: self.tree_head,
            lineage_head: self.lineage_head,
        });
        Ok(transition)
    }
}
