//! Keeps the one claimed native replay context across finite upper Root seams.
//!
//! The guard owns the original authority lock and physical snapshot. Its short
//! context owns the same claim, native targets, partitions and replay view while
//! the upper programme performs the four existing full Root checks. No callback,
//! Journal getter or caller-supplied successful Root result crosses this seam.

use aos_sandbox_protocol::cache_state::hold_state::q04_recipes::Q04CacheTerminalPhaseV1;

use super::*;
use crate::error::CacheQ04ErrorV1;
use crate::physical::CacheOwnerHeldSnapshotV1;
use std::sync::MutexGuard;

struct Q04BorrowedCacheTerminalReadbackV1<'capture, 'cut> {
    authority: ProtectedJournalAuthority<'capture>,
    state: &'capture mut Journal,
    source: &'capture ProtectedCacheResidencyReplayAuthorityV1,
    clock: &'capture CacheClockWriterReadbackGuard<'capture>,
    position: Q04BorrowedCacheReadPositionV1<'capture, 'cut>,
    snapshot: ProtectedJournalSnapshot,
    partitions: CacheReplayPartitionEvidenceMapV1,
    view: VerifiedCacheAuthorityViewV1,
}

enum Q04BorrowedCacheReadPositionV1<'capture, 'cut> {
    Prepare {
        native: crate::journal::Q04CachePrepareNativeLoanV1<'capture>,
        project: ProjectId,
    },
    Terminal {
        native: crate::journal::Q04CacheTerminalNativeLoanV1<'capture, 'capture, 'cut>,
    },
}

impl Q04BorrowedCacheReadPositionV1<'_, '_> {
    fn require_current(
        &mut self,
        state: &Journal,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), CacheQ04ErrorV1> {
        match self {
            Self::Prepare { native, .. } => native.require_current(state, authority),
            Self::Terminal { native, .. } => native.require_current(state, authority),
        }
    }
}

enum Q04CacheReadRequestV1<'capture, 'cut> {
    Prepare(ProjectId),
    Terminal {
        recipes: &'capture crate::journal::CacheQ04TransactionRecipesV1<'cut>,
        phase: Q04CacheTerminalPhaseV1,
    },
}

#[cfg(target_os = "linux")]
enum Q04CacheReadDestinationV1<'resident> {
    Prepare(
        &'resident mut Option<
            Result<super::super::super::Q04CachePrepareReadbackV1, crate::error::CacheQ04ErrorV1>,
        >,
    ),
    Terminal(
        &'resident mut Option<
            Result<
                super::super::super::CacheResidencyWriterReadbackV2,
                crate::error::CacheQ04ErrorV1,
            >,
        >,
    ),
}

#[cfg(target_os = "linux")]
impl Q04CacheReadDestinationV1<'_> {
    fn vacant_for(&self, request: &Q04CacheReadRequestV1<'_, '_>) -> bool {
        match (self, request) {
            (Self::Prepare(destination), Q04CacheReadRequestV1::Prepare(_)) => {
                destination.is_none()
            }
            (Self::Terminal(destination), Q04CacheReadRequestV1::Terminal { .. }) => {
                destination.is_none()
            }
            _ => false,
        }
    }

    // The returned replay/result is transformed and immediately parked in
    // the actual initializer's destination, before any currentness postcheck.
    fn capture(
        &mut self,
        returned: Result<Vec<CacheRecoveryInventoryV1>, crate::error::CacheQ04ErrorV1>,
        position: &Q04BorrowedCacheReadPositionV1<'_, '_>,
        physical: super::super::super::CacheOwnerLimitsV1,
    ) {
        match (self, position) {
            (
                Self::Prepare(destination),
                Q04BorrowedCacheReadPositionV1::Prepare { project, .. },
            ) => {
                **destination = Some(returned.and_then(|inventories| {
                    let readback =
                        super::super::super::Q04CachePrepareReadbackV1::from_current_inventories(
                            *project,
                            inventories,
                        )?;
                    readback.require_physical_limits(physical)?;
                    Ok(readback)
                }));
            }
            (
                Self::Terminal(destination),
                Q04BorrowedCacheReadPositionV1::Terminal { native, .. },
            ) => {
                **destination = Some(returned.and_then(|inventories| {
                    let readback = super::super::super::CacheResidencyWriterReadbackV2::from_original_q04_inventories(
                        native.hold(), inventories, native.identity(),
                    )?;
                    readback.require_original_q04_physical_limits(physical)?;
                    Ok(readback)
                }));
            }
            _ => {}
        }
    }

    fn retain_first_error(&mut self, first: &mut Option<crate::error::CacheQ04ErrorV1>) {
        macro_rules! retain {
            ($destination:expr) => {
                if matches!($destination, Some(Err(_))) {
                    match $destination.take() {
                        Some(Err(cause)) => {
                            first.get_or_insert(cause);
                        }
                        returned => {
                            **$destination = returned;
                        }
                    }
                }
            };
        }
        match self {
            Self::Prepare(destination) => retain!(destination),
            Self::Terminal(destination) => retain!(destination),
        }
    }

    fn succeeded(&self) -> bool {
        match self {
            Self::Prepare(destination) => matches!(destination.as_ref(), Some(Ok(_))),
            Self::Terminal(destination) => matches!(destination.as_ref(), Some(Ok(_))),
        }
    }
}

impl<'capture, 'cut> Q04BorrowedCacheTerminalReadbackV1<'capture, 'cut> {
    #[allow(clippy::too_many_arguments)]
    fn capture(
        journal: &'capture mut Journal,
        state: &'capture mut Journal,
        hold: &'capture mut Journal,
        source: &'capture ProtectedCacheResidencyReplayAuthorityV1,
        clock: &'capture CacheClockWriterReadbackGuard<'capture>,
        request: Q04CacheReadRequestV1<'capture, 'cut>,
    ) -> Result<Self, CacheQ04ErrorV1> {
        let position = match request {
            Q04CacheReadRequestV1::Prepare(project) => Q04BorrowedCacheReadPositionV1::Prepare {
                native: Journal::borrow_q04_cache_prepare_native_v1(state, journal, hold)?,
                project,
            },
            Q04CacheReadRequestV1::Terminal { recipes, phase } => {
                Q04BorrowedCacheReadPositionV1::Terminal {
                    native: Journal::borrow_q04_cache_terminal_native_v1(
                        state, journal, hold, recipes, phase,
                    )?,
                }
            }
        };
        let authority = journal.claim_cache_authority_v1()?;
        let snapshot = authority.snapshot()?;
        let partitions = source
            .partitions
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?
            .clone();
        let owner =
            CacheAuthorityOwner::new(&authority, source.owner_scope, source.maximum_record_bytes)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let view = verify_replay(
            &authority,
            &owner,
            source.owner_scope,
            source.limits,
            &partitions,
            Vec::new(),
            clock.current_unix_seconds()?,
        )?;
        drop(owner);
        Ok(Self {
            authority,
            state,
            source,
            clock,
            position,
            snapshot,
            partitions,
            view,
        })
    }

    // The full upper Root check follows this exact native prefix. Keeping it
    // outside this method preserves the original short-circuit frontier.
    fn recheck_native(&mut self) -> Result<(), CacheQ04ErrorV1> {
        self.authority
            .validate_snapshot_for_effect(&self.snapshot)?;
        self.position.require_current(self.state, &self.authority)?;
        self.clock
            .require_time_authority(&self.source.current_time)?;
        let partitions = self
            .source
            .partitions
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if *partitions != self.partitions {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        drop(partitions);

        let owner = CacheAuthorityOwner::new(
            &self.authority,
            self.source.owner_scope,
            self.source.maximum_record_bytes,
        )
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        validate_current(&owner, &[], &self.view, self.clock.current_unix_seconds()?)?;
        self.position.require_current(self.state, &self.authority)?;
        self.clock.revalidate().map_err(CacheQ04ErrorV1::from)
    }

    fn reconstruct(&mut self) -> Result<Vec<CacheRecoveryInventoryV1>, CacheQ04ErrorV1> {
        let projection =
            CacheResidencyProtectedJournalV1::claim(self.state, self.view.validator.clone())?
                .replay()?;
        Ok(reconstruct_cache_history(
            projection.records(),
            &self.view.validator,
        )?)
    }
}

/// Retains the actual authority lock and physical snapshot across Root checks.
///
/// Only the same native initializer constructs this guard. It exposes neither
/// a writer nor an authority claim; its context can run only the fixed replay.
pub struct CacheQ04ReadbackGuardV1<'capture, 'cut> {
    journal: MutexGuard<'capture, Journal>,
    physical_snapshot: CacheOwnerHeldSnapshotV1<'capture>,
    source: &'capture ProtectedCacheResidencyReplayAuthorityV1,
    state: &'capture mut Journal,
    hold: &'capture mut Journal,
    clock: &'capture CacheClockWriterReadbackGuard<'capture>,
    physical_limits: super::super::super::CacheOwnerLimitsV1,
    request: Option<Q04CacheReadRequestV1<'capture, 'cut>>,
    destination: Option<Q04CacheReadDestinationV1<'capture>>,
    first: &'capture mut Option<CacheQ04ErrorV1>,
    postcheck: &'capture mut Option<CacheQ04ErrorV1>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Q04ReadbackStageV1 {
    Before,
    Ready,
    Captured,
    After,
    Posts,
}

/// Suspends one native replay at the original full upper Root frontiers.
///
/// Every native result is parked in the same initializer before returning.
/// Negative-only skipping cannot complete a readback or release the parent.
pub struct CacheQ04ReadbackContextV1<'capture, 'cut> {
    core: Q04BorrowedCacheTerminalReadbackV1<'capture, 'cut>,
    destination: Q04CacheReadDestinationV1<'capture>,
    first: &'capture mut Option<CacheQ04ErrorV1>,
    postcheck: &'capture mut Option<CacheQ04ErrorV1>,
    physical_snapshot: &'capture CacheOwnerHeldSnapshotV1<'capture>,
    physical_limits: super::super::super::CacheOwnerLimitsV1,
    stage: Q04ReadbackStageV1,
}

impl<'capture, 'cut> CacheQ04ReadbackGuardV1<'capture, 'cut> {
    /// Borrows this guard's sole complete replay context without reopening it.
    ///
    /// # Errors
    /// Parks native target, claim, snapshot or replay-view failure in the same
    /// original and refuses repeated context entry.
    pub fn borrow_context_once_v1<'context>(
        &'context mut self,
    ) -> Result<CacheQ04ReadbackContextV1<'context, 'cut>, ()> {
        let Some(request) = self.request.take() else {
            self.first.get_or_insert(CacheQ04ErrorV1::ChangedCut);
            return Err(());
        };
        let core = match Q04BorrowedCacheTerminalReadbackV1::capture(
            &mut self.journal,
            self.state,
            self.hold,
            self.source,
            self.clock,
            request,
        ) {
            Ok(core) => core,
            Err(cause) => {
                self.first.get_or_insert(cause);
                return Err(());
            }
        };
        let Some(destination) = self.destination.take() else {
            self.first.get_or_insert(CacheQ04ErrorV1::ChangedCut);
            return Err(());
        };
        Ok(CacheQ04ReadbackContextV1 {
            core,
            destination,
            first: self.first,
            postcheck: self.postcheck,
            physical_snapshot: &self.physical_snapshot,
            physical_limits: self.physical_limits,
            stage: Q04ReadbackStageV1::Before,
        })
    }
}

impl CacheQ04ReadbackContextV1<'_, '_> {
    fn require_stage(&mut self, expected: Q04ReadbackStageV1) -> Result<(), ()> {
        if self.stage != expected {
            self.first.get_or_insert(CacheQ04ErrorV1::ChangedCut);
            return Err(());
        }
        Ok(())
    }

    /// Runs the native prefix immediately before the full Root replay check.
    ///
    /// # Errors
    /// Parks the exact prefix failure and skips only the unentered replay body.
    pub fn prepare_reconstruction_once_v1(&mut self) -> Result<(), ()> {
        self.require_stage(Q04ReadbackStageV1::Before)?;
        self.stage = Q04ReadbackStageV1::Captured;
        if let Err(cause) = self.core.recheck_native() {
            self.first.get_or_insert(cause);
            return Err(());
        }
        self.stage = Q04ReadbackStageV1::Ready;
        Ok(())
    }

    /// Runs and parks the sole canonical replay after the upper Root check.
    ///
    /// # Errors
    /// Retains the actual reconstruction or physical-limits comparison cause.
    pub fn capture_reconstruction_once_v1(&mut self) -> Result<(), ()> {
        self.require_stage(Q04ReadbackStageV1::Ready)?;
        self.stage = Q04ReadbackStageV1::Captured;
        let returned = self.core.reconstruct();
        self.destination
            .capture(returned, &self.core.position, self.physical_limits);
        self.destination.retain_first_error(self.first);
        if self.first.is_some() || !self.destination.succeeded() {
            return Err(());
        }
        Ok(())
    }

    /// Skips reconstruction after an upper refusal without issuing completion.
    ///
    /// # Errors
    /// Refuses any position other than the exact pre-reconstruction seam.
    pub fn refuse_reconstruction_after_upper_root_v1(&mut self) -> Result<(), ()> {
        self.require_stage(Q04ReadbackStageV1::Ready)?;
        self.stage = Q04ReadbackStageV1::Captured;
        Ok(())
    }

    /// Runs the original native after even when the replay already failed.
    ///
    /// # Errors
    /// Parks the native after failure; only its success reaches that after's
    /// full upper Root check.
    pub fn observe_native_after_once_v1(&mut self) -> Result<(), ()> {
        self.require_stage(Q04ReadbackStageV1::Captured)?;
        self.stage = Q04ReadbackStageV1::After;
        if let Err(cause) = self.core.recheck_native() {
            self.postcheck.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }

    /// Runs both independently owed physical and Clock posts in their old order.
    ///
    /// # Errors
    /// Retains both reached posts and reports the first native post cause.
    pub fn observe_physical_clock_posts_once_v1(&mut self) -> Result<(), ()> {
        self.require_stage(Q04ReadbackStageV1::After)?;
        self.stage = Q04ReadbackStageV1::Posts;
        let mut failed = false;
        if let Err(cause) = self.physical_snapshot.revalidate() {
            self.postcheck.get_or_insert(cause.into());
            failed = true;
        }
        if let Err(cause) = self.core.clock.revalidate() {
            self.postcheck.get_or_insert(cause.into());
            failed = true;
        }
        if failed {
            return Err(());
        }
        Ok(())
    }

    /// Finishes this observation after its independently owed full Root post.
    ///
    /// This does not mark the parent Q04 complete or release any Clock guard.
    ///
    /// # Errors
    /// Refuses missing posts, any retained native cause or absent actual replay.
    pub fn finish_after_upper_root_post_v1(mut self) -> Result<(), ()> {
        self.require_stage(Q04ReadbackStageV1::Posts)?;
        if self.first.is_some() || self.postcheck.is_some() || !self.destination.succeeded() {
            return Err(());
        }
        Ok(())
    }
}

impl ProtectedCacheResidencyReplayAuthorityV1 {
    #[allow(clippy::too_many_arguments)]
    fn begin_borrowed_q04_readback_v1<'capture, 'cut>(
        &'capture self,
        state: &'capture mut Journal,
        hold: &'capture mut Journal,
        clock: &'capture CacheClockWriterReadbackGuard<'capture>,
        request: Q04CacheReadRequestV1<'capture, 'cut>,
        physical: &'capture super::super::super::DormantCacheOwnerV1,
        destination: Q04CacheReadDestinationV1<'capture>,
        first: &'capture mut Option<CacheQ04ErrorV1>,
        postcheck: &'capture mut Option<CacheQ04ErrorV1>,
    ) -> Result<CacheQ04ReadbackGuardV1<'capture, 'cut>, ()> {
        let returned = (|| {
            if !destination.vacant_for(&request) || first.is_some() || postcheck.is_some() {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            if matches!(&request, Q04CacheReadRequestV1::Prepare(project) if project.as_bytes() == &[0; 16])
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            clock.require_time_authority(&self.current_time)?;
            let physical_snapshot = physical.held_snapshot()?;
            let journal = self
                .journal
                .lock()
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            clock.require_cache_targets(state, &journal)?;
            if physical_snapshot.owner_uid() != hold.protected_owner_uid()? {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            Ok((physical_snapshot, journal))
        })();
        let (physical_snapshot, journal) = match returned {
            Ok(originals) => originals,
            Err(cause) => {
                first.get_or_insert(cause);
                return Err(());
            }
        };
        Ok(CacheQ04ReadbackGuardV1 {
            journal,
            physical_snapshot,
            source: self,
            state,
            hold,
            clock,
            physical_limits: physical.limits(),
            request: Some(request),
            destination: Some(destination),
            first,
            postcheck,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_borrowed_q04_terminal_readback_v1<'capture, 'cut>(
        &'capture self,
        state: &'capture mut Journal,
        hold: &'capture mut Journal,
        clock: &'capture CacheClockWriterReadbackGuard<'capture>,
        recipes: &'capture crate::journal::CacheQ04TransactionRecipesV1<'cut>,
        phase: Q04CacheTerminalPhaseV1,
        physical: &'capture super::super::super::DormantCacheOwnerV1,
        destination: &'capture mut Option<
            Result<super::super::super::CacheResidencyWriterReadbackV2, CacheQ04ErrorV1>,
        >,
        first: &'capture mut Option<CacheQ04ErrorV1>,
        postcheck: &'capture mut Option<CacheQ04ErrorV1>,
    ) -> Result<CacheQ04ReadbackGuardV1<'capture, 'cut>, ()> {
        self.begin_borrowed_q04_readback_v1(
            state,
            hold,
            clock,
            Q04CacheReadRequestV1::Terminal { recipes, phase },
            physical,
            Q04CacheReadDestinationV1::Terminal(destination),
            first,
            postcheck,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture_borrowed_q04_prepare_readback_v1(
        &self,
        state: &mut Journal,
        hold: &mut Journal,
        clock: &CacheClockWriterReadbackGuard<'_>,
        project: ProjectId,
        physical: &super::super::super::DormantCacheOwnerV1,
        destination: &mut Option<
            Result<super::super::super::Q04CachePrepareReadbackV1, CacheQ04ErrorV1>,
        >,
        first: &mut Option<CacheQ04ErrorV1>,
        postcheck: &mut Option<CacheQ04ErrorV1>,
    ) -> Result<(), CacheQ04ErrorV1> {
        let mut guard = self
            .begin_borrowed_q04_readback_v1(
                state,
                hold,
                clock,
                Q04CacheReadRequestV1::Prepare(project),
                physical,
                Q04CacheReadDestinationV1::Prepare(destination),
                first,
                postcheck,
            )
            .map_err(|()| CacheQ04ErrorV1::ChangedCut)?;
        let mut context = guard
            .borrow_context_once_v1()
            .map_err(|()| CacheQ04ErrorV1::ChangedCut)?;
        if context.prepare_reconstruction_once_v1().is_ok() {
            let _ = context.capture_reconstruction_once_v1();
        }
        let _ = context.observe_native_after_once_v1();
        let _ = context.observe_physical_clock_posts_once_v1();
        context
            .finish_after_upper_root_post_v1()
            .map_err(|()| CacheQ04ErrorV1::ChangedCut)
    }
}

// The actual full Q fixed capture invoice calls this before replay growth.
// Constructor, ABI Result and caller-held guard/context are distinct planes;
// no optimiser-dependent elision or old unrelated backing pays these headers.
pub(crate) fn q04_readback_control_receiving_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    // A core is constructed in capture(), returned in its owning Result,
    // then moved from the caller's core local into the context constructor.
    let core = size_of::<Q04BorrowedCacheTerminalReadbackV1<'_, '_>>()
        .checked_mul(2)?
        .checked_add(size_of::<
            Result<Q04BorrowedCacheTerminalReadbackV1<'_, '_>, CacheQ04ErrorV1>,
        >())?;
    // The guard crosses the common constructor, finite Terminal delegate and
    // actual initializer delegate. Each real ABI return gets its own plane.
    let guard = size_of::<CacheQ04ReadbackGuardV1<'_, '_>>()
        .checked_mul(2)?
        .checked_add(size_of::<Result<CacheQ04ReadbackGuardV1<'_, '_>, ()>>().checked_mul(3)?)?;
    // The context has one constructor and one Result return, then the actual
    // caller-held context. There is no unused CacheQ04Error Result variant.
    let context = size_of::<CacheQ04ReadbackContextV1<'_, '_>>()
        .checked_mul(2)?
        .checked_add(size_of::<Result<CacheQ04ReadbackContextV1<'_, '_>, ()>>())?;
    // The setup closure borrows nine distinct source places before its
    // physical/lock tuple is returned. Price construction and invocation;
    // its output tuple is not a substitute for the capture environment.
    let setup_capture = size_of::<(
        &Q04CacheReadDestinationV1<'_>, &Q04CacheReadRequestV1<'_, '_>,
        &Option<CacheQ04ErrorV1>, &Option<CacheQ04ErrorV1>,
        &CacheClockWriterReadbackGuard<'_>, &ProtectedCacheResidencyReplayAuthorityV1,
        &crate::DormantCacheOwnerV1, &Journal, &Journal,
    )>();
    core.checked_add(guard)?
        .checked_add(context)?
        .checked_add(size_of::<Q04BorrowedCacheReadPositionV1<'_, '_>>().checked_mul(2)?)?
        .checked_add(size_of::<Q04CacheReadRequestV1<'_, '_>>().checked_mul(2)?)?
        .checked_add(size_of::<Q04CacheReadDestinationV1<'_>>().checked_mul(2)?)?
        .checked_add(
            size_of::<Result<Vec<CacheRecoveryInventoryV1>, CacheQ04ErrorV1>>().checked_mul(3)?,
        )?
        .checked_add(size_of::<Result<(), CacheQ04ErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(3)?)?
        .checked_add(
            size_of::<(CacheOwnerHeldSnapshotV1<'_>, MutexGuard<'_, Journal>)>().checked_mul(2)?,
        )?
        .checked_add(size_of::<
            Result<(CacheOwnerHeldSnapshotV1<'_>, MutexGuard<'_, Journal>), CacheQ04ErrorV1>,
        >())?
        .checked_add(size_of::<bool>())?
        .checked_add(setup_capture.checked_mul(2)?)
}
