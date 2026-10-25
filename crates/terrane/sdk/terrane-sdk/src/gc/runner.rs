//! Coordinates genuine selected roots and resumable metadata-only mark checkpoints.
//!
//! Every operation refreshes its exact whole lease before acquiring the real
//! namespace holder. Checkpoint data grants no retirement, restoration, deletion,
//! source-preservation or remote D-82 authority. Failed renewal or cancellation
//! permanently stops this session before subsequent publication.

use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::lease::{Collector, LeaseError};
use crate::guard::{Guard, OriginalAuthority};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::gc::{GcError, GcLease, GcRoots, GcState, Windows};

/// Authenticates the complete selected root inventory and its retention policy.
pub(crate) mod roots;
/// Retains actual lease ownership, clock continuity and cancellation poison.
pub(crate) mod session;

#[path = "local_ownership.rs"]
mod local_ownership;

#[path = "local_deletion.rs"]
mod local_deletion;

/// Expands authenticated metadata contexts without reading chunk plaintext.
pub(crate) mod walk;

/// Coordinates copied destination barriers and checked first ownership.
#[path = "copied_retirement.rs"]
pub mod copied_retirement;

/// Coordinates permanent local recovery and restoration through fresh placements.
#[path = "permanent_local.rs"]
pub mod permanent_local;

#[cfg(all(test, feature = "tokio", unix))]
pub(crate) mod fixture;
#[cfg(all(test, feature = "tokio", unix))]
mod tests;

#[cfg(all(test, feature = "tokio", unix))]
#[path = "runner/tests/copied_retirement.rs"]
mod copied_retirement_tests;

#[cfg(all(test, feature = "tokio", unix))]
#[path = "runner/tests/permanent_local.rs"]
mod permanent_local_tests;

/// Reports refused traversal, fenced ownership or failed native checkpoint effects.
#[derive(Debug)]
pub enum CollectionError {
    /// Canonical records or collector arithmetic were rejected.
    Record(GcError),
    /// Actual native lease selection was refused or failed.
    Lease(LeaseError),
    /// Fresh historical verification, retained inputs or storage failed.
    Store(StoreFailure),
}

impl core::fmt::Display for CollectionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Record(error) => error.fmt(formatter),
            Self::Lease(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CollectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Record(error) => Some(error),
            Self::Lease(error) => Some(error),
            Self::Store(error) => Some(error),
        }
    }
}

impl From<GcError> for CollectionError {
    fn from(error: GcError) -> Self {
        Self::Record(error)
    }
}

impl From<LeaseError> for CollectionError {
    fn from(error: LeaseError) -> Self {
        Self::Lease(error)
    }
}

impl From<StoreFailure> for CollectionError {
    fn from(error: StoreFailure) -> Self {
        Self::Store(error)
    }
}

/// Reports a refused current configured collector session or checkpoint.
pub(crate) fn denied() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "gc-checkpoint",
        pattern: "current configured collector session".into(),
    })
}

/// Owns a fresh native maintenance lease without requiring old marking progress.
///
/// Restoration qualifies current roots using the retained candidate metadata
/// view. A newly opened holder can therefore restore a retired Meta pack needed
/// by those roots without treating its old marking epoch as current permission.
pub struct Restoration<'configuration, F, B, V, C> {
    guard: &'configuration Guard<FileBucket<F, B, V>, C>,
    authority: &'configuration OriginalAuthority,
    session: session::Session,
    cycle: u64,
    windows: Windows,
}

impl<'configuration, F, B, V, C> Restoration<'configuration, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Acquires actual collector ownership before any candidate root traversal.
    ///
    /// # Errors
    /// Refuses competing ownership, unsupported native clocks, invalid leases
    /// and failed whole selected lease publication. No marking cycle is created.
    pub async fn start(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
        holder: String,
        duration: u64,
        cycle: u64,
        windows: Windows,
    ) -> Result<Self, CollectionError> {
        let lease = Collector::new(guard, authority)
            .acquire(holder, duration)
            .await?
            .lease;
        let clock = guard.clock().retain_native_clock().map_err(|_| denied())?;
        let session = session::Session::new(lease, duration, clock)?;
        Ok(Self {
            guard,
            authority,
            session,
            cycle,
            windows,
        })
    }

    /// Restores eligible old placements and clears precisely the selected binding.
    ///
    /// The tuple selects a candidate; complete fresh qualification and native
    /// retention provide permission. False means its binding is no longer current.
    /// Trash age is unused, and permanent ownership or burn always refuses.
    ///
    /// # Errors
    /// Refuses incomplete current history, unsafe or missing pair, permanent
    /// ownership and failed native acknowledgment. Cancellation poisons the session.
    pub async fn restore_pack(
        &mut self,
        requested: terrane_format::bucket::PackExclusion,
    ) -> Result<bool, CollectionError> {
        let operation = self.session.operation()?;
        self.session
            .renew(&Collector::new(self.guard, self.authority))
            .await?;
        let result = crate::selected_bridge::native_collection_restore::restore_pack(
            self.guard,
            self.authority,
            &mut self.session,
            (self.cycle, self.windows),
            &requested,
        )
        .await?;
        operation.complete();
        Ok(result)
    }

    /// Borrows the exact whole currently acknowledged native maintenance lease.
    pub fn lease(&self) -> &GcLease {
        self.session.lease()
    }
}

/// Owns a genuine lease session and its last acknowledged whole mark checkpoint.
pub struct Collection<'configuration, F, B, V, C> {
    guard: &'configuration Guard<FileBucket<F, B, V>, C>,
    authority: &'configuration OriginalAuthority,
    session: session::Session,
    windows: Windows,
    roots: GcRoots,
    state: GcState,
}

impl<'configuration, F, B, V, C> Collection<'configuration, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Acquires native collector ownership and selects a complete new root snapshot.
    ///
    /// # Errors
    /// Refuses competition, incomplete inventories, unverified original history,
    /// unsupported source/control cases, existing cycles and failed native durability.
    pub async fn start(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
        holder: String,
        duration: u64,
        cycle: u64,
        windows: Windows,
    ) -> Result<Self, CollectionError> {
        let lease = Collector::new(guard, authority)
            .acquire(holder, duration)
            .await?
            .lease;
        let clock = guard.clock().retain_native_clock().map_err(|_| denied())?;
        let session = session::Session::new(lease, duration, clock)?;
        let operation = session.operation()?;
        let (roots, state) = crate::selected_bridge::native_collection_checkpoints::begin(
            guard, authority, &session, cycle, windows,
        )
        .await?;
        operation.complete();
        Ok(Self {
            guard,
            authority,
            session,
            windows,
            roots,
            state,
        })
    }

    /// Reconciles permanent residues under this collection's original live session.
    ///
    /// Marking roots and checkpoints remain unchanged. The owner key is only a
    /// candidate hint; the original producer independently checks current owner,
    /// physical controls, history and whole lease before every native effect.
    ///
    /// # Errors
    /// Rejects invalid bounds, unknown ownership, lost leases, changed controls,
    /// unsafe artifacts and incomplete native durability. Cancellation stops the
    /// session and queued native work retains its exclusions.
    ///
    /// # Panics
    /// In test builds, panics if opt-in phase diagnostics cannot write to stderr.
    pub async fn reconcile_permanent(
        &mut self,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
        owner_key: &str,
        maximum_requests: usize,
    ) -> Result<permanent_local::Reconciliation, CollectionError> {
        permanent_local::check_configuration(self.guard, coordinator, self.windows)?;
        permanent_local::reconcile_current(
            self.guard,
            self.authority,
            &mut self.session,
            &self.windows,
            owner_key,
            maximum_requests,
        )
        .await
    }

    /// Reopens selected progress after renewing an exact whole lease through native selection.
    ///
    /// Persisted traversal claims are replayed against actual authenticated roots
    /// before any checkpoint carrier can be constructed. Resume requires the
    /// original marking epoch; a takeover must start a different cycle.
    ///
    /// # Errors
    /// Refuses stale ownership, a different marking epoch, malformed progress,
    /// changed contexts, incomplete historical controls and unsupported resumed phases.
    pub async fn resume(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
        lease: GcLease,
        duration: u64,
        cycle: u64,
        windows: Windows,
    ) -> Result<Self, CollectionError> {
        let clock = guard.clock().retain_native_clock().map_err(|_| denied())?;
        let mut session = session::Session::new(lease, duration, clock)?;
        let operation = session.operation()?;
        session.renew(&Collector::new(guard, authority)).await?;
        let (roots, state) = crate::selected_bridge::native_collection_checkpoints::resume(
            guard, authority, &session, cycle, windows,
        )
        .await?;
        operation.complete();
        Ok(Self {
            guard,
            authority,
            session,
            windows,
            roots,
            state,
        })
    }

    /// Borrows the complete selected roots last acknowledged by this session.
    pub fn roots(&self) -> &GcRoots {
        &self.roots
    }

    /// Borrows the complete durable traversal checkpoint last acknowledged.
    pub fn state(&self) -> &GcState {
        &self.state
    }

    /// Borrows the exact whole currently acknowledged collector lease.
    pub fn lease(&self) -> &GcLease {
        self.session.lease()
    }

    /// Tombstones at most one genuinely eligible listed unburned pack and creates Trash.
    ///
    /// A returned record acknowledges actual durable Trash creation. It grants
    /// no deletion age, restore, recovery or physical unlink permission; selected
    /// deletion progress remains unchanged. None means this listing found none.
    /// The borrowed coordinator must own the same Guard and supply the actual
    /// enforced commit bound, conservatively rounded upward to whole seconds.
    ///
    /// # Errors
    /// Permanently stops on renewal failure or cancellation. Refuses incomplete
    /// current roots/catalog/controls, unknown native incarnations, unsafe inputs
    /// and failed exclusion or Trash durability. A failure after selection can
    /// leave the pack excluded with missing Trash, which remains undeletable.
    pub async fn retire_one(
        &mut self,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
    ) -> Result<Option<terrane_format::gc::Tombstone>, CollectionError> {
        self.retire(coordinator, None).await
    }

    /// Retires one requested pack only when fresh native qualification permits it.
    ///
    /// The pack identifier narrows candidate selection; it supplies no authority,
    /// age, marking result or deletion permission. Every lease, complete current
    /// root, catalog, incarnation, grace and durable Trash check is identical to
    /// [`Self::retire_one`]. Other eligible packs are left unchanged. Returns
    /// `None` when the requested pack is absent or ineligible in this observation.
    ///
    /// # Errors
    /// Preserves every qualification, cancellation, lease, timing and native
    /// durability failure from [`Self::retire_one`], including unknown creation
    /// history. A selected exclusion can remain without acknowledged Trash.
    pub async fn retire_pack(
        &mut self,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
        pack: crate::pack::PackId,
    ) -> Result<Option<terrane_format::gc::Tombstone>, CollectionError> {
        self.retire(coordinator, Some(pack)).await
    }

    async fn retire(
        &mut self,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
        requested: Option<crate::pack::PackId>,
    ) -> Result<Option<terrane_format::gc::Tombstone>, CollectionError> {
        if !std::ptr::eq(self.guard, coordinator.guard()) {
            return Err(denied().into());
        }
        let maximum = coordinator.maximum_commit_duration();
        let commit = maximum
            .as_secs()
            .checked_add(u64::from(maximum.subsec_nanos() != 0))
            .ok_or(GcError::Exhausted)?;
        if self.windows.commit() != commit
            || self.windows.grace() <= commit
            || self.windows.deletion() < self.windows.grace()
        {
            return Err(GcError::Window.into());
        }
        let operation = self.session.operation()?;
        self.session
            .renew(&Collector::new(self.guard, self.authority))
            .await?;
        let result = crate::selected_bridge::native_collection_retirement::retire_one(
            self.guard,
            self.authority,
            &self.session,
            (&self.roots, &self.state),
            self.windows,
            requested,
        )
        .await?;
        operation.complete();
        Ok(result)
    }

    /// Restores one exact current binding using independently fresh qualification.
    ///
    /// Old cycle marks and retirement age do not grant restoration permission.
    /// A new holder can use [`Restoration`] without replaying an old marking epoch.
    ///
    /// # Errors
    /// Refuses incomplete current history, unsafe or missing pair, permanent
    /// ownership and failed native acknowledgment. Cancellation poisons the session.
    pub async fn restore_pack(
        &mut self,
        requested: terrane_format::bucket::PackExclusion,
    ) -> Result<bool, CollectionError> {
        let operation = self.session.operation()?;
        self.session
            .renew(&Collector::new(self.guard, self.authority))
            .await?;
        let result = crate::selected_bridge::native_collection_restore::restore_pack(
            self.guard,
            self.authority,
            &mut self.session,
            (self.roots.cycle, self.windows),
            &requested,
        )
        .await?;
        operation.complete();
        Ok(result)
    }

    /// Expands a bounded number of authenticated commit contexts and selects progress.
    ///
    /// # Errors
    /// Permanently stops on renewal failure or cancellation. Refuses stale
    /// checkpoints, expired clocks, malformed metadata and failed native effects.
    pub async fn mark_batch(&mut self, limit: usize) -> Result<(), CollectionError> {
        let operation = self.session.operation()?;
        self.session
            .renew(&Collector::new(self.guard, self.authority))
            .await?;
        let state = crate::selected_bridge::native_collection_checkpoints::advance(
            self.guard,
            self.authority,
            &self.session,
            &self.roots,
            &self.state,
            self.windows,
            crate::selected_bridge::native_collection_checkpoints::Step::Mark { limit },
        )
        .await?;
        self.state = state;
        operation.complete();
        Ok(())
    }

    /// Completes selected immutable mark revisions and selects sweep phase.
    ///
    /// This acknowledgment grants no sweep or physical deletion permission.
    ///
    /// # Errors
    /// Refuses a nonempty frontier, stale whole progress, lost ownership,
    /// cancellation, altered immutable shards and failed native durability.
    pub async fn finish_mark(&mut self) -> Result<(), CollectionError> {
        let operation = self.session.operation()?;
        self.session
            .renew(&Collector::new(self.guard, self.authority))
            .await?;
        let state = crate::selected_bridge::native_collection_checkpoints::advance(
            self.guard,
            self.authority,
            &self.session,
            &self.roots,
            &self.state,
            self.windows,
            crate::selected_bridge::native_collection_checkpoints::Step::Finish,
        )
        .await?;
        self.state = state;
        operation.complete();
        Ok(())
    }
}
