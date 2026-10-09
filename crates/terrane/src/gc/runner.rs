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
use terrane_core::gc::{GcError, GcLease, GcRoots, GcState, Windows};

/// Authenticates the complete selected root inventory and its retention policy.
pub(crate) mod roots;
/// Retains actual lease ownership, clock continuity and cancellation poison.
pub(crate) mod session;
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
