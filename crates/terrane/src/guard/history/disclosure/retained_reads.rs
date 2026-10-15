//! Separates candidate and current read preparation from owning completion.
//!
//! These private selectors borrow genuine read scopes. Pending histories retain
//! their actual purpose until the native producer closes the original inputs;
//! neither selector converts read evidence into permission or a mutation grant.

#[cfg(all(feature = "std", feature = "tokio", unix))]
use super::invalid;
use super::{CompletedCollectionHistory, StoreFailure};

/// Retains the distinct owning purpose of one deferred history preparation.
#[cfg(all(feature = "std", feature = "tokio", unix))]
#[derive(Clone, Copy)]
pub(super) enum RetainedReadPurpose<'scope, 'history, 'held> {
    /// Borrows the existing sealed candidate relationship reader.
    Candidate(&'scope dyn crate::bucket::held::NodeReads),
    /// Borrows one genuine current invocation and its complete DATA ledger.
    Current {
        /// The exact current whole-ref, holder and resolver purpose.
        purpose: &'scope crate::guard::current_history::CurrentPurpose<'history, 'held>,
        /// The sealed reader whose original physical inputs must close.
        reads: &'scope dyn crate::bucket::held::CurrentNodeReads,
    },
    /// Borrows one fresh authorization under its unchanged existing held purpose.
    Held {
        /// Retains the actual whole ref and every original observation distinction.
        purpose: &'scope crate::guard::held_history::HeldPurpose<'history, 'held>,
        /// Retains one invocation's complete immutable DATA ledger.
        reads: &'scope dyn crate::bucket::held::CurrentNodeReads,
    },
    /// Borrows one immutable signed layer under its actual existing holder.
    Overlay {
        /// Binds the exact layer and original observation without current rights.
        purpose: &'scope crate::guard::overlay_history::OverlayPurpose<'history, 'held>,
        /// Borrows the same invocation-local canonical DATA ledger.
        reads: &'scope dyn crate::bucket::held::OverlayNodeReads,
    },
    /// Borrows one tokenless immutable invocation, independently from current refs.
    Direct {
        /// Binds the actual target, native selection and original observation.
        purpose: &'scope crate::guard::direct_history::DirectPurpose<'history, 'held>,
        /// Borrows every canonical DATA recipe consumed by this owning walk.
        reads: &'scope dyn crate::bucket::held::DirectNodeReads,
    },
}

/// Keeps deferred histories distinct from complete owning history evidence.
pub(super) enum HistoryCompletion<'scope, 'history, 'held> {
    /// Contains an ordinarily completed history and its collection observations.
    Complete(
        CompletedCollectionHistory,
        std::marker::PhantomData<(&'scope (), &'history (), &'held ())>,
    ),
    /// Retains the original candidate preparation without promoting its inputs.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    Pending(super::super::PendingCandidateHistory<'scope, 'history>),
    /// Retains the actual current-purpose preparation without promoting inputs.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    PendingCurrent(crate::guard::current_history::PendingCurrentHistory<'scope, 'history, 'held>),
    /// Retains the held-purpose walk until its independent physical close.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    PendingHeld(crate::guard::held_history::PendingHeldHistory<'scope, 'history, 'held>),
    /// Retains immutable layer completion until its own exact native close.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    PendingOverlay(crate::guard::overlay_history::PendingOverlayHistory<'scope, 'history, 'held>),
    /// Retains immutable completion until its distinct native direct close succeeds.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    PendingDirect(crate::guard::direct_history::PendingDirectHistory<'scope, 'history, 'held>),
}

impl HistoryCompletion<'_, '_, '_> {
    /// Returns only history whose owning completion already succeeded.
    ///
    /// # Errors
    /// Refuses candidate or current preparation awaiting genuine native closure.
    pub(super) fn completed(self) -> Result<CompletedCollectionHistory, StoreFailure> {
        match self {
            Self::Complete(completed, _) => Ok(completed),
            #[cfg(all(feature = "std", feature = "tokio", unix))]
            Self::Pending(_)
            | Self::PendingCurrent(_)
            | Self::PendingHeld(_)
            | Self::PendingDirect(_)
            | Self::PendingOverlay(_) => Err(invalid()),
        }
    }
}
