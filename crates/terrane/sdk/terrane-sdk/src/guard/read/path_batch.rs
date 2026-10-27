//! Requires one unchanged live policy reference across a complete metadata read.

use super::{AuthorizedSnapshot, Guard, HistoryObservation, denied};
use crate::store::{Clock, Store, StoreFailure};
use terrane_format::{auth::Verb, refs::RefRecord};

/// Tracks invocation-local agreement between independently authorized paths.
///
/// The selected commit can remain historical. Its separate live policy head
/// must agree across all checks, so a bulk disclosure cannot combine permissions
/// obtained before and after a policy transition. This is no enduring permit.
pub(crate) struct SnapshotPathBatch<'a, S, C> {
    guard: &'a Guard<S, C>,
    snapshot: &'a AuthorizedSnapshot,
    head: SnapshotPathHead,
}

/// Binds fresh path checks to one complete live policy record.
///
/// The caller retains the original private snapshot separately. This allows a
/// scoped file operation to own its snapshot without a self-referential borrow.
pub(crate) struct SnapshotPathHead {
    record: RefRecord,
}

impl<'a, S: Store, C: Clock> SnapshotPathBatch<'a, S, C> {
    /// Copies the exact comparison record for a later ordinary closing check.
    ///
    /// This grants no authority and does not replace this batch's finish.
    pub(crate) fn retained_head(&self) -> SnapshotPathHead {
        SnapshotPathHead {
            record: self.head.record.clone(),
        }
    }

    /// Captures the actual complete policy head after a fresh scoped root check.
    pub(crate) async fn begin(
        guard: &'a Guard<S, C>,
        snapshot: &'a AuthorizedSnapshot,
    ) -> Result<Self, StoreFailure> {
        Ok(Self {
            guard,
            snapshot,
            head: SnapshotPathHead::begin(guard, snapshot, b"/").await?,
        })
    }

    /// Checks ordinary path trust and Read against this invocation's policy head.
    pub(crate) async fn authorize_path(&self, path: &[u8]) -> Result<(), StoreFailure> {
        self.head
            .authorize_path(self.guard, self.snapshot, path)
            .await
    }

    /// Closes the read after result allocation and all descendant checks finish.
    pub(crate) async fn finish(self) -> Result<(), StoreFailure> {
        self.authorize_path(b"/").await
    }
}

impl SnapshotPathHead {
    /// Captures a complete policy head after a fresh check of exactly this scope.
    pub(crate) async fn begin<S: Store, C: Clock>(
        guard: &Guard<S, C>,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
    ) -> Result<Self, StoreFailure> {
        let requests = guard
            .snapshot_authorizations_observed(
                snapshot,
                path,
                HistoryObservation::default().requested_target(),
            )
            .await?;
        let record = requests
            .first()
            .and_then(|request| request.record())
            .cloned()
            .ok_or_else(|| denied(&snapshot.authority_reference, Verb::Read))?;
        let head = Self { record };
        head.check_requests(snapshot, &requests)?;
        Ok(head)
    }

    /// Repeats ordinary scoped Read and refuses any complete policy-head change.
    pub(crate) async fn authorize_path<S: Store, C: Clock>(
        &self,
        guard: &Guard<S, C>,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
    ) -> Result<(), StoreFailure> {
        let requests = guard
            .snapshot_authorizations_observed(
                snapshot,
                path,
                HistoryObservation::default().requested_target(),
            )
            .await?;
        self.check_requests(snapshot, &requests)
    }

    fn check_requests(
        &self,
        snapshot: &AuthorizedSnapshot,
        requests: &[super::super::AuthorizedRef],
    ) -> Result<(), StoreFailure> {
        if requests.is_empty()
            || requests.iter().any(|request| {
                request.reference() != snapshot.authority_reference
                    || request.record() != Some(&self.record)
            })
        {
            return Err(denied(&snapshot.authority_reference, Verb::Read));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "tokio", unix))]
mod tests;
