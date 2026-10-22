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
    record: RefRecord,
}

impl<'a, S: Store, C: Clock> SnapshotPathBatch<'a, S, C> {
    /// Captures the actual complete policy head after a fresh scoped root check.
    pub(crate) async fn begin(
        guard: &'a Guard<S, C>,
        snapshot: &'a AuthorizedSnapshot,
    ) -> Result<Self, StoreFailure> {
        let requests = guard
            .snapshot_authorizations_observed(
                snapshot,
                b"/",
                HistoryObservation::default().requested_target(),
            )
            .await?;
        let record = requests
            .first()
            .and_then(|request| request.record())
            .cloned()
            .ok_or_else(|| denied(&snapshot.authority_reference, Verb::Read))?;
        let batch = Self {
            guard,
            snapshot,
            record,
        };
        batch.check_requests(&requests)?;
        Ok(batch)
    }

    /// Checks ordinary path trust and Read against this invocation's policy head.
    pub(crate) async fn authorize_path(&self, path: &[u8]) -> Result<(), StoreFailure> {
        let requests = self
            .guard
            .snapshot_authorizations_observed(
                self.snapshot,
                path,
                HistoryObservation::default().requested_target(),
            )
            .await?;
        self.check_requests(&requests)
    }

    /// Closes the read after result allocation and all descendant checks finish.
    pub(crate) async fn finish(self) -> Result<(), StoreFailure> {
        self.authorize_path(b"/").await
    }

    fn check_requests(&self, requests: &[super::super::AuthorizedRef]) -> Result<(), StoreFailure> {
        if requests.is_empty()
            || requests.iter().any(|request| {
                request.reference() != self.snapshot.authority_reference
                    || request.record() != Some(&self.record)
            })
        {
            return Err(denied(&self.snapshot.authority_reference, Verb::Read));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "tokio", unix))]
mod tests;
