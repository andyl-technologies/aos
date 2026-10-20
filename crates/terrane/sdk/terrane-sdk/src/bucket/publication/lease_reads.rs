//! Resolves exact collector lease preimages without repairing payload caches.
//!
//! Lease verification must finish before any filesystem effect. This path keeps
//! the actual held role, complete selected-chain checks and operation-local
//! revalidation while leaving all materialized cache repair to the checked lane.

use super::{BucketBinding, SelectedObservation, SelectedRecheck, unsupported};
use crate::bucket::held::HeldBucket;
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};

impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> HeldBucket<'_, F, C, V, WRITABLE>
{
    /// Resolves a fresh complete selection without performing repair or writes.
    ///
    /// Writable adapters must retain their actual namespace exclusion. The
    /// observation borrows that adapter and grants no lease, actor or collection
    /// permission; the dedicated producer verifies those inputs independently.
    ///
    /// # Errors
    /// Rejects unavailable retention, changed physical bindings, malformed or
    /// unavailable selected evidence and missing trusted operator configuration.
    pub(crate) async fn observe_publication_unrepaired(
        &self,
    ) -> Result<SelectedObservation<'_>, StoreFailure> {
        let selected = self.selected_held().await?;
        if WRITABLE {
            self.retained_namespace()?;
        }
        let recheck: SelectedRecheck<'_> = Box::new(move || Box::pin(self.selected_held()));

        Ok(SelectedObservation {
            selected,
            operator_uid: self
                .bucket()
                .publication_operator_uid()
                .ok_or_else(unsupported)?,
            identity: self.identity_proof(),
            recheck,
        })
    }
}
