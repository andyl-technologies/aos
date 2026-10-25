//! Retains the repository's original coordinator throughout native collection.
//!
//! Public callers supply scheduling inputs, never an original-authority receipt
//! or a replacement coordinator. Every effect delegates to the existing
//! singleton-lease collector and its checked native publication paths.

use super::{MetadataValidator, Repository};
use crate::{
    bucket::{BucketBinding, FileBucket},
    gc::runner::{Collection, CollectionError},
    ref_advance::Coordinator,
    store::{Clock, LocalFs},
};
use terrane_format::gc::{DeleteOperation, GcLease, GcRoots, GcState, Tombstone, Windows};

/// Keeps native collection bound to one repository's original coordinator.
pub struct LocalCollection<'repository, F: LocalFs, C: Clock> {
    collection: Collection<'repository, F, C, MetadataValidator, C>,
    coordinator: &'repository Coordinator<FileBucket<F, C, MetadataValidator>, C, F>,
}

impl<F, C> Repository<FileBucket<F, C, MetadataValidator>, C, F>
where
    F: LocalFs + BucketBinding + Sync + 'static,
    C: Clock + BucketBinding + Sync + 'static,
{
    /// Starts collection using this repository's independently checked authority.
    ///
    /// The native collector acquires its actual singleton lease, authenticates
    /// the complete current root inventory and writes its original checkpoint.
    /// No signing capability is needed or constructed.
    ///
    /// # Errors
    /// Rejects a repository without protected native retention, competing or
    /// invalid leases, incomplete current roots, failed historical verification,
    /// existing cycles and actual checkpoint durability failures.
    pub async fn start_local_collection(
        &self,
        holder: String,
        duration: u64,
        cycle: u64,
        windows: Windows,
    ) -> Result<LocalCollection<'_, F, C>, CollectionError> {
        let retention = self
            .local_retention
            .as_ref()
            .ok_or_else(crate::gc::runner::denied)?;
        let collection = Collection::start(
            self.coordinator.guard(),
            &retention.authority,
            holder,
            duration,
            cycle,
            windows,
        )
        .await?;
        Ok(LocalCollection {
            collection,
            coordinator: &self.coordinator,
        })
    }

    /// Resumes selected progress under its exact freshly renewed collector lease.
    ///
    /// Decoded progress and the supplied lease grant no authority themselves.
    /// The original collector verifies live ownership and replays retained
    /// traversal against authenticated roots before returning this session.
    ///
    /// # Errors
    /// Rejects missing native retention, stale or foreign ownership, a different
    /// marking epoch, malformed progress, changed contexts and unsupported phases.
    pub async fn resume_local_collection(
        &self,
        lease: GcLease,
        duration: u64,
        cycle: u64,
        windows: Windows,
    ) -> Result<LocalCollection<'_, F, C>, CollectionError> {
        let retention = self
            .local_retention
            .as_ref()
            .ok_or_else(crate::gc::runner::denied)?;
        let collection = Collection::resume(
            self.coordinator.guard(),
            &retention.authority,
            lease,
            duration,
            cycle,
            windows,
        )
        .await?;
        Ok(LocalCollection {
            collection,
            coordinator: &self.coordinator,
        })
    }
}

impl<F, C> LocalCollection<'_, F, C>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
{
    /// Borrows the complete root inventory acknowledged by this session.
    pub fn roots(&self) -> &GcRoots {
        self.collection.roots()
    }

    /// Borrows the complete durable traversal checkpoint last acknowledged.
    pub fn state(&self) -> &GcState {
        self.collection.state()
    }

    /// Borrows the exact whole currently acknowledged collector lease.
    pub fn lease(&self) -> &GcLease {
        self.collection.lease()
    }

    /// Advances bounded metadata traversal through the original collector.
    ///
    /// # Errors
    /// Rejects invalid bounds, lost ownership, failed authenticated traversal or
    /// checkpoint durability. Cancellation permanently stops this session.
    pub async fn mark_batch(&mut self, limit: usize) -> Result<(), CollectionError> {
        self.collection.mark_batch(limit).await
    }

    /// Selects completed marking after the entire authenticated frontier finishes.
    ///
    /// # Errors
    /// Rejects unfinished traversal, lost ownership and failed durable selection.
    /// Cancellation permanently stops this session.
    pub async fn finish_mark(&mut self) -> Result<(), CollectionError> {
        self.collection.finish_mark().await
    }

    /// Retires at most one eligible pack through the original coordinator.
    ///
    /// # Errors
    /// Preserves collector renewal, complete current-root, incarnation, grace,
    /// exclusion and Trash durability failures. Cancellation stops the session.
    pub async fn retire_one(&mut self) -> Result<Option<Tombstone>, CollectionError> {
        self.collection.retire_one(self.coordinator).await
    }

    /// Restores one exact current pack binding under fresh native qualification.
    ///
    /// Returns whether native qualification selected an actual restoration.
    ///
    /// # Errors
    /// Refuses lost ownership, changed current roots or physical bindings and
    /// failed restoration durability; old marks grant no restoration permission.
    pub async fn restore_pack(
        &mut self,
        requested: terrane_format::bucket::PackExclusion,
    ) -> Result<bool, CollectionError> {
        self.collection.restore_pack(requested).await
    }

    /// Deletes one exact retired triple after native ownership and deletion wait.
    ///
    /// # Errors
    /// Preserves current-root, whole-lease, incarnation, unlink, synchronization
    /// and protected progress failures from the existing deletion producer.
    pub async fn delete_local_pack(
        &mut self,
        requested: terrane_format::bucket::PackExclusion,
    ) -> Result<DeleteOperation, CollectionError> {
        self.collection
            .delete_local_pack(self.coordinator, requested)
            .await
    }

    /// Resumes one protected deletion after this session completes current marking.
    ///
    /// The operation key is a lookup hint, never a permission receipt.
    ///
    /// # Errors
    /// Refuses incomplete marking, lost ownership, unsafe operation state,
    /// changed authority or replacement artifacts and failed native durability.
    pub async fn resume_local_delete(
        &mut self,
        operation_key: &str,
    ) -> Result<DeleteOperation, CollectionError> {
        self.collection
            .resume_local_delete(self.coordinator, operation_key)
            .await
    }
}
