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

    /// Starts a genuine collection above every retained selected cycle number.
    ///
    /// Acquires the actual singleton lease before selecting a cycle and checking
    /// current roots. This requires no signing capability or caller-chosen cycle.
    /// Retained absent entries and copied cycle reservations remain occupied.
    ///
    /// # Errors
    /// Preserves [`Self::start_local_collection`] failures and rejects exhausted
    /// cycle numbers or malformed registered cycle keys. Unselected physical
    /// leftovers still fail the original create-once publication checks.
    pub async fn start_next_local_collection(
        &self,
        holder: String,
        duration: u64,
        windows: Windows,
    ) -> Result<LocalCollection<'_, F, C>, CollectionError> {
        let retention = self
            .local_retention
            .as_ref()
            .ok_or_else(crate::gc::runner::denied)?;
        let collection = Collection::start_next(
            self.coordinator.guard(),
            &retention.authority,
            holder,
            duration,
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

    /// Reconciles bounded permanent residues using this same original collector.
    ///
    /// The producer renews this session's whole lease and independently resolves
    /// each owner and physical request. Marking progress remains intact.
    ///
    /// # Errors
    /// Rejects invalid bounds, stale ownership, changed controls, unsafe artifacts
    /// and failed native acknowledgments. Cancellation stops the session.
    ///
    /// # Panics
    /// In test builds, panics if opt-in phase diagnostics cannot write to stderr.
    pub async fn reconcile_permanent(
        &mut self,
        owner_key: &str,
        maximum_requests: usize,
    ) -> Result<crate::gc::runner::permanent_local::Reconciliation, CollectionError> {
        self.collection
            .reconcile_permanent(self.coordinator, owner_key, maximum_requests)
            .await
    }

    /// Selects genuine copied first ownership under this same live collector lease.
    ///
    /// The destination producer independently checks complete DATA and a new
    /// full-wait barrier. This does not unlink residue or change mark checkpoints.
    ///
    /// # Errors
    /// Preserves current configuration, DATA, lease, control and durability
    /// refusals. Work failure or cancellation stops the original session.
    pub async fn own_copied_pack(
        &mut self,
        pack: [u8; 16],
    ) -> Result<terrane_format::gc::retirement::PermanentDeleteOperation, CollectionError> {
        self.collection
            .own_copied_pack(self.coordinator, pack)
            .await
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

    /// Starts a fresh authenticated mark cycle under the original collector lease.
    ///
    /// Requires the current frontier to have reached sweep. Existing cycle
    /// records and permanent recovery duties remain unchanged; this completes
    /// no deletion pass and acquires no replacement collector session.
    ///
    /// # Errors
    /// Rejects unfinished marking, nonincreasing or occupied cycles, lost leases,
    /// incomplete roots and native checkpoint failures. Actual work failure or
    /// cancellation stops the session; phase/number preflight has no effects.
    pub async fn begin_cycle(&mut self, cycle: u64) -> Result<(), CollectionError> {
        self.collection.begin_cycle(cycle).await
    }

    /// Starts a fresh cycle selected under this collector's original held lease.
    ///
    /// # Errors
    /// Rejects unfinished marking, lost ownership, exhausted cycle numbers and
    /// original authenticated checkpoint failures. Work failure stops the session.
    pub async fn begin_next_cycle(&mut self) -> Result<(), CollectionError> {
        self.collection.begin_next_cycle().await
    }

    /// Selects bounded recurring hints under this collection's original session.
    ///
    /// Permanent owners remain discoverable after completed passes. Current
    /// exclusions and copied visibility are lookup candidates only; native
    /// producers independently decide every effect. Legacy deletion intents
    /// require separate recovery discovery.
    ///
    /// # Errors
    /// Rejects invalid bounds, lost ownership, incomplete catalogs and changed
    /// observations. Actual failure or cancellation stops the original session.
    pub async fn maintenance_hints(
        &mut self,
        cursor: &mut crate::gc::runner::maintenance::MaintenanceCursor,
        maximum: usize,
    ) -> Result<Vec<crate::gc::runner::maintenance::MaintenanceHint>, CollectionError> {
        self.collection.maintenance_hints(cursor, maximum).await
    }

    /// Discovers retained ordinary deletion intents, including terminal progress.
    ///
    /// Renews this collection's original lease. The bounded lookup results retain
    /// no witness or permission; recovery independently qualifies current inputs.
    /// Permanent-v2 owners remain in their separate recurring inventory.
    ///
    /// # Errors
    /// Rejects invalid bounds, unfinished marking, malformed protected records,
    /// lost ownership and changed observations. Actual failure or cancellation stops
    /// the session; the cursor changes only after successful observation revalidation.
    pub async fn local_deletion_hints(
        &mut self,
        cursor: &mut crate::gc::runner::maintenance::local_deletion::LocalDeletionCursor,
        maximum: usize,
    ) -> Result<
        Vec<crate::gc::runner::maintenance::local_deletion::LocalDeletionHint>,
        CollectionError,
    > {
        self.collection.local_deletion_hints(cursor, maximum).await
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

    /// Restores an older exclusion and repeats retirement checks in this cycle.
    ///
    /// Uses the original coordinator and session. The separately durable restore
    /// remains available if the pack is no longer eligible for retirement. Missing
    /// old Trash is never backfilled or reused as deletion-age evidence.
    ///
    /// # Errors
    /// Rejects incomplete marking or a non-older cycle before effects. Preserves
    /// native restoration, retirement, ownership and durability failures;
    /// cancellation or failure after preflight stops the original session.
    pub async fn refresh_exclusion(
        &mut self,
        requested: terrane_format::bucket::PackExclusion,
    ) -> Result<Option<Tombstone>, CollectionError> {
        self.collection
            .refresh_exclusion(self.coordinator, requested)
            .await
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
