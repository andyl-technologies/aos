//! Drives ordinary local-v1 reclamation through a genuinely current Collection.

use super::*;

impl<F, B, V, C> Collection<'_, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Owns and removes one exact retired local triple after the complete deletion wait.
    ///
    /// Ownership uses the ordinary live first-ownership producer. Subsequent
    /// reclamation reopens protected intent under fresh current authority; the
    /// returned operation is status data and cannot authorize another effect.
    ///
    /// # Errors
    /// Preserves first-ownership failures, changed current roots or incarnations,
    /// lost whole lease and actual unlink, synchronization or progress failures.
    pub async fn delete_local_pack(
        &mut self,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
        requested: terrane_format::bucket::PackExclusion,
    ) -> Result<terrane_format::gc::DeleteOperation, CollectionError> {
        let owned = self.own_local_pack(coordinator, requested).await?;
        self.resume_local_delete(coordinator, &owned.authorization.operation_key())
            .await
    }

    /// Resumes an exact protected local operation using this collector's current cycle.
    ///
    /// The key is only a lookup hint. This collector must have completed its own
    /// marking; old authorization leases, marks and persisted phase numbers do
    /// not substitute for current roots, trust, backend or physical observations.
    ///
    /// # Errors
    /// Refuses a foreign Coordinator, incomplete marking, unsafe or unrelated
    /// ownership, changed authority, replacement artifacts and durability failure.
    /// Failure or cancellation permanently stops this Session.
    pub async fn resume_local_delete(
        &mut self,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
        operation_key: &str,
    ) -> Result<terrane_format::gc::DeleteOperation, CollectionError> {
        if !std::ptr::eq(self.guard, coordinator.guard()) {
            return Err(denied().into());
        }
        let operation = self.session.operation()?;
        self.session
            .renew(&Collector::new(self.guard, self.authority))
            .await?;
        let result = crate::selected_bridge::native_local_deletion::resume(
            self.guard,
            self.authority,
            &mut self.session,
            (&self.roots, &self.state),
            self.windows,
            operation_key,
        )
        .await?;
        self.session.recheck()?;
        operation.complete();
        Ok(result)
    }
}
