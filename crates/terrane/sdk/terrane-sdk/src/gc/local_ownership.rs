//! Drives first local ownership through the actual collector Session.

use super::*;

impl<F, B, V, C> Collection<'_, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Durably owns one exact retired local triple after uninterrupted full-D waiting.
    ///
    /// The returned Invalidated operation is status data. No artifact is unlinked;
    /// physical recovery and durable cancellation require separate producers.
    ///
    /// # Errors
    /// Cancellation or failure after starting the operation poisons the Session.
    /// Refuses mismatched Coordinator,
    /// invalid enforced windows, unknown incarnations, changed current authority,
    /// unavailable timing, lost renewal and failed protected native durability.
    pub async fn own_local_pack(
        &mut self,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
        requested: terrane_format::bucket::PackExclusion,
    ) -> Result<terrane_format::gc::DeleteOperation, CollectionError> {
        if !std::ptr::eq(self.guard, coordinator.guard()) {
            return Err(denied().into());
        }
        let maximum = coordinator.maximum_commit_duration();
        let commit = maximum
            .as_secs()
            .checked_add(u64::from(maximum.subsec_nanos() != 0))
            .ok_or(terrane_format::gc::GcError::Exhausted)?;
        if self.windows.commit() != commit
            || self.windows.grace() <= commit
            || self.windows.deletion() < self.windows.grace()
        {
            return Err(terrane_format::gc::GcError::Window.into());
        }
        let operation = self.session.operation()?;
        self.session
            .renew(&crate::gc::lease::Collector::new(
                self.guard,
                self.authority,
            ))
            .await
            .map_err(|error| owning_failure(&self.session, error))?;
        let result = crate::selected_bridge::native_local_ownership::own(
            self.guard,
            self.authority,
            &mut self.session,
            (&self.roots, &self.state),
            self.windows,
            &requested,
        )
        .await
        .map_err(|error| owning_failure(&self.session, error))?;
        self.session.recheck()?;
        operation.complete();
        Ok(result)
    }
}

// The owning operation reports its now-stopped Session after a precise lease
// denial. The lease/session facade keeps its original error contract unchanged.
fn owning_failure(
    session: &crate::gc::runner::session::Session,
    error: CollectionError,
) -> CollectionError {
    if matches!(
        &error,
        CollectionError::Lease(crate::gc::lease::LeaseError::Store(failure))
            if matches!(
                failure.kind(),
                crate::store::StoreErrorKind::Denied { verb: "gc-lease", pattern }
                    if pattern == "configured collector lease"
            )
    ) && let Err(stopped) = session.recheck()
    {
        return stopped.into();
    }
    error
}
