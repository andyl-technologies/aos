//! Admission of thin-attempt worlds kept at their published child boundary.
//!
//! A published root is a depth-0 source: the complete world a thin attempt
//! stopped with at a next-choice boundary, keyed by lineage and that child
//! configuration. Admission is fit-or-reject. Roots use the deployment's
//! initial hotness signals, which never outrank an already retained source,
//! so admitting a root never evicts genesis or another root. The root's
//! [`HotCheckpointFallback::Thin`] record for the published child artifact is
//! persisted before the source becomes reusable.

use super::*;
use crate::qemu_hot_fork_source_capture::AuthenticatedPublishedRootQemuHotForkSource;

impl<D, R> ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    /// Admits a thin attempt's world at its published child boundary.
    ///
    /// Binding rechecks the published boundary predicates and measures the
    /// world. Admission then authenticates and durably stores the thin
    /// fallback for the published child artifact before installing the
    /// source.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkAuthenticatedAdmissionFailure`] retaining
    /// the complete source authority when binding, measurement, fallback
    /// persistence, or managed admission fails.
    pub(crate) fn admit_authenticated_published_root(
        &mut self,
        authenticated: AuthenticatedPublishedRootQemuHotForkSource,
        signals: HotCheckpointHotnessSignals,
    ) -> Result<
        HotCheckpointAdmissionCommit,
        ManagedQemuHotForkAuthenticatedAdmissionFailure<D::Error>,
    > {
        let (key, published, source) = authenticated.into_parts();
        let world = ManagedQemuHotForkSourceWorld::bind_published_root(key, source)
            .map_err(ManagedQemuHotForkAuthenticatedAdmissionFailure::Binding)?;

        self.admit_source(world, signals, HotCheckpointFallback::Thin(published))
            .map_err(ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission)
    }

    /// Reports whether the template-count limit leaves room for one more source.
    pub(crate) fn has_free_template_slot(&self) -> bool {
        self.manager.usage().templates() < self.manager.limits().maximum_templates()
    }
}

impl<D, R> SharedManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    /// Admits a published root through the shared owner.
    ///
    /// # Errors
    ///
    /// Returns [`SharedManagedQemuHotForkAdmissionFailure::Poisoned`] after
    /// quarantining the root when the pool lock is poisoned, or the pool's
    /// admission failure with the root's complete authority.
    pub(crate) fn admit_authenticated_published_root(
        &self,
        source: AuthenticatedPublishedRootQemuHotForkSource,
        signals: HotCheckpointHotnessSignals,
    ) -> Result<HotCheckpointAdmissionCommit, SharedManagedQemuHotForkAdmissionFailure<D::Error>>
    {
        let mut pool = match self.pool.lock() {
            Ok(pool) => pool,
            Err(_error) => {
                let _retained_for_process_lifetime = Box::leak(Box::new(source));
                return Err(SharedManagedQemuHotForkAdmissionFailure::Poisoned);
            }
        };
        pool.admit_authenticated_published_root(source, signals)
            .map_err(SharedManagedQemuHotForkAdmissionFailure::Admission)
    }

    /// Reports whether the shared pool has room for one more source.
    ///
    /// A poisoned pool admits nothing.
    pub(crate) fn has_free_template_slot(&self) -> bool {
        self.pool
            .lock()
            .is_ok_and(|pool| pool.has_free_template_slot())
    }
}
