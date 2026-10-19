//! Admission of thin-attempt worlds kept at their published child boundary.
//!
//! A published root is a depth-0 source: the complete world a thin attempt
//! stopped with at a next-choice boundary, keyed by lineage and that child
//! configuration. Admission is fit-or-reject. Roots use the deployment's
//! initial hotness signals, which never outrank an already retained source,
//! so admitting a root never evicts genesis or another root. The root's
//! [`HotCheckpointFallback::Thin`] record for the published child artifact is
//! persisted before the source becomes reusable. Each root keeps its
//! operational provenance: how it was produced, its exact boundary
//! configuration, and the live-network pause mode over its prefix.

use super::*;
use crate::qemu_hot_fork_source_capture::AuthenticatedPublishedRootQemuHotForkSource;
use crate::{QemuPublishedRootAdmission, QemuPublishedRootRetirementError, QemuPublishedRootSink};

/// Longest diagnostic recorded for one rejected root.
const MAX_REJECTION_DIAGNOSTIC_CHARS: usize = 512;

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
        let (key, published, source, provenance) = authenticated.into_parts();
        let world = ManagedQemuHotForkSourceWorld::bind_published_root(key, source, provenance)
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

/// Published-root sink over the shared managed pool.
pub(crate) struct ManagedQemuPublishedRootSink<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    pool: SharedManagedQemuHotForkSourceWorldPool<D, R>,
    signals: HotCheckpointHotnessSignals,
}

impl<D, R> ManagedQemuPublishedRootSink<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    /// Admits roots into `pool` with the deployment's initial hotness signals.
    pub(crate) const fn new(
        pool: SharedManagedQemuHotForkSourceWorldPool<D, R>,
        signals: HotCheckpointHotnessSignals,
    ) -> Self {
        Self { pool, signals }
    }
}

impl<D, R> QemuPublishedRootSink for ManagedQemuPublishedRootSink<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld> + Send,
    D::Error: std::error::Error + 'static,
    R: HotCheckpointFallbackRetentionStore + Send,
{
    fn may_admit(&self) -> bool {
        self.pool.has_free_template_slot()
    }

    fn admit(
        &self,
        root: AuthenticatedPublishedRootQemuHotForkSource,
    ) -> Result<QemuPublishedRootAdmission, QemuPublishedRootRetirementError> {
        let failure = match self
            .pool
            .admit_authenticated_published_root(root, self.signals)
        {
            Ok(_commit) => return Ok(QemuPublishedRootAdmission::Admitted),
            Err(SharedManagedQemuHotForkAdmissionFailure::Poisoned) => {
                return Err(QemuPublishedRootRetirementError::new(
                    "shared source-world pool lock is poisoned",
                ));
            }
            Err(SharedManagedQemuHotForkAdmissionFailure::Admission(failure)) => failure,
        };

        // A durable record left behind by a failed cleanup still names the
        // stored child artifact, so it remains a valid cold fallback root.
        let (source, reason) = match failure {
            ManagedQemuHotForkAuthenticatedAdmissionFailure::Binding(failure) => {
                let (source, error) = failure.into_parts();
                (source, rejection_diagnostic(&error))
            }
            ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) => {
                let (candidate, _cleanup_slot, error) = failure.into_parts();
                let reason = rejection_diagnostic(&error);
                match candidate.into_source() {
                    Ok(source) => (source, reason),
                    Err(candidate) => {
                        let _retained_for_process_lifetime = Box::leak(candidate);
                        return Err(QemuPublishedRootRetirementError::new(format!(
                            "rejected root lost its source ({reason})"
                        )));
                    }
                }
            }
        };
        source
            .retire()
            .map(|()| QemuPublishedRootAdmission::Rejected(reason.clone()))
            .map_err(|error| {
                QemuPublishedRootRetirementError::new(format!("{error} (rejected: {reason})"))
            })
    }
}

/// Joins a bounded error chain into one diagnostic line.
fn rejection_diagnostic<E: std::error::Error>(error: &E) -> String {
    let mut message = error.to_string();
    let mut cause = error.source();
    while let Some(current) = cause {
        if message.chars().count() >= MAX_REJECTION_DIAGNOSTIC_CHARS {
            break;
        }
        message.push_str(": ");
        message.push_str(&current.to_string());
        cause = current.source();
    }
    message
        .chars()
        .take(MAX_REJECTION_DIAGNOSTIC_CHARS)
        .collect()
}
