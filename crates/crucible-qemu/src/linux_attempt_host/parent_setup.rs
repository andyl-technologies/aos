//! Retains the external Parent's partial setup and cleanup causes permanently.
//!
//! Every returned storage/cgroup failure stays owned before diagnostics or an
//! original postcheck. Configured process authority is published before watcher
//! and contract effects. This route never transfers to an ordinary worker.

use super::*;
use crate::linux_attempt_storage::LinuxQemuAttemptStorageCreateError;
use crate::linux_cgroup::{LinuxQemuAttemptProcessOwnerError, LinuxQemuCgroupCreateError};
use crucible_linux_resource::host_services::process_birth::OriginalParentAttempt;

/// Inline remnants whose lifetime is enclosed by the original external pair.
pub(crate) struct OriginalParentSetup {
    pub(crate) storage_failure: Option<LinuxQemuAttemptStorageCreateError>,
    pub(crate) group_failure: Option<LinuxQemuCgroupCreateError>,
    pub(crate) process_failure: Option<LinuxQemuAttemptProcessOwnerError>,
    // The existing error owns its watcher or cgroup together with the raw cause.
    pub(crate) watcher_cleanup_failure:
        Option<crate::linux_cgroup::LinuxQemuCgroupWatcherWaitError>,
    pub(crate) group_cleanup_failure: Option<crate::linux_cgroup::LinuxQemuCgroupReleaseError>,
    pub(crate) cleanup_original_post:
        Option<crucible_linux_resource::host_services::process_birth::OriginalParentAttemptRefusal>,
}

impl OriginalParentSetup {
    pub(crate) const fn empty() -> Self {
        Self {
            storage_failure: None,
            group_failure: None,
            process_failure: None,
            watcher_cleanup_failure: None,
            group_cleanup_failure: None,
            cleanup_original_post: None,
        }
    }

    pub(crate) fn has_retained_cleanup(&self) -> bool {
        self.watcher_cleanup_failure.is_some()
            || self.group_cleanup_failure.is_some()
            || self.cleanup_original_post.is_some()
    }

    /// Retains the entire creation error before any postcheck or reporting.
    pub(crate) fn retain_storage_failure(&mut self, error: LinuxQemuAttemptStorageCreateError) {
        self.storage_failure = Some(error);
    }

    /// Retains the incomplete group and its exact creation cause together.
    pub(crate) fn retain_group_failure(&mut self, error: LinuxQemuCgroupCreateError) {
        self.group_failure = Some(error);
    }
}

impl LinuxQemuAttemptHostFactory {
    /// Publishes complete or partial setup directly into the original caller.
    pub(crate) fn begin_under_original_parent(
        &mut self,
        original: &OriginalParentAttempt,
        ceilings: (u32, u64, u64),
        saved: &mut Option<LinuxQemuAttemptHostOwner>,
        setup: &mut OriginalParentSetup,
    ) -> Result<(), QemuVmRealizationError> {
        original.check_original().map_err(parent_original_error)?;
        if self.poisoned
            || self.process.is_poisoned()
            || self.original_accounts.is_some()
            || saved.is_some()
        {
            return Err(missing_authority("begin retained original Parent setup"));
        }
        let (maximum_vcpus, maximum_resident_bytes, maximum_writable_bytes) = ceilings;
        *saved = Some(LinuxQemuAttemptHostOwner {
            process: None,
            storage: None,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            quarantine: None,
            native_resources: None,
            original_retirement_pinned: false,
            original_account: None,
            terminal: false,
        });
        let owner = saved
            .as_mut()
            .ok_or_else(|| missing_authority("retain Parent setup"))?;
        let storage = self.storage.begin(maximum_writable_bytes);
        match storage {
            Ok(storage) => owner.storage = Some(storage),
            Err(error) => {
                self.poisoned = true;
                setup.retain_storage_failure(error);
                // The actual error and its owner are reachable before either
                // the postcheck or the inherited allocating error conversion.
                let _original_after = original.check_original();
                return Err(map_storage_error(
                    "create original Parent storage",
                    setup
                        .storage_failure
                        .as_ref()
                        .ok_or_else(|| missing_authority("retain Parent storage error"))?
                        .source_error(),
                ));
            }
        }
        original.check_original().map_err(parent_original_error)?;
        let result =
            self.process
                .begin_under_original_parent(original, ceilings, &mut owner.process, setup);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

pub(crate) fn parent_original_error(
    source: crucible_linux_resource::host_services::process_birth::OriginalParentAttemptRefusal,
) -> QemuVmRealizationError {
    QemuVmRealizationError::ModelCopy {
        source: Box::new(source),
    }
}
