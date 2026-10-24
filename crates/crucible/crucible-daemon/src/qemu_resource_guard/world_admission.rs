//! Bounds Source admission with its already-issued World Preparation.
//!
//! The caller retains the move-only native token and exact Main role. This
//! module waits only for the shared allocator, observes acquisition's independent
//! post before entry, and retains both refusals without allocating an error owner.

use super::*;
use std::sync::{MutexGuard, TryLockError};
use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};

/// Retains the actual World Preparation with its one nominal Pending selection.
pub(crate) struct SourceWorldAdmission {
    pub(super) preparation: crucible_qemu_host::LinuxQemuNativeWorldPreparation,
    selection: crate::PreparedSourceSelector,
    history: SourceWorldAdmissionHistory,
}

/// Preserves admission's initiating refusal and independent Original post.
#[derive(Debug, Default)]
pub(crate) struct SourceWorldAdmissionHistory {
    first: Option<AdmissionFirst>,
    post: Option<HostSupervisionError>,
}

#[derive(Debug)]
enum AdmissionFirst {
    Original(HostSupervisionError),
    Custody,
}

impl SourceWorldAdmissionHistory {
    /// Borrows the original supervision failure without replacing its native report.
    pub(crate) fn first_failure(&self) -> Option<crate::LifecycleFailureRef<'_>> {
        match &self.first {
            Some(AdmissionFirst::Original(first)) => {
                Some(crate::LifecycleFailureRef::Supervision(first))
            }
            // The existing native constructor report retains the typed mutex
            // custody refusal. Its independent Original post stays below.
            Some(AdmissionFirst::Custody) => None,
            None => self
                .post
                .as_ref()
                .map(crate::LifecycleFailureRef::Supervision),
        }
    }

    /// Borrows the independent post of this same World Preparation.
    pub(crate) fn post(&self) -> Option<&HostSupervisionError> {
        self.post.as_ref()
    }
}

impl SourceWorldAdmission {
    pub(super) fn new(
        preparation: crucible_qemu_host::LinuxQemuNativeWorldPreparation,
        selection: crate::PreparedSourceSelector,
    ) -> Self {
        Self {
            preparation,
            selection,
            history: SourceWorldAdmissionHistory::default(),
        }
    }

    pub(super) fn matches(&self, receiver: &NativeWorldBeforeEffects<'_>) -> bool {
        self.selection.same_role(receiver.source_selection())
    }

    /// Moves observed causes into the same Pending's lasting inline history.
    pub(crate) fn take_history(&mut self) -> SourceWorldAdmissionHistory {
        std::mem::take(&mut self.history)
    }

    pub(super) fn lock_host<'a, H>(
        &mut self,
        host: &'a Mutex<H>,
    ) -> Result<MutexGuard<'a, H>, QemuVmRealizationError> {
        let observed = acquire_host(host, self.preparation.operation());
        if let Some(first) = observed.first {
            self.history.first.get_or_insert(first);
        }
        if let Err(post) = observed.post {
            self.history.post.get_or_insert(post);
        }
        observed.host
    }
}

struct HostAcquisition<'a, H> {
    host: Result<MutexGuard<'a, H>, QemuVmRealizationError>,
    first: Option<AdmissionFirst>,
    post: Result<(), HostSupervisionError>,
}

fn acquire_host<'a, H>(
    host: &'a Mutex<H>,
    original: &HostOperationGuard,
) -> HostAcquisition<'a, H> {
    acquire_host_with_wait(host, original, || original.wait_for_change())
}

fn acquire_host_with_wait<'a, H>(
    host: &'a Mutex<H>,
    original: &HostOperationGuard,
    mut wait: impl FnMut() -> Result<(), HostSupervisionError>,
) -> HostAcquisition<'a, H> {
    let mut first = None;
    let acquired = (|| {
        loop {
            if let Err(refusal) = original.wait_slice() {
                first = Some(AdmissionFirst::Original(refusal));
                return Err(QemuVmRealizationError::CleanupRetained {
                    operation: "admit shared World under its saved Preparation",
                });
            }
            match host.try_lock() {
                Ok(host) => return Ok(host),
                Err(TryLockError::Poisoned(_)) => {
                    first = Some(AdmissionFirst::Custody);
                    return Err(QemuVmRealizationError::ExecutorUnavailable {
                        operation: "install shared native node World",
                        message: String::from("host-resource allocator lock is poisoned"),
                    });
                }
                Err(TryLockError::WouldBlock) => {
                    if let Err(refusal) = wait() {
                        first = Some(AdmissionFirst::Original(refusal));
                        return Err(QemuVmRealizationError::CleanupRetained {
                            operation: "wait for shared World under its saved Preparation",
                        });
                    }
                }
            }
        }
    })();
    observe_acquisition(acquired, first, original)
}

fn observe_acquisition<'a, H>(
    acquired: Result<MutexGuard<'a, H>, QemuVmRealizationError>,
    first: Option<AdmissionFirst>,
    original: &HostOperationGuard,
) -> HostAcquisition<'a, H> {
    // This post belongs to acquisition, before the infallible constructor-entry
    // seam. Lower claim/window/setup effects retain their own original posts.
    // A successful lower constructor completes Preparation and is not waited again.
    let post = original.wait_slice().map(|_| ());
    let host = match (acquired, &post) {
        (Ok(host), Ok(())) => Ok(host),
        (Ok(host), Err(_)) => {
            drop(host);
            Err(QemuVmRealizationError::CleanupRetained {
                operation: "observe shared World admission post before entry",
            })
        }
        (Err(first), _) => Err(first),
    };
    HostAcquisition { host, first, post }
}

#[cfg(test)]
mod tests;
