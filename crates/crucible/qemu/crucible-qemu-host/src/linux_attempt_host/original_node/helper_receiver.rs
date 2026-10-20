//! Retains one issued helper and its output before independent Original posts.
//!
//! Node and helper use distinct existing Source fields. Neither body owns its
//! controller; returned diagnostics share only the concrete first error.

use super::*;
use crate::spawn::helper_receiver::{HelperOutput, RetainedHelperOutput};
use std::process::Command;

type SharedFirst = crucible_engine::SharedOperationalCause<crate::QemuSpawnError>;

#[derive(Default)]
pub(super) struct HelperDebt {
    pub(super) child: Option<crate::node::RetainedChild>,
    lender: Option<crate::linux_attempt_host::SourceCleanupLender>,
    first: Option<SharedFirst>,
    before: Option<HostSupervisionError>,
    after: Option<HostSupervisionError>,
    output: Option<RetainedHelperOutput>,
    panicked: bool,
    first_cleanup: Option<crate::QemuNodeError>,
    latest_cleanup: Option<crate::QemuNodeError>,
}

/// Borrows one issued helper's distinct raw causes and actual retained output.
///
/// These facts grant no helper effect, return loan or continuation permission.
pub struct QemuIssuedHelperHistory<'a> {
    /// Actual initiating typed error, shared with the original controller.
    pub first: Option<&'a crate::QemuSpawnError>,
    /// Same saved creation Original's actual entry refusal.
    pub before: Option<HostSupervisionError>,
    /// Independently observed creation Original post, including on unwind.
    pub after: Option<HostSupervisionError>,
    /// First typed physical cleanup refusal.
    pub first_cleanup: Option<&'a crate::QemuNodeError>,
    /// Distinct later typed physical cleanup refusal.
    pub latest_cleanup: Option<&'a crate::QemuNodeError>,
    /// Actual retained helper identity, absent only under known empty custody.
    pub process_id: Option<u32>,
    /// Actual retained probe bytes and exit output before a refused post.
    pub probe_output: Option<&'a std::process::Output>,
    /// Whether an image helper's successful body output remains retained.
    pub image_completed: bool,
    /// Whether the real callback unwound while this helper field was borrowed.
    pub panicked: bool,
}

impl HelperDebt {
    pub(super) fn history(&self) -> QemuIssuedHelperHistory<'_> {
        QemuIssuedHelperHistory {
            first: self.first.as_ref().map(SharedFirst::source_ref),
            before: self.before,
            after: self.after,
            first_cleanup: self.first_cleanup.as_ref(),
            latest_cleanup: self.latest_cleanup.as_ref(),
            process_id: self
                .child
                .as_ref()
                .map(crate::node::RetainedChild::process_id),
            probe_output: match &self.output {
                Some(RetainedHelperOutput::Probe(output)) => Some(output),
                _ => None,
            },
            image_completed: matches!(self.output, Some(RetainedHelperOutput::Image)),
            panicked: self.panicked,
        }
    }

    fn observe(&mut self, first: crate::QemuNodeError) {
        if self.first_cleanup.is_none() {
            self.first_cleanup = Some(first);
        } else if self.latest_cleanup.as_ref() != Some(&first) {
            self.latest_cleanup = Some(first);
        }
    }

    fn save_first(&mut self, first: crate::QemuSpawnError) {
        if self.first.is_none() {
            self.first = Some(SharedFirst::new(first));
        }
    }
}

struct HelperPost<'a> {
    original: &'a HostOperationGuard,
    slot: &'a mut HelperDebt,
}

impl Drop for HelperPost<'_> {
    fn drop(&mut self) {
        self.slot.after = self.original.wait_slice().err();
        self.slot.panicked |= std::thread::panicking();
    }
}

impl OriginalNativeFreshLaunchError {
    /// Projects the actual helper journal while retaining its same owner.
    ///
    /// The callback must not enter helper cleanup or another helper operation.
    ///
    /// # Errors
    /// Refuses contended or poisoned access rather than reporting empty history.
    ///
    /// # Panics
    /// Propagates a callback panic; the same retained helper journal remains owned
    /// and later projections refuse its poisoned mutex.
    pub fn with_helper_history<T>(
        &self,
        apply: impl for<'a> FnOnce(QemuIssuedHelperHistory<'a>) -> T,
    ) -> Result<T, OriginalActorAccountError> {
        let slot = self
            .helper
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        Ok(apply(slot.history()))
    }

    pub(crate) fn with_spawned_helper<T: HelperOutput>(
        self: &Arc<Self>,
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
        mut command: Command,
        operation: &'static str,
        body: impl FnOnce(&mut crate::QemuNodeChild) -> Result<T, crate::QemuSpawnError>,
    ) -> Result<T, crate::spawn::QemuGuardedImagePreparationError> {
        let refused = || {
            crate::spawn::QemuGuardedImagePreparationError::issued(
                crate::spawn::helper_receiver::helper_custody_refusal(),
                self,
            )
        };
        let mut slot = self.helper.try_lock().map_err(|_| refused())?;
        if let Some(first) = &slot.first {
            return Err(crate::spawn::QemuGuardedImagePreparationError::issued(
                crate::QemuSpawnError::HelperFailure {
                    first: first.clone(),
                },
                self,
            ));
        }
        if slot.panicked
            || slot.child.is_some()
            || slot.output.is_some()
            || slot.before.is_some()
            || slot.after.is_some()
            || slot.first_cleanup.is_some()
        {
            return Err(refused());
        }

        slot.lender = Some(receiver.clone());
        let before = self.origin.wait_slice();
        slot.before = before.as_ref().err().copied();
        let post = HelperPost {
            original: &self.origin,
            slot: &mut slot,
        };
        match before {
            Err(first) => post
                .slot
                .save_first(crate::QemuSpawnError::SourceAdmission {
                    source: first.into(),
                }),
            Ok(_) => match command.spawn() {
                Err(source) => post
                    .slot
                    .save_first(crate::QemuSpawnError::Io { operation, source }),
                Ok(child) => {
                    // Save the actual child before pipe validation or any post.
                    post.slot.child = Some(crate::node::RetainedChild::new(
                        crate::QemuNodeChild::new(child),
                        None,
                    ));
                    let result = match post
                        .slot
                        .child
                        .as_mut()
                        .and_then(crate::node::RetainedChild::direct_child_mut)
                    {
                        Some(child) => body(child),
                        None => Err(crate::spawn::helper_receiver::helper_custody_refusal()),
                    };
                    match result {
                        Ok(output) => post.slot.output = Some(output.retain()),
                        Err(first) => post.slot.save_first(first),
                    }
                }
            },
        }
        drop(post);
        if let Some(first) = slot.after {
            slot.save_first(crate::QemuSpawnError::SourceAdmission {
                source: first.into(),
            });
        }
        if let Some(first) = &slot.first {
            let _ = self.helper_first.set(first.clone());
        }
        self.settle_helper(&mut slot, receiver);
        if let Some(first) = &slot.first {
            return Err(crate::spawn::QemuGuardedImagePreparationError::issued(
                crate::QemuSpawnError::HelperFailure {
                    first: first.clone(),
                },
                self,
            ));
        }
        if slot.child.is_none() && slot.first_cleanup.is_none() {
            if let Some(output) = slot.output.take() {
                return T::take(output).ok_or_else(refused);
            }
        }
        Err(refused())
    }

    fn settle_helper(
        &self,
        slot: &mut HelperDebt,
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
    ) {
        let Some(child) = slot.child.as_mut() else {
            return;
        };
        if !child.child_reaped() {
            let original = match receiver.clone().retained_original() {
                Ok(original) => original,
                Err(first) => {
                    slot.observe(crate::QemuNodeError::RamCleanupLender {
                        source: crucible_engine::BackendOperationalCause::new(first),
                    });
                    return;
                }
            };
            child.retain_source_original(original);
            if let Err(first) = child.retry_cleanup() {
                slot.observe(first);
            }
        }
        // Helpers have no RAM source; actual reap closes their physical leaves.
        if slot
            .child
            .as_ref()
            .is_some_and(crate::node::RetainedChild::child_reaped)
        {
            drop(slot.child.take());
        }
    }

    /// Observes the issued helper's actual process without fabricating absence.
    ///
    /// # Errors
    /// Refuses contended or poisoned access to the retained helper field.
    pub fn retained_helper_process(&self) -> Result<Option<u32>, OriginalActorAccountError> {
        let slot = self
            .helper
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        Ok(slot
            .child
            .as_ref()
            .map(crate::node::RetainedChild::process_id))
    }

    /// Continues physical helper cleanup under the same constructor-bound loan.
    ///
    /// Sticky first/post history remains after known physical return.
    #[must_use]
    pub fn retry_retained_helper(&self) -> bool {
        let Ok(mut slot) = self.helper.try_lock() else {
            return false;
        };
        if slot.child.is_none() {
            return true;
        }
        let Some(receiver) = slot.lender.clone() else {
            return false;
        };
        self.settle_helper(&mut slot, &receiver);
        slot.child.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    #[test]
    fn helper_post_observes_same_original_on_pre_refusal_without_effect() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        supervisor.cancel().unwrap();
        let mut slot = HelperDebt::default();
        slot.before = original.wait_slice().err();
        let effects = std::sync::atomic::AtomicUsize::new(0);
        let refused = slot.before.is_some();
        {
            let _post = HelperPost {
                original: &original,
                slot: &mut slot,
            };
            if !refused {
                effects.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        assert!(slot.before.is_some());
        assert!(slot.after.is_some());
        assert_eq!(effects.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn helper_unwind_preserves_actual_panic_and_independent_original_post() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let mut slot = HelperDebt::default();
        let actual = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _post = HelperPost {
                original: &original,
                slot: &mut slot,
            };
            supervisor.cancel().unwrap();
            std::panic::panic_any("actual helper panic");
        }))
        .unwrap_err();
        assert_eq!(actual.downcast_ref::<&str>(), Some(&"actual helper panic"));
        assert!(slot.panicked);
        assert!(slot.after.is_some());
    }

    #[test]
    fn helper_projection_keeps_first_post_and_cleanup_as_distinct_typed_causes() {
        let mut slot = HelperDebt::default();
        slot.save_first(crate::QemuSpawnError::Io {
            operation: "component helper body",
            source: std::io::Error::from_raw_os_error(libc::EIO),
        });
        slot.before = Some(HostSupervisionError::Unavailable);
        slot.after = Some(HostSupervisionError::CapacityExhausted);
        slot.observe(crate::QemuNodeError::RamCleanupPending);
        slot.observe(crate::QemuNodeError::RamCleanupLender {
            source: crucible_engine::BackendOperationalCause::new(
                HostSupervisionError::Unavailable,
            ),
        });
        slot.output = Some(RetainedHelperOutput::Image);

        let history = slot.history();
        assert!(
            matches!(history.first, Some(crate::QemuSpawnError::Io { source, .. })
            if source.raw_os_error() == Some(libc::EIO))
        );
        assert_eq!(history.before, Some(HostSupervisionError::Unavailable));
        assert_eq!(history.after, Some(HostSupervisionError::CapacityExhausted));
        assert!(matches!(
            history.first_cleanup,
            Some(crate::QemuNodeError::RamCleanupPending)
        ));
        assert!(matches!(
            history.latest_cleanup,
            Some(crate::QemuNodeError::RamCleanupLender { .. })
        ));
        assert!(history.image_completed);
        assert!(history.probe_output.is_none());
        assert!(std::ptr::eq(
            history.first.unwrap(),
            slot.first.as_ref().unwrap().source_ref()
        ));
    }
}
