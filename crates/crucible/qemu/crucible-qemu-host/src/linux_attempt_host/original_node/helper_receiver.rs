//! Retains one issued helper and its output before independent Original posts.
//!
//! Node and helper use distinct existing Source fields. Neither body owns its
//! controller; returned diagnostics share only the concrete first error.

use super::*;
use crate::spawn::helper_receiver::{HelperOutput, RetainedHelperOutput};
use std::process::Command;

type SharedFirst = crate::QemuIssuedHelperFailure;

#[derive(Default)]
pub(super) struct HelperDebt {
    pub(super) child: Option<crate::node::RetainedChild>,
    lender: Option<crate::linux_attempt_host::SourceCleanupLender>,
    first: Option<SharedFirst>,
    unshared_first: Option<crate::QemuSpawnError>,
    first_funding:
        Option<crucible_host_resources::host_services::process_birth::SourceHostControlLease>,
    before: Option<HostSupervisionError>,
    source_after: Option<HostSupervisionError>,
    after: Option<HostSupervisionError>,
    output: Option<RetainedHelperOutput>,
    panicked: bool,
    probe_prepared: bool,
    effect_original: Option<crate::QemuHotForkSourceOriginal>,
    // This borrower outlives both the actual child and its retained captures.
    controls: Option<crucible_host_resources::host_services::process_birth::SourceHostControlLease>,
    first_cleanup: Option<crate::QemuNodeError>,
    latest_cleanup: Option<crate::QemuNodeError>,
}

/// Borrows one issued helper's distinct raw causes and actual retained output.
///
/// These facts grant no helper effect, return loan or continuation permission.
pub struct QemuIssuedHelperHistory<'a> {
    /// Actual initiating typed error, shared with the original controller.
    pub first: Option<&'a crate::QemuSpawnError>,
    /// Same saved effect Original's actual entry refusal.
    pub before: Option<HostSupervisionError>,
    /// Independent retained Source/event post, distinct from the guard post.
    pub source_after: Option<HostSupervisionError>,
    /// Independently observed effect Original post, including on unwind.
    pub after: Option<HostSupervisionError>,
    /// First typed physical cleanup refusal.
    pub first_cleanup: Option<&'a crate::QemuNodeError>,
    /// Distinct later typed physical cleanup refusal.
    pub latest_cleanup: Option<&'a crate::QemuNodeError>,
    /// Actual retained helper identity, absent only under known empty custody.
    pub process_id: Option<u32>,
    /// Actual retained probe bytes and exit output before a refused post.
    pub probe_output: Option<&'a std::process::Output>,
    /// Actual stdout bytes, including a partial capture retained on refusal.
    pub probe_stdout: Option<&'a [u8]>,
    /// Actual stderr bytes, including a partial capture retained on refusal.
    pub probe_stderr: Option<&'a [u8]>,
    /// Actual observed exit, independent of stream completion and later refusal.
    pub probe_status: Option<std::process::ExitStatus>,
    /// Whether an image helper's successful body output remains retained.
    pub image_completed: bool,
    /// Whether the real callback unwound while this helper field was borrowed.
    pub panicked: bool,
}

impl HelperDebt {
    pub(super) fn new(
        first_funding: Option<
            crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        >,
    ) -> Self {
        let mut debt = Self::default();
        debt.first_funding = first_funding;
        debt
    }

    fn first_cause(&self) -> Option<&crate::QemuSpawnError> {
        self.first
            .as_ref()
            .map(SharedFirst::source_ref)
            .or(self.unshared_first.as_ref())
    }

    pub(super) fn history(&self) -> QemuIssuedHelperHistory<'_> {
        let probe_bytes = self
            .output
            .as_ref()
            .and_then(RetainedHelperOutput::probe_bytes);

        QemuIssuedHelperHistory {
            first: self.first_cause(),
            before: self.before,
            source_after: self.source_after,
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
            probe_stdout: probe_bytes.map(|(stdout, _)| stdout),
            probe_stderr: probe_bytes.map(|(_, stderr)| stderr),
            probe_status: self
                .output
                .as_ref()
                .and_then(RetainedHelperOutput::probe_status),
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
        if self.first_cause().is_some() {
            return;
        }
        match self.first_funding.take() {
            Some(funding) => self.first = Some(SharedFirst::new(first, funding)),
            // An unissued fixture can retain a local refusal in its existing
            // journal, but cannot publish a shared diagnostic without a payer.
            None => self.unshared_first = Some(first),
        }
    }
}

impl Drop for HelperDebt {
    fn drop(&mut self) {
        if self.child.is_some() || self.panicked {
            // Unknown process return cannot replenish the containing Main's
            // descriptor/metadata window, even during terminal destruction.
            if let Some(controls) = self.controls.take() {
                std::mem::forget(controls);
            }
            if let Some(original) = self.effect_original.take() {
                std::mem::forget(original);
            }
        }
    }
}

struct HelperPost<'a> {
    original: &'a HostOperationGuard,
    effect: Option<(
        &'a crate::QemuHotForkSourceOriginal,
        &'a crate::linux_attempt_host::SourceCleanupLender,
    )>,
    slot: &'a mut HelperDebt,
}

impl Drop for HelperPost<'_> {
    fn drop(&mut self) {
        // Authenticate the retained action and sample its independent post even
        // when the helper body or its preceding check already refused.
        let boundary = self
            .effect
            .map_or(Ok(()), |(effect, receiver)| effect.check(receiver));
        let post = self.original.wait_slice();
        self.slot.source_after = boundary.err();
        self.slot.after = post.err();
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

    fn reserve_helper_controls(
        &self,
        original: &HostOperationGuard,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        OriginalActorAccountError,
    > {
        let bytes = crate::spawn::helper_receiver::retained_control_bytes()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let controls = self
            .retained_source_host()?
            .reserve_controls(crate::spawn::helper_receiver::DESCRIPTOR_PEAK, bytes)?;
        controls.verify_original_capacity(
            original,
            crate::spawn::helper_receiver::DESCRIPTOR_PEAK,
            bytes,
        )?;
        Ok(controls)
    }

    pub(crate) fn with_spawned_helper<T: HelperOutput>(
        &self,
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
        command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut crate::QemuNodeChild,
            &HostOperationGuard,
            &mut Option<RetainedHelperOutput>,
        ) -> Result<T, crate::QemuSpawnError>,
    ) -> Result<T::Received, crate::spawn::QemuGuardedImagePreparationError> {
        self.with_spawned_helper_original(receiver, None, command, operation, body)
    }

    /// Retains the exact helper effect Original before entry, birth and post.
    ///
    /// # Errors
    /// Refuses changed custody, unavailable funding, Original refusal, helper
    /// failure or unresolved physical return, preserving the issued recipient.
    ///
    /// # Panics
    /// Propagates a body panic while retaining uncertain helper and Original debt.
    pub(crate) fn with_spawned_helper_original<T: HelperOutput>(
        &self,
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
        effect_original: Option<&crate::QemuHotForkSourceOriginal>,
        command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut crate::QemuNodeChild,
            &HostOperationGuard,
            &mut Option<RetainedHelperOutput>,
        ) -> Result<T, crate::QemuSpawnError>,
    ) -> Result<T::Received, crate::spawn::QemuGuardedImagePreparationError> {
        let refused = || {
            crate::spawn::QemuGuardedImagePreparationError::issued(
                crate::spawn::helper_receiver::helper_custody_refusal(),
                receiver,
            )
        };
        if !receiver
            .controller()
            .is_ok_and(|current| std::ptr::eq(self, current.as_ref()))
        {
            return Err(crate::spawn::QemuGuardedImagePreparationError::local(
                crate::spawn::helper_receiver::helper_custody_refusal(),
            ));
        }
        let mut slot = self.helper.try_lock().map_err(|_| refused())?;
        if let Some(first) = &slot.first {
            return Err(crate::spawn::QemuGuardedImagePreparationError::issued(
                crate::QemuSpawnError::HelperFailure {
                    first: first.clone(),
                },
                receiver,
            ));
        }
        if slot.first_funding.is_none()
            || slot.unshared_first.is_some()
            || (T::CAPTURES_PROBE && slot.probe_prepared)
            || slot.controls.is_some()
            || slot.panicked
            || slot.child.is_some()
            || slot.output.is_some()
            || slot.before.is_some()
            || slot.source_after.is_some()
            || slot.after.is_some()
            || slot.first_cleanup.is_some()
        {
            return Err(refused());
        }

        slot.lender = Some(receiver.clone());
        slot.effect_original = effect_original.cloned();
        let effect = slot.effect_original.clone();
        let original = effect
            .as_ref()
            .map_or(self.origin.as_ref(), |effect| effect.guard());
        let before = effect
            .as_ref()
            .map_or(Ok(()), |effect| effect.check(receiver))
            .and_then(|()| original.wait_slice());
        slot.before = before.as_ref().err().copied();
        let post = HelperPost {
            original,
            effect: effect.as_ref().map(|effect| (effect, receiver)),
            slot: &mut slot,
        };
        match before {
            Err(first) => post
                .slot
                .save_first(crate::QemuSpawnError::SourceAdmission {
                    source: first.into(),
                }),
            Ok(_) => self.run_helper(post.slot, original, command, operation, body),
        }
        drop(post);
        for first in [slot.source_after, slot.after].into_iter().flatten() {
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
                receiver,
            ));
        }
        if slot.child.is_none() && slot.first_cleanup.is_none() && slot.output.is_some() {
            // The returned captures keep their original loan independently of
            // this controller. No raw Output can detach the funded buffers.
            let controls = slot.controls.take().ok_or_else(refused)?;
            let output = slot.output.take().ok_or_else(refused)?;
            let output = T::take(output).ok_or_else(refused)?;
            drop(slot.effect_original.take());
            return Ok(output.receive(controls));
        }
        Err(refused())
    }

    /// Funds buffers and process custody before either can become live.
    fn run_helper<T: HelperOutput>(
        &self,
        slot: &mut HelperDebt,
        original: &HostOperationGuard,
        mut command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut crate::QemuNodeChild,
            &HostOperationGuard,
            &mut Option<RetainedHelperOutput>,
        ) -> Result<T, crate::QemuSpawnError>,
    ) {
        let controls = match self.reserve_helper_controls(original) {
            Ok(controls) => controls,
            Err(source) => {
                slot.save_first(crate::QemuSpawnError::SourceAdmission { source });
                return;
            }
        };
        slot.controls = Some(controls);
        slot.probe_prepared |= T::CAPTURES_PROBE;
        slot.output = T::prepare_storage();

        let child = match command.spawn() {
            Ok(child) => child,
            Err(source) => {
                slot.save_first(crate::QemuSpawnError::Io { operation, source });
                return;
            }
        };
        // Publish the actual child before pipe validation or any Original post.
        slot.child = Some(crate::node::RetainedChild::new(
            crate::QemuNodeChild::new(child),
            None,
        ));

        let result = match slot
            .child
            .as_mut()
            .and_then(crate::node::RetainedChild::direct_child_mut)
        {
            Some(child) => body(child, original, &mut slot.output),
            None => Err(crate::spawn::helper_receiver::helper_custody_refusal()),
        };
        match result {
            Ok(output) => slot.output = Some(output.retain()),
            Err(first) => slot.save_first(first),
        }
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
    fn unfunded_helper_refuses_before_buffers_or_process_birth() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let controller = OriginalNativeFreshLaunchError::prepare_unissued(&original);
        let mut slot = HelperDebt::default();
        let effects = std::sync::atomic::AtomicUsize::new(0);

        controller.run_helper::<std::process::Output>(
            &mut slot,
            &original,
            Command::new("/nonexistent-unfunded-helper"),
            "unfunded helper",
            |_, _, _| {
                effects.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                unreachable!("an unfunded helper must never enter its body")
            },
        );

        assert!(matches!(
            slot.first_cause(),
            Some(crate::QemuSpawnError::SourceAdmission {
                source: OriginalActorAccountError::Unavailable,
            })
        ));
        assert!(slot.child.is_none());
        assert!(slot.controls.is_none());
        assert!(slot.output.is_none());
        assert!(!slot.probe_prepared);
        assert_eq!(effects.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

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
                effect: None,
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
                effect: None,
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
    fn unfunded_helper_first_stays_in_preborn_journal_without_shared_birth() {
        let mut slot = HelperDebt::default();
        let first = crate::QemuSpawnError::Io {
            operation: "unfunded first error",
            source: std::io::Error::from_raw_os_error(libc::EIO),
        };
        let ((), counts) =
            crucible_host_resources::test_support::TestAllocationObserver::count(|| {
                slot.save_first(first);
            });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(slot.first.is_none());
        assert!(slot.first_funding.is_none());
        assert!(matches!(slot.history().first,
            Some(crate::QemuSpawnError::Io { source, .. })
            if source.raw_os_error() == Some(libc::EIO)));
    }

    #[test]
    fn helper_projection_keeps_first_post_and_cleanup_as_distinct_typed_causes() {
        let mut slot = HelperDebt::default();
        slot.save_first(crate::QemuSpawnError::Io {
            operation: "component helper body",
            source: std::io::Error::from_raw_os_error(libc::EIO),
        });
        slot.before = Some(HostSupervisionError::Unavailable);
        slot.source_after = Some(HostSupervisionError::Unavailable);
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
        assert_eq!(
            history.source_after,
            Some(HostSupervisionError::Unavailable)
        );
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
            slot.first_cause().unwrap()
        ));
    }
}
