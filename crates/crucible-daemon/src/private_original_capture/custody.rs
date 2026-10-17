//! Retains the actual actor, watcher and prepaid storage through uncertain capture.
//!
//! An armed scope cannot refund its physical borrowers during unwinding. Its
//! error-only owning box has been reserved before capture effects; a clean
//! close drops the real watcher and actor before returning unused box credit.

use std::sync::Arc;

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeScratch};

use super::{
    OriginalCaptureCompletion, OriginalCaptureWatchdog, OriginalCaptureWatcherRefusal,
    OriginalPreparation,
};

struct CaptureBorrowers {
    _actor: Arc<dyn Send + Sync>,
    _original: OriginalPreparation,
    watchdog: Option<OriginalCaptureWatchdog>,
}

struct QuarantinedCapture {
    _borrowers: CaptureBorrowers,
    _credit: DecodeScratch,
}

/// Holds the finite capture borrowers until an explicit clean close.
pub(crate) struct OriginalCaptureCustody {
    borrowers: Option<CaptureBorrowers>,
    credit: Option<DecodeScratch>,
    reserved: bool,
}

impl OriginalCaptureCustody {
    pub(crate) fn reserve(decoding: &DecodeBudget) -> Result<DecodeScratch, DecodeAdmissionError> {
        decoding.reserve_scratch_array::<QuarantinedCapture>(1)
    }

    pub(crate) fn stage(
        actor: Arc<dyn Send + Sync>,
        original: OriginalPreparation,
        credit: DecodeScratch,
    ) -> Self {
        Self {
            borrowers: Some(CaptureBorrowers {
                _actor: actor,
                _original: original,
                watchdog: None,
            }),
            credit: Some(credit),
            reserved: false,
        }
    }

    pub(crate) fn arm_reserved(&mut self) {
        // This infallible store immediately follows the actual service reserve,
        // before configuration or any fallible post-original observation.
        self.reserved = true;
    }

    pub(crate) fn attach_watchdog(&mut self, watchdog: OriginalCaptureWatchdog) {
        if let Some(body) = self.borrowers.as_mut() {
            body.watchdog = Some(watchdog);
        } else {
            // A violated private transition still cannot drop an unjoined
            // watcher. Normal construction stages borrowers exactly once.
            std::mem::forget(watchdog);
        }
    }

    pub(crate) fn first_refusal(&self) -> Option<OriginalCaptureWatcherRefusal> {
        self.borrowers
            .as_ref()
            .and_then(|body| body.watchdog.as_ref())
            .and_then(OriginalCaptureWatchdog::first_refusal)
    }

    pub(crate) fn finish(&mut self) -> Option<OriginalCaptureCompletion> {
        self.borrowers
            .as_mut()
            .and_then(|body| body.watchdog.as_mut())
            .map(OriginalCaptureWatchdog::finish)
    }

    pub(crate) fn close(mut self) {
        // The actual borrowers close before the unused, external box credit.
        self.borrowers = None;
        self.credit = None;
    }
}

impl Drop for OriginalCaptureCustody {
    fn drop(&mut self) {
        if !self.reserved {
            return;
        }
        if let Some(borrowers) = self.borrowers.take() {
            if let Some(credit) = self.credit.take() {
                // Panic and ambiguous native retirement take the SAME custody.
                // No fresh guard, clock, bank or uncharged late tuple is born.
                let _retained = Box::leak(Box::new(QuarantinedCapture {
                    _borrowers: borrowers,
                    _credit: credit,
                }));
            } else {
                // Only a corrupted internal transition can lose prepaid credit.
                // Preserve physical borrowers rather than falsely closing them.
                std::mem::forget(borrowers);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use crucible::owned_decode::{DecodeResourceAuthority, ResourceLoan};

    struct Authority(Arc<AtomicU64>);

    struct Credit {
        counter: Arc<AtomicU64>,
        bytes: u64,
    }

    impl Drop for Credit {
        fn drop(&mut self) {
            self.counter.fetch_sub(self.bytes, Ordering::SeqCst);
        }
    }

    impl DecodeResourceAuthority for Authority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            if self.0.load(Ordering::SeqCst) > 64 * 1024 {
                return Err(DecodeAdmissionError::new(std::io::Error::other(
                    "finite custody fixture exhausted",
                )));
            }
            Ok(())
        }

        fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            self.0
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                    used.checked_add(bytes).filter(|total| *total <= 64 * 1024)
                })
                .map_err(|_| {
                    DecodeAdmissionError::new(std::io::Error::other(
                        "finite custody fixture exhausted",
                    ))
                })?;
            Ok(ResourceLoan::new(Credit {
                counter: Arc::clone(&self.0),
                bytes,
            }))
        }
    }

    fn budget(counter: &Arc<AtomicU64>) -> DecodeBudget {
        // This finite existing decoder-credit mechanism proves drop order,
        // never a PID1, prebirth, native-domain or complete-purpose grant.
        DecodeBudget::new(Arc::new(Authority(Arc::clone(counter))), 64 * 1024).unwrap()
    }

    fn watcher() -> (
        crucible_linux_resource::host_supervision::HostOperationSupervisor,
        Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
        OriginalCaptureWatchdog,
    ) {
        let (owner, original) = super::super::tests::original(Duration::from_secs(10));
        let watcher = super::super::tests::engine(
            &owner,
            Arc::clone(&original),
            Duration::from_secs(10),
            crate::ExecutionCancellation::default(),
        );
        (owner, original, watcher)
    }

    #[test]
    fn explicit_clean_close_joins_actual_watcher_before_returning_box_credit() {
        let counter = Arc::new(AtomicU64::new(0));
        let decoding = budget(&counter);
        let baseline = counter.load(Ordering::SeqCst);
        let credit = OriginalCaptureCustody::reserve(&decoding).unwrap();
        let admitted = counter.load(Ordering::SeqCst);
        assert!(admitted > baseline);
        let (owner, original, watcher) = watcher();
        let actor: Arc<dyn Send + Sync> = Arc::new(());
        let actor_weak = Arc::downgrade(&actor);
        let scope = OriginalPreparation::retain_admitted(Arc::clone(&original), owner.clone());
        let mut custody = OriginalCaptureCustody::stage(actor, scope, credit);
        custody.arm_reserved();
        custody.attach_watchdog(watcher);

        assert!(custody.finish().unwrap().accepted());
        assert_eq!(counter.load(Ordering::SeqCst), admitted);
        custody.close();

        assert!(actor_weak.upgrade().is_none());
        assert!(original.wait_slice().is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), baseline);
        drop(decoding);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        eprintln!(
            "capture_quarantine_body={} custody_stack={}",
            std::mem::size_of::<QuarantinedCapture>(),
            std::mem::size_of::<OriginalCaptureCustody>()
        );
    }

    #[test]
    fn actual_unwind_retains_same_borrowers_and_prepaid_box_credit() {
        let counter = Arc::new(AtomicU64::new(0));
        let decoding = budget(&counter);
        let baseline = counter.load(Ordering::SeqCst);
        let credit = OriginalCaptureCustody::reserve(&decoding).unwrap();
        let admitted = counter.load(Ordering::SeqCst);
        let (owner, original, watcher) = watcher();
        let original_weak = Arc::downgrade(&original);
        let actor: Arc<dyn Send + Sync> = Arc::new(());
        let actor_weak = Arc::downgrade(&actor);
        let scope = OriginalPreparation::retain_admitted(Arc::clone(&original), owner.clone());
        let mut custody = OriginalCaptureCustody::stage(actor, scope, credit);
        custody.arm_reserved();
        custody.attach_watchdog(watcher);
        drop(original);

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _armed = custody;
            panic!("actual capture unwind control");
        }));

        assert!(unwind.is_err());
        assert!(actor_weak.upgrade().is_some());
        assert!(original_weak.upgrade().is_some());
        assert!(admitted > baseline);
        assert_eq!(counter.load(Ordering::SeqCst), admitted);
        // The mechanism deliberately retains the actual join handle/body until
        // process containment. Cancellation stops work but is not retirement.
        owner.cancel().unwrap();
        drop(decoding);
        assert!(counter.load(Ordering::SeqCst) >= admitted);
    }

    #[test]
    fn pre_watcher_refusal_retains_same_original_and_prepaid_reserved_custody() {
        let counter = Arc::new(AtomicU64::new(0));
        let decoding = budget(&counter);
        let credit = OriginalCaptureCustody::reserve(&decoding).unwrap();
        let admitted = counter.load(Ordering::SeqCst);
        let (owner, original) = super::super::tests::original(Duration::from_secs(10));
        let original_weak = Arc::downgrade(&original);
        let scope = OriginalPreparation::retain_admitted(original, owner.clone());
        let actor: Arc<dyn Send + Sync> = Arc::new(());
        let actor_weak = Arc::downgrade(&actor);
        let mut custody = OriginalCaptureCustody::stage(actor, scope.clone(), credit);
        custody.arm_reserved();

        // A real refusal prevents cleanup before any watcher has been attached.
        // This proves borrower/credit retention, not native or ledger retirement.
        owner.cancel().unwrap();
        assert!(scope.boundary().is_err());
        assert!(custody.finish().is_none());
        drop(scope);
        drop(custody);

        assert!(actor_weak.upgrade().is_some());
        assert!(original_weak.upgrade().is_some());
        assert_eq!(counter.load(Ordering::SeqCst), admitted);
        drop(decoding);
        assert!(counter.load(Ordering::SeqCst) >= admitted);
    }

    #[test]
    fn an_unreserved_stage_closes_without_creating_quarantine() {
        let counter = Arc::new(AtomicU64::new(0));
        let decoding = budget(&counter);
        let baseline = counter.load(Ordering::SeqCst);
        let credit = OriginalCaptureCustody::reserve(&decoding).unwrap();
        let (owner, original) = super::super::tests::original(Duration::from_secs(10));
        let original_weak = Arc::downgrade(&original);
        let scope = OriginalPreparation::retain_admitted(original, owner);
        let actor: Arc<dyn Send + Sync> = Arc::new(());
        let actor_weak = Arc::downgrade(&actor);

        drop(OriginalCaptureCustody::stage(actor, scope, credit));

        assert!(actor_weak.upgrade().is_none());
        assert!(original_weak.upgrade().is_none());
        assert_eq!(counter.load(Ordering::SeqCst), baseline);
    }
}
