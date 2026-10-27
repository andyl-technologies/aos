//! Serializes the SAME permanent Root invocation's native lifetime fence.
//!
//! Startup settlement is one-way. A refusal cannot heal; ending Initial closes
//! every later native serving entry even while a real writer retains its shared
//! physical enrollment. Stable once-only causes remain borrowed in place. Native
//! effect/observation guards are private and hold this same phase lock through
//! actual IO; no copied flag, public callback or success scalar admits a loan.

use std::sync::{Mutex, MutexGuard, OnceLock};

use super::RootObservationErrorV1 as Error;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Armed,
    Serving,
    Refused,
    Ended,
}

pub(crate) struct RootInvocationOriginalV1 {
    phase: Mutex<Phase>,
    refusal: OnceLock<Error>,
    startup_settlement: OnceLock<Result<(), Error>>,
}

impl RootInvocationOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            phase: Mutex::new(Phase::Armed),
            refusal: OnceLock::new(),
            startup_settlement: OnceLock::new(),
        }
    }

    pub(super) fn latch_refusal(&self) {
        match self.phase.lock() {
            Ok(mut phase) => {
                *phase = Phase::Refused;
                self.refusal.get_or_init(|| Error::Service);
            }
            Err(_) => {
                self.refusal.get_or_init(|| Error::Service);
            }
        }
    }

    pub(super) fn settle_checked_startup_once(&self, checked: Result<(), Error>)
        -> Result<(), Error>
    {
        let mut phase = self.phase.lock().map_err(|_| {
            self.refusal.get_or_init(|| Error::Service);
            Error::Service
        })?;
        if *phase != Phase::Armed || self.startup_settlement.get().is_some()
            || self.refusal.get().is_some()
        {
            *phase = Phase::Refused;
            self.refusal.get_or_init(|| Error::Service);
            return Err(Error::Service);
        }
        if self.startup_settlement.set(checked).is_err() {
            *phase = Phase::Refused;
            self.refusal.get_or_init(|| Error::Service);
            return Err(Error::Service);
        }
        if matches!(self.startup_settlement.get(), Some(Ok(()))) {
            *phase = Phase::Serving;
            Ok(())
        } else {
            *phase = Phase::Refused;
            self.refusal.get_or_init(|| Error::Service);
            Err(Error::Service)
        }
    }

    pub(super) fn construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Phase>().checked_mul(2)?
            .checked_add(std::mem::size_of::<RootNativeInvocationGuardV1<'_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<RootNativeInvocationGuardV1<'_>, Error>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<std::sync::LockResult<MutexGuard<'_, Phase>>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<(), Result<(), Error>>>().checked_mul(2)?)
    }

    pub(super) fn failure(&self) -> Option<&Error> {
        self.startup_settlement.get().and_then(|result| result.as_ref().err())
            .or_else(|| self.refusal.get())
    }

    pub(super) fn abort_if_armed(&self) {
        match self.phase.lock() {
            Ok(phase) if matches!(*phase, Phase::Serving | Phase::Ended) => {}
            _ => std::process::abort(),
        }
    }

    // Healthy destruction denies future native entry without turning the old
    // successful shutdown into an abort. Refusal is never demoted to Ended.
    pub(super) fn end_initial(&self) {
        match self.phase.lock() {
            Ok(mut phase) if *phase == Phase::Serving => {
                *phase = Phase::Ended;
            }
            Ok(phase) if *phase == Phase::Ended => {}
            // Refusal or poison must abort at Initial's original pre-release
            // fence, even if it arose after an earlier healthy check.
            _ => std::process::abort(),
        }
    }

    pub(super) fn is_serving(&self) -> bool {
        self.phase.lock().is_ok_and(|phase| *phase == Phase::Serving)
            && self.refusal.get().is_none()
    }

    pub(crate) fn enter_native(&self) -> Result<RootNativeInvocationGuardV1<'_>, Error> {
        let phase = self.phase.lock().map_err(|_| Error::Service)?;
        if *phase != Phase::Serving || self.refusal.get().is_some() {
            return Err(Error::Service);
        }
        Ok(RootNativeInvocationGuardV1 { phase, refusal: &self.refusal })
    }

    // Observations are independent paid debt, including after refusal. Ending
    // Initial still denies fresh observation entry; an already-held guard can
    // finish before end_initial takes this SAME lock.
    pub(super) fn enter_observation(&self)
        -> Result<RootNativeInvocationGuardV1<'_>, Error>
    {
        let phase = self.phase.lock().map_err(|_| Error::Service)?;
        if !matches!(*phase, Phase::Serving | Phase::Refused) {
            return Err(Error::Service);
        }
        Ok(RootNativeInvocationGuardV1 { phase, refusal: &self.refusal })
    }
}

impl Drop for RootInvocationOriginalV1 {
    fn drop(&mut self) {
        self.abort_if_armed();
    }
}

pub(crate) struct RootNativeInvocationGuardV1<'owner> {
    phase: MutexGuard<'owner, Phase>,
    refusal: &'owner OnceLock<Error>,
}

impl RootNativeInvocationGuardV1<'_> {
    // The caller parks the real native/model cause first. Closing while this
    // guard is held leaves no serving-entry window between failure and refusal.
    pub(crate) fn refuse(&mut self) {
        *self.phase = Phase::Refused;
        self.refusal.get_or_init(|| Error::Service);
    }
}

impl Drop for RootNativeInvocationGuardV1<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.refuse();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::ManuallyDrop;
    use std::sync::{Arc, Barrier, mpsc};

    #[test]
    fn failed_native_handoff_retains_its_first_result_and_cannot_heal() {
        let original = ManuallyDrop::new(RootInvocationOriginalV1::new());
        assert!(original.settle_checked_startup_once(Err(Error::Profile)).is_err());
        let cause = original.failure().unwrap() as *const Error;

        assert!(original.settle_checked_startup_once(Ok(())).is_err());

        assert!(!original.is_serving());
        assert_eq!(original.failure(), Some(&Error::Profile));
        assert_eq!(original.failure().unwrap() as *const Error, cause);
    }

    #[test]
    fn ended_initial_closes_every_later_native_entry_on_the_same_allocation() {
        let original = Arc::new(RootInvocationOriginalV1::new());
        original.settle_checked_startup_once(Ok(())).unwrap();
        let writer = Arc::clone(&original);
        let held = writer.enter_native().unwrap();
        let (sender, receiver) = mpsc::channel();
        let barrier = Arc::new(Barrier::new(2));
        let child_barrier = Arc::clone(&barrier);
        let ender = std::thread::spawn(move || {
            child_barrier.wait();
            original.end_initial();
            sender.send(()).unwrap();
        });

        barrier.wait();
        assert!(matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(held);
        receiver.recv().unwrap();
        ender.join().unwrap();

        assert!(!writer.is_serving());
        assert!(writer.enter_native().is_err());
        assert!(writer.enter_observation().is_err());
    }

    #[test]
    fn later_refusal_closes_serving_but_keeps_original_observation_debt_possible() {
        let original = ManuallyDrop::new(RootInvocationOriginalV1::new());
        original.settle_checked_startup_once(Ok(())).unwrap();
        let mut native = original.enter_native().unwrap();
        native.refuse();
        drop(native);
        let cause = original.failure().unwrap() as *const Error;

        assert!(original.enter_native().is_err());
        let observation = original.enter_observation().unwrap();
        drop(observation);
        original.latch_refusal();

        assert_eq!(original.failure().unwrap() as *const Error, cause);
        assert!(!original.is_serving());
    }

    #[test]
    fn prior_refusal_cannot_be_healed_by_a_later_positive_check() {
        let original = ManuallyDrop::new(RootInvocationOriginalV1::new());
        original.latch_refusal();
        let first = original.failure().unwrap() as *const Error;

        assert!(original.settle_checked_startup_once(Ok(())).is_err());

        assert!(original.startup_settlement.get().is_none());
        assert_eq!(original.failure().unwrap() as *const Error, first);
        assert!(!original.is_serving());
    }

    #[test]
    fn native_guard_unwind_permanently_closes_before_mutex_release() {
        let original = ManuallyDrop::new(RootInvocationOriginalV1::new());
        original.settle_checked_startup_once(Ok(())).unwrap();

        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _native = original.enter_native().unwrap();
            panic!("native caller unwound");
        }));

        assert!(caught.is_err());
        assert_eq!(original.failure(), Some(&Error::Service));
        assert!(original.enter_native().is_err());
        assert!(!original.is_serving());
    }

}

#[cfg(test)]
mod coordinator_cursor_tests {
    use super::*;
    use std::io::{self, Read as _, Write as _};
    use aos_sandbox_journal::storage::{JournalReadIdentityDataV1 as _, ReadOnlyCapturedFileCursorV1};
    use crate::canonical_journal::coordinator::CanonicalCoordinatorReadCursorV1;

    #[test]
    fn retained_root_cursor_refuses_io_after_initial_end() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"original-root").unwrap();
        let invocation = RootInvocationOriginalV1::new();
        invocation.settle_checked_startup_once(Ok(())).unwrap();
        let mut cursor = CanonicalCoordinatorReadCursorV1::from_parts(
            ReadOnlyCapturedFileCursorV1::new(&file, 13), Some(&invocation),
        );
        let mut prefix = [0; 8];
        cursor.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"original");

        invocation.end_initial();
        let read = cursor.read(&mut [0; 5]);
        let identity = cursor.sample_file_identity_v1();

        assert_eq!(read.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(matches!(identity, Err(cause) if cause.kind() == io::ErrorKind::PermissionDenied));
        assert!(!invocation.is_serving());
    }

}
