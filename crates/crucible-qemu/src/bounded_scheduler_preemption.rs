//! Resource-bounded host-scheduling adversary for live QEMU gates.
//!
//! Deterministic guest execution must not depend on uninterrupted host CPU
//! scheduling. This module perturbs the actual authenticated QEMU child with a
//! fixed sequence of `SIGSTOP`/`SIGCONT` pairs. It creates no CPU load: six
//! requested 15 ms pauses, separated by 1 ms sleeps, are the complete resource
//! budget. An independent watchdog resumes QEMU after two wall-clock seconds
//! if the controller is descheduled during a stopped interval.

use std::sync::mpsc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::shutdown::{QemuShutdownTargetError, signal_child};

pub(crate) const BOUNDED_PREEMPTION_COUNT: u32 = 6;
pub(crate) const BOUNDED_PREEMPTION_PAUSE_MILLISECONDS: u64 = 15;
pub(crate) const BOUNDED_PREEMPTION_PAUSE: Duration =
    Duration::from_millis(BOUNDED_PREEMPTION_PAUSE_MILLISECONDS);
pub(crate) const BOUNDED_PREEMPTION_INTERVAL: Duration = Duration::from_millis(1);
pub(crate) const BOUNDED_PREEMPTION_WALL_TIMEOUT: Duration = Duration::from_secs(2);

/// Evidence from one bounded scheduler-preemption run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundedSchedulerPreemptionReport {
    pub(crate) perturbations: u32,
    pub(crate) requested_stopped_milliseconds: u64,
}

/// Failure while applying the bounded host-scheduling adversary.
#[derive(Debug, Error)]
pub enum BoundedSchedulerPreemptionError {
    /// A signal could not be delivered to the authenticated QEMU child.
    #[error("bounded scheduler preemption could not signal QEMU")]
    Signal {
        /// Typed failure returned by the authenticated child signal helper.
        #[source]
        source: QemuShutdownTargetError,
    },
    /// The independent resume watchdog could not be created.
    #[error("bounded scheduler preemption could not start its resume watchdog")]
    WatchdogSpawn {
        /// Host thread-creation failure.
        #[source]
        source: std::io::Error,
    },
    /// The resume watchdog thread panicked.
    #[error("bounded scheduler preemption resume watchdog panicked")]
    WatchdogPanicked,
    /// The overall perturbation exceeded its wall-clock safety bound.
    #[error("bounded scheduler preemption exceeded its two-second wall-clock bound")]
    WallTimeout,
}

struct ResumeGuard {
    pid: u32,
    armed: bool,
}

impl ResumeGuard {
    const fn new(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    fn resume(&mut self) -> Result<(), BoundedSchedulerPreemptionError> {
        signal_child(
            self.pid,
            libc::SIGCONT,
            "resume bounded scheduler preemption",
        )
        .map_err(|source| BoundedSchedulerPreemptionError::Signal { source })?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for ResumeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = signal_child(
                self.pid,
                libc::SIGCONT,
                "clean up bounded scheduler preemption",
            );
        }
    }
}

/// Applies the fixed scheduler-preemption budget to an actual QEMU child.
///
/// The caller supplies the PID read directly from [`crate::QemuNodeChild`], so
/// signals cannot land on an outer timeout wrapper. The routine is synchronous:
/// it returns only after every perturbation and watchdog cleanup completes.
///
/// # Errors
///
/// Returns a typed error if QEMU cannot be stopped or resumed, the watchdog
/// cannot be created, the watchdog panics, or the two-second wall bound expires.
pub(crate) fn apply_bounded_scheduler_preemption(
    pid: u32,
) -> Result<BoundedSchedulerPreemptionReport, BoundedSchedulerPreemptionError> {
    let (finished_tx, finished_rx) = mpsc::channel();
    let timed_out = Arc::new(AtomicBool::new(false));
    let watchdog_timed_out = Arc::clone(&timed_out);
    let watchdog = thread::Builder::new()
        .name(String::from("crucible-qemu-resume-watchdog"))
        .spawn(
            move || match finished_rx.recv_timeout(BOUNDED_PREEMPTION_WALL_TIMEOUT) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(false),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    watchdog_timed_out.store(true, Ordering::Release);
                    signal_child(
                        pid,
                        libc::SIGCONT,
                        "watchdog resume bounded scheduler preemption",
                    )
                    .map(|()| true)
                }
            },
        )
        .map_err(|source| BoundedSchedulerPreemptionError::WatchdogSpawn { source })?;

    let perturbation_result = (|| {
        for iteration in 0..BOUNDED_PREEMPTION_COUNT {
            if timed_out.load(Ordering::Acquire) {
                return Err(BoundedSchedulerPreemptionError::WallTimeout);
            }
            let mut resume = ResumeGuard::new(pid);
            signal_child(
                pid,
                libc::SIGSTOP,
                "stop QEMU for bounded scheduler preemption",
            )
            .map_err(|source| BoundedSchedulerPreemptionError::Signal { source })?;
            if timed_out.load(Ordering::Acquire) {
                return Err(BoundedSchedulerPreemptionError::WallTimeout);
            }
            thread::sleep(BOUNDED_PREEMPTION_PAUSE);
            resume.resume()?;
            if timed_out.load(Ordering::Acquire) {
                return Err(BoundedSchedulerPreemptionError::WallTimeout);
            }
            if iteration + 1 < BOUNDED_PREEMPTION_COUNT {
                thread::sleep(BOUNDED_PREEMPTION_INTERVAL);
            }
        }
        Ok(())
    })();

    let _ = finished_tx.send(());
    let watchdog_resumed = watchdog
        .join()
        .map_err(|_panic| BoundedSchedulerPreemptionError::WatchdogPanicked)?
        .map_err(|source| BoundedSchedulerPreemptionError::Signal { source })?;
    if watchdog_resumed {
        return Err(BoundedSchedulerPreemptionError::WallTimeout);
    }
    perturbation_result?;

    Ok(BoundedSchedulerPreemptionReport {
        perturbations: BOUNDED_PREEMPTION_COUNT,
        requested_stopped_milliseconds: BOUNDED_PREEMPTION_PAUSE_MILLISECONDS
            .saturating_mul(u64::from(BOUNDED_PREEMPTION_COUNT)),
    })
}
