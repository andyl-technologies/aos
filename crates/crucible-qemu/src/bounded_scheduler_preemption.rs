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

#[derive(Clone, Copy)]
struct PreemptionPolicy {
    perturbations: u32,
    pause: Duration,
    interval: Duration,
    wall_timeout: Duration,
}

const DEFAULT_PREEMPTION_POLICY: PreemptionPolicy = PreemptionPolicy {
    perturbations: BOUNDED_PREEMPTION_COUNT,
    pause: BOUNDED_PREEMPTION_PAUSE,
    interval: BOUNDED_PREEMPTION_INTERVAL,
    wall_timeout: BOUNDED_PREEMPTION_WALL_TIMEOUT,
};

/// Evidence from one bounded scheduler-preemption run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundedSchedulerPreemptionReport {
    pub(crate) perturbations: u32,
    pub(crate) requested_stopped_milliseconds: u64,
}

/// Failure while applying the bounded host-scheduling adversary.
#[derive(Debug, Error)]
pub enum BoundedSchedulerPreemptionError {
    /// The controller that owns the finite perturbation sequence could not be created.
    #[error("bounded scheduler preemption could not start its controller")]
    ControllerSpawn {
        /// Host thread-creation failure.
        #[source]
        source: std::io::Error,
    },
    /// The controller thread panicked.
    #[error("bounded scheduler preemption controller panicked")]
    ControllerPanicked,
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

/// One asynchronously running bounded scheduler-preemption adversary.
///
/// The controller owns no CPU burner. It delivers the fixed signal sequence on
/// one short-lived thread while the caller executes the workload being tested.
/// Dropping it publishes cancellation and synchronously joins the controller,
/// so early-return and error paths cannot leave QEMU stopped.
pub(crate) struct BoundedSchedulerPreemption {
    cancel: Arc<AtomicBool>,
    controller: Option<
        thread::JoinHandle<
            Result<BoundedSchedulerPreemptionReport, BoundedSchedulerPreemptionError>,
        >,
    >,
}

impl BoundedSchedulerPreemption {
    /// Starts the adversary only when the caller selected the hostile run.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the controller thread cannot be created.
    pub(crate) fn start_if(
        enabled: bool,
        pid: u32,
    ) -> Result<Option<Self>, BoundedSchedulerPreemptionError> {
        Self::start_with_policy(enabled, pid, DEFAULT_PREEMPTION_POLICY)
    }

    fn start_with_policy(
        enabled: bool,
        pid: u32,
        policy: PreemptionPolicy,
    ) -> Result<Option<Self>, BoundedSchedulerPreemptionError> {
        if !enabled {
            return Ok(None);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let controller_cancel = Arc::clone(&cancel);
        let controller = thread::Builder::new()
            .name(String::from("crucible-qemu-scheduler-preemption"))
            .spawn(move || {
                apply_bounded_scheduler_preemption_with_cancel(pid, &controller_cancel, policy)
            })
            .map_err(|source| BoundedSchedulerPreemptionError::ControllerSpawn { source })?;
        Ok(Some(Self {
            cancel,
            controller: Some(controller),
        }))
    }

    /// Joins the controller and returns evidence for every configured perturbation.
    ///
    /// # Errors
    ///
    /// Returns the controller's typed signaling/watchdog error, or reports that
    /// the controller panicked.
    pub(crate) fn finish(
        mut self,
    ) -> Result<BoundedSchedulerPreemptionReport, BoundedSchedulerPreemptionError> {
        let Some(controller) = self.controller.take() else {
            return Err(BoundedSchedulerPreemptionError::ControllerPanicked);
        };
        controller
            .join()
            .map_err(|_panic| BoundedSchedulerPreemptionError::ControllerPanicked)?
    }
}

impl Drop for BoundedSchedulerPreemption {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(controller) = self.controller.take() {
            let _ = controller.join();
        }
    }
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

fn apply_bounded_scheduler_preemption_with_cancel(
    pid: u32,
    cancel: &AtomicBool,
    policy: PreemptionPolicy,
) -> Result<BoundedSchedulerPreemptionReport, BoundedSchedulerPreemptionError> {
    let (finished_tx, finished_rx) = mpsc::channel();
    let timed_out = Arc::new(AtomicBool::new(false));
    let watchdog_timed_out = Arc::clone(&timed_out);
    let watchdog = thread::Builder::new()
        .name(String::from("crucible-qemu-resume-watchdog"))
        .spawn(
            move || match finished_rx.recv_timeout(policy.wall_timeout) {
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

    let mut perturbations = 0;
    let perturbation_result = (|| {
        for iteration in 0..policy.perturbations {
            if cancel.load(Ordering::Acquire) {
                break;
            }
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
            thread::sleep(policy.pause);
            resume.resume()?;
            perturbations += 1;
            if cancel.load(Ordering::Acquire) {
                break;
            }
            if timed_out.load(Ordering::Acquire) {
                return Err(BoundedSchedulerPreemptionError::WallTimeout);
            }
            if iteration + 1 < policy.perturbations {
                thread::sleep(policy.interval);
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
        perturbations,
        requested_stopped_milliseconds: u64::try_from(policy.pause.as_millis())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::from(policy.perturbations)),
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    use super::*;

    const TARGET_ENV: &str = "CRUCIBLE_BOUNDED_PREEMPTION_TARGET";
    const TARGET_READY_PATH_ENV: &str = "CRUCIBLE_BOUNDED_PREEMPTION_READY_PATH";
    static TARGET_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestTarget {
        child: Child,
        ready_path: PathBuf,
    }

    impl TestTarget {
        fn spawn() -> Result<Self, Box<dyn Error>> {
            let executable = std::env::current_exe()?;
            let sequence = TARGET_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let ready_path = std::env::temp_dir().join(format!(
                "crucible-bounded-preemption-{}-{sequence}.ready",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&ready_path);
            let mut child = Command::new(executable)
                .arg("--exact")
                .arg("bounded_scheduler_preemption::tests::preemption_target_process")
                .arg("--ignored")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env(TARGET_ENV, "1")
                .env(TARGET_READY_PATH_ENV, &ready_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;
            for attempt in 0..2_000 {
                if ready_path.is_file() {
                    break;
                }
                if child.try_wait()?.is_some() {
                    return Err("target exited before its readiness marker".into());
                }
                if attempt + 1 == 2_000 {
                    return Err("target did not publish its readiness marker".into());
                }
                thread::sleep(Duration::from_millis(1));
            }
            Ok(Self { child, ready_path })
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }

        fn is_running(&mut self) -> Result<bool, Box<dyn Error>> {
            Ok(self.child.try_wait()?.is_none())
        }
    }

    impl Drop for TestTarget {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_file(&self.ready_path);
        }
    }

    fn process_state(pid: u32) -> Result<Option<char>, Box<dyn Error>> {
        let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(status) => status,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(status
            .lines()
            .find_map(|line| line.strip_prefix("State:\t"))
            .and_then(|state| state.chars().next()))
    }

    fn wait_for_state(pid: u32, expected: char) -> Result<(), Box<dyn Error>> {
        for _ in 0..1_000 {
            if process_state(pid)? == Some(expected) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(1));
        }
        Err(format!("process {pid} never entered state {expected}").into())
    }

    #[test]
    #[ignore = "spawned as the hermetic signal target by the parent tests"]
    fn preemption_target_process() -> Result<(), Box<dyn Error>> {
        if std::env::var_os(TARGET_ENV).is_none() {
            return Ok(());
        }
        let ready_path = std::env::var_os(TARGET_READY_PATH_ENV)
            .ok_or("target readiness path was not supplied")?;
        std::fs::write(ready_path, b"ready\n")?;
        thread::sleep(Duration::from_secs(10));
        Ok(())
    }

    #[test]
    fn asynchronous_preemption_completes_while_target_runs() -> Result<(), Box<dyn Error>> {
        let mut target = TestTarget::spawn()?;
        let adversary = BoundedSchedulerPreemption::start_if(true, target.pid())?
            .ok_or("enabled adversary was not created")?;
        let report = adversary.finish()?;

        assert_eq!(report.perturbations, BOUNDED_PREEMPTION_COUNT);
        assert_eq!(report.requested_stopped_milliseconds, 90);
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn watchdog_expiry_directly_resumes_stopped_target() -> Result<(), Box<dyn Error>> {
        let mut target = TestTarget::spawn()?;
        let policy = PreemptionPolicy {
            perturbations: 1,
            pause: Duration::from_millis(250),
            interval: Duration::ZERO,
            wall_timeout: Duration::from_millis(20),
        };
        let error = apply_bounded_scheduler_preemption_with_cancel(
            target.pid(),
            &AtomicBool::new(false),
            policy,
        )
        .err()
        .ok_or("watchdog fixture unexpectedly succeeded")?;

        assert!(matches!(
            error,
            BoundedSchedulerPreemptionError::WallTimeout
        ));
        assert_ne!(process_state(target.pid())?, Some('T'));
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn dropping_controller_resumes_and_joins_stopped_target() -> Result<(), Box<dyn Error>> {
        let mut target = TestTarget::spawn()?;
        let policy = PreemptionPolicy {
            perturbations: 1,
            pause: Duration::from_millis(250),
            interval: Duration::ZERO,
            wall_timeout: Duration::from_secs(2),
        };
        let adversary = BoundedSchedulerPreemption::start_with_policy(true, target.pid(), policy)?
            .ok_or("enabled adversary was not created")?;
        wait_for_state(target.pid(), 'T')?;
        drop(adversary);

        assert_ne!(process_state(target.pid())?, Some('T'));
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn signal_failure_is_reported_and_joined() -> Result<(), Box<dyn Error>> {
        let adversary = BoundedSchedulerPreemption::start_if(true, u32::MAX)?
            .ok_or("enabled adversary was not created")?;
        let error = adversary
            .finish()
            .err()
            .ok_or("invalid target unexpectedly accepted signals")?;
        assert!(matches!(
            error,
            BoundedSchedulerPreemptionError::Signal { .. }
        ));
        Ok(())
    }

    #[test]
    fn disabled_adversary_spawns_no_controller() -> Result<(), Box<dyn Error>> {
        assert!(BoundedSchedulerPreemption::start_if(false, u32::MAX)?.is_none());
        Ok(())
    }
}
