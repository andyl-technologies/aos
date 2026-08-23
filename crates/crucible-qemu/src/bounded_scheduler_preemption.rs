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
    /// The workload-pending barrier was released more than once.
    #[error("bounded scheduler preemption was already released")]
    AlreadyStarted,
    /// The controller exited before the workload-pending barrier was released.
    #[error("bounded scheduler preemption controller exited before release")]
    ControllerExitedBeforeStart,
    /// The caller tried to finish without proving that work was pending.
    #[error("bounded scheduler preemption was never released over pending work")]
    NotStarted,
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
    start: Option<mpsc::Sender<()>>,
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
        let (start_tx, start_rx) = mpsc::channel();
        let controller = thread::Builder::new()
            .name(String::from("crucible-qemu-scheduler-preemption"))
            .spawn(move || {
                if start_rx.recv().is_err() {
                    return Err(BoundedSchedulerPreemptionError::ControllerExitedBeforeStart);
                }
                apply_bounded_scheduler_preemption_with_cancel(pid, &controller_cancel, policy)
            })
            .map_err(|source| BoundedSchedulerPreemptionError::ControllerSpawn { source })?;
        Ok(Some(Self {
            cancel,
            start: Some(start_tx),
            controller: Some(controller),
        }))
    }

    /// Releases the controller only after the caller has published real QEMU work.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the controller was already released or exited
    /// before accepting the workload-pending signal.
    pub(crate) fn begin(&mut self) -> Result<(), BoundedSchedulerPreemptionError> {
        let start = self
            .start
            .take()
            .ok_or(BoundedSchedulerPreemptionError::AlreadyStarted)?;
        start
            .send(())
            .map_err(|_error| BoundedSchedulerPreemptionError::ControllerExitedBeforeStart)
    }

    /// Releases the controller once and reports whether this call owned release.
    ///
    /// This supports multi-quantum workloads whose first published quantum is
    /// the synchronization point. Later quanta observe `false` without
    /// re-running or extending the finite adversary budget.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the controller exits before accepting the
    /// first workload-pending signal.
    pub(crate) fn begin_once(&mut self) -> Result<bool, BoundedSchedulerPreemptionError> {
        if self.start.is_none() {
            return Ok(false);
        }
        self.begin()?;
        Ok(true)
    }

    /// Releases an optional controller once work has been published.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the present controller exits before accepting
    /// its first workload-pending signal.
    pub(crate) fn begin_if_present(
        adversary: &mut Option<Self>,
    ) -> Result<bool, BoundedSchedulerPreemptionError> {
        adversary
            .as_mut()
            .map(Self::begin_once)
            .transpose()
            .map(|release| release.unwrap_or(false))
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
        if self.start.is_some() {
            return Err(BoundedSchedulerPreemptionError::NotStarted);
        }
        let Some(controller) = self.controller.take() else {
            return Err(BoundedSchedulerPreemptionError::ControllerPanicked);
        };
        controller
            .join()
            .map_err(|_panic| BoundedSchedulerPreemptionError::ControllerPanicked)?
    }

    /// Finishes an optional controller before the authenticated child is reaped.
    ///
    /// # Errors
    ///
    /// Returns the same typed failures as [`Self::finish`] for a present
    /// controller.
    pub(crate) fn finish_if_present(
        adversary: &mut Option<Self>,
    ) -> Result<Option<BoundedSchedulerPreemptionReport>, BoundedSchedulerPreemptionError> {
        adversary.take().map(Self::finish).transpose()
    }
}

impl Drop for BoundedSchedulerPreemption {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(start) = self.start.take() {
            let _ = start.send(());
        }
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
        let mut adversary = BoundedSchedulerPreemption::start_if(true, target.pid())?
            .ok_or("enabled adversary was not created")?;
        adversary.begin()?;
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
        let mut adversary =
            BoundedSchedulerPreemption::start_with_policy(true, target.pid(), policy)?
                .ok_or("enabled adversary was not created")?;
        adversary.begin()?;
        wait_for_state(target.pid(), 'T')?;
        drop(adversary);

        assert_ne!(process_state(target.pid())?, Some('T'));
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn signal_failure_is_reported_and_joined() -> Result<(), Box<dyn Error>> {
        let mut adversary = BoundedSchedulerPreemption::start_if(true, u32::MAX)?
            .ok_or("enabled adversary was not created")?;
        adversary.begin()?;
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

    #[test]
    fn controller_waits_for_pending_work_release() -> Result<(), Box<dyn Error>> {
        let mut target = TestTarget::spawn()?;
        let mut adversary = BoundedSchedulerPreemption::start_if(true, target.pid())?
            .ok_or("enabled adversary was not created")?;
        thread::sleep(Duration::from_millis(25));
        assert_ne!(process_state(target.pid())?, Some('T'));

        adversary.begin()?;
        let report = adversary.finish()?;
        assert_eq!(report.perturbations, BOUNDED_PREEMPTION_COUNT);
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn exited_target_fails_after_pending_work_release() -> Result<(), Box<dyn Error>> {
        let mut target = TestTarget::spawn()?;
        let mut adversary = BoundedSchedulerPreemption::start_if(true, target.pid())?
            .ok_or("enabled adversary was not created")?;
        target.child.kill()?;
        let _status = target.child.wait()?;

        adversary.begin()?;
        let error = adversary
            .finish()
            .err()
            .ok_or("exited target unexpectedly accepted scheduler preemption")?;
        assert!(matches!(
            error,
            BoundedSchedulerPreemptionError::Signal { .. }
        ));
        Ok(())
    }
}
