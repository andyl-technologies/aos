//! Resource-bounded host-scheduling adversary for live QEMU gates.
//!
//! Deterministic guest execution must not depend on uninterrupted host CPU
//! scheduling. This module perturbs the actual authenticated QEMU child with a
//! fixed sequence of `SIGSTOP`/`SIGCONT` pairs. It creates no CPU load: six
//! requested 15 ms pauses, separated by 1 ms sleeps, are the complete resource
//! budget. An independent watchdog resumes QEMU after two wall-clock seconds
//! if the controller is descheduled during a stopped interval.

use std::os::fd::AsFd;
use std::sync::mpsc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{
    Pid, PidfdFlags, Signal, WaitId, WaitIdOptions, pidfd_open, pidfd_send_signal, waitid,
};
use thiserror::Error;

use crate::async_driver::QemuAsyncNodeStepTarget;
use crate::{
    QemuMappedQuantumShmemHotPath, QemuNodeChannelError, QemuNodePendingQuantum,
    QemuShmemHotPathChannel,
};

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
    /// The target process ID could not be represented by the kernel PID API.
    #[error("bounded scheduler preemption received invalid QEMU pid {pid}")]
    InvalidPid {
        /// Rejected numeric process identifier.
        pid: u32,
    },
    /// A stable kernel process handle could not be opened.
    #[error("bounded scheduler preemption could not open a QEMU pidfd")]
    PidfdOpen {
        /// Kernel pidfd failure.
        #[source]
        source: rustix::io::Errno,
    },
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
    /// QEMU completed the published quantum before the first stop was observed.
    #[error("bounded scheduler preemption first stop did not overlap pending QEMU work")]
    QuantumCompletedBeforeFirstStop,
    /// The controller did not publish its first-stop observation in time.
    #[error("bounded scheduler preemption did not observe its first stop before timeout")]
    FirstStopObservationTimeout,
    /// The first-stop observation owner disappeared without releasing QEMU.
    #[error("bounded scheduler preemption first-stop observation was not released")]
    FirstStopObservationAbandoned,
    /// Inspecting the stopped shared-memory quantum failed non-retryably.
    #[error("bounded scheduler preemption could not inspect the stopped QEMU quantum")]
    QuantumInspection {
        /// Typed shared-memory channel failure.
        #[source]
        source: QemuNodeChannelError,
    },
    /// A signal could not be delivered through the authenticated QEMU pidfd.
    #[error("bounded scheduler preemption could not signal the authenticated QEMU process")]
    PidfdSignal {
        /// Typed kernel pidfd signaling failure.
        #[source]
        source: rustix::io::Errno,
    },
    /// The kernel could not observe the authenticated process's stop state.
    #[error("bounded scheduler preemption could not observe the QEMU stop state")]
    StopObservation {
        /// Typed kernel wait failure.
        #[source]
        source: rustix::io::Errno,
    },
    /// QEMU exited before the requested stop became observable.
    #[error("bounded scheduler preemption target exited before entering the stopped state")]
    TargetExitedBeforeStop,
    /// The stop notification disappeared while QEMU remained held stopped.
    #[error("bounded scheduler preemption lost the observed QEMU stop notification")]
    StopObservationLost,
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
    first_stop: Option<mpsc::Receiver<()>>,
    release_first_stop: Option<mpsc::Sender<()>>,
    wall_timeout: Duration,
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
        let raw_pid = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or(BoundedSchedulerPreemptionError::InvalidPid { pid })?;
        let pidfd = Arc::new(
            pidfd_open(raw_pid, PidfdFlags::empty())
                .map_err(|source| BoundedSchedulerPreemptionError::PidfdOpen { source })?,
        );
        let cancel = Arc::new(AtomicBool::new(false));
        let controller_cancel = Arc::clone(&cancel);
        let (start_tx, start_rx) = mpsc::channel();
        let (first_stop_tx, first_stop_rx) = mpsc::channel();
        let (release_first_stop_tx, release_first_stop_rx) = mpsc::channel();
        let controller = thread::Builder::new()
            .name(String::from("crucible-qemu-scheduler-preemption"))
            .spawn(move || {
                if start_rx.recv().is_err() {
                    return Err(BoundedSchedulerPreemptionError::ControllerExitedBeforeStart);
                }
                apply_bounded_scheduler_preemption_with_cancel(
                    pidfd,
                    &controller_cancel,
                    policy,
                    first_stop_tx,
                    release_first_stop_rx,
                )
            })
            .map_err(|source| BoundedSchedulerPreemptionError::ControllerSpawn { source })?;
        Ok(Some(Self {
            cancel,
            start: Some(start_tx),
            first_stop: Some(first_stop_rx),
            release_first_stop: Some(release_first_stop_tx),
            wall_timeout: policy.wall_timeout,
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

    /// Releases an optional controller and waits for its first authenticated stop.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the present controller exits before accepting
    /// its first workload-pending signal or publishing the first stop.
    pub(crate) fn observe_first_stop_if_present(
        adversary: &mut Option<Self>,
    ) -> Result<Option<PendingQuantumStopObservation>, BoundedSchedulerPreemptionError> {
        let Some(adversary) = adversary.as_mut() else {
            return Ok(None);
        };
        if adversary.start.is_none() {
            return Ok(None);
        }
        adversary.observe_first_stop().map(Some)
    }

    /// Certifies that the first pidfd stop overlapped a mapped pending quantum.
    ///
    /// # Errors
    ///
    /// Returns a typed preemption or shared-memory inspection error, and rejects
    /// a quantum that completed before the first stop was observed.
    pub(crate) fn certify_mapped_quantum_pending(
        adversary: &mut Option<Self>,
        hot_path: &mut QemuMappedQuantumShmemHotPath,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<bool, BoundedSchedulerPreemptionError> {
        let Some(observation) = Self::observe_first_stop_if_present(adversary)? else {
            return Ok(false);
        };
        let pending_at_stop = match QemuShmemHotPathChannel::poll_quantum(hot_path, pending) {
            Err(source) if source.retryable => true,
            Ok(_completion) => false,
            Err(source) => {
                return Err(BoundedSchedulerPreemptionError::QuantumInspection { source });
            }
        };
        observation.confirm_pending(pending_at_stop)?;
        Ok(true)
    }

    /// Certifies the first pidfd stop through an async-driver quantum target.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::certify_mapped_quantum_pending`].
    pub(crate) fn certify_async_quantum_pending<T>(
        adversary: &mut Option<Self>,
        target: &mut T,
        pending: &mut T::PendingQuantum,
    ) -> Result<bool, BoundedSchedulerPreemptionError>
    where
        T: QemuAsyncNodeStepTarget + ?Sized,
    {
        let Some(observation) = Self::observe_first_stop_if_present(adversary)? else {
            return Ok(false);
        };
        let pending_at_stop = match target.finish_quantum(pending) {
            Err(source) if source.retryable => true,
            Ok(_completion) => false,
            Err(source) => {
                return Err(BoundedSchedulerPreemptionError::QuantumInspection { source });
            }
        };
        observation.confirm_pending(pending_at_stop)?;
        Ok(true)
    }

    fn observe_first_stop(
        &mut self,
    ) -> Result<PendingQuantumStopObservation, BoundedSchedulerPreemptionError> {
        self.begin()?;
        let first_stop = self
            .first_stop
            .take()
            .ok_or(BoundedSchedulerPreemptionError::ControllerExitedBeforeStart)?;
        first_stop
            .recv_timeout(self.wall_timeout)
            .map_err(|_error| BoundedSchedulerPreemptionError::FirstStopObservationTimeout)?;
        let release = self
            .release_first_stop
            .take()
            .ok_or(BoundedSchedulerPreemptionError::ControllerExitedBeforeStart)?;
        Ok(PendingQuantumStopObservation {
            release: Some(release),
        })
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

/// Ownership of QEMU's first stopped interval while a quantum is inspected.
///
/// Dropping the observation releases the controller, so an inspection error
/// cannot strand QEMU stopped. Certification succeeds only when the caller
/// explicitly confirms that its published quantum remained incomplete.
pub(crate) struct PendingQuantumStopObservation {
    release: Option<mpsc::Sender<()>>,
}

impl PendingQuantumStopObservation {
    /// Records whether the first stop overlapped an incomplete quantum.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedSchedulerPreemptionError::QuantumCompletedBeforeFirstStop`]
    /// when QEMU had already completed the published work before inspection.
    pub(crate) fn confirm_pending(
        mut self,
        pending: bool,
    ) -> Result<(), BoundedSchedulerPreemptionError> {
        self.release();
        if pending {
            Ok(())
        } else {
            Err(BoundedSchedulerPreemptionError::QuantumCompletedBeforeFirstStop)
        }
    }

    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for PendingQuantumStopObservation {
    fn drop(&mut self) {
        self.release();
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
    pidfd: Arc<std::os::fd::OwnedFd>,
    armed: bool,
}

impl ResumeGuard {
    fn new(pidfd: Arc<std::os::fd::OwnedFd>) -> Self {
        Self { pidfd, armed: true }
    }

    fn resume(&mut self) -> Result<(), BoundedSchedulerPreemptionError> {
        signal_pidfd(&self.pidfd, Signal::CONT)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for ResumeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = signal_pidfd(&self.pidfd, Signal::CONT);
        }
    }
}

fn signal_pidfd(
    pidfd: &std::os::fd::OwnedFd,
    signal: Signal,
) -> Result<(), BoundedSchedulerPreemptionError> {
    pidfd_send_signal(pidfd, signal)
        .map_err(|source| BoundedSchedulerPreemptionError::PidfdSignal { source })
}

/// Waits until the kernel reports that the exact pidfd target entered a
/// process-wide job-control stop.
///
/// The first wait leaves the state change waitable so an exit is never reaped
/// by the adversary. Once a stop is proven, the second nonblocking wait consumes
/// only that stop notification; QEMU remains held until the paired `SIGCONT`.
fn observe_pidfd_stopped(
    pidfd: &std::os::fd::OwnedFd,
    cancel: &AtomicBool,
    timed_out: &AtomicBool,
) -> Result<(), BoundedSchedulerPreemptionError> {
    let status = loop {
        if cancel.load(Ordering::Acquire) {
            return Err(BoundedSchedulerPreemptionError::FirstStopObservationAbandoned);
        }
        if timed_out.load(Ordering::Acquire) {
            return Err(BoundedSchedulerPreemptionError::WallTimeout);
        }
        if let Some(status) = waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitIdOptions::STOPPED
                | WaitIdOptions::EXITED
                | WaitIdOptions::NOWAIT
                | WaitIdOptions::NOHANG,
        )
        .map_err(|source| BoundedSchedulerPreemptionError::StopObservation { source })?
        {
            break status;
        }
        thread::sleep(BOUNDED_PREEMPTION_INTERVAL);
    };
    if !status.stopped() {
        return Err(BoundedSchedulerPreemptionError::TargetExitedBeforeStop);
    }

    let consumed = waitid(
        WaitId::PidFd(pidfd.as_fd()),
        WaitIdOptions::STOPPED | WaitIdOptions::NOHANG,
    )
    .map_err(|source| BoundedSchedulerPreemptionError::StopObservation { source })?;
    if !consumed.is_some_and(|status| status.stopped()) {
        return Err(BoundedSchedulerPreemptionError::StopObservationLost);
    }
    Ok(())
}

// crucible-lint: allow clippy-disallowed-method -- wall time bounds only this noncanonical test adversary.
#[allow(clippy::disallowed_methods)]
fn apply_bounded_scheduler_preemption_with_cancel(
    pidfd: Arc<std::os::fd::OwnedFd>,
    cancel: &AtomicBool,
    policy: PreemptionPolicy,
    first_stop: mpsc::Sender<()>,
    release_first_stop: mpsc::Receiver<()>,
) -> Result<BoundedSchedulerPreemptionReport, BoundedSchedulerPreemptionError> {
    let (finished_tx, finished_rx) = mpsc::channel();
    let timed_out = Arc::new(AtomicBool::new(false));
    let watchdog_timed_out = Arc::clone(&timed_out);
    let watchdog_pidfd = Arc::clone(&pidfd);
    let watchdog = thread::Builder::new()
        .name(String::from("crucible-qemu-resume-watchdog"))
        .spawn(move || {
            resume_on_watchdog_expiry(
                &watchdog_pidfd,
                &watchdog_timed_out,
                finished_rx,
                policy.wall_timeout,
            )
        })
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
            let mut resume = ResumeGuard::new(Arc::clone(&pidfd));
            signal_pidfd(&pidfd, Signal::STOP)?;
            observe_pidfd_stopped(&pidfd, cancel, &timed_out)?;
            let stopped_at = Instant::now();
            if timed_out.load(Ordering::Acquire) {
                return Err(BoundedSchedulerPreemptionError::WallTimeout);
            }
            if iteration == 0 {
                first_stop.send(()).map_err(|_error| {
                    BoundedSchedulerPreemptionError::FirstStopObservationAbandoned
                })?;
                match release_first_stop.recv_timeout(policy.wall_timeout) {
                    Ok(()) => {}
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        return Err(BoundedSchedulerPreemptionError::WallTimeout);
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(BoundedSchedulerPreemptionError::FirstStopObservationAbandoned);
                    }
                }
            }
            if let Some(remaining) = policy.pause.checked_sub(stopped_at.elapsed()) {
                thread::sleep(remaining);
            }
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
        .map_err(|_panic| BoundedSchedulerPreemptionError::WatchdogPanicked)??;
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

/// Resumes the exact child directly, without waiting for the controller to run.
fn resume_on_watchdog_expiry(
    pidfd: &std::os::fd::OwnedFd,
    timed_out: &AtomicBool,
    finished: mpsc::Receiver<()>,
    timeout: Duration,
) -> Result<bool, BoundedSchedulerPreemptionError> {
    match finished.recv_timeout(timeout) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(false),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            timed_out.store(true, Ordering::Release);
            signal_pidfd(pidfd, Signal::CONT).map(|()| true)
        }
    }
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
                .arg("supervision::bounded_scheduler_preemption::tests::preemption_target_process")
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
        let observation = adversary.observe_first_stop()?;
        assert_eq!(process_state(target.pid())?, Some('T'));
        observation.confirm_pending(true)?;
        let report = adversary.finish()?;

        assert_eq!(report.perturbations, BOUNDED_PREEMPTION_COUNT);
        assert_eq!(report.requested_stopped_milliseconds, 90);
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn watchdog_expiry_directly_resumes_stopped_target() -> Result<(), Box<dyn Error>> {
        let mut target = TestTarget::spawn()?;
        let pid = Pid::from_raw(i32::try_from(target.pid())?).ok_or("invalid target PID")?;
        let pidfd = Arc::new(pidfd_open(pid, PidfdFlags::empty())?);
        let _resume = ResumeGuard::new(Arc::clone(&pidfd));
        signal_pidfd(&pidfd, Signal::STOP)?;
        wait_for_state(target.pid(), 'T')?;

        // Establish the kernel stop before expiring the real watchdog wait.
        // A short timeout racing controller thread startup tested host load,
        // not the watchdog's ability to resume a stalled controller's child.
        let (_finished, pending) = mpsc::channel();
        let timed_out = AtomicBool::new(false);
        assert!(resume_on_watchdog_expiry(
            &pidfd,
            &timed_out,
            pending,
            Duration::ZERO,
        )?);
        assert!(timed_out.load(Ordering::Acquire));
        assert_ne!(process_state(target.pid())?, Some('T'));
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn completed_controller_disarms_watchdog_before_expiry() -> Result<(), Box<dyn Error>> {
        let target = TestTarget::spawn()?;
        let pid = Pid::from_raw(i32::try_from(target.pid())?).ok_or("invalid target PID")?;
        let pidfd = Arc::new(pidfd_open(pid, PidfdFlags::empty())?);
        let _resume = ResumeGuard::new(Arc::clone(&pidfd));
        signal_pidfd(&pidfd, Signal::STOP)?;
        wait_for_state(target.pid(), 'T')?;

        let (finished, pending) = mpsc::channel();
        finished.send(())?;
        let timed_out = AtomicBool::new(false);
        assert!(!resume_on_watchdog_expiry(
            &pidfd,
            &timed_out,
            pending,
            Duration::ZERO,
        )?);
        assert!(!timed_out.load(Ordering::Acquire));
        assert_eq!(process_state(target.pid())?, Some('T'));
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
        let observation = adversary.observe_first_stop()?;
        wait_for_state(target.pid(), 'T')?;
        drop(observation);
        drop(adversary);

        assert_ne!(process_state(target.pid())?, Some('T'));
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn signal_failure_is_reported_and_joined() -> Result<(), Box<dyn Error>> {
        let error = BoundedSchedulerPreemption::start_if(true, u32::MAX)
            .err()
            .ok_or("invalid target unexpectedly opened a pidfd")?;
        assert!(matches!(
            error,
            BoundedSchedulerPreemptionError::InvalidPid { .. }
        ));
        Ok(())
    }

    #[test]
    fn stop_observation_honors_timeout_without_a_state_change() -> Result<(), Box<dyn Error>> {
        let target = TestTarget::spawn()?;
        let raw_pid = i32::try_from(target.pid())
            .ok()
            .and_then(Pid::from_raw)
            .ok_or("test target PID was not representable")?;
        let pidfd = pidfd_open(raw_pid, PidfdFlags::empty())?;
        let cancel = AtomicBool::new(false);
        let timed_out = Arc::new(AtomicBool::new(false));
        let watchdog_timed_out = Arc::clone(&timed_out);
        let watchdog = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            watchdog_timed_out.store(true, Ordering::Release);
        });

        let error = observe_pidfd_stopped(&pidfd, &cancel, &timed_out)
            .err()
            .ok_or("stop observation ignored an active timeout")?;
        watchdog
            .join()
            .map_err(|_panic| "test timeout publisher panicked")?;

        assert!(matches!(
            error,
            BoundedSchedulerPreemptionError::WallTimeout
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

        adversary.observe_first_stop()?.confirm_pending(true)?;
        let report = adversary.finish()?;
        assert_eq!(report.perturbations, BOUNDED_PREEMPTION_COUNT);
        assert!(target.is_running()?);
        Ok(())
    }

    #[test]
    fn first_stop_rejects_an_already_completed_quantum() -> Result<(), Box<dyn Error>> {
        let mut target = TestTarget::spawn()?;
        let mut adversary = BoundedSchedulerPreemption::start_if(true, target.pid())?
            .ok_or("enabled adversary was not created")?;
        let observation = adversary.observe_first_stop()?;
        wait_for_state(target.pid(), 'T')?;
        let error = observation
            .confirm_pending(false)
            .err()
            .ok_or("completed quantum unexpectedly certified overlap")?;
        assert!(matches!(
            error,
            BoundedSchedulerPreemptionError::QuantumCompletedBeforeFirstStop
        ));
        let _report = adversary.finish()?;
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

        let error = adversary
            .observe_first_stop()
            .err()
            .ok_or("exited target unexpectedly accepted scheduler preemption")?;
        assert!(matches!(
            error,
            BoundedSchedulerPreemptionError::FirstStopObservationTimeout
        ));
        Ok(())
    }
}
