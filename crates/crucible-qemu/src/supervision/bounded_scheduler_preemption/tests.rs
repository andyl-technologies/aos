//! Real-process signal, startup-barrier, and resume-watchdog regressions.

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
    let ready_path =
        std::env::var_os(TARGET_READY_PATH_ENV).ok_or("target readiness path was not supplied")?;
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
    let mut adversary = BoundedSchedulerPreemption::start_with_policy(true, target.pid(), policy)?
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
fn prepared_watchdog_does_not_expire_during_guest_priming() -> Result<(), Box<dyn Error>> {
    let mut target = TestTarget::spawn()?;
    let mut adversary = BoundedSchedulerPreemption::start_if(true, target.pid())?
        .ok_or("enabled adversary was not created")?;

    // Readiness means the watchdog thread exists, not that its safety clock
    // has started. Real guest priming can outlast this entire interval.
    thread::sleep(BOUNDED_PREEMPTION_WALL_TIMEOUT + Duration::from_millis(25));
    assert_ne!(process_state(target.pid())?, Some('T'));
    adversary.observe_first_stop()?.confirm_pending(true)?;
    let report = adversary.finish()?;
    assert_eq!(report.perturbations, BOUNDED_PREEMPTION_COUNT);
    assert!(target.is_running()?);
    Ok(())
}

#[test]
fn dropping_prepared_controller_joins_without_stopping_target() -> Result<(), Box<dyn Error>> {
    let mut target = TestTarget::spawn()?;
    let adversary = BoundedSchedulerPreemption::start_if(true, target.pid())?
        .ok_or("enabled adversary was not created")?;
    drop(adversary);

    assert_ne!(process_state(target.pid())?, Some('T'));
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
fn completed_quantum_error_preserves_the_effective_boundary() {
    let completion = crate::QemuAsyncQuantumCompletion {
        ceiling: crucible::Icount { retired: 8_000_001 },
        outcome: crucible::AdvanceOutcome::Paused {
            at: crucible::Icount { retired: 4_000_001 },
        },
        final_state: crate::QemuNodeIdleState {
            current_icount: crucible::Icount { retired: 4_000_001 },
            next_deadline: None,
        },
        inbound_frames_consumed: 1,
        emitted_frames: Vec::new(),
        operations: Vec::new(),
    };

    let error = completed_quantum_at_first_stop(&completion);
    assert!(matches!(
        error,
        BoundedSchedulerPreemptionError::CompletedQuantumAtFirstStop {
            ceiling_icount: 8_000_001,
            current_icount: 4_000_001,
            inbound_frames_consumed: 1,
            emitted_frames: 0,
        }
    ));
    assert_eq!(
        error.to_string(),
        "bounded scheduler preemption first stop observed a completed quantum: ceiling=8000001, current=4000001, inbound_consumed=1, emitted_frames=0"
    );
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
