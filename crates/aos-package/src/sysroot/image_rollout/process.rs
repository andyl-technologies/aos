//! Bounded subprocess execution for disruptive rollout platform operations.
//!
//! Every helper runs in a fresh process group. The runner polls the live
//! ability attempt and recovery budgets, kills the complete group on timeout or
//! cancellation, and always reaps the direct child.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use aos_ability_runtime::adapter::RuntimeControl;

const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Runs one command within the caller's remaining checked runtime budget.
pub(super) fn run_bounded_command(
    command: &mut Command,
    control: &dyn RuntimeControl,
) -> Result<ExitStatus, io::Error> {
    let budget = control
        .attempt_remaining_millis()
        .min(control.recovery_remaining_millis());
    if control.is_cancelled() || budget == 0 {
        return Err(budget_exhausted(control));
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(budget))
        .ok_or_else(|| budget_exhausted(control))?;

    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let group = match child_process_group(&child) {
        Ok(group) => group,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let leader = match rustix::process::pidfd_open(group, rustix::process::PidfdFlags::empty()) {
        Ok(leader) => leader,
        Err(rustix::io::Errno::SRCH) => return finish_fast_exit(&mut child, group),
        Err(error) => {
            terminate_and_reap(&mut child, group);
            return Err(error.into());
        }
    };

    loop {
        if control.is_cancelled()
            || control.attempt_remaining_millis() == 0
            || control.recovery_remaining_millis() == 0
            || Instant::now() >= deadline
        {
            terminate_and_reap(&mut child, group);
            return Err(budget_exhausted(control));
        }
        if observe_child_exit(&leader)?.is_some() {
            // Keep the pidfd-observed leader waitable so its process-group ID
            // cannot be reused before all inherited descendants are removed.
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            return child.wait();
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn finish_fast_exit(
    child: &mut Child,
    group: rustix::process::Pid,
) -> Result<ExitStatus, io::Error> {
    // The leader remains waitable, which keeps its PID and process-group ID
    // from reuse while inherited descendants are terminated. Waiting then
    // preserves the leader's original success or failure status.
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    child.wait()
}

fn observe_child_exit(leader: &OwnedFd) -> Result<Option<()>, io::Error> {
    rustix::process::waitid(
        rustix::process::WaitId::PidFd(leader.as_fd()),
        rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOWAIT,
    )
    .map(|status| status.map(|_| ()))
    .map_err(io::Error::from)
}

fn child_process_group(child: &Child) -> Result<rustix::process::Pid, io::Error> {
    i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| io::Error::other("rollout helper has no valid process group"))
}

fn terminate_and_reap(child: &mut Child, group: rustix::process::Pid) {
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

fn budget_exhausted(control: &dyn RuntimeControl) -> io::Error {
    let (kind, message) = if control.is_cancelled() {
        (io::ErrorKind::Interrupted, "rollout helper was cancelled")
    } else {
        (
            io::ErrorKind::TimedOut,
            "rollout helper exhausted its runtime budget",
        )
    };
    io::Error::new(kind, message)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Instant;

    use super::*;

    const HELPER_TEST: &str = "sysroot::image_rollout::process::tests::rollout_process_helper";

    struct TimedControl {
        started: Instant,
        cancel_after: Option<Duration>,
        budget_millis: u64,
    }

    impl TimedControl {
        fn timeout(budget_millis: u64) -> Self {
            Self {
                started: Instant::now(),
                cancel_after: None,
                budget_millis,
            }
        }

        fn cancellation(after_millis: u64, budget_millis: u64) -> Self {
            Self {
                started: Instant::now(),
                cancel_after: Some(Duration::from_millis(after_millis)),
                budget_millis,
            }
        }
    }

    impl RuntimeControl for TimedControl {
        fn is_cancelled(&self) -> bool {
            self.cancel_after
                .is_some_and(|after| self.started.elapsed() >= after)
        }

        fn elapsed_millis(&self) -> u64 {
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
        }

        fn attempt_remaining_millis(&self) -> u64 {
            self.budget_millis.saturating_sub(self.elapsed_millis())
        }

        fn recovery_remaining_millis(&self) -> u64 {
            self.attempt_remaining_millis()
        }
    }

    #[test]
    fn timeout_kills_and_reaps_the_helper() {
        assert_interrupted_helper(TimedControl::timeout(100), io::ErrorKind::TimedOut);
    }

    #[test]
    fn cancellation_kills_and_reaps_the_helper() {
        assert_interrupted_helper(
            TimedControl::cancellation(100, 2_000),
            io::ErrorKind::Interrupted,
        );
    }

    #[test]
    fn fast_success_preserves_the_command_status() {
        let mut command = fast_helper_command(0);
        let status = run_bounded_command(&mut command, &TimedControl::timeout(2_000))
            .expect("fast helper completes");
        assert!(status.success());
    }

    #[test]
    fn fast_failure_preserves_the_command_status() {
        let mut command = fast_helper_command(23);
        let status = run_bounded_command(&mut command, &TimedControl::timeout(2_000))
            .expect("fast helper completes");
        assert_eq!(status.code(), Some(23));
    }

    #[test]
    fn rollout_process_helper() {
        if let Some(code) = std::env::var_os("AOS_ROLLOUT_HELPER_EXIT") {
            let code = code
                .to_string_lossy()
                .parse()
                .expect("helper exit status is numeric");
            std::process::exit(code);
        }
        let Some(path) = std::env::var_os("AOS_ROLLOUT_HELPER_PID") else {
            return;
        };
        std::fs::write(path, std::process::id().to_string()).expect("record helper PID");
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn assert_interrupted_helper(control: TimedControl, expected: io::ErrorKind) {
        let directory = tempfile::TempDir::new().expect("temporary process fixture");
        let pid_path = directory.path().join("pid");
        let mut command = helper_command(&pid_path);

        let error = run_bounded_command(&mut command, &control).expect_err("helper must stop");
        assert_eq!(error.kind(), expected);

        let pid: i32 = std::fs::read_to_string(&pid_path)
            .expect("helper wrote its PID")
            .parse()
            .expect("helper PID is numeric");
        let process = rustix::process::Pid::from_raw(pid).expect("positive helper PID");
        assert_eq!(
            rustix::process::test_kill_process(process)
                .unwrap_err()
                .raw_os_error(),
            libc::ESRCH
        );
    }

    fn helper_command(pid_path: &PathBuf) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable exists"));
        command
            .args(["--exact", HELPER_TEST, "--nocapture"])
            .env("AOS_ROLLOUT_HELPER_PID", pid_path);
        command
    }

    fn fast_helper_command(code: i32) -> Command {
        let executable = std::env::current_exe().expect("test executable exists");
        let mut command = Command::new(executable);
        command
            .args(["--exact", HELPER_TEST, "--nocapture"])
            .env("AOS_ROLLOUT_HELPER_EXIT", code.to_string());
        command
    }
}
