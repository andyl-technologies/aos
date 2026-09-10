//! Process-signal cancellation for native ability activation.
//!
//! Native effect execution is synchronous, while `package_runtime` runs on the
//! multi-thread scheduler created by `#[tokio::main]`. This module installs
//! SIGINT and SIGTERM listeners on that runtime and translates the first signal
//! into the executor's shared [`CancellationToken`]. A second signal exits with
//! its conventional shell status (130 for SIGINT, 143 for SIGTERM) so a stalled
//! adapter cannot suppress termination.
//! The executor remains responsible for recording pending effect ownership
//! before returning after the first signal.

use std::io;

use aos_ability_runtime::adapter::CancellationToken;
use tokio::runtime::{Handle, RuntimeFlavor};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::task::JoinHandle;

const INTERRUPT_EXIT_CODE: i32 = 130;
const TERMINATE_EXIT_CODE: i32 = 143;

/// Keeps native activation signal listeners alive and exposes their token.
pub(super) struct NativeCancellationGuard {
    token: CancellationToken,
    watcher: JoinHandle<()>,
}

impl NativeCancellationGuard {
    /// Installs SIGINT and SIGTERM listeners on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error when called outside a Tokio runtime or when either
    /// process signal listener cannot be installed.
    pub(super) fn install() -> io::Result<Self> {
        let runtime = Handle::try_current().map_err(|error| {
            io::Error::other(format!(
                "native cancellation requires an active Tokio runtime: {error}"
            ))
        })?;
        if runtime.runtime_flavor() != RuntimeFlavor::MultiThread {
            return Err(io::Error::other(
                "native cancellation requires the package runtime's multi-thread Tokio scheduler",
            ));
        }
        let interrupt = signal(SignalKind::interrupt())?;
        let terminate = signal(SignalKind::terminate())?;
        let token = CancellationToken::default();
        let watcher = runtime.spawn(watch_signals(token.clone(), interrupt, terminate));

        Ok(Self { token, watcher })
    }

    /// Returns the token shared with native effect execution.
    pub(super) const fn token(&self) -> &CancellationToken {
        &self.token
    }
}

impl Drop for NativeCancellationGuard {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

async fn watch_signals(token: CancellationToken, mut interrupt: Signal, mut terminate: Signal) {
    let mut interrupt_open = true;
    let mut terminate_open = true;
    let mut cancellation_signal_received = false;

    while interrupt_open || terminate_open {
        tokio::select! {
            signal = interrupt.recv(), if interrupt_open => match signal {
                Some(()) => request_cancellation_or_exit(
                    &token,
                    &mut cancellation_signal_received,
                    INTERRUPT_EXIT_CODE,
                ),
                None => interrupt_open = false,
            },
            signal = terminate.recv(), if terminate_open => match signal {
                Some(()) => request_cancellation_or_exit(
                    &token,
                    &mut cancellation_signal_received,
                    TERMINATE_EXIT_CODE,
                ),
                None => terminate_open = false,
            },
        }
    }
}

fn request_cancellation_or_exit(
    token: &CancellationToken,
    signal_received: &mut bool,
    exit_code: i32,
) {
    if *signal_received {
        std::process::exit(exit_code);
    }

    *signal_received = true;
    token.cancel();
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use rustix::process::{Pid, Signal, kill_process};

    use super::NativeCancellationGuard;

    const PROBE_READY_ENV: &str = "AOS_NATIVE_CANCELLATION_PROBE_READY";
    const PROBE_CANCELLED_ENV: &str = "AOS_NATIVE_CANCELLATION_PROBE_CANCELLED";
    const PROBE_TEST: &str = "config_eval::native_cancellation::tests::signal_probe";
    const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn sigint_requests_native_cancellation() {
        run_signal_probe(Signal::INT);
    }

    #[test]
    fn sigterm_requests_native_cancellation() {
        run_signal_probe(Signal::TERM);
    }

    #[test]
    fn a_second_signal_forces_process_interruption() {
        run_escalation_probe(Signal::INT, super::INTERRUPT_EXIT_CODE);
        run_escalation_probe(Signal::TERM, super::TERMINATE_EXIT_CODE);
    }

    fn run_escalation_probe(signal: Signal, expected_exit_code: i32) {
        let probe_dir = tempfile::tempdir().expect("probe directory");
        let ready_path = probe_dir.path().join("ready");
        let cancelled_path = probe_dir.path().join("cancelled");
        let mut child = probe_command(&ready_path)
            .env(PROBE_CANCELLED_ENV, &cancelled_path)
            .spawn()
            .expect("spawn isolated escalation probe");

        wait_for_probe_readiness(&mut child, &ready_path);
        kill_process(Pid::from_child(&child), signal).expect("request cancellation");
        wait_for_probe_readiness(&mut child, &cancelled_path);
        assert!(
            child.try_wait().expect("poll cancelled probe").is_none(),
            "first signal terminated the cancellation probe"
        );

        kill_process(Pid::from_child(&child), signal).expect("escalate cancellation");
        let status = wait_for_probe_exit(&mut child);
        assert_eq!(status.code(), Some(expected_exit_code), "{status}");
    }

    #[test]
    fn signal_probe() {
        let Ok(ready_path) = env::var(PROBE_READY_ENV) else {
            return;
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("probe Tokio runtime");

        runtime.block_on(async {
            let cancellation =
                NativeCancellationGuard::install().expect("probe cancellation listeners");
            fs::write(ready_path, b"ready").expect("publish probe readiness");

            tokio::time::timeout(PROBE_TIMEOUT, async {
                while !cancellation.token().is_cancelled() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("process signal requests cancellation");

            if let Ok(cancelled_path) = env::var(PROBE_CANCELLED_ENV) {
                fs::write(cancelled_path, b"cancelled").expect("publish probe cancellation");
                std::future::pending::<()>().await;
            }
        });
    }

    fn run_signal_probe(signal: Signal) {
        let probe_dir = tempfile::tempdir().expect("probe directory");
        let ready_path = probe_dir.path().join("ready");
        let mut child = probe_command(&ready_path)
            .spawn()
            .expect("spawn isolated signal probe");

        wait_for_probe_readiness(&mut child, &ready_path);
        kill_process(Pid::from_child(&child), signal).expect("signal isolated probe");

        let status = wait_for_probe_exit(&mut child);
        assert!(status.success(), "isolated signal probe failed: {status}");
    }

    fn probe_command(ready_path: &std::path::Path) -> Command {
        let mut command = Command::new(env::current_exe().expect("current test executable"));
        command
            .args(["--exact", PROBE_TEST, "--nocapture"])
            .env(PROBE_READY_ENV, ready_path)
            .env_remove(PROBE_CANCELLED_ENV)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn wait_for_probe_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + PROBE_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait().expect("poll isolated probe") {
                return status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out signal probe");
                panic!("isolated signal probe did not exit");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_for_probe_readiness(child: &mut std::process::Child, ready_path: &std::path::Path) {
        let deadline = Instant::now() + PROBE_TIMEOUT;
        while !ready_path.is_file() {
            if let Some(status) = child.try_wait().expect("poll probe readiness") {
                panic!("isolated signal probe exited before readiness: {status}");
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill unready signal probe");
                panic!("isolated signal probe did not become ready");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
