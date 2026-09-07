//! Bounded execution of one fixed executable in a fresh process group.
//!
//! This primitive supplies exact `posix_spawn(3)` argv, an empty environment,
//! `/dev/null` standard input, descriptor closure above standard error,
//! concurrent bounded output capture, and one monotonic deadline. The fresh
//! process group makes prompt cooperative cleanup possible, but is not a
//! process-tree containment boundary: callers that require that guarantee must
//! run the entire caller and child lifetime in a separately enforced cgroup.

use std::ffi::{CString, OsString};
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};
use std::time::Duration;

use crate::pidfd::PidFd;
use crate::uapi;
use crate::{Error, Result};

const MAXIMUM_EXECUTABLE_BYTES: usize = 4096;
const MAXIMUM_ARGUMENTS: usize = 64;
const MAXIMUM_ARGUMENT_BYTES: usize = 64 * 1024;
const DUPLICATE_FD_MINIMUM: libc::c_int = 64;

/// Configures one exact, bounded child invocation.
#[derive(Clone, Copy, Debug)]
pub struct FixedProcessRequest<'a> {
    /// Absolute executable path used without `PATH` lookup.
    pub executable: &'a Path,
    /// Exact argument sequence after `argv[0]`.
    pub arguments: &'a [OsString],
    /// Monotonic budget before cancellation begins while awaiting exit and output closure.
    pub timeout: Duration,
    /// Maximum captured standard-output bytes.
    pub maximum_stdout_bytes: usize,
    /// Maximum captured standard-error bytes.
    pub maximum_stderr_bytes: usize,
}

/// Reports the normally completed fixed child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedProcessOutput {
    /// Normal exit code, or `None` when a signal terminated the leader.
    pub exit_code: Option<i32>,
    /// Terminating signal, or `None` after a normal exit.
    pub signal: Option<i32>,
    /// Complete bounded standard output.
    pub stdout: Vec<u8>,
    /// Complete bounded standard error.
    pub stderr: Vec<u8>,
}

/// Classifies completion or fail-stop cancellation of a fixed invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixedProcessOutcome {
    /// The leader exited and both output streams reached end-of-file in time.
    Completed(FixedProcessOutput),
    /// The budget elapsed; the process group was killed and the leader was reaped.
    TimedOut,
    /// A stream crossed its configured byte ceiling; the group was killed.
    OutputLimitExceeded,
}

/// Runs one executable with a closed environment and bounded output.
///
/// The child is placed in a new process group before `execve`. Cancellation
/// signals that group and reaps its leader. A process can leave a process group,
/// so a privileged caller must additionally provide cgroup containment when
/// descendants must remain bounded after caller failure.
///
/// The calling process must have exactly one thread and retain the default
/// `SIGCHLD` disposition without `SA_NOCLDWAIT`. The function checks both
/// conditions before spawning. Exclusive reaping keeps the unreaped leader's
/// numeric PID and process-group ID unavailable for reuse throughout cleanup.
/// Cancellation starts when the monotonic budget expires, but a subsequent
/// blocking reap can finish later if the kernel has not made the leader
/// waitable yet. Callers must not treat the budget as a strict whole-call
/// wall-clock bound.
///
/// # Errors
///
/// Returns an error unless the caller exclusively owns child reaping as an
/// exactly single-threaded process with default `SIGCHLD` behavior. Also
/// returns an error for invalid path/argv/limits, pipe or descriptor setup,
/// `posix_spawn` (including its preserved `execve` errno), output I/O, signal,
/// or wait failures.
pub fn run_fixed_process(request: FixedProcessRequest<'_>) -> Result<FixedProcessOutcome> {
    validate_exclusive_reaping_owner()?;
    run_fixed_process_owned(request)
}

fn run_fixed_process_owned(request: FixedProcessRequest<'_>) -> Result<FixedProcessOutcome> {
    let invocation = PreparedInvocation::new(request)?;
    let spawned = invocation.spawn()?;
    supervise(spawned, request)
}

fn validate_exclusive_reaping_owner() -> Result<()> {
    uapi::validate_child_reaping_disposition()?;

    let mut tasks = std::fs::read_dir("/proc/self/task").map_err(|source| Error::Syscall {
        operation: "open process task directory",
        source,
    })?;
    let first = tasks.next().transpose().map_err(|source| Error::Syscall {
        operation: "read process task directory",
        source,
    })?;
    let second = tasks.next().transpose().map_err(|source| Error::Syscall {
        operation: "read process task directory",
        source,
    })?;
    if first.is_none() || second.is_some() {
        return Err(Error::invalid(
            "fixed process reaping ownership",
            "requires an exactly single-threaded calling process",
        ));
    }
    Ok(())
}

struct PreparedInvocation {
    executable: CString,
    arguments: Vec<CString>,
}

impl PreparedInvocation {
    fn new(request: FixedProcessRequest<'_>) -> Result<Self> {
        validate_request(request)?;
        let executable = CString::new(request.executable.as_os_str().as_bytes())
            .map_err(|_| Error::invalid("fixed process executable", "must not contain NUL"))?;
        let arguments = request
            .arguments
            .iter()
            .map(|argument| {
                CString::new(argument.as_os_str().as_bytes())
                    .map_err(|_| Error::invalid("fixed process argument", "must not contain NUL"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            executable,
            arguments,
        })
    }

    fn spawn(&self) -> Result<SpawnedProcess> {
        let null = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| kernel_error("open(/dev/null)", error))?;
        let (stdout_read, stdout_write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
            .map_err(|error| kernel_error("pipe(fixed stdout)", error))?;
        let (stderr_read, stderr_write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
            .map_err(|error| kernel_error("pipe(fixed stderr)", error))?;
        let null = duplicate_high(null)?;
        let stdout_write = duplicate_high(stdout_write)?;
        let stderr_write = duplicate_high(stderr_write)?;

        let pid = uapi::posix_spawn_fixed(
            &self.executable,
            &self.arguments,
            null.as_fd(),
            stdout_write.as_fd(),
            stderr_write.as_fd(),
        )?;
        // Own cancellation immediately: pidfd and output setup can still fail.
        let mut guard = ChildGuard::new(pid);

        drop(null);
        drop(stdout_write);
        drop(stderr_write);
        let raw_pid = u32::try_from(pid.as_raw_nonzero().get())
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| Error::invalid("fixed process PID", "must be a positive u32"))?;
        let pidfd = PidFd::open(raw_pid)?;
        guard.attach_pidfd(pidfd);
        Ok(SpawnedProcess {
            guard,
            stdout: stdout_read,
            stderr: stderr_read,
        })
    }
}

struct SpawnedProcess {
    guard: ChildGuard,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

struct OutputStream {
    descriptor: OwnedFd,
    bytes: Vec<u8>,
    maximum: usize,
    closed: bool,
}

impl OutputStream {
    fn new(descriptor: OwnedFd, maximum: usize) -> Result<Self> {
        set_nonblocking(&descriptor)?;
        Ok(Self {
            descriptor,
            bytes: Vec::with_capacity(maximum.min(8192)),
            maximum,
            closed: false,
        })
    }

    fn drain(&mut self) -> Result<bool> {
        let mut chunk = [0_u8; 8192];
        loop {
            match rustix::io::read(&self.descriptor, &mut chunk) {
                Ok(0) => {
                    self.closed = true;
                    return Ok(false);
                }
                Ok(count) => {
                    let exceeds = self
                        .bytes
                        .len()
                        .checked_add(count)
                        .is_none_or(|length| length > self.maximum);
                    if exceeds {
                        return Ok(true);
                    }
                    self.bytes.extend_from_slice(&chunk[..count]);
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::AGAIN) => return Ok(false),
                Err(error) => return Err(kernel_error("read fixed process output", error)),
            }
        }
    }
}

fn supervise(
    spawned: SpawnedProcess,
    request: FixedProcessRequest<'_>,
) -> Result<FixedProcessOutcome> {
    let started = monotonic_now();
    let mut guard = spawned.guard;
    let mut stdout = OutputStream::new(spawned.stdout, request.maximum_stdout_bytes)?;
    let mut stderr = OutputStream::new(spawned.stderr, request.maximum_stderr_bytes)?;
    let mut leader_exited = false;

    loop {
        if leader_exited && stdout.closed && stderr.closed {
            // The unreaped leader pins the process-group ID while any residual
            // same-group descendants are killed before ownership is released.
            let status = guard.cancel_and_reap()?;
            return Ok(FixedProcessOutcome::Completed(FixedProcessOutput {
                exit_code: status.exit_code,
                signal: status.signal,
                stdout: stdout.bytes,
                stderr: stderr.bytes,
            }));
        }

        let elapsed = monotonic_now().saturating_sub(started);
        let Some(remaining) = request.timeout.checked_sub(elapsed) else {
            guard.cancel_and_reap()?;
            return Ok(FixedProcessOutcome::TimedOut);
        };
        let timeout = rustix::event::Timespec::try_from(remaining)
            .map_err(|_| Error::invalid("fixed process timeout", "does not fit timespec"))?;
        let leader_ready = {
            let pidfd = guard.pidfd()?.as_fd();
            let stdout_fd = stdout.descriptor.as_fd();
            let stderr_fd = stderr.descriptor.as_fd();
            let mut descriptors = Vec::with_capacity(3);
            let leader_index = (!leader_exited).then(|| {
                descriptors.push(rustix::event::PollFd::new(
                    &pidfd,
                    rustix::event::PollFlags::IN,
                ));
                descriptors.len() - 1
            });
            if !stdout.closed {
                descriptors.push(rustix::event::PollFd::new(
                    &stdout_fd,
                    rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP,
                ));
            }
            if !stderr.closed {
                descriptors.push(rustix::event::PollFd::new(
                    &stderr_fd,
                    rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP,
                ));
            }
            match rustix::event::poll(&mut descriptors, Some(&timeout)) {
                Ok(_) => leader_index.is_some_and(|index| {
                    descriptors[index]
                        .revents()
                        .contains(rustix::event::PollFlags::IN)
                }),
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(kernel_error("poll fixed process", error)),
            }
        };
        if leader_ready && !leader_exited {
            leader_exited = true;
            // Once the leader is known exited, stop residual same-group
            // descendants before waiting for their inherited pipes to close.
            guard.cancel()?;
        }
        if !stdout.closed && stdout.drain()? {
            guard.cancel_and_reap()?;
            return Ok(FixedProcessOutcome::OutputLimitExceeded);
        }
        if !stderr.closed && stderr.drain()? {
            guard.cancel_and_reap()?;
            return Ok(FixedProcessOutcome::OutputLimitExceeded);
        }
    }
}

#[derive(Clone, Copy)]
struct ProcessStatus {
    exit_code: Option<i32>,
    signal: Option<i32>,
}

fn wait_blocking(pid: rustix::process::Pid) -> Result<ProcessStatus> {
    loop {
        match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()) {
            Ok(Some((_, status))) => return decode_status(status),
            Ok(None) => continue,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(kernel_error("reap fixed process", error)),
        }
    }
}

fn decode_status(status: rustix::process::WaitStatus) -> Result<ProcessStatus> {
    if status.exited() {
        Ok(ProcessStatus {
            exit_code: status.exit_status(),
            signal: None,
        })
    } else if status.signaled() {
        Ok(ProcessStatus {
            exit_code: None,
            signal: status.terminating_signal(),
        })
    } else {
        Err(Error::invalid(
            "fixed process status",
            "wait returned neither exit nor signal termination",
        ))
    }
}

struct ChildGuard {
    pid: rustix::process::Pid,
    pidfd: Option<PidFd>,
    armed: bool,
}

impl ChildGuard {
    const fn new(pid: rustix::process::Pid) -> Self {
        Self {
            pid,
            pidfd: None,
            armed: true,
        }
    }

    fn attach_pidfd(&mut self, pidfd: PidFd) {
        self.pidfd = Some(pidfd);
    }

    fn pidfd(&self) -> Result<&PidFd> {
        self.pidfd
            .as_ref()
            .ok_or_else(|| Error::invalid("fixed process pidfd", "was not attached"))
    }

    fn reap(&mut self) -> Result<ProcessStatus> {
        let status = wait_blocking(self.pid)?;
        self.armed = false;
        Ok(status)
    }

    fn cancel_and_reap(&mut self) -> Result<ProcessStatus> {
        self.cancel()?;
        self.reap()
    }

    fn cancel(&self) -> Result<()> {
        kill_group(self.pid)?;
        kill_leader(self.pid, self.pidfd.as_ref())?;
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = kill_group(self.pid);
            let _ = kill_leader(self.pid, self.pidfd.as_ref());
            let _ = wait_blocking(self.pid);
        }
    }
}

fn kill_leader(pid: rustix::process::Pid, pidfd: Option<&PidFd>) -> Result<()> {
    let result = if let Some(pidfd) = pidfd {
        rustix::process::pidfd_send_signal(pidfd.as_fd(), rustix::process::Signal::KILL)
    } else {
        // The child remains unreaped, so its numeric PID cannot be recycled.
        rustix::process::kill_process(pid, rustix::process::Signal::KILL)
    };
    match result {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(kernel_error("kill fixed process leader", error)),
    }
}

fn kill_group(pid: rustix::process::Pid) -> Result<()> {
    // The leader remains an unreaped child while this can run, so its PID and
    // process-group ID cannot be recycled to an unrelated process.
    match rustix::process::kill_process_group(pid, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(kernel_error("kill fixed process group", error)),
    }
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)
        .map_err(|error| kernel_error("inspect fixed process output flags", error))?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|error| kernel_error("set fixed process output nonblocking", error))
}

fn validate_request(request: FixedProcessRequest<'_>) -> Result<()> {
    let executable = request.executable.as_os_str().as_bytes();
    let normalized = request
        .executable
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if executable.is_empty()
        || executable.len() > MAXIMUM_EXECUTABLE_BYTES
        || !request.executable.is_absolute()
        || !normalized
    {
        return Err(Error::invalid(
            "fixed process executable",
            "must be a normalized absolute path within 4096 bytes",
        ));
    }
    if request.arguments.len() > MAXIMUM_ARGUMENTS {
        return Err(Error::ObservationLimitExceeded {
            object: "fixed process arguments",
            limit: MAXIMUM_ARGUMENTS,
        });
    }
    let argument_bytes = request.arguments.iter().try_fold(0_usize, |total, value| {
        total.checked_add(value.as_os_str().as_bytes().len())
    });
    if argument_bytes.is_none_or(|bytes| bytes > MAXIMUM_ARGUMENT_BYTES) {
        return Err(Error::ObservationLimitExceeded {
            object: "fixed process argument bytes",
            limit: MAXIMUM_ARGUMENT_BYTES,
        });
    }
    if request.timeout.is_zero() {
        return Err(Error::invalid("fixed process timeout", "must be nonzero"));
    }
    Ok(())
}

fn duplicate_high(descriptor: OwnedFd) -> Result<OwnedFd> {
    rustix::io::fcntl_dupfd_cloexec(&descriptor, DUPLICATE_FD_MINIMUM)
        .map_err(|error| kernel_error("duplicate fixed process descriptor", error))
}

fn kernel_error(operation: &'static str, error: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(error.raw_os_error()),
    }
}

fn monotonic_now() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn test_process(test: &str, timeout: Duration, maximum: usize) -> FixedProcessOutcome {
        let executable = std::env::current_exe().unwrap();
        let arguments = ["--exact", test, "--nocapture"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        run_fixed_process_owned(FixedProcessRequest {
            executable: &executable,
            arguments: &arguments,
            timeout,
            maximum_stdout_bytes: maximum,
            maximum_stderr_bytes: maximum,
        })
        .unwrap()
    }

    #[test]
    fn captures_both_streams_and_exit_status() {
        let outcome = test_process(
            "process::tests::child_writes_both_streams",
            Duration::from_secs(2),
            4096,
        );
        let FixedProcessOutcome::Completed(output) = outcome else {
            panic!("fixture did not complete")
        };
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.signal, None);
        assert!(output.stdout.windows(3).any(|bytes| bytes == b"out"));
        assert!(output.stderr.windows(3).any(|bytes| bytes == b"err"));
    }

    #[test]
    fn deadline_kills_and_reaps_the_process_group() {
        assert_eq!(
            test_process(
                "process::tests::child_waits",
                Duration::from_millis(25),
                4096,
            ),
            FixedProcessOutcome::TimedOut
        );
    }

    #[test]
    fn output_ceiling_cancels_before_unbounded_allocation() {
        assert_eq!(
            test_process(
                "process::tests::child_writes_past_limit",
                Duration::from_secs(2),
                1024,
            ),
            FixedProcessOutcome::OutputLimitExceeded
        );
    }

    #[test]
    fn normal_leader_exit_cleans_pipe_holding_group_descendant() {
        let outcome = test_process(
            "process::tests::child_spawns_pipe_holding_descendant",
            Duration::from_secs(2),
            4096,
        );
        let FixedProcessOutcome::Completed(output) = outcome else {
            panic!("residual same-group descendant prevented completion")
        };
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.signal, None);
    }

    #[test]
    fn missing_executable_preserves_spawn_error() {
        let error = run_fixed_process_owned(FixedProcessRequest {
            executable: Path::new("/definitely/absent/aos-test-program"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 1,
            maximum_stderr_bytes: 1,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Syscall { source, .. } if source.raw_os_error() == Some(libc::ENOENT)
        ));
    }

    #[test]
    fn public_api_rejects_a_process_with_competing_threads() {
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        let child_release = release.clone();
        let competing_thread = std::thread::spawn(move || child_release.wait());

        let error = run_fixed_process(FixedProcessRequest {
            executable: Path::new("/definitely/absent/aos-test-program"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 1,
            maximum_stderr_bytes: 1,
        })
        .unwrap_err();
        release.wait();
        competing_thread.join().unwrap();

        assert!(matches!(
            error,
            Error::InvalidInput {
                field: "fixed process reaping ownership",
                ..
            }
        ));
    }

    #[test]
    fn public_api_rejects_nondefault_sigchld_in_isolated_processes() {
        let executable = std::env::current_exe().unwrap();
        for disposition in ["ignore", "no-cld-wait"] {
            let status = std::process::Command::new(&executable)
                .args([
                    "--ignored",
                    "--exact",
                    "process::tests::isolated_nondefault_sigchld_case",
                    "--nocapture",
                ])
                .env("AOS_FIXED_PROCESS_SIGCHLD_CASE", disposition)
                .status()
                .unwrap();
            assert!(status.success(), "isolated {disposition} case failed");
        }
    }

    #[test]
    #[ignore = "launched alone by the isolated SIGCHLD disposition test"]
    fn isolated_nondefault_sigchld_case() {
        let disposition = std::env::var("AOS_FIXED_PROCESS_SIGCHLD_CASE").unwrap();
        // SAFETY: this ignored test runs alone in a disposable subprocess, and
        // initializes the complete Linux sigaction before installing it.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&raw mut action.sa_mask);
            action.sa_sigaction = if disposition == "ignore" {
                libc::SIG_IGN
            } else {
                libc::SIG_DFL
            };
            action.sa_flags = if disposition == "no-cld-wait" {
                libc::SA_NOCLDWAIT
            } else {
                0
            };
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut()),
                0
            );
        }

        let error = run_fixed_process(FixedProcessRequest {
            executable: Path::new("/definitely/absent/aos-test-program"),
            arguments: &[],
            timeout: Duration::from_secs(1),
            maximum_stdout_bytes: 1,
            maximum_stderr_bytes: 1,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidInput {
                field: "fixed process reaping ownership",
                message,
            } if message.contains("default SIGCHLD")
        ));
    }

    #[test]
    fn child_writes_both_streams() {
        use std::io::Write as _;

        std::io::stdout().write_all(b"out").unwrap();
        std::io::stderr().write_all(b"err").unwrap();
    }

    #[test]
    fn child_waits() {
        std::thread::sleep(Duration::from_secs(10));
    }

    #[test]
    fn child_writes_past_limit() {
        use std::io::Write as _;

        let bytes = vec![b'x'; 4096];
        std::io::stdout().write_all(&bytes).unwrap();
    }

    #[test]
    #[allow(
        clippy::zombie_processes,
        reason = "the outer fixed-process supervisor owns and reaps the process-group leader"
    )]
    fn child_spawns_pipe_holding_descendant() {
        let executable = std::env::current_exe().unwrap();
        let _descendant = std::process::Command::new(executable)
            .args([
                "--exact",
                "process::tests::pipe_holding_descendant",
                "--nocapture",
            ])
            .spawn()
            .unwrap();
    }

    #[test]
    fn pipe_holding_descendant() {
        std::thread::sleep(Duration::from_secs(10));
    }
}
