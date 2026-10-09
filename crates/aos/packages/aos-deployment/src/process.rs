//! Bounded subprocess transport for authenticated native handlers.
//!
//! Every helper runs in a fresh process group with an empty environment. The
//! transport polls the native runtime's cancellation and recovery budgets,
//! bounds all input and output, kills the full helper group, and reaps the
//! direct child on every incomplete outcome. Descendants are reparented by
//! Linux after termination.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

use aos_activation::adapter::RuntimeControl;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_HELPER_INPUT_BYTES: usize = 256 * 1024;

const DIAGNOSTIC_CHUNK_BYTES: usize = 4096;
const DIAGNOSTIC_QUEUE_CHUNKS: usize = 16;

/// Decouples best-effort console writes from activation deadlines.
pub(crate) struct OperatorDiagnostics {
    sender: Option<mpsc::SyncSender<Vec<u8>>>,
}

impl OperatorDiagnostics {
    /// Creates a nonblocking diagnostic sink for the operator's standard error.
    pub(crate) fn stderr() -> Self {
        static SENDER: OnceLock<Option<mpsc::SyncSender<Vec<u8>>>> = OnceLock::new();
        let sender = SENDER.get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(DIAGNOSTIC_QUEUE_CHUNKS);
            std::thread::Builder::new()
                .name("handler-diagnostics".into())
                .spawn(move || {
                    let mut console = std::io::stderr();
                    while let Ok(bytes) = receiver.recv() {
                        if console.write_all(&bytes).is_err() {
                            break;
                        }
                    }
                })
                .ok()
                .map(|_| sender)
        });
        Self {
            sender: sender.as_ref().cloned(),
        }
    }
}

impl Write for OperatorDiagnostics {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(sender) = &self.sender {
            for chunk in bytes.chunks(DIAGNOSTIC_CHUNK_BYTES) {
                if sender.try_send(chunk.to_vec()).is_err() {
                    break;
                }
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Never wait for the console worker; diagnostics cannot delay effects.
        Ok(())
    }
}

/// Supplies a fixed budget for effect-free catalog and drift probes.
pub struct FixedBudgetControl {
    remaining_millis: u64,
}

impl FixedBudgetControl {
    /// Creates a fixed runtime budget measured in milliseconds.
    pub const fn new(remaining_millis: u64) -> Self {
        Self { remaining_millis }
    }
}

impl RuntimeControl for FixedBudgetControl {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn elapsed_millis(&self) -> u64 {
        0
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.remaining_millis
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.remaining_millis
    }
}

/// Carries the bounded output of one fully reaped helper process.
pub struct ProcessOutput {
    /// Records the exit status after the child is fully reaped.
    pub status: ExitStatus,
    /// Contains bounded bytes from the typed standard-output stream.
    pub stdout: Vec<u8>,
    /// Contains bounded diagnostic bytes from standard error.
    pub stderr: Vec<u8>,
}

/// Runs one preconfigured command within the caller's remaining runtime budget.
///
/// # Errors
/// Returns an error for oversized input or output, process or pipe failures, timeout, or
/// cancellation.
pub fn run_bounded(
    command: &mut Command,
    input: Option<&[u8]>,
    output_limit: usize,
    control: &dyn RuntimeControl,
    environment: &[(OsString, OsString)],
) -> Result<ProcessOutput, io::Error> {
    run_bounded_with_input_limit(
        command,
        input,
        MAX_HELPER_INPUT_BYTES,
        output_limit,
        control,
        environment,
    )
}

/// Runs the same transport with an explicit input bound for module evaluation.
///
/// # Errors
/// Returns an error for oversized input or output, process or pipe failures, timeout, or
/// cancellation.
pub fn run_bounded_with_input_limit(
    command: &mut Command,
    input: Option<&[u8]>,
    input_limit: usize,
    output_limit: usize,
    control: &dyn RuntimeControl,
    environment: &[(OsString, OsString)],
) -> Result<ProcessOutput, io::Error> {
    run_with_diagnostics(
        command,
        input,
        input_limit,
        output_limit,
        control,
        environment,
        None,
    )
}

/// Streams bounded handler diagnostics independently of the typed result pipe.
///
/// # Errors
/// Returns an error for oversized input or output, process or pipe failures, timeout, or
/// cancellation.
pub(crate) fn run_handler(
    command: &mut Command,
    input: &[u8],
    output_limit: usize,
    control: &dyn RuntimeControl,
    diagnostics: &mut dyn Write,
) -> Result<ProcessOutput, io::Error> {
    run_with_diagnostics(
        command,
        Some(input),
        MAX_HELPER_INPUT_BYTES,
        output_limit,
        control,
        &[],
        Some(diagnostics),
    )
}

fn run_with_diagnostics(
    command: &mut Command,
    input: Option<&[u8]>,
    input_limit: usize,
    output_limit: usize,
    control: &dyn RuntimeControl,
    environment: &[(OsString, OsString)],
    diagnostics: Option<&mut dyn Write>,
) -> Result<ProcessOutput, io::Error> {
    if input.is_some_and(|bytes| bytes.len() > input_limit) {
        return Err(invalid("native handler input exceeds its size bound"));
    }
    let budget = control
        .attempt_remaining_millis()
        .min(control.recovery_remaining_millis());
    if control.is_cancelled() || budget == 0 {
        return Err(budget_exhausted());
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(budget))
        .ok_or_else(budget_exhausted)?;

    command
        .process_group(0)
        .env_clear()
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.envs(environment.iter().cloned());
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
        Err(error) => {
            terminate_and_reap(&mut child, group);
            return Err(error.into());
        }
    };
    let result = exchange_io(
        &mut child,
        &leader,
        group,
        input,
        output_limit,
        control,
        deadline,
        diagnostics,
    );
    if result.is_err() {
        terminate_and_reap(&mut child, group);
    }
    result
}

fn exchange_io(
    child: &mut Child,
    leader: &OwnedFd,
    group: rustix::process::Pid,
    input: Option<&[u8]>,
    output_limit: usize,
    control: &dyn RuntimeControl,
    deadline: Instant,
    mut diagnostics: Option<&mut dyn Write>,
) -> Result<ProcessOutput, io::Error> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("native handler stdout is unavailable"))?;
    set_nonblocking(&stdout)?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("process stderr is unavailable"))?;
    set_nonblocking(&stderr)?;
    let mut stdin = match input {
        Some(_) => {
            let pipe = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("native handler stdin is unavailable"))?;
            set_nonblocking(&pipe)?;
            Some(pipe)
        }
        None => None,
    };
    let mut input_offset = 0;
    let mut output = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut errors = Vec::new();
    let mut leader_succeeded = None;
    let mut group_terminated = false;

    loop {
        require_budget(control, deadline)?;

        if let (Some(bytes), Some(pipe)) = (input, stdin.as_mut()) {
            while input_offset < bytes.len() {
                require_budget(control, deadline)?;
                match pipe.write(&bytes[input_offset..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "native handler stopped accepting input",
                        ));
                    }
                    Ok(written) => input_offset += written,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            if input_offset == bytes.len() {
                stdin = None;
            }
        }

        if !stdout_eof {
            stdout_eof = read_available(&mut stdout, &mut output, output_limit, control, deadline)?;
        }
        if !stderr_eof {
            let previous_length = errors.len();
            stderr_eof = read_available(&mut stderr, &mut errors, output_limit, control, deadline)?;
            if let Some(writer) = diagnostics.as_mut() {
                // A closed operator console must not change mutation semantics.
                let _ = writer.write_all(&errors[previous_length..]);
                let _ = writer.flush();
            }
        }

        if leader_succeeded.is_none() {
            leader_succeeded = observe_child_exit(leader)?;
        }
        if leader_succeeded.is_some() && !group_terminated {
            // The pidfd-observed leader remains waitable, pinning the PGID while
            // every descendant is terminated and closes inherited pipes.
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            group_terminated = true;
        }
        if stdout_eof && stderr_eof && leader_succeeded.is_some() {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    let status = child.wait()?;
    let _observed_success =
        leader_succeeded.ok_or_else(|| io::Error::other("native handler exit was not observed"))?;
    Ok(ProcessOutput {
        status,
        stdout: output,
        stderr: errors,
    })
}

fn read_available(
    pipe: &mut impl Read,
    output: &mut Vec<u8>,
    limit: usize,
    control: &dyn RuntimeControl,
    deadline: Instant,
) -> Result<bool, io::Error> {
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        require_budget(control, deadline)?;
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(read) => {
                if output.len().saturating_add(read) > limit {
                    return Err(invalid("process output exceeds its size bound"));
                }
                output.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

fn observe_child_exit(leader: &OwnedFd) -> Result<Option<bool>, io::Error> {
    let status = rustix::process::waitid(
        rustix::process::WaitId::PidFd(leader.as_fd()),
        rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOWAIT,
    )?;
    Ok(status.map(|status| status.exit_status() == Some(0)))
}

fn require_budget(control: &dyn RuntimeControl, deadline: Instant) -> Result<(), io::Error> {
    if control.is_cancelled()
        || control.attempt_remaining_millis() == 0
        || control.recovery_remaining_millis() == 0
        || Instant::now() >= deadline
    {
        Err(budget_exhausted())
    } else {
        Ok(())
    }
}

fn set_nonblocking<Fd: AsFd>(descriptor: Fd) -> Result<(), io::Error> {
    let flags = rustix::fs::fcntl_getfl(&descriptor).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(&descriptor, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(io::Error::from)
}

fn child_process_group(child: &Child) -> Result<rustix::process::Pid, io::Error> {
    i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| io::Error::other("native handler has no valid process group"))
}

fn terminate_and_reap(child: &mut Child, group: rustix::process::Pid) {
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

fn budget_exhausted() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "native handler exhausted its runtime budget",
    )
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELPER_TEST: &str = "deployment::process::tests::bounded_process_helper";

    #[test]
    fn bounded_handler_runs_with_usable_control() {
        let mut command = helper_command();
        let control = FixedBudgetControl::new(2_000);

        let output = run_bounded(&mut command, None, 16 * 1024, &control, &[])
            .expect("bounded native handler completes");

        let marker = b"postcondition-established";
        assert!(output.status.success());
        assert!(
            output
                .stderr
                .windows(marker.len())
                .any(|window| window == marker)
        );
        assert!(
            output
                .stdout
                .windows(marker.len())
                .any(|window| window == marker)
        );
    }

    #[test]
    fn bounded_process_helper() {
        print!("postcondition-established");
        eprint!("postcondition-established");
    }

    #[test]
    fn stalled_diagnostic_console_does_not_delay_a_handler() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(b"console-backpressure".to_vec())
            .expect("fill queue");
        let mut diagnostics = OperatorDiagnostics {
            sender: Some(sender),
        };
        let mut command = helper_command();
        let control = FixedBudgetControl::new(2_000);

        let output = run_handler(&mut command, b"", 16 * 1024, &control, &mut diagnostics)
            .expect("a full diagnostic queue cannot block the handler");

        assert!(output.status.success());
        assert_eq!(
            receiver.recv().expect("original queued chunk"),
            b"console-backpressure"
        );
        assert!(receiver.try_recv().is_err());
        assert!(String::from_utf8_lossy(&output.stderr).contains("postcondition-established"));
    }

    #[test]
    fn handler_diagnostics_arrive_before_the_helper_exits() {
        struct AcknowledgeDiagnostics {
            marker: std::path::PathBuf,
            bytes: Vec<u8>,
        }

        impl Write for AcknowledgeDiagnostics {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                std::fs::write(&self.marker, b"observed")?;
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let temporary = tempfile::tempdir().expect("diagnostic test directory");
        let marker = temporary.path().join("diagnostic-observed");
        let mut diagnostics = AcknowledgeDiagnostics {
            marker: marker.clone(),
            bytes: Vec::new(),
        };
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command.args([
            "--exact",
            "deployment::process::tests::diagnostic_process_helper",
            "--nocapture",
        ]);
        let control = FixedBudgetControl::new(5_000);

        let output = run_handler(
            &mut command,
            marker.to_str().expect("test marker path").as_bytes(),
            16 * 1024,
            &control,
            &mut diagnostics,
        )
        .expect("helper observes diagnostics before it can exit");

        assert!(output.status.success());
        assert!(marker.exists());
        assert_eq!(diagnostics.bytes, output.stderr);
        assert!(String::from_utf8_lossy(&output.stderr).contains("waiting-for-diagnostic-reader"));
    }

    #[test]
    fn diagnostic_process_helper() {
        if !std::env::args()
            .any(|argument| argument == "deployment::process::tests::diagnostic_process_helper")
        {
            return;
        }

        let mut marker = String::new();
        std::io::stdin()
            .read_to_string(&mut marker)
            .expect("helper input");
        if marker.is_empty() {
            return;
        }

        eprint!("waiting-for-diagnostic-reader");
        std::io::stderr().flush().expect("helper diagnostic flush");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !std::path::Path::new(&marker).exists() {
            assert!(
                Instant::now() < deadline,
                "diagnostic reader did not acknowledge"
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn helper_command() -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable exists"));
        command.args(["--exact", HELPER_TEST, "--nocapture"]);
        command
    }
}
