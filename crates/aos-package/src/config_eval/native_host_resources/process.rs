//! Bounded subprocess transport for privileged host-resource adapters.
//!
//! Every helper runs in a fresh process group with an empty environment. The
//! transport polls the native runtime's cancellation and recovery budgets,
//! bounds all input and output, kills the full helper group, and reaps the
//! direct child on every incomplete outcome. Descendants are reparented by
//! Linux after termination.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use aos_ability_runtime::adapter::RuntimeControl;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_HELPER_INPUT_BYTES: usize = 256 * 1024;

/// Supplies a fixed budget for effect-free catalog and drift probes.
pub(super) struct FixedBudgetControl {
    remaining_millis: u64,
}

impl FixedBudgetControl {
    pub(super) const fn new(remaining_millis: u64) -> Self {
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
pub(super) struct ProcessOutput {
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
}

/// Defines whether a successful launcher may leave its daemon descendants alive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DescendantPolicy {
    /// Kills any descendant that survives the admitted helper process.
    Reap,
    /// Preserves descendants only after a successful helper exit.
    PreserveOnSuccess,
}

/// Runs one preconfigured command within the caller's remaining runtime budget.
pub(super) fn run_bounded(
    command: &mut Command,
    input: Option<&[u8]>,
    output_limit: usize,
    descendants: DescendantPolicy,
    control: &dyn RuntimeControl,
) -> Result<ProcessOutput, io::Error> {
    if input.is_some_and(|bytes| bytes.len() > MAX_HELPER_INPUT_BYTES) {
        return Err(invalid("host-resource helper input exceeds its size bound"));
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
        descendants,
        control,
        deadline,
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
    descendants: DescendantPolicy,
    control: &dyn RuntimeControl,
    deadline: Instant,
) -> Result<ProcessOutput, io::Error> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("host-resource helper stdout is unavailable"))?;
    set_nonblocking(&stdout)?;
    let mut stdin = match input {
        Some(_) => {
            let pipe = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("host-resource helper stdin is unavailable"))?;
            set_nonblocking(&pipe)?;
            Some(pipe)
        }
        None => None,
    };
    let mut input_offset = 0;
    let mut output = Vec::new();
    let mut stdout_eof = false;
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
                            "host-resource helper stopped accepting input",
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
            let mut chunk = [0_u8; 16 * 1024];
            loop {
                require_budget(control, deadline)?;
                match stdout.read(&mut chunk) {
                    Ok(0) => {
                        stdout_eof = true;
                        break;
                    }
                    Ok(read) => {
                        if output.len().saturating_add(read) > output_limit {
                            return Err(invalid(
                                "host-resource helper output exceeds its size bound",
                            ));
                        }
                        output.extend_from_slice(&chunk[..read]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        }

        if leader_succeeded.is_none() {
            leader_succeeded = observe_child_exit(leader)?;
        }
        if let Some(succeeded) = leader_succeeded
            && !group_terminated
            && (descendants == DescendantPolicy::Reap || !succeeded)
        {
            // The pidfd-observed leader remains waitable, pinning the PGID while
            // every descendant is terminated and closes inherited pipes.
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            group_terminated = true;
        }
        if stdout_eof && leader_succeeded.is_some() {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    let status = child.wait()?;
    let _observed_success = leader_succeeded
        .ok_or_else(|| io::Error::other("host-resource helper exit was not observed"))?;
    Ok(ProcessOutput {
        status,
        stdout: output,
    })
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
        .ok_or_else(|| io::Error::other("host-resource helper has no valid process group"))
}

fn terminate_and_reap(child: &mut Child, group: rustix::process::Pid) {
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

fn budget_exhausted() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "host-resource helper exhausted its runtime budget",
    )
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
