//! Event-driven exchanges with a live fixed child process.
//!
//! The session supervisor extends the fixed-process boundary with one borrowed
//! nonblocking control descriptor. It keeps the child pidfd retained, runs a
//! caller-defined nonblocking exchange, drains both output pipes concurrently,
//! and owns cancellation and reaping until the complete operation terminates.

use std::fmt;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::time::Duration;

use crate::pidfd::{PidFd, PidFdInfo};
use crate::{Error, Result};

use super::{
    ChildGuard, FixedProcessOutput, FixedProcessRequest, OutputStream, PreparedInvocation,
    ProcessStatus, SpawnedProcess, kernel_error, monotonic_now, validate_exclusive_reaping_owner,
};

/// Configures one fixed child process and its parent-side control descriptor.
#[derive(Debug)]
pub struct FixedProcessSessionRequest<'a> {
    /// Fixed invocation, shared deadline, and output limits.
    pub process: FixedProcessRequest<'a>,
    /// Owned standard input transferred into the session, or `/dev/null`.
    ///
    /// The descriptor is consumed even when validation or spawning fails. The
    /// parent copy is closed after spawn and before the first callback.
    pub stdin: Option<OwnedFd>,
    /// Owned descriptors mapped contiguously to child FDs 3 through 6.
    ///
    /// These descriptors are consumed even when validation or spawning fails.
    /// Every parent-side source is closed after spawn and before `start`, so a
    /// transferred peer endpoint cannot suppress peer-close readiness.
    pub inherited: Vec<OwnedFd>,
    /// Parent endpoint used exclusively by the exchange callbacks.
    ///
    /// The descriptor must already have `O_NONBLOCK`. This generic supervisor
    /// does not infer or validate a socket type, connection state, peer
    /// identity, or application protocol.
    pub control: BorrowedFd<'a>,
}

/// Exposes the retained identity of a child that was live before a callback.
#[derive(Clone, Copy, Debug)]
pub struct FixedLiveChild<'a> {
    pidfd: &'a PidFd,
    initial_info: PidFdInfo,
    deadline: Duration,
}

impl<'a> FixedLiveChild<'a> {
    /// Borrows the pidfd retained by the supervisor until the child is reaped.
    #[must_use]
    pub const fn pidfd(&self) -> &'a PidFd {
        self.pidfd
    }

    /// Returns the first pidfd information observed before the exchange began.
    #[must_use]
    pub const fn initial_info(&self) -> PidFdInfo {
        self.initial_info
    }

    /// Returns the absolute `CLOCK_MONOTONIC` deadline shared by the session.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }
}

/// Selects the only control readiness that the next callback may consume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedProcessControlInterest {
    /// Waits for the control descriptor to become readable.
    Readable,
    /// Waits for the control descriptor to become writable.
    Writable,
    /// Waits until the control descriptor is readable or writable.
    ReadableOrWritable,
}

impl FixedProcessControlInterest {
    fn poll_flags(self) -> rustix::event::PollFlags {
        match self {
            Self::Readable => rustix::event::PollFlags::IN,
            Self::Writable => rustix::event::PollFlags::OUT,
            Self::ReadableOrWritable => {
                rustix::event::PollFlags::IN | rustix::event::PollFlags::OUT
            }
        }
    }

    const fn includes_readable(self) -> bool {
        matches!(self, Self::Readable | Self::ReadableOrWritable)
    }
}

/// Reports the requested readiness observed for one exchange callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedProcessControlReadiness {
    readable: bool,
    writable: bool,
}

impl FixedProcessControlReadiness {
    /// Reports whether the control descriptor was readable.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        self.readable
    }

    /// Reports whether the control descriptor was writable.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.writable
    }
}

/// Directs the supervisor either to wait for more readiness or finish exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExchangeStep<T> {
    /// Waits for the selected control readiness before the next callback.
    Pending(FixedProcessControlInterest),
    /// Finishes the exchange while retaining supervision until child exit.
    Complete(T),
}

/// Implements a synchronous, nonblocking exchange with one fixed child.
///
/// `start` and `advance` run inline and are not forcibly preempted. They must
/// not block, sleep, spawn threads, reap children, or retain any borrowed
/// descriptor. `advance` may consume only the readiness reported to it. The
/// supervisor checks its deadline and child liveness before and after every
/// callback, but a callback that violates this contract can exceed the budget.
pub trait FixedProcessSessionExchange {
    /// Successful value produced once the exchange is complete.
    type Output;
    /// Typed protocol or exchange failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Starts the exchange without waiting for readiness.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the initial nonblocking protocol action fails.
    fn start(
        &mut self,
        child: &FixedLiveChild<'_>,
        control: BorrowedFd<'_>,
    ) -> std::result::Result<ExchangeStep<Self::Output>, Self::Error>;

    /// Advances the exchange after the requested control readiness occurs.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the next nonblocking protocol action fails.
    fn advance(
        &mut self,
        child: &FixedLiveChild<'_>,
        control: BorrowedFd<'_>,
        readiness: FixedProcessControlReadiness,
    ) -> std::result::Result<ExchangeStep<Self::Output>, Self::Error>;
}

/// Classifies completion or fail-stop cancellation of a fixed child session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixedProcessSessionOutcome<T> {
    /// The exchange completed and the leader later reached a terminal status.
    Completed {
        /// Terminal child status and complete bounded output.
        process: FixedProcessOutput,
        /// Value produced by the exchange.
        exchange: T,
    },
    /// The leader exited before the exchange produced a complete value.
    ChildExitedBeforeExchange(FixedProcessOutput),
    /// The shared monotonic deadline expired before complete termination.
    TimedOut,
    /// Standard output or standard error crossed its configured byte ceiling.
    OutputLimitExceeded,
}

/// Separates process-boundary, exchange, and fail-stop cleanup failures.
#[derive(Debug)]
pub enum FixedProcessSessionError<E> {
    /// Setup, descriptor polling, liveness, output, or process control failed.
    Process {
        /// Primary process-boundary failure.
        source: Error,
        /// Additional failure while cancelling and reaping an already-spawned child.
        cleanup: Option<Error>,
    },
    /// The caller-defined exchange callback failed.
    Exchange {
        /// Primary exchange failure.
        source: E,
        /// Additional failure while cancelling and reaping the child.
        cleanup: Option<Error>,
    },
    /// Cancellation or reaping failed without an earlier primary error.
    Cleanup(Error),
}

impl<E> FixedProcessSessionError<E> {
    /// Returns an additional cleanup error attached to a primary failure.
    #[must_use]
    pub const fn cleanup_error(&self) -> Option<&Error> {
        match self {
            Self::Process { cleanup, .. } | Self::Exchange { cleanup, .. } => cleanup.as_ref(),
            Self::Cleanup(_) => None,
        }
    }
}

impl<E: fmt::Display> fmt::Display for FixedProcessSessionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process { source, cleanup } => {
                write!(formatter, "fixed process session failed: {source}")?;
                format_cleanup(formatter, cleanup.as_ref())
            }
            Self::Exchange { source, cleanup } => {
                write!(formatter, "fixed process exchange failed: {source}")?;
                format_cleanup(formatter, cleanup.as_ref())
            }
            Self::Cleanup(source) => write!(formatter, "fixed process cleanup failed: {source}"),
        }
    }
}

impl<E> std::error::Error for FixedProcessSessionError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Process { source, .. } | Self::Cleanup(source) => Some(source),
            Self::Exchange { source, .. } => Some(source),
        }
    }
}

fn format_cleanup(formatter: &mut fmt::Formatter<'_>, cleanup: Option<&Error>) -> fmt::Result {
    if let Some(cleanup) = cleanup {
        write!(formatter, "; cleanup also failed: {cleanup}")?;
    }
    Ok(())
}

/// Runs one live-child exchange and retains ownership until cancellation or reap.
///
/// One absolute `CLOCK_MONOTONIC` deadline begins before invocation preparation,
/// spawning, the exchange, and output collection. Standard output and standard
/// error are drained concurrently in bounded chunks. The control descriptor is
/// borrowed for the call and never closed or detached. Owned standard input and
/// child roles are consumed on every path and their parent copies close before
/// the first callback. Every return after a successful spawn has synchronously
/// attempted to kill the process group and reap its leader; the guard repeats
/// that cleanup during unwinding.
///
/// The fresh process group is not a process-tree containment boundary. A
/// privileged caller must provide an independently enforced cgroup when no
/// descendant may escape cleanup.
///
/// # Errors
///
/// Returns [`FixedProcessSessionError::Process`] for the fixed-process errors
/// documented by [`super::run_fixed_process_with_descriptors`], a control
/// descriptor without `O_NONBLOCK`, invalid poll state, child-observation or
/// output failures. Returns [`FixedProcessSessionError::Exchange`] when a
/// callback fails. Either variant reports a second cleanup failure separately.
/// Returns [`FixedProcessSessionError::Cleanup`] when cancellation or reaping
/// alone fails.
///
/// # Panics
///
/// Propagates a panic from an exchange callback after the child guard attempts
/// to kill the process group and reap its leader.
pub fn run_fixed_process_session<X>(
    request: FixedProcessSessionRequest<'_>,
    exchange: &mut X,
) -> std::result::Result<FixedProcessSessionOutcome<X::Output>, FixedProcessSessionError<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    let started = monotonic_now();
    let Some(deadline) = started.checked_add(request.process.timeout) else {
        return Err(process_error(Error::invalid(
            "fixed process timeout",
            "absolute deadline overflows CLOCK_MONOTONIC duration",
        )));
    };

    validate_session_request(&request).map_err(process_error)?;
    validate_exclusive_reaping_owner().map_err(process_error)?;
    spawn_and_supervise_session(request, deadline, exchange)
}

/// Runs one live-child exchange by executing a retained regular-file descriptor.
///
/// `request.process.executable` remains the exact argument-zero value, but the
/// kernel resolves `executable` directly with `execveat(2)`. Before entering
/// the executable or its dynamic loader, the child enables no-new-privileges
/// and clears its effective, permitted, inheritable, and ambient capabilities.
/// The caller must already have locked `noroot` and `no-setuid-fixup` securebits
/// so UID 0 cannot regain those capabilities across exec. The descriptor is
/// mapped immediately after the caller's inherited roles and remains open at
/// entry so the program can authenticate and close it. The capability bounding
/// set is inherited unchanged; a role-specific entrypoint must validate that
/// separately because an already-minimized caller may lack `CAP_SETPCAP`.
///
/// # Errors
///
/// Returns the errors documented by [`run_fixed_process_session`]. It also
/// rejects a non-regular, writable, non-executable, or non-CLOEXEC executable
/// descriptor, a request with more than four inherited roles, or a caller
/// without the required locked securebits.
///
/// # Panics
///
/// Propagates callback panics as documented by [`run_fixed_process_session`].
pub fn run_fixed_process_session_from_executable_descriptor<X>(
    request: FixedProcessSessionRequest<'_>,
    executable: OwnedFd,
    exchange: &mut X,
) -> std::result::Result<FixedProcessSessionOutcome<X::Output>, FixedProcessSessionError<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    let started = monotonic_now();
    let Some(deadline) = started.checked_add(request.process.timeout) else {
        return Err(process_error(Error::invalid(
            "fixed process timeout",
            "absolute deadline overflows CLOCK_MONOTONIC duration",
        )));
    };
    if request.inherited.len() > super::MAXIMUM_INHERITED_DESCRIPTORS {
        return Err(process_error(Error::invalid(
            "fixed process inherited descriptors",
            "exceeds the four-descriptor ceiling",
        )));
    }
    validate_executable_descriptor(executable.as_fd()).map_err(process_error)?;

    validate_session_request(&request).map_err(process_error)?;
    validate_exclusive_reaping_owner().map_err(process_error)?;
    spawn_and_supervise_descriptor_session(request, executable, deadline, exchange)
}

fn spawn_and_supervise_session<X>(
    request: FixedProcessSessionRequest<'_>,
    deadline: Duration,
    exchange: &mut X,
) -> std::result::Result<FixedProcessSessionOutcome<X::Output>, FixedProcessSessionError<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    let FixedProcessSessionRequest {
        process,
        stdin,
        inherited,
        control,
    } = request;
    let invocation = PreparedInvocation::new(process).map_err(process_error)?;
    let inherited_borrows = inherited
        .iter()
        .map(|descriptor| descriptor.as_fd())
        .collect::<Vec<_>>();
    let spawned = invocation
        .spawn(
            stdin.as_ref().map(|descriptor| descriptor.as_fd()),
            &inherited_borrows,
        )
        .map_err(process_error)?;

    drop(inherited_borrows);
    drop(inherited);
    drop(stdin);
    supervise_session(spawned, process, control, deadline, exchange)
}

fn spawn_and_supervise_descriptor_session<X>(
    request: FixedProcessSessionRequest<'_>,
    executable: OwnedFd,
    deadline: Duration,
    exchange: &mut X,
) -> std::result::Result<FixedProcessSessionOutcome<X::Output>, FixedProcessSessionError<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    let FixedProcessSessionRequest {
        process,
        stdin,
        inherited,
        control,
    } = request;
    let invocation = PreparedInvocation::new(process).map_err(process_error)?;
    let inherited_borrows = inherited
        .iter()
        .map(|descriptor| descriptor.as_fd())
        .collect::<Vec<_>>();
    let spawned = invocation
        .spawn_from_executable_descriptor(
            executable.as_fd(),
            stdin.as_ref().map(|descriptor| descriptor.as_fd()),
            &inherited_borrows,
        )
        .map_err(process_error)?;

    drop(inherited_borrows);
    drop(executable);
    drop(inherited);
    drop(stdin);
    supervise_session(spawned, process, control, deadline, exchange)
}

#[cfg(test)]
fn run_fixed_process_session_under_libtest<X>(
    request: FixedProcessSessionRequest<'_>,
    exchange: &mut X,
) -> std::result::Result<FixedProcessSessionOutcome<X::Output>, FixedProcessSessionError<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    let started = monotonic_now();
    let Some(deadline) = started.checked_add(request.process.timeout) else {
        return Err(process_error(Error::invalid(
            "fixed process timeout",
            "absolute deadline overflows CLOCK_MONOTONIC duration",
        )));
    };

    validate_session_request(&request).map_err(process_error)?;
    spawn_and_supervise_session(request, deadline, exchange)
}

#[cfg(test)]
fn run_descriptor_session_under_libtest<X>(
    request: FixedProcessSessionRequest<'_>,
    executable: OwnedFd,
    exchange: &mut X,
) -> std::result::Result<FixedProcessSessionOutcome<X::Output>, FixedProcessSessionError<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    let deadline = monotonic_now()
        .checked_add(request.process.timeout)
        .ok_or_else(|| process_error(Error::invalid("fixed process timeout", "overflow")))?;

    validate_session_request(&request).map_err(process_error)?;
    validate_executable_descriptor(executable.as_fd()).map_err(process_error)?;
    spawn_and_supervise_descriptor_session(request, executable, deadline, exchange)
}

fn validate_executable_descriptor(descriptor: BorrowedFd<'_>) -> Result<()> {
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|source| kernel_error("inspect executable descriptor flags", source))?;
    let status_flags = rustix::fs::fcntl_getfl(descriptor)
        .map_err(|source| kernel_error("inspect executable status flags", source))?;
    let status = rustix::fs::fstat(descriptor)
        .map_err(|source| kernel_error("inspect executable descriptor", source))?;
    if !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || status_flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        || status_flags.contains(rustix::fs::OFlags::PATH)
        || status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_mode & 0o222 != 0
        || status.st_mode & 0o111 == 0
    {
        return Err(Error::invalid(
            "fixed process executable descriptor",
            "must be a CLOEXEC, read-only, immutable-mode executable regular file",
        ));
    }
    Ok(())
}

fn validate_session_request(request: &FixedProcessSessionRequest<'_>) -> Result<()> {
    if request.inherited.len() > super::MAXIMUM_INHERITED_DESCRIPTORS {
        return Err(Error::invalid(
            "fixed process inherited descriptors",
            "exceeds the four-descriptor ceiling",
        ));
    }
    let flags = rustix::fs::fcntl_getfl(request.control)
        .map_err(|error| kernel_error("inspect fixed process control flags", error))?;
    if !flags.contains(rustix::fs::OFlags::NONBLOCK) {
        return Err(Error::invalid(
            "fixed process control descriptor",
            "must have O_NONBLOCK",
        ));
    }
    Ok(())
}

fn process_error<E>(source: Error) -> FixedProcessSessionError<E> {
    FixedProcessSessionError::Process {
        source,
        cleanup: None,
    }
}

struct SessionState<T> {
    exchange: Option<T>,
    interest: Option<FixedProcessControlInterest>,
    leader_exited: bool,
}

impl<T> SessionState<T> {
    const fn pending() -> Self {
        Self {
            exchange: None,
            interest: None,
            leader_exited: false,
        }
    }

    fn apply(&mut self, step: ExchangeStep<T>) {
        match step {
            ExchangeStep::Pending(interest) => self.interest = Some(interest),
            ExchangeStep::Complete(output) => {
                self.exchange = Some(output);
                self.interest = None;
            }
        }
    }

    fn mark_leader_exited(&mut self) {
        self.leader_exited = true;
        self.interest = None;
    }
}

fn supervise_session<X>(
    spawned: SpawnedProcess,
    process: FixedProcessRequest<'_>,
    control: BorrowedFd<'_>,
    deadline: Duration,
    exchange: &mut X,
) -> std::result::Result<FixedProcessSessionOutcome<X::Output>, FixedProcessSessionError<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    let mut guard = spawned.guard;
    let mut stdout = match OutputStream::new(spawned.stdout, process.maximum_stdout_bytes) {
        Ok(stream) => stream,
        Err(source) => return fail_process(&mut guard, source),
    };
    let mut stderr = match OutputStream::new(spawned.stderr, process.maximum_stderr_bytes) {
        Ok(stream) => stream,
        Err(source) => return fail_process(&mut guard, source),
    };
    let initial_info = match guard.pidfd().and_then(PidFd::info) {
        Ok(info) => info,
        Err(source) => return fail_process(&mut guard, source),
    };
    let mut state = SessionState::pending();

    if deadline_expired(deadline) {
        return finish_cancelled(&mut guard, FixedProcessSessionOutcome::TimedOut);
    }
    match child_is_alive(&guard) {
        Ok(true) => {}
        Ok(false) => state.mark_leader_exited(),
        Err(source) => return fail_process(&mut guard, source),
    }
    if !state.leader_exited {
        let step = {
            let child = match live_child(&guard, initial_info, deadline) {
                Ok(child) => child,
                Err(source) => return fail_process(&mut guard, source),
            };
            exchange.start(&child, control)
        };
        match step {
            Ok(step) => state.apply(step),
            Err(source) => return fail_exchange(&mut guard, source),
        }
        if deadline_expired(deadline) {
            return finish_cancelled(&mut guard, FixedProcessSessionOutcome::TimedOut);
        }
        match child_is_alive(&guard) {
            Ok(true) => {}
            Ok(false) => state.mark_leader_exited(),
            Err(source) => return fail_process(&mut guard, source),
        }
    }
    let early_exit_cleanup = if state.leader_exited {
        guard.cancel()
    } else {
        Ok(())
    };
    if let Err(source) = early_exit_cleanup {
        return fail_process(&mut guard, source);
    }

    loop {
        if state.leader_exited && stdout.closed && stderr.closed {
            return finish_reaped(guard, stdout, stderr, state.exchange);
        }
        if deadline_expired(deadline) {
            return finish_cancelled(&mut guard, FixedProcessSessionOutcome::TimedOut);
        }

        let ready = match poll_session(
            &guard,
            &stdout,
            &stderr,
            control,
            state.interest,
            state.leader_exited,
            deadline,
        ) {
            Ok(ready) => ready,
            Err(source) => return fail_process(&mut guard, source),
        };

        if ready.stdout && !stdout.closed {
            match drain_output_once(&mut stdout) {
                Ok(OutputDrain::Open | OutputDrain::Closed) => {}
                Ok(OutputDrain::LimitExceeded) => {
                    return finish_cancelled(
                        &mut guard,
                        FixedProcessSessionOutcome::OutputLimitExceeded,
                    );
                }
                Err(source) => return fail_process(&mut guard, source),
            }
        }
        if ready.stderr && !stderr.closed {
            match drain_output_once(&mut stderr) {
                Ok(OutputDrain::Open | OutputDrain::Closed) => {}
                Ok(OutputDrain::LimitExceeded) => {
                    return finish_cancelled(
                        &mut guard,
                        FixedProcessSessionOutcome::OutputLimitExceeded,
                    );
                }
                Err(source) => return fail_process(&mut guard, source),
            }
        }
        if deadline_expired(deadline) {
            return finish_cancelled(&mut guard, FixedProcessSessionOutcome::TimedOut);
        }

        if ready.leader {
            state.mark_leader_exited();
            if let Err(source) = guard.cancel() {
                return fail_process(&mut guard, source);
            }
        }
        if state.leader_exited || state.exchange.is_some() {
            continue;
        }
        if ready.control_invalid {
            return fail_process(
                &mut guard,
                Error::invalid(
                    "fixed process control descriptor",
                    "poll reported an invalid descriptor",
                ),
            );
        }
        if ready.control_error {
            return fail_process(
                &mut guard,
                Error::invalid(
                    "fixed process control descriptor",
                    "poll reported a terminal I/O error",
                ),
            );
        }

        let Some(interest) = state.interest else {
            return fail_process(
                &mut guard,
                Error::invalid(
                    "fixed process exchange state",
                    "pending exchange omitted control interest",
                ),
            );
        };
        let hup_read = ready.control_hangup && interest.includes_readable();
        let readable = ready.control_readable || hup_read;
        let writable = ready.control_writable && !ready.control_hangup;
        if readable || writable {
            if deadline_expired(deadline) {
                return finish_cancelled(&mut guard, FixedProcessSessionOutcome::TimedOut);
            }
            match child_is_alive(&guard) {
                Ok(true) => {}
                Ok(false) => {
                    state.mark_leader_exited();
                    if let Err(source) = guard.cancel() {
                        return fail_process(&mut guard, source);
                    }
                    continue;
                }
                Err(source) => return fail_process(&mut guard, source),
            }

            let step = {
                let child = match live_child(&guard, initial_info, deadline) {
                    Ok(child) => child,
                    Err(source) => return fail_process(&mut guard, source),
                };
                exchange.advance(
                    &child,
                    control,
                    FixedProcessControlReadiness { readable, writable },
                )
            };
            match step {
                Ok(step) => state.apply(step),
                Err(source) => return fail_exchange(&mut guard, source),
            }
            if deadline_expired(deadline) {
                return finish_cancelled(&mut guard, FixedProcessSessionOutcome::TimedOut);
            }
            match child_is_alive(&guard) {
                Ok(true) => {}
                Ok(false) => {
                    state.mark_leader_exited();
                    if let Err(source) = guard.cancel() {
                        return fail_process(&mut guard, source);
                    }
                }
                Err(source) => return fail_process(&mut guard, source),
            }
        }
        if ready.control_hangup && state.exchange.is_none() {
            return fail_process(
                &mut guard,
                Error::invalid(
                    "fixed process control descriptor",
                    "hung up before exchange completion",
                ),
            );
        }
    }
}

fn live_child<'a>(
    guard: &'a ChildGuard,
    initial_info: PidFdInfo,
    deadline: Duration,
) -> Result<FixedLiveChild<'a>> {
    Ok(FixedLiveChild {
        pidfd: guard.pidfd()?,
        initial_info,
        deadline,
    })
}

fn child_is_alive(guard: &ChildGuard) -> Result<bool> {
    guard.pidfd()?.is_alive()
}

fn deadline_expired(deadline: Duration) -> bool {
    monotonic_now() >= deadline
}

fn finish_reaped<T, E>(
    mut guard: ChildGuard,
    stdout: OutputStream,
    stderr: OutputStream,
    exchange: Option<T>,
) -> std::result::Result<FixedProcessSessionOutcome<T>, FixedProcessSessionError<E>> {
    let status = guard
        .cancel_and_reap()
        .map_err(FixedProcessSessionError::Cleanup)?;
    let process = process_output(status, stdout, stderr);
    Ok(match exchange {
        Some(exchange) => FixedProcessSessionOutcome::Completed { process, exchange },
        None => FixedProcessSessionOutcome::ChildExitedBeforeExchange(process),
    })
}

fn finish_cancelled<T, E>(
    guard: &mut ChildGuard,
    outcome: FixedProcessSessionOutcome<T>,
) -> std::result::Result<FixedProcessSessionOutcome<T>, FixedProcessSessionError<E>> {
    guard
        .cancel_and_reap()
        .map_err(FixedProcessSessionError::Cleanup)?;
    Ok(outcome)
}

fn fail_process<T, E>(
    guard: &mut ChildGuard,
    source: Error,
) -> std::result::Result<T, FixedProcessSessionError<E>> {
    let cleanup = guard.cancel_and_reap().err();
    Err(FixedProcessSessionError::Process { source, cleanup })
}

fn fail_exchange<T, E>(
    guard: &mut ChildGuard,
    source: E,
) -> std::result::Result<T, FixedProcessSessionError<E>> {
    let cleanup = guard.cancel_and_reap().err();
    Err(FixedProcessSessionError::Exchange { source, cleanup })
}

fn process_output(
    status: ProcessStatus,
    stdout: OutputStream,
    stderr: OutputStream,
) -> FixedProcessOutput {
    FixedProcessOutput {
        exit_code: status.exit_code,
        signal: status.signal,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    }
}

enum OutputDrain {
    Open,
    Closed,
    LimitExceeded,
}

fn drain_output_once(stream: &mut OutputStream) -> Result<OutputDrain> {
    let mut chunk = [0_u8; 8192];
    match rustix::io::read(&stream.descriptor, &mut chunk) {
        Ok(0) => {
            stream.closed = true;
            Ok(OutputDrain::Closed)
        }
        Ok(count) => {
            let exceeds = stream
                .bytes
                .len()
                .checked_add(count)
                .is_none_or(|length| length > stream.maximum);
            if exceeds {
                return Ok(OutputDrain::LimitExceeded);
            }
            stream.bytes.extend_from_slice(&chunk[..count]);
            Ok(OutputDrain::Open)
        }
        Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => Ok(OutputDrain::Open),
        Err(error) => Err(kernel_error("read fixed process session output", error)),
    }
}

#[derive(Default)]
struct SessionReadiness {
    leader: bool,
    stdout: bool,
    stderr: bool,
    control_readable: bool,
    control_writable: bool,
    control_hangup: bool,
    control_error: bool,
    control_invalid: bool,
}

fn poll_session(
    guard: &ChildGuard,
    stdout: &OutputStream,
    stderr: &OutputStream,
    control: BorrowedFd<'_>,
    interest: Option<FixedProcessControlInterest>,
    leader_exited: bool,
    deadline: Duration,
) -> Result<SessionReadiness> {
    let remaining = deadline.saturating_sub(monotonic_now());
    let timeout = rustix::event::Timespec::try_from(remaining)
        .map_err(|_| Error::invalid("fixed process timeout", "does not fit timespec"))?;
    let pidfd = guard.pidfd()?.as_fd();
    let stdout_fd = stdout.descriptor.as_fd();
    let stderr_fd = stderr.descriptor.as_fd();
    let mut descriptors = Vec::with_capacity(4);
    let leader_index = (!leader_exited).then(|| {
        descriptors.push(rustix::event::PollFd::new(
            &pidfd,
            rustix::event::PollFlags::IN | rustix::event::PollFlags::RDNORM,
        ));
        descriptors.len() - 1
    });
    let stdout_index = (!stdout.closed).then(|| {
        descriptors.push(rustix::event::PollFd::new(
            &stdout_fd,
            rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP,
        ));
        descriptors.len() - 1
    });
    let stderr_index = (!stderr.closed).then(|| {
        descriptors.push(rustix::event::PollFd::new(
            &stderr_fd,
            rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP,
        ));
        descriptors.len() - 1
    });
    let control_index = interest.map(|interest| {
        descriptors.push(rustix::event::PollFd::new(&control, interest.poll_flags()));
        descriptors.len() - 1
    });

    match rustix::event::poll(&mut descriptors, Some(&timeout)) {
        Ok(_) => {}
        Err(rustix::io::Errno::INTR) => return Ok(SessionReadiness::default()),
        Err(error) => return Err(kernel_error("poll fixed process session", error)),
    }

    let mut ready = SessionReadiness::default();
    if let Some(index) = leader_index {
        let flags = descriptors[index].revents();
        let allowed = rustix::event::PollFlags::IN
            | rustix::event::PollFlags::RDNORM
            | rustix::event::PollFlags::HUP;
        if flags.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
            || !flags.difference(allowed).is_empty()
        {
            return Err(Error::MalformedKernelResponse {
                object: "fixed process pidfd poll",
                message: "kernel reported invalid or unexpected readiness flags".to_owned(),
            });
        }
        ready.leader = flags.intersects(allowed);
    }
    if let Some(index) = stdout_index {
        ready.stdout = validate_output_readiness(descriptors[index].revents())?;
    }
    if let Some(index) = stderr_index {
        ready.stderr = validate_output_readiness(descriptors[index].revents())?;
    }
    if let Some(index) = control_index {
        let requested = interest.ok_or_else(|| {
            Error::invalid(
                "fixed process exchange state",
                "control poll omitted pending interest",
            )
        })?;
        let control = validate_control_readiness(descriptors[index].revents(), requested)?;
        ready.control_readable = control.readable;
        ready.control_writable = control.writable;
        ready.control_hangup = control.hangup;
        ready.control_error = control.error;
        ready.control_invalid = control.invalid;
    }
    Ok(ready)
}

struct ControlPollReadiness {
    readable: bool,
    writable: bool,
    hangup: bool,
    error: bool,
    invalid: bool,
}

fn validate_control_readiness(
    flags: rustix::event::PollFlags,
    interest: FixedProcessControlInterest,
) -> Result<ControlPollReadiness> {
    let allowed = rustix::event::PollFlags::IN
        | rustix::event::PollFlags::OUT
        | rustix::event::PollFlags::HUP
        | rustix::event::PollFlags::ERR
        | rustix::event::PollFlags::NVAL;
    if !flags.difference(allowed).is_empty() {
        return Err(Error::MalformedKernelResponse {
            object: "fixed process control poll",
            message: "kernel reported unexpected readiness flags".to_owned(),
        });
    }
    let requested = interest.poll_flags();
    Ok(ControlPollReadiness {
        readable: flags.contains(rustix::event::PollFlags::IN)
            && requested.contains(rustix::event::PollFlags::IN),
        writable: flags.contains(rustix::event::PollFlags::OUT)
            && requested.contains(rustix::event::PollFlags::OUT),
        hangup: flags.contains(rustix::event::PollFlags::HUP),
        error: flags.contains(rustix::event::PollFlags::ERR),
        invalid: flags.contains(rustix::event::PollFlags::NVAL),
    })
}

fn validate_output_readiness(flags: rustix::event::PollFlags) -> Result<bool> {
    let allowed = rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP;
    if flags.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
        || !flags.difference(allowed).is_empty()
    {
        return Err(Error::MalformedKernelResponse {
            object: "fixed process output poll",
            message: "kernel reported invalid or unexpected readiness flags".to_owned(),
        });
    }
    Ok(flags.intersects(allowed))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ffi::OsString;
    use std::path::Path;

    use super::*;
    use crate::uapi;

    const ISOLATED_CASE_ENVIRONMENT: &str = "AOS_FIXED_PROCESS_SESSION_CASE_V1";
    const CHILD_TEST: &str = "process::session::tests::session_child_fixture";
    const DESCENDANT_TEST: &str = "process::session::tests::session_descendant_waits";

    #[test]
    fn session_completes_a_staged_exchange_and_output() {
        run_isolated_case("staged");
    }

    #[test]
    fn descriptor_exec_maps_four_roles_without_leaking_its_error_channel() {
        run_isolated_case("descriptor-layout");
    }

    #[test]
    fn output_limit_cancels_while_exchange_is_pending() {
        run_isolated_case("output-limit");
    }

    #[test]
    fn one_deadline_bounds_repeated_dual_stream_pressure() {
        run_isolated_case("deadline");
    }

    #[test]
    fn deadline_is_rechecked_after_a_delayed_callback() {
        run_isolated_case("delayed-callback");
    }

    #[test]
    fn child_exit_before_exchange_is_classified() {
        run_isolated_case("early-exit");
    }

    #[test]
    fn exchange_error_kills_the_leader_and_group_descendant() {
        run_isolated_case("exchange-error");
    }

    #[test]
    fn cleanup_failure_is_typed_and_drop_still_reaps() {
        run_isolated_case("cleanup-failure");
    }

    #[test]
    fn panic_guard_kills_and_reaps_the_child_group() {
        run_isolated_case("panic");
    }

    #[test]
    fn completed_exchange_retains_nonzero_child_status() {
        run_isolated_case("nonzero");
    }

    #[test]
    fn writable_then_readable_interest_advances_once_each() {
        run_isolated_case("write-read");
    }

    #[test]
    fn hangup_gets_one_read_attempt_then_fails_without_spinning() {
        run_isolated_case("hangup");
    }

    #[test]
    fn spawn_failure_never_starts_the_exchange() {
        run_isolated_case("spawn-failure");
    }

    #[test]
    fn blocking_control_is_rejected_before_spawning() {
        let (control, child) = uapi::seqpacket_pair_with_flags(libc::SOCK_CLOEXEC).unwrap();
        let mut exchange = ScenarioExchange::new("staged");
        let error = run_fixed_process_session(
            session_request(
                Path::new("/definitely/absent/aos-test-program"),
                &[],
                control.as_fd(),
                vec![child],
                Duration::from_secs(1),
                1,
            ),
            &mut exchange,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            FixedProcessSessionError::Process {
                source: Error::InvalidInput {
                    field: "fixed process control descriptor",
                    ..
                },
                cleanup: None,
            }
        ));
        assert_eq!(exchange.starts, 0);
    }

    #[test]
    fn descriptor_session_accepts_four_roles_and_rejects_a_fifth() {
        let (control, child) = uapi::seqpacket_pair().unwrap();
        let roles = (0..5)
            .map(|_| child.as_fd().try_clone_to_owned().unwrap())
            .collect::<Vec<_>>();
        let request = session_request(
            Path::new("/definitely/absent/aos-test-program"),
            &[],
            control.as_fd(),
            roles,
            Duration::from_secs(1),
            1,
        );

        assert!(matches!(
            validate_session_request(&request),
            Err(Error::InvalidInput {
                field: "fixed process inherited descriptors",
                ..
            })
        ));

        let four_roles = session_request(
            Path::new("/definitely/absent/aos-test-program"),
            &[],
            control.as_fd(),
            request.inherited.into_iter().take(4).collect(),
            Duration::from_secs(1),
            1,
        );
        assert!(validate_session_request(&four_roles).is_ok());
    }

    #[test]
    fn terminal_and_unexpected_poll_flags_are_rejected() {
        assert!(validate_output_readiness(rustix::event::PollFlags::NVAL).is_err());
        assert!(validate_output_readiness(rustix::event::PollFlags::ERR).is_err());
        assert!(validate_output_readiness(rustix::event::PollFlags::PRI).is_err());

        let hangup = validate_control_readiness(
            rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP,
            FixedProcessControlInterest::Readable,
        )
        .unwrap();
        assert!(hangup.readable && hangup.hangup);
        assert!(
            validate_control_readiness(
                rustix::event::PollFlags::ERR,
                FixedProcessControlInterest::Readable,
            )
            .unwrap()
            .error
        );
        assert!(
            validate_control_readiness(
                rustix::event::PollFlags::NVAL,
                FixedProcessControlInterest::Writable,
            )
            .unwrap()
            .invalid
        );
        assert!(
            validate_control_readiness(
                rustix::event::PollFlags::PRI,
                FixedProcessControlInterest::Readable,
            )
            .is_err()
        );
    }

    fn run_isolated_case(case: &str) {
        let executable = std::env::current_exe().unwrap();
        let status = std::process::Command::new(executable)
            .args([
                "--ignored",
                "--exact",
                "process::session::tests::isolated_session_case",
                "--nocapture",
            ])
            .env(ISOLATED_CASE_ENVIRONMENT, case)
            .status()
            .unwrap();

        assert!(status.success(), "isolated session case {case} failed");
    }

    #[test]
    #[ignore = "launched alone by each public fixed-session regression"]
    fn isolated_session_case() {
        let Some(case) = std::env::var_os(ISOLATED_CASE_ENVIRONMENT) else {
            return;
        };
        let case = case.to_str().unwrap();
        if case == "spawn-failure" {
            assert_spawn_failure();
            return;
        }
        if case == "descriptor-layout" {
            assert_descriptor_layout();
            return;
        }

        let (control, child_control) = uapi::seqpacket_pair().unwrap();
        let executable = std::env::current_exe().unwrap();
        let arguments = child_arguments();
        let timeout = match case {
            "deadline" => Duration::from_millis(250),
            "delayed-callback" => Duration::from_secs(1),
            _ => Duration::from_secs(2),
        };
        let maximum = if case == "output-limit" {
            1024
        } else if case == "deadline" {
            4 << 20
        } else {
            1 << 20
        };
        let mut exchange = ScenarioExchange::new(case);
        if case == "early-exit" {
            // Keep an independent peer clone only in this classification test
            // so pidfd readiness, rather than peer HUP, drives the transition.
            // The dedicated HUP regression below transfers the sole child end.
            exchange.peer_hold = Some(child_control.as_fd().try_clone_to_owned().unwrap());
        }
        let started = monotonic_now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_fixed_process_session_under_libtest(
                session_request(
                    &executable,
                    &arguments,
                    control.as_fd(),
                    vec![child_control],
                    timeout,
                    maximum,
                ),
                &mut exchange,
            )
        }));
        let elapsed = monotonic_now().saturating_sub(started);

        assert_scenario_result(case, result, elapsed, &exchange);
    }

    fn assert_spawn_failure() {
        let (control, _child_control) = uapi::seqpacket_pair().unwrap();
        let mut exchange = ScenarioExchange::new("spawn-failure");
        let error = run_fixed_process_session_under_libtest(
            session_request(
                Path::new("/definitely/absent/aos-test-program"),
                &[],
                control.as_fd(),
                Vec::new(),
                Duration::from_secs(1),
                1,
            ),
            &mut exchange,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            FixedProcessSessionError::Process {
                source: Error::Syscall { source, .. },
                cleanup: None,
            } if source.raw_os_error() == Some(libc::ENOENT)
        ));
        assert_eq!(exchange.starts, 0);
        assert_eq!(exchange.advances, 0);
    }

    fn assert_descriptor_layout() {
        let (control, child_control) = uapi::seqpacket_pair().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let executable = temporary.path().join("fixed-descriptor-test");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o555);
        std::fs::set_permissions(&executable, permissions).unwrap();
        let retained_executable = std::fs::File::open(&executable).unwrap();
        let mut inherited = vec![child_control];
        for _ in 0..3 {
            inherited.push(std::fs::File::open("/dev/null").unwrap().into());
        }
        let mut exchange = DescriptorLayoutExchange;

        let outcome = run_descriptor_session_under_libtest(
            session_request(
                &executable,
                &child_arguments(),
                control.as_fd(),
                inherited,
                Duration::from_secs(2),
                4096,
            ),
            retained_executable.into(),
            &mut exchange,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            FixedProcessSessionOutcome::Completed {
                process: super::super::FixedProcessOutput {
                    exit_code: Some(0),
                    ..
                },
                exchange: true,
            }
        ));
    }

    struct DescriptorLayoutExchange;

    impl FixedProcessSessionExchange for DescriptorLayoutExchange {
        type Output = bool;
        type Error = Error;

        fn start(
            &mut self,
            _child: &FixedLiveChild<'_>,
            control: BorrowedFd<'_>,
        ) -> std::result::Result<ExchangeStep<Self::Output>, Self::Error> {
            send_record(control, b"R")?;
            Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
        }

        fn advance(
            &mut self,
            _child: &FixedLiveChild<'_>,
            control: BorrowedFd<'_>,
            _readiness: FixedProcessControlReadiness,
        ) -> std::result::Result<ExchangeStep<Self::Output>, Self::Error> {
            Ok(ExchangeStep::Complete(receive_record(control)? == b"K"))
        }
    }

    fn assert_scenario_result(
        case: &str,
        result: std::thread::Result<
            std::result::Result<
                FixedProcessSessionOutcome<&'static str>,
                FixedProcessSessionError<Error>,
            >,
        >,
        elapsed: Duration,
        exchange: &ScenarioExchange,
    ) {
        match case {
            "staged" => {
                let FixedProcessSessionOutcome::Completed {
                    process,
                    exchange: value,
                } = result.unwrap().unwrap()
                else {
                    panic!("staged exchange did not complete")
                };
                assert_eq!(value, "done");
                assert_eq!(process.exit_code, Some(0));
                assert!(process.stdout.windows(5).any(|bytes| bytes == b"first"));
                assert!(process.stdout.windows(6).any(|bytes| bytes == b"second"));
                assert_eq!(exchange.starts, 1);
                assert_eq!(exchange.advances, 2);
            }
            "output-limit" => assert_eq!(
                result.unwrap().unwrap(),
                FixedProcessSessionOutcome::OutputLimitExceeded
            ),
            "deadline" => {
                assert_eq!(
                    result.unwrap().unwrap(),
                    FixedProcessSessionOutcome::TimedOut
                );
                assert_eq!(exchange.starts, 1);
                assert_eq!(exchange.advances, 0);
                assert!(elapsed >= Duration::from_millis(250));
                assert!(elapsed < Duration::from_secs(2));
            }
            "delayed-callback" => {
                assert_eq!(
                    result.unwrap().unwrap(),
                    FixedProcessSessionOutcome::TimedOut
                );
                assert_eq!(exchange.starts, 1);
                assert_eq!(exchange.advances, 0);
                assert!(elapsed >= Duration::from_millis(1_200));
                assert!(elapsed < Duration::from_secs(3));
            }
            "early-exit" => {
                let FixedProcessSessionOutcome::ChildExitedBeforeExchange(process) =
                    result.unwrap().unwrap()
                else {
                    panic!("early exit was not classified")
                };
                assert_eq!(process.exit_code, Some(0));
            }
            "exchange-error" => {
                assert!(matches!(
                    result.unwrap().unwrap_err(),
                    FixedProcessSessionError::Exchange {
                        source: Error::InvalidInput {
                            field: "test exchange",
                            ..
                        },
                        cleanup: None,
                    }
                ));
                assert_retained_processes_dead(exchange);
            }
            "cleanup-failure" => {
                assert!(matches!(
                    result.unwrap().unwrap_err(),
                    FixedProcessSessionError::Exchange {
                        source: Error::InvalidInput {
                            field: "test exchange",
                            ..
                        },
                        cleanup: Some(Error::InvalidInput {
                            field: "fixed process cleanup test injection",
                            ..
                        }),
                    }
                ));
                let mut status = 0;
                // SAFETY: the recorded positive PID named this supervisor's
                // exact child; WNOHANG performs no blocking operation.
                let waited = unsafe {
                    libc::waitpid(
                        i32::try_from(exchange.child_pid.unwrap()).unwrap(),
                        &raw mut status,
                        libc::WNOHANG,
                    )
                };
                assert_eq!(waited, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECHILD)
                );
            }
            "panic" => {
                assert!(result.is_err());
                assert_retained_processes_dead(exchange);
            }
            "nonzero" => {
                let FixedProcessSessionOutcome::Completed { process, .. } =
                    result.unwrap().unwrap()
                else {
                    panic!("nonzero child did not complete after exchange")
                };
                assert_eq!(process.exit_code, Some(7));
                assert_eq!(process.signal, None);
            }
            "write-read" => {
                assert!(matches!(
                    result.unwrap().unwrap(),
                    FixedProcessSessionOutcome::Completed {
                        exchange: "done",
                        ..
                    }
                ));
                assert_eq!(exchange.readiness, vec![(false, true), (true, false)]);
            }
            "hangup" => {
                assert!(matches!(
                    result.unwrap().unwrap_err(),
                    FixedProcessSessionError::Process {
                        source: Error::InvalidInput {
                            field: "fixed process control descriptor",
                            ..
                        },
                        cleanup: None,
                    }
                ));
                assert_eq!(exchange.advances, 1);
                assert!(elapsed < Duration::from_secs(1));
            }
            _ => panic!("unknown isolated session case {case}"),
        }
    }

    fn assert_retained_processes_dead(exchange: &ScenarioExchange) {
        for process in [
            exchange.leader.as_ref().unwrap(),
            exchange.descendant.as_ref().unwrap(),
        ] {
            let deadline = monotonic_now() + Duration::from_secs(1);
            while process.is_alive().unwrap() && monotonic_now() < deadline {
                std::thread::yield_now();
            }
            assert!(!process.is_alive().unwrap());
        }
    }

    fn session_request<'a>(
        executable: &'a Path,
        arguments: &'a [OsString],
        control: BorrowedFd<'a>,
        inherited: Vec<OwnedFd>,
        timeout: Duration,
        maximum: usize,
    ) -> FixedProcessSessionRequest<'a> {
        FixedProcessSessionRequest {
            process: super::super::FixedProcessRequest {
                executable,
                arguments,
                timeout,
                maximum_stdout_bytes: maximum,
                maximum_stderr_bytes: maximum,
            },
            stdin: None,
            inherited,
            control,
        }
    }

    fn child_arguments() -> Vec<OsString> {
        ["--ignored", "--exact", CHILD_TEST, "--nocapture"]
            .into_iter()
            .map(OsString::from)
            .collect()
    }

    struct ScenarioExchange {
        case: &'static str,
        starts: usize,
        advances: usize,
        phase: usize,
        readiness: Vec<(bool, bool)>,
        leader: Option<PidFd>,
        descendant: Option<PidFd>,
        peer_hold: Option<OwnedFd>,
        cleanup_injection: Option<super::super::CleanupFailureInjection>,
        child_pid: Option<u32>,
    }

    impl ScenarioExchange {
        fn new(case: &str) -> Self {
            let case = match case {
                "staged" => "staged",
                "output-limit" => "output-limit",
                "deadline" => "deadline",
                "delayed-callback" => "delayed-callback",
                "early-exit" => "early-exit",
                "exchange-error" => "exchange-error",
                "cleanup-failure" => "cleanup-failure",
                "panic" => "panic",
                "nonzero" => "nonzero",
                "write-read" => "write-read",
                "hangup" => "hangup",
                "spawn-failure" => "spawn-failure",
                _ => panic!("unknown test exchange {case}"),
            };
            Self {
                case,
                starts: 0,
                advances: 0,
                phase: 0,
                readiness: Vec::new(),
                leader: None,
                descendant: None,
                peer_hold: None,
                cleanup_injection: None,
                child_pid: None,
            }
        }

        fn command(&self) -> u8 {
            match self.case {
                "staged" => b'S',
                "output-limit" => b'X',
                "deadline" => b'T',
                "delayed-callback" => b'L',
                "early-exit" => b'E',
                "exchange-error" => b'D',
                "cleanup-failure" => b'F',
                "panic" => b'P',
                "nonzero" => b'N',
                "hangup" => b'H',
                "write-read" => b'O',
                _ => b'?',
            }
        }

        fn retain_leader(&mut self, child: &FixedLiveChild<'_>) -> Result<()> {
            let descriptor = child
                .pidfd()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|source| Error::Syscall {
                    operation: "duplicate test leader pidfd",
                    source,
                })?;
            self.leader = Some(PidFd::from_owned(descriptor)?);
            Ok(())
        }
    }

    impl FixedProcessSessionExchange for ScenarioExchange {
        type Output = &'static str;
        type Error = Error;

        fn start(
            &mut self,
            child: &FixedLiveChild<'_>,
            control: BorrowedFd<'_>,
        ) -> std::result::Result<ExchangeStep<Self::Output>, Self::Error> {
            self.starts += 1;
            assert!(child.initial_info().pid() > 0);
            assert!(child.deadline() > monotonic_now());
            if self.case == "cleanup-failure" {
                self.child_pid = Some(child.initial_info().pid());
                self.cleanup_injection = Some(super::super::inject_cleanup_failure_once());
                return Err(Error::invalid("test exchange", "intentional failure"));
            }
            if self.case == "write-read" {
                return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Writable));
            }
            send_record(control, &[self.command()])?;
            if self.case == "delayed-callback" {
                // Deliberately violate the callback latency contract to prove
                // that the supervisor checks, but cannot preempt, its return.
                std::thread::sleep(Duration::from_millis(1_200));
            }
            Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
        }

        fn advance(
            &mut self,
            child: &FixedLiveChild<'_>,
            control: BorrowedFd<'_>,
            readiness: FixedProcessControlReadiness,
        ) -> std::result::Result<ExchangeStep<Self::Output>, Self::Error> {
            self.advances += 1;
            self.readiness
                .push((readiness.is_readable(), readiness.is_writable()));
            if self.case == "write-read" && self.phase == 0 {
                assert!(readiness.is_writable());
                send_record(control, &[self.command()])?;
                self.phase = 1;
                return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable));
            }

            let record = receive_record(control)?;
            match self.case {
                "staged" if self.phase == 0 => {
                    assert_eq!(record, b"A");
                    send_record(control, b"C")?;
                    self.phase = 1;
                    Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
                }
                "staged" => {
                    assert_eq!(record, b"B");
                    send_record(control, b"K")?;
                    Ok(ExchangeStep::Complete("done"))
                }
                "nonzero" | "write-read" => {
                    assert_eq!(record, b"K");
                    send_record(control, b"A")?;
                    Ok(ExchangeStep::Complete("done"))
                }
                "exchange-error" | "panic" => {
                    assert_eq!(record.len(), 4);
                    let pid = u32::from_le_bytes(record.try_into().unwrap());
                    self.retain_leader(child)?;
                    self.descendant = Some(PidFd::open(std::num::NonZeroU32::new(pid).unwrap())?);
                    if self.case == "panic" {
                        panic!("intentional exchange panic")
                    }
                    Err(Error::invalid("test exchange", "intentional failure"))
                }
                "hangup" => {
                    assert!(record.is_empty());
                    Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
                }
                _ => Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable)),
            }
        }
    }

    fn send_record(descriptor: BorrowedFd<'_>, record: &[u8]) -> Result<()> {
        let sent = uapi::send_seqpacket(descriptor, record)?;
        if sent != record.len() {
            return Err(Error::MalformedKernelResponse {
                object: "test session send",
                message: "sequenced packet was partially sent".to_owned(),
            });
        }
        Ok(())
    }

    fn receive_record(descriptor: BorrowedFd<'_>) -> Result<Vec<u8>> {
        let mut payload = [0_u8; 64];
        let received = uapi::recv_seqpacket(descriptor, &mut payload, 0)?;
        Ok(payload[..received.bytes].to_vec())
    }

    #[test]
    #[ignore = "launched only as a fixed session child"]
    fn session_child_fixture() {
        // SAFETY: the fixed descriptor request maps the connected child endpoint
        // to FD 3 for the lifetime of this isolated fixture.
        let control = unsafe { BorrowedFd::borrow_raw(3) };
        let command = receive_record_waiting(control);
        match command.as_slice() {
            b"S" => {
                write_stdout(b"first");
                send_record_waiting(control, b"A");
                assert_eq!(receive_record_waiting(control), b"C");
                write_stdout(b"second");
                send_record_waiting(control, b"B");
                assert_eq!(receive_record_waiting(control), b"K");
            }
            b"X" => {
                write_stdout(&vec![b'x'; 8192]);
                std::thread::sleep(Duration::from_secs(10));
            }
            b"T" => loop {
                // One enforced sleep per 8 KiB pair caps each stream near
                // 2 MiB in 250 ms, so the 4 MiB ceiling cannot win first.
                write_stdout(&[b't'; 8192]);
                write_stderr(&[b'e'; 8192]);
                std::thread::sleep(Duration::from_millis(1));
            },
            b"L" => std::thread::sleep(Duration::from_secs(10)),
            b"E" => {}
            b"D" | b"P" => {
                let executable = std::env::current_exe().unwrap();
                let descendant = std::process::Command::new(executable)
                    .args(["--ignored", "--exact", DESCENDANT_TEST, "--nocapture"])
                    .spawn()
                    .unwrap();
                send_record_waiting(control, &descendant.id().to_le_bytes());
                std::mem::forget(descendant);
                std::thread::sleep(Duration::from_secs(10));
            }
            b"F" => std::thread::sleep(Duration::from_secs(10)),
            b"N" => {
                send_record_waiting(control, b"K");
                assert_eq!(receive_record_waiting(control), b"A");
                std::process::exit(7);
            }
            b"O" => {
                send_record_waiting(control, b"K");
                assert_eq!(receive_record_waiting(control), b"A");
            }
            b"H" => {
                // SAFETY: FD 3 is this fixture's owned inherited descriptor;
                // closing it deliberately produces HUP at the parent endpoint.
                assert_eq!(unsafe { libc::close(3) }, 0);
                std::thread::sleep(Duration::from_secs(10));
            }
            b"R" => {
                let roles_present = (0..=7).all(|fd| {
                    // SAFETY: F_GETFD only inspects the numbered descriptor.
                    (unsafe { libc::fcntl(fd, libc::F_GETFD) }) >= 0
                });
                // SAFETY: F_GETFD cannot create a descriptor or change state.
                let error_absent = unsafe { libc::fcntl(8, libc::F_GETFD) } == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
                send_record_waiting(
                    control,
                    if roles_present && error_absent {
                        b"K"
                    } else {
                        b"X"
                    },
                );
            }
            other => panic!("unknown child command {other:?}"),
        }
    }

    #[test]
    #[ignore = "launched only as a same-group session descendant"]
    fn session_descendant_waits() {
        std::thread::sleep(Duration::from_secs(10));
    }

    fn receive_record_waiting(descriptor: BorrowedFd<'_>) -> Vec<u8> {
        loop {
            match receive_record(descriptor) {
                Ok(record) => return record,
                Err(Error::Syscall { source, .. })
                    if matches!(source.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) =>
                {
                    std::thread::yield_now();
                }
                Err(error) => panic!("fixture receive failed: {error}"),
            }
        }
    }

    fn send_record_waiting(descriptor: BorrowedFd<'_>, record: &[u8]) {
        loop {
            match send_record(descriptor, record) {
                Ok(()) => return,
                Err(Error::Syscall { source, .. })
                    if matches!(source.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) =>
                {
                    std::thread::yield_now();
                }
                Err(error) => panic!("fixture send failed: {error}"),
            }
        }
    }

    fn write_stdout(bytes: &[u8]) {
        write_output(libc::STDOUT_FILENO, bytes);
    }

    fn write_stderr(bytes: &[u8]) {
        write_output(libc::STDERR_FILENO, bytes);
    }

    fn write_output(descriptor: libc::c_int, bytes: &[u8]) {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            // SAFETY: the selected standard stream is a live pipe in this fixed
            // child and the slice remains readable for the complete call.
            let count =
                unsafe { libc::write(descriptor, remaining.as_ptr().cast(), remaining.len()) };
            assert!(count > 0, "fixture output write failed");
            remaining = &remaining[usize::try_from(count).unwrap()..];
        }
    }

    #[test]
    fn error_display_includes_secondary_cleanup_failure() {
        let error = FixedProcessSessionError::<Error>::Process {
            source: Error::invalid("primary", "failed"),
            cleanup: Some(Error::invalid("cleanup", "also failed")),
        };
        let display = error.to_string();

        assert!(display.contains("primary"));
        assert!(display.contains("cleanup also failed"));
    }

    #[test]
    fn poll_interest_contains_only_read_and_write_bits() {
        assert_eq!(
            FixedProcessControlInterest::Readable.poll_flags(),
            rustix::event::PollFlags::IN
        );
        assert_eq!(
            FixedProcessControlInterest::Writable.poll_flags(),
            rustix::event::PollFlags::OUT
        );
        assert_eq!(
            FixedProcessControlInterest::ReadableOrWritable.poll_flags(),
            rustix::event::PollFlags::IN | rustix::event::PollFlags::OUT
        );
    }

    #[test]
    fn leader_exit_discards_pending_control_interest() {
        let mut state = SessionState::<()>::pending();
        state.apply(ExchangeStep::Pending(FixedProcessControlInterest::Readable));

        state.mark_leader_exited();

        assert!(state.leader_exited);
        assert_eq!(state.interest, None);
    }
}
