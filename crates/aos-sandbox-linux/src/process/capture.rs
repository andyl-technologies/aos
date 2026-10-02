//! Caller-held bounded output and historical observations for one fixed session.
//!
//! Public capture types expose in-memory historical DATA, not a capability,
//! live session, currentness witness or drain receipt. The private `SessionRun`
//! temporarily owns the actual child and readers with an exclusive reservoir
//! loan. Only actual reads establish EOF. Group cancellation and exact leader
//! reaping do not prove descendant or repository-owner drain; exact wait can
//! block even though terminal output reads are finite and nonblocking.
//! A borrowed reservoir survives callback unwind when its caller retains it;
//! worker abort, OOM, SIGKILL and dropping the reservoir do not preserve it.

use std::collections::TryReserveError;
use std::fmt;
use std::os::fd::AsFd as _;

use crate::{Error, Result};
use crate::pidfd::PidFd;

use super::{
    ChildGuard, CleanupDisposition, FixedProcessRequest, OutputStream, ProcessStatus, SpawnedProcess,
    decode_status, kernel_error, set_nonblocking,
    wait_status_blocking, wait_status_once,
};
use super::session::FixedProcessSessionError;

const OUTPUT_CHUNK: usize = 8192;
const CLEANUP_ERRORS: usize = 10;
const CLEANUP_INTERRUPTS: usize = 16;
const INVALID_WAIT_MESSAGE: &str = "wait returned neither exit nor signal termination";

/// Describes the observed execution stage of the original child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedProcessDispatchV1 {
    /// No successful fork has been handed to the session.
    NoChildProduced,
    /// The actual fork is retained, but entry into the executable is unknown.
    ChildOwned,
    /// Zero-byte exec-status EOF and live original-child observation succeeded.
    ExecConfirmed,
    /// The child returned the original exec-status errno record.
    ExecRejected,
}

/// Describes why the retained supervisor stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedProcessStopV1 {
    /// The session has not reached a stop observation.
    Running,
    /// The exchange and original leader reached completion.
    Completed,
    /// The leader exited before exchange completion.
    ChildExitedBeforeExchange,
    /// The original absolute supervisor deadline expired.
    TimedOut,
    /// Standard output crossed its byte ceiling.
    StdoutLimit,
    /// Standard error crossed its byte ceiling.
    StderrLimit,
    /// A process/exchange failure or selected drive cancellation was observed.
    Error,
    /// Unwinding interrupted the call; the original panic was not converted.
    Unwound,
}

/// Describes bounded capture completeness without asserting process-tree drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedProcessCapturedStreamV1 {
    /// No child output stream has been handed to the session.
    Unobserved,
    /// No EOF was observed; unread or future bytes may exist.
    Incomplete,
    /// A real zero-length read established EOF on this pipe.
    Eof,
    /// A read contained bytes beyond the retained ceiling.
    Truncated,
}

/// Exposes historical observations written only by the fixed supervisor.
#[derive(Debug)]
pub struct FixedProcessCaptureObservationV1 {
    dispatch: FixedProcessDispatchV1,
    stop: FixedProcessStopV1,
    stdout: FixedProcessCapturedStreamV1,
    stderr: FixedProcessCapturedStreamV1,
    exit_code: Option<i32>,
    signal: Option<i32>,
    reaped: bool,
    ownership_lost: bool,
    returned_cleanup_error: bool,
}

impl FixedProcessCaptureObservationV1 {
    /// Returns the observed original-child execution stage.
    #[must_use]
    pub const fn dispatch(&self) -> FixedProcessDispatchV1 {
        self.dispatch
    }

    /// Returns the original stop trigger, even if cleanup subsequently failed.
    #[must_use]
    pub const fn stop(&self) -> FixedProcessStopV1 {
        self.stop
    }

    /// Returns standard-output completeness.
    #[must_use]
    pub const fn stdout(&self) -> FixedProcessCapturedStreamV1 {
        self.stdout
    }

    /// Returns standard-error completeness.
    #[must_use]
    pub const fn stderr(&self) -> FixedProcessCapturedStreamV1 {
        self.stderr
    }

    /// Returns a status obtained only from successful exact-child wait.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Returns a terminating signal obtained only from exact-child wait.
    #[must_use]
    pub const fn signal(&self) -> Option<i32> {
        self.signal
    }

    /// Reports that the exact child was consumed by a successful wait.
    #[must_use]
    pub const fn reaped(&self) -> bool {
        self.reaped
    }

    /// Reports ECHILD and loss of numerical unreaped-child ownership.
    #[must_use]
    pub const fn ownership_lost(&self) -> bool {
        self.ownership_lost
    }

    /// Reports that the returned typed error owns the first cleanup cause.
    #[must_use]
    pub const fn returned_cleanup_error(&self) -> bool {
        self.returned_cleanup_error
    }
}

/// Retains both bounded output streams across return and callback unwind.
///
/// The type is move-only and has no descriptor, output or authority factory.
/// Keep it outside the call's unwind scope to retain observations after panic.
/// It cannot be reused after a child has been handed to the supervisor.
#[derive(Debug)]
pub struct FixedProcessCaptureV1 {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    observation: FixedProcessCaptureObservationV1,
    errors: Vec<Error>,
    invalid_wait_message: String,
}

impl FixedProcessCaptureV1 {
    /// Creates an empty DATA reservoir without an execution or output claim.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            observation: FixedProcessCaptureObservationV1 {
                dispatch: FixedProcessDispatchV1::NoChildProduced,
                stop: FixedProcessStopV1::Running,
                stdout: FixedProcessCapturedStreamV1::Unobserved,
                stderr: FixedProcessCapturedStreamV1::Unobserved,
                exit_code: None,
                signal: None,
                reaped: false,
                ownership_lost: false,
                returned_cleanup_error: false,
            },
            errors: Vec::new(),
            invalid_wait_message: String::new(),
        }
    }

    /// Borrows every retained standard-output byte without copying it.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Borrows every retained standard-error byte without copying it.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Borrows historical observations, never currentness or drain authority.
    #[must_use]
    pub const fn observation(&self) -> &FixedProcessCaptureObservationV1 {
        &self.observation
    }

    /// Borrows additional concrete cleanup and terminal capture failures.
    ///
    /// The first normal cleanup error is owned by the returned session error.
    /// During unwind all observed cleanup failures remain here.
    #[must_use]
    pub fn additional_cleanup_errors(&self) -> &[Error] {
        &self.errors
    }

    /// Moves the complete retained DATA into independently owned parts.
    #[must_use]
    pub fn into_retained_parts(self) -> FixedProcessCapturePartsV1 {
        FixedProcessCapturePartsV1 {
            stdout: self.stdout,
            stderr: self.stderr,
            observation: self.observation,
            additional_cleanup_errors: self.errors,
        }
    }

    pub(super) fn prepare<E>(
        &mut self,
        request: FixedProcessRequest<'_>,
    ) -> std::result::Result<(), FixedProcessRetainedSessionError<E>> {
        self.prepare_limits(request.maximum_stdout_bytes, request.maximum_stderr_bytes)
    }

    pub(super) fn prepare_limits<E>(
        &mut self,
        maximum_stdout_bytes: usize,
        maximum_stderr_bytes: usize,
    ) -> std::result::Result<(), FixedProcessRetainedSessionError<E>> {
        if self.observation.dispatch != FixedProcessDispatchV1::NoChildProduced {
            return Err(FixedProcessRetainedSessionError::Session(
                FixedProcessSessionError::Process {
                    source: Error::invalid("fixed process capture", "has already retained a child"),
                    cleanup: None,
                },
            ));
        }

        maximum_stdout_bytes
            .checked_add(maximum_stderr_bytes)
            .ok_or_else(|| FixedProcessRetainedSessionError::Session(
                FixedProcessSessionError::Process {
                    source: Error::invalid(
                        "fixed process capture",
                        "aggregate byte ceiling overflows",
                    ),
                    cleanup: None,
                },
            ))?;

        self.stdout
            .try_reserve_exact(maximum_stdout_bytes)
            .map_err(FixedProcessRetainedSessionError::CaptureAllocation)?;
        self.stderr
            .try_reserve_exact(maximum_stderr_bytes)
            .map_err(FixedProcessRetainedSessionError::CaptureAllocation)?;
        self.errors
            .try_reserve_exact(CLEANUP_ERRORS)
            .map_err(FixedProcessRetainedSessionError::CaptureAllocation)?;
        self.invalid_wait_message
            .try_reserve_exact(INVALID_WAIT_MESSAGE.len())
            .map_err(FixedProcessRetainedSessionError::CaptureAllocation)?;

        if self.invalid_wait_message.is_empty() {
            self.invalid_wait_message.push_str(INVALID_WAIT_MESSAGE);
        }

        Ok(())
    }

    fn record_error(&mut self, error: Error) {
        // At most seven secondary errors on normal return and five on unwind
        // fit ten pre-reserved slots. Retained Drop must not allocate.
        self.errors.push(error);
    }
}

impl Default for FixedProcessCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Owns the output, observations and typed diagnostics from one consumed capture.
#[derive(Debug)]
pub struct FixedProcessCapturePartsV1 {
    /// Bounded original standard output.
    pub stdout: Vec<u8>,
    /// Bounded original standard error.
    pub stderr: Vec<u8>,
    /// Historical observations, not a live session or drain receipt.
    pub observation: FixedProcessCaptureObservationV1,
    /// Concrete secondary failures not already owned by the returned error.
    pub additional_cleanup_errors: Vec<Error>,
}

/// Classifies a session while its caller-held reservoir owns output exactly once.
#[derive(Debug, Eq, PartialEq)]
pub enum FixedProcessRetainedSessionOutcome<T> {
    /// The exchange completed and exact-child wait supplied terminal status.
    Completed {
        /// Original child exit code, if it exited normally.
        exit_code: Option<i32>,
        /// Original child terminating signal, if it was signaled.
        signal: Option<i32>,
        /// Completed exchange value.
        exchange: T,
    },
    /// Exact-child wait completed before the exchange produced a value.
    ChildExitedBeforeExchange {
        /// Original child exit code.
        exit_code: Option<i32>,
        /// Original child terminating signal.
        signal: Option<i32>,
    },
    /// The original monotonic deadline expired.
    TimedOut,
    /// One original output ceiling was exceeded.
    OutputLimitExceeded,
}

/// Retains original typed session causes and fallible pre-fork reservations.
#[derive(Debug)]
pub enum FixedProcessRetainedSessionError<E> {
    /// Reserving bounded capture storage failed before a child was forked.
    CaptureAllocation(TryReserveError),
    /// The original concrete process, exchange or cleanup error.
    Session(FixedProcessSessionError<E>),
}

impl<E: fmt::Display> fmt::Display for FixedProcessRetainedSessionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureAllocation(source) => write!(
                formatter,
                "fixed process capture reservation failed: {source}",
            ),
            Self::Session(source) => fmt::Display::fmt(source, formatter),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::error::Error
    for FixedProcessRetainedSessionError<E>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CaptureAllocation(source) => Some(source),
            Self::Session(source) => Some(source),
        }
    }
}

/// Keeps child ownership, pipe buffers and the external capture loan together.
enum CaptureDestination<'a> {
    Local,
    Retained(RetainedCapture<'a>),
}

enum RetainedCapture<'a> {
    Borrowed(&'a mut FixedProcessCaptureV1),
    Resident(FixedProcessCaptureV1),
}

impl CaptureDestination<'_> {
    fn as_mut(&mut self) -> Option<&mut FixedProcessCaptureV1> {
        match self {
            Self::Local => None,
            Self::Retained(RetainedCapture::Borrowed(capture)) => Some(capture),
            Self::Retained(RetainedCapture::Resident(capture)) => Some(capture),
        }
    }

    fn as_ref(&self) -> Option<&FixedProcessCaptureV1> {
        match self {
            Self::Local => None,
            Self::Retained(RetainedCapture::Borrowed(capture)) => Some(capture),
            Self::Retained(RetainedCapture::Resident(capture)) => Some(capture),
        }
    }
}

pub(super) struct SessionRun<'a> {
    // Legacy locals dropped stderr, then stdout, then the child guard. Retain
    // that order even when a callback unwinds through the shared run owner.
    pub(super) stderr: OutputStream,
    pub(super) stdout: OutputStream,
    pub(super) guard: ChildGuard,
    pub(super) exec_status: Option<crate::uapi::FixedExecStatusReader>,
    capture: CaptureDestination<'a>,
    cleanup_passes: u8,
    terminal: Option<[TerminalCaptureState; 2]>,
    terminal_settled: bool,
}

impl<'a> SessionRun<'a> {
    pub(super) fn legacy(guard: ChildGuard, stdout: OutputStream, stderr: OutputStream) -> Self {
        Self {
            guard,
            stdout,
            stderr,
            exec_status: None,
            capture: CaptureDestination::Local,
            cleanup_passes: 0,
            terminal: None,
            terminal_settled: false,
        }
    }

    pub(super) fn retained(
        spawned: SpawnedProcess,
        process: FixedProcessRequest<'_>,
        capture: &'a mut FixedProcessCaptureV1,
    ) -> Self {
        Self::retained_destination(
            spawned, process.maximum_stdout_bytes, process.maximum_stderr_bytes,
            RetainedCapture::Borrowed(capture),
        )
    }

    pub(super) fn resident(
        spawned: SpawnedProcess,
        maximum_stdout_bytes: usize,
        maximum_stderr_bytes: usize,
        capture: FixedProcessCaptureV1,
    ) -> SessionRun<'static> {
        SessionRun::retained_destination(
            spawned, maximum_stdout_bytes, maximum_stderr_bytes,
            RetainedCapture::Resident(capture),
        )
    }

    fn retained_destination(
        spawned: SpawnedProcess,
        maximum_stdout_bytes: usize,
        maximum_stderr_bytes: usize,
        mut destination: RetainedCapture<'a>,
    ) -> Self {
        // The closed retained destination makes the post-fork handoff infallible.
        let capture = match &mut destination {
            RetainedCapture::Borrowed(capture) => &mut **capture,
            RetainedCapture::Resident(capture) => capture,
        };
        capture.observation.dispatch = FixedProcessDispatchV1::ChildOwned;
        capture.observation.stdout = FixedProcessCapturedStreamV1::Incomplete;
        capture.observation.stderr = FixedProcessCapturedStreamV1::Incomplete;
        Self {
            guard: spawned.guard,
            stdout: OutputStream {
                descriptor: spawned.stdout,
                bytes: std::mem::take(&mut capture.stdout),
                maximum: maximum_stdout_bytes,
                closed: false,
            },
            stderr: OutputStream {
                descriptor: spawned.stderr,
                bytes: std::mem::take(&mut capture.stderr),
                maximum: maximum_stderr_bytes,
                closed: false,
            },
            exec_status: spawned.exec_status,
            capture: CaptureDestination::Retained(destination),
            cleanup_passes: 0,
            terminal: None,
            terminal_settled: false,
        }
    }

    pub(super) fn initialize_retained(&mut self) -> Result<()> {
        let pid = std::num::NonZeroU32::new(
            u32::try_from(self.guard.pid.as_raw_nonzero().get())
                .map_err(|_| Error::invalid("fixed process PID", "must be a positive u32"))?,
        )
        .ok_or_else(|| Error::invalid("fixed process PID", "must be a positive u32"))?;

        self.guard.attach_pidfd(PidFd::open(pid)?);
        set_nonblocking(&self.stdout.descriptor)?;
        set_nonblocking(&self.stderr.descriptor)?;
        if let Some(status) = &mut self.exec_status {
            status.enable_nonblocking()?;
        }

        Ok(())
    }

    pub(super) fn stop(&mut self, stop: FixedProcessStopV1) {
        if let Some(capture) = self.capture.as_mut() {
            capture.observation.stop = stop;
        }
    }

    pub(super) fn limit(&mut self, stdout: bool) {
        if let Some(capture) = self.capture.as_mut() {
            let observation = &mut capture.observation;
            if stdout {
                observation.stdout = FixedProcessCapturedStreamV1::Truncated;
                observation.stop = FixedProcessStopV1::StdoutLimit;
            } else {
                observation.stderr = FixedProcessCapturedStreamV1::Truncated;
                observation.stop = FixedProcessStopV1::StderrLimit;
            }
        }
    }

    pub(super) fn exec_confirmed(&mut self) {
        if let Some(capture) = self.capture.as_mut() {
            capture.observation.dispatch = FixedProcessDispatchV1::ExecConfirmed;
        }
    }

    pub(super) fn exec_failed(&mut self, error: &Error) {
        if matches!(
            error,
            Error::Syscall {
                operation: "execveat fixed descriptor process",
                ..
            }
        ) {
            if let Some(capture) = self.capture.as_mut() {
                capture.observation.dispatch = FixedProcessDispatchV1::ExecRejected;
            }
        }
    }

    pub(super) fn retains_output(&self) -> bool {
        self.capture.as_ref().is_some()
    }

    pub(super) fn cleanup_error_returned(&mut self) {
        if let Some(capture) = self.capture.as_mut() {
            capture.observation.returned_cleanup_error = true;
        }
    }

    pub(super) fn cancel_and_reap(&mut self) -> Result<ProcessStatus> {
        let Some(capture) = self.capture.as_mut() else {
            return self.guard.cancel_and_reap();
        };

        self.cleanup_passes += 1;
        let (first, status) = observed_cleanup(&mut self.guard, capture);

        match (first, status) {
            (Some(error), _) => Err(error),
            (None, Some(status)) => Ok(status),
            (None, None) => Err(Error::invalid("fixed process cleanup", "omitted terminal status")),
        }
    }

    pub(super) fn capture(&self) -> Option<&FixedProcessCaptureV1> {
        self.capture.as_ref()
    }

    pub(super) fn record_driven_error(&mut self, source: Error) {
        if let Some(capture) = self.capture.as_mut() {
            capture.record_error(source);
        }
    }

    pub(super) fn take_ended_capture(&mut self) -> Option<FixedProcessCaptureV1> {
        if self.guard.armed || !self.terminal_settled {
            return None;
        }
        if !matches!(self.capture, CaptureDestination::Retained(RetainedCapture::Resident(_))) {
            return None;
        }
        match std::mem::replace(&mut self.capture, CaptureDestination::Local) {
            CaptureDestination::Retained(RetainedCapture::Resident(capture)) => Some(capture),
            _ => None,
        }
    }

    /// Signals only once during borrowed driving. Parent Drop owns the second
    /// original fallback pass; Pending waits never repeat this signal stage.
    pub(super) fn signal_driven_cleanup(&mut self) -> Result<()> {
        if !self.guard.armed || self.cleanup_passes != 0 {
            return Ok(());
        }
        self.cleanup_passes = 1;
        let Some(capture) = self.capture.as_mut() else {
            return self.guard.cancel();
        };
        let mut first = None;
        let signals = self.guard.cancel_with_disposition(CleanupDisposition::Retained {
            first: &mut first, capture,
        });
        record_cleanup_result(signals, &mut first, capture);
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Calls the sole exact-child wait engine without blocking or reaping any
    /// other child. The common observer owns ECHILD/disarm and status semantics.
    pub(super) fn poll_driven_reap(&mut self) -> Result<Option<ProcessStatus>> {
        let result = match wait_status_once(self.guard.pid, rustix::process::WaitOptions::NOHANG) {
            Ok(status) => Ok(status),
            Err(rustix::io::Errno::INTR) => Ok(None),
            Err(error) => Err(kernel_error("reap fixed process", error)),
        };
        let Some(capture) = self.capture.as_mut() else {
            return Err(Error::invalid("fixed process driven capture", "is absent"));
        };
        let mut first = None;
        let status = observe_wait_result(&mut self.guard, capture, result, &mut first);
        match first {
            Some(error) => Err(error),
            None => Ok(status),
        }
    }

    /// Takes one finite terminal read, keeping stdout-before-stderr priority.
    pub(super) fn settle_driven_capture_once(&mut self) -> bool {
        if self.terminal_settled {
            return true;
        }
        let states = self.terminal.get_or_insert_with(|| [
            TerminalCaptureState::new(), TerminalCaptureState::new(),
        ]);
        let Some(capture) = self.capture.as_mut() else {
            return false;
        };
        if !states[0].finished {
            terminal_capture_once(
                &mut self.stdout, &mut capture.observation.stdout, &mut capture.errors,
                &mut states[0],
            );
        } else if !states[1].finished {
            terminal_capture_once(
                &mut self.stderr, &mut capture.observation.stderr, &mut capture.errors,
                &mut states[1],
            );
        }
        if states[0].finished && states[1].finished {
            capture.stdout = std::mem::take(&mut self.stdout.bytes);
            capture.stderr = std::mem::take(&mut self.stderr.bytes);
            self.terminal_settled = true;
        }
        self.terminal_settled
    }
}

impl Drop for SessionRun<'_> {
    fn drop(&mut self) {
        let Some(capture) = self.capture.as_mut() else {
            return;
        };

        if std::thread::panicking() {
            capture.observation.stop = FixedProcessStopV1::Unwound;
        }
        if self.guard.armed && self.cleanup_passes < 2 {
            self.cleanup_passes += 1;
            let (first, _) = observed_cleanup(&mut self.guard, capture);
            if let Some(error) = first {
                capture.record_error(error);
            }
        }

        // All attempts are now accounted for. In particular, ECHILD must not
        // reach ChildGuard's numerical signaling fallback on a recycled PID.
        self.guard.armed = false;
        if self.terminal_settled {
            return;
        }
        if let Some(states) = &mut self.terminal {
            finish_terminal_capture(
                &mut self.stdout, &mut capture.observation.stdout, &mut capture.errors,
                &mut states[0],
            );
            finish_terminal_capture(
                &mut self.stderr, &mut capture.observation.stderr, &mut capture.errors,
                &mut states[1],
            );
        } else {
            terminal_capture(
                &mut self.stdout,
                &mut capture.observation.stdout,
                &mut capture.errors,
            );
            terminal_capture(
                &mut self.stderr,
                &mut capture.observation.stderr,
                &mut capture.errors,
            );
        }

        capture.stdout = std::mem::take(&mut self.stdout.bytes);
        capture.stderr = std::mem::take(&mut self.stderr.bytes);
    }
}

/// Performs the same signaling/wait operations without short-circuiting errors.
fn observed_cleanup(
    guard: &mut ChildGuard,
    capture: &mut FixedProcessCaptureV1,
) -> (Option<Error>, Option<ProcessStatus>) {
    let mut first = None;
    let signals = guard.cancel_with_disposition(CleanupDisposition::Retained {
        first: &mut first,
        capture,
    });
    record_cleanup_result(signals, &mut first, capture);

    let result = wait_status_blocking(guard.pid).map(Some);
    let status = observe_wait_result(guard, capture, result, &mut first);
    (first, status)
}

/// Sole decoder/bookend for blocking and nonblocking exact-child observations.
fn observe_wait_result(
    guard: &mut ChildGuard,
    capture: &mut FixedProcessCaptureV1,
    result: Result<Option<rustix::process::WaitStatus>>,
    first: &mut Option<Error>,
) -> Option<ProcessStatus> {
    match result {
        Ok(Some(raw)) => {
            guard.armed = false;
            capture.observation.reaped = true;
            if raw.exited() || raw.signaled() {
                match decode_status(raw) {
                    Ok(status) => {
                        capture.observation.exit_code = status.exit_code;
                        capture.observation.signal = status.signal;
                        Some(status)
                    }
                    Err(error) => {
                        record_cleanup_result(Err(error), first, capture);
                        None
                    }
                }
            } else {
                record_cleanup_result(
                    Err(Error::InvalidInput {
                        field: "fixed process status",
                        message: std::mem::take(&mut capture.invalid_wait_message),
                    }),
                    first,
                    capture,
                );
                None
            }
        }
        Ok(None) => None,
        Err(error) => {
            if matches!(
                &error,
                Error::Syscall { source, .. }
                    if source.raw_os_error() == Some(libc::ECHILD)
            ) {
                guard.armed = false;
                capture.observation.ownership_lost = true;
            }
            record_cleanup_result(Err(error), first, capture);
            None
        }
    }
}

pub(super) fn record_cleanup_result(
    result: Result<()>,
    first: &mut Option<Error>,
    capture: &mut FixedProcessCaptureV1,
) {
    if let Err(error) = result {
        if first.is_none() {
            *first = Some(error);
        } else {
            capture.record_error(error);
        }
    }
}

/// Makes finite nonblocking observations, never a descendant-drain assertion.
fn terminal_capture(
    stream: &mut OutputStream,
    completeness: &mut FixedProcessCapturedStreamV1,
    errors: &mut Vec<Error>,
) {
    finish_terminal_capture(stream, completeness, errors, &mut TerminalCaptureState::new());
}

struct TerminalCaptureState {
    prepared: bool,
    reads_left: usize,
    interrupts: usize,
    finished: bool,
}

impl TerminalCaptureState {
    const fn new() -> Self {
        Self { prepared: false, reads_left: 0, interrupts: 0, finished: false }
    }
}

fn finish_terminal_capture(
    stream: &mut OutputStream,
    completeness: &mut FixedProcessCapturedStreamV1,
    errors: &mut Vec<Error>,
    state: &mut TerminalCaptureState,
) {
    while !state.finished {
        terminal_capture_once(stream, completeness, errors, state);
    }
}

/// Shares the old finite read/interrupt budget; a driving yield never resets it.
fn terminal_capture_once(
    stream: &mut OutputStream,
    completeness: &mut FixedProcessCapturedStreamV1,
    errors: &mut Vec<Error>,
    state: &mut TerminalCaptureState,
) {
    if state.finished {
        return;
    }
    if !state.prepared {
        if stream.closed {
            if *completeness != FixedProcessCapturedStreamV1::Truncated {
                *completeness = FixedProcessCapturedStreamV1::Eof;
            }
            state.finished = true;
            return;
        }
        if let Err(error) = set_nonblocking(&stream.descriptor) {
            errors.push(error);
            state.finished = true;
            return;
        }
        let remaining = stream.maximum.saturating_sub(stream.bytes.len());
        state.reads_left = remaining / OUTPUT_CHUNK
            + usize::from(remaining % OUTPUT_CHUNK != 0) + 1;
        state.prepared = true;
    }

    let mut chunk = [0; OUTPUT_CHUNK];
    match rustix::io::read(&stream.descriptor, &mut chunk) {
        Ok(0) => {
            stream.closed = true;
            if *completeness != FixedProcessCapturedStreamV1::Truncated {
                *completeness = FixedProcessCapturedStreamV1::Eof;
            }
            state.finished = true;
        }
        Ok(count) => {
            state.reads_left -= 1;
            let available = stream.maximum.saturating_sub(stream.bytes.len());
            let retained = available.min(count);
            stream.bytes.extend_from_slice(&chunk[..retained]);
            if retained != count {
                *completeness = FixedProcessCapturedStreamV1::Truncated;
                state.finished = true;
            }
        }
        Err(rustix::io::Errno::AGAIN) => state.finished = true,
        Err(rustix::io::Errno::INTR) => state.interrupts += 1,
        Err(error) => {
            errors.push(kernel_error("read fixed process session output", error));
            state.finished = true;
        }
    }
    if state.reads_left == 0 || state.interrupts == CLEANUP_INTERRUPTS {
        state.finished = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_capture_makes_no_execution_or_eof_claim() {
        let capture = FixedProcessCaptureV1::new();

        assert!(capture.stdout().is_empty());
        assert!(capture.stderr().is_empty());
        assert_eq!(
            capture.observation().dispatch(),
            FixedProcessDispatchV1::NoChildProduced,
        );
        assert_eq!(
            capture.observation().stdout(),
            FixedProcessCapturedStreamV1::Unobserved,
        );
        assert!(!capture.observation().reaped());
    }

    fn request(stdout: usize, stderr: usize) -> FixedProcessRequest<'static> {
        FixedProcessRequest {
            executable: std::path::Path::new("/aos/fixed-test"),
            arguments: &[],
            timeout: std::time::Duration::from_secs(1),
            maximum_stdout_bytes: stdout,
            maximum_stderr_bytes: stderr,
        }
    }

    #[test]
    fn aggregate_overflow_is_rejected_without_a_child_claim() {
        let mut capture = FixedProcessCaptureV1::new();
        let error = capture
            .prepare::<std::io::Error>(request(usize::MAX, 1))
            .unwrap_err();

        assert!(matches!(
            error,
            FixedProcessRetainedSessionError::Session(
                FixedProcessSessionError::Process {
                    source: Error::InvalidInput {
                        field: "fixed process capture",
                        ..
                    },
                    cleanup: None,
                },
            )
        ));
        assert_eq!(
            capture.observation().dispatch(),
            FixedProcessDispatchV1::NoChildProduced,
        );
    }

    #[test]
    fn impossible_reservation_preserves_its_typed_cause() {
        let mut capture = FixedProcessCaptureV1::new();
        let error = capture
            .prepare::<std::io::Error>(request(usize::MAX, 0))
            .unwrap_err();

        assert!(matches!(
            error,
            FixedProcessRetainedSessionError::CaptureAllocation(_),
        ));
        assert_eq!(
            capture.observation().dispatch(),
            FixedProcessDispatchV1::NoChildProduced,
        );
    }

    fn terminal_pipe(
        bytes: &[u8],
        maximum: usize,
        eof: bool,
    ) -> (Vec<u8>, FixedProcessCapturedStreamV1) {
        let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        assert_eq!(rustix::io::write(&writer, bytes).unwrap(), bytes.len());
        let retained_writer = if eof {
            drop(writer);
            None
        } else {
            Some(writer)
        };
        let mut stream = OutputStream {
            descriptor: reader,
            bytes: Vec::with_capacity(maximum),
            maximum,
            closed: false,
        };
        let mut state = FixedProcessCapturedStreamV1::Incomplete;
        let mut errors = Vec::with_capacity(CLEANUP_ERRORS);

        terminal_capture(&mut stream, &mut state, &mut errors);

        assert!(errors.is_empty());
        drop(retained_writer);
        (stream.bytes, state)
    }

    #[test]
    fn terminal_crossing_read_retains_only_the_prefix_and_marks_truncation() {
        let (bytes, state) = terminal_pipe(b"twelve-bytes", 5, true);

        assert_eq!(bytes, b"twelv");
        assert_eq!(state, FixedProcessCapturedStreamV1::Truncated);
    }

    #[test]
    fn held_writer_remains_incomplete_without_false_eof() {
        let (bytes, state) = terminal_pipe(b"data", 8, false);

        assert_eq!(bytes, b"data");
        assert_eq!(state, FixedProcessCapturedStreamV1::Incomplete);
    }

    #[test]
    fn real_pipe_eof_is_observed_after_retaining_the_data() {
        let (bytes, state) = terminal_pipe(b"data", 8, true);

        assert_eq!(bytes, b"data");
        assert_eq!(state, FixedProcessCapturedStreamV1::Eof);
    }

    #[test]
    fn zero_ceiling_marks_positive_data_as_truncated() {
        let (bytes, state) = terminal_pipe(b"x", 0, true);

        assert!(bytes.is_empty());
        assert_eq!(state, FixedProcessCapturedStreamV1::Truncated);
    }
}
