//! Resident, output-only driving of the existing fixed descriptor supervisor.
//!
//! Preparation is pure DATA. A parent parks all original inputs before a loan
//! can perform effects. Dropping the loan closes and signals, but retains the
//! child, streams and first cause in that parent. Exact NOHANG waits use the
//! same observer as the synchronous supervisor. Parent destruction retains the
//! existing blocking cleanup fallback; neither endpoint proves owner drain.

use std::convert::Infallible;
use std::fmt;
use std::marker::PhantomData;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::rc::Rc;
use std::time::Duration;

use crate::{Error, Result, uapi};
use super::super::capture::{
    FixedProcessCapturePartsV1, FixedProcessCaptureV1, FixedProcessRetainedSessionError,
    FixedProcessRetainedSessionOutcome, FixedProcessStopV1, SessionRun,
};
use super::super::{FixedProcessRequest, PreparedInvocation, kernel_error};
use super::{
    ExchangeStep, FixedLiveChild, FixedProcessControlReadiness, FixedProcessSessionExchange,
    KernelDeadline, KernelExchange, KernelFailure, KernelState, KernelTurn,
    advance_session_kernel, validate_executable_descriptor, validate_exclusive_reaping_owner,
};

/// Owns the existing validated CStrings and mechanical output limits.
pub struct FixedProcessPreparedInvocationV1 {
    invocation: PreparedInvocation,
    maximum_stdout_bytes: usize,
    maximum_stderr_bytes: usize,
}

/// Prepares the sole fixed invocation without opening, sampling or launching.
///
/// # Errors
/// Returns the existing path, argument, timeout and output-limit errors.
pub fn prepare_fixed_process_driven_invocation_v1(
    request: FixedProcessRequest<'_>,
) -> Result<FixedProcessPreparedInvocationV1> {
    let invocation = PreparedInvocation::new(request)?;
    Ok(FixedProcessPreparedInvocationV1 {
        invocation,
        maximum_stdout_bytes: request.maximum_stdout_bytes,
        maximum_stderr_bytes: request.maximum_stderr_bytes,
    })
}

/// Transfers real descriptor inputs and the original capture, not permission.
pub struct FixedProcessDrivenInputsV1 {
    /// Actual executable descriptor for the existing LockedNoroot recipe.
    pub executable: OwnedFd,
    /// Actual standard input, or the existing `/dev/null` route when absent.
    pub stdin: Option<OwnedFd>,
    /// Actual contiguous child roles, bounded by the existing four-role limit.
    pub inherited: Vec<OwnedFd>,
    /// Original DATA reservoir, consumed without cloning its buffers.
    pub capture: FixedProcessCaptureV1,
}

/// Carries a finite exclusive BOOTTIME endpoint as nonauthorizing DATA.
#[derive(Clone, Copy, Debug)]
pub struct FixedProcessBoottimeCutV1(u64);

impl FixedProcessBoottimeCutV1 {
    /// Validates a numeric endpoint without sampling or asserting its origin.
    ///
    /// # Errors
    /// Rejects zero and the unbounded sentinel. The caller retains authority.
    pub fn new(exclusive_nanoseconds: u64) -> Result<Self> {
        if exclusive_nanoseconds == 0 || exclusive_nanoseconds == u64::MAX {
            return Err(Error::invalid(
                "fixed process BOOTTIME cut", "must be finite and nonzero"
            ));
        }

        Ok(Self(exclusive_nanoseconds))
    }

    /// Projects the original numeric endpoint without creating authority.
    #[must_use]
    pub const fn exclusive_nanoseconds(self) -> u64 {
        self.0
    }

    /// Samples the sole existing BOOTTIME reader against this DATA endpoint.
    /// This checks mechanics only; it authenticates no boot, owner or permit.
    ///
    /// # Errors
    /// Preserves actual clock failures and rejects the exclusive endpoint.
    pub fn check(self) -> Result<()> {
        if uapi::boottime_nanoseconds()? >= self.0 {
            return Err(Error::DeadlineExceeded {
                operation: "fixed process original BOOTTIME cut"
            });
        }

        Ok(())
    }
}

/// Owns the first actual driving failure, separately from cleanup debt.
pub enum FixedProcessDrivenCauseV1 {
    /// The shared kernel/process engine failed.
    Process(Error),
    /// Pre-fork capture reservation failed with its original allocator cause.
    CaptureAllocation(std::collections::TryReserveError),
    /// Reading the original clock failed.
    Clock(Error),
    /// Creating or arming the sole wake timer failed.
    Wake(Error),
    /// Registering or waiting in the caller's reactor failed.
    Reactor(std::io::Error),
    /// The immutable original exclusive endpoint expired.
    TimedOut,
    /// An original stream exceeded its bounded capture.
    OutputLimit,
    /// A borrowing drive was dropped before completing.
    Cancelled,
    /// A borrowing drive was unwound, without converting the panic.
    Unwound,
}

/// Owns finite typed cleanup sources with stable first-debt ordering.
/// Additional process-site errors remain in the same capture report. A wake or
/// reactor failure irrevocably stops automatic driving, so these slots never
/// grow, repeat or discard an earlier actual process failure.
pub struct FixedProcessDrivenDebtV1 {
    process: Option<Error>,
    wake: Option<Error>,
    reactor: Option<std::io::Error>,
    first: DebtSource,
}

enum DebtSource {
    Process,
    Wake,
    Reactor,
}

impl FixedProcessDrivenDebtV1 {
    fn process(source: Error) -> Self {
        Self {
            process: Some(source),
            wake: None,
            reactor: None,
            first: DebtSource::Process
        }
    }

    fn wake(source: Error) -> Self {
        Self {
            process: None,
            wake: Some(source),
            reactor: None,
            first: DebtSource::Wake
        }
    }

    fn reactor(source: std::io::Error) -> Self {
        Self {
            process: None,
            wake: None,
            reactor: Some(source),
            first: DebtSource::Reactor
        }
    }

    fn insert_process(&mut self, source: Error) -> std::result::Result<(), Error> {
        if self.process.is_some() {
            return Err(source);
        }

        self.process = Some(source);

        Ok(())
    }

    /// Borrows the first actual original signaling/wait failure.
    pub fn process_cause(&self) -> Option<&Error> {
        self.process.as_ref()
    }

    /// Borrows the actual cleanup-only clock/arming failure, if present.
    pub fn wake_cause(&self) -> Option<&Error> {
        self.wake.as_ref()
    }

    /// Borrows the actual cleanup reactor failure, if present.
    pub fn reactor_cause(&self) -> Option<&std::io::Error> {
        self.reactor.as_ref()
    }
}

fn record_process_debt(
    run: &mut SessionRun<'_>,
    debt: &mut Option<FixedProcessDrivenDebtV1>,
    source: Error,
) {
    match debt {
        Some(debt) => {
            if let Err(source) = debt.insert_process(source) {
                run.record_driven_error(source);
            }
        }
        None => *debt = Some(FixedProcessDrivenDebtV1::process(source)),
    }
}

impl fmt::Debug for FixedProcessDrivenCauseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for FixedProcessDrivenCauseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Process(_) => "fixed process engine failed",
            Self::CaptureAllocation(_) => "fixed process capture allocation failed",
            Self::Clock(_) => "fixed process original clock failed",
            Self::Wake(_) => "fixed process wake failed",
            Self::Reactor(_) => "fixed process reactor failed",
            Self::TimedOut => "fixed process original cut expired",
            Self::OutputLimit => "fixed process output limit exceeded",
            Self::Cancelled => "fixed process drive cancelled",
            Self::Unwound => "fixed process drive unwound",
        })
    }
}

impl std::error::Error for FixedProcessDrivenCauseV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Process(source) | Self::Clock(source) | Self::Wake(source) => Some(source),
            Self::CaptureAllocation(source) => Some(source),
            Self::Reactor(source) => Some(source),
            _ => None,
        }
    }
}

impl fmt::Debug for FixedProcessDrivenDebtV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for FixedProcessDrivenDebtV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed process original cleanup debt")
    }
}

impl std::error::Error for FixedProcessDrivenDebtV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.first {
            DebtSource::Process => self.process.as_ref()
                .map(|source| source as &dyn std::error::Error),
            DebtSource::Wake => self.wake.as_ref()
                .map(|source| source as &dyn std::error::Error),
            DebtSource::Reactor => self.reactor.as_ref()
                .map(|source| source as &dyn std::error::Error),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Parked,
    Running,
    Cleaning,
    Ended,
    Debt,
}

enum Finish {
    Reaped(bool),
    TimedOut,
    OutputLimit,
    Failed,
}

/// Reports mechanics progress without currentness, terminal rights or Drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedProcessDrivenProgressV1 {
    /// A short view can wait for an actual original descriptor wake.
    Waiting,
    /// One bounded turn progressed; the caller should yield before repeating.
    Progressed,
    /// No armed child remains and finite terminal capture was settled.
    Ended,
    /// Automatic progress stopped with the original child/capture still resident.
    Debt,
}

/// Retains one real output-only attempt across borrowed cancellation and unwind.
///
/// The owner is deliberately !Send and !Sync. The caller must retain exclusive
/// exactly-single-thread child reaping, authenticate the original boot/cut and
/// fund all retained inputs, descriptors, wake and capture resources separately.
/// Dropping this parent can perform the existing blocking cleanup fallback.
pub struct FixedProcessDrivenSessionV1 {
    run: Option<SessionRun<'static>>,
    prepared: FixedProcessPreparedInvocationV1,
    executable: Option<OwnedFd>,
    stdin: Option<OwnedFd>,
    inherited: Vec<OwnedFd>,
    capture: FixedProcessCaptureV1,
    cut: FixedProcessBoottimeCutV1,
    timer: Option<OwnedFd>,
    kernel: KernelState<()>,
    phase: Phase,
    finish: Option<Finish>,
    cause: Option<FixedProcessDrivenCauseV1>,
    debt: Option<FixedProcessDrivenDebtV1>,
    outcome: Option<FixedProcessRetainedSessionOutcome<()>>,
    single_thread: PhantomData<Rc<()>>,
}

impl FixedProcessDrivenSessionV1 {
    /// Parks original inputs infallibly before any clock, FD setup or fork.
    #[must_use]
    pub fn park(
        prepared: FixedProcessPreparedInvocationV1,
        inputs: FixedProcessDrivenInputsV1,
        cut: FixedProcessBoottimeCutV1,
    ) -> Self {
        Self {
            run: None,
            prepared,
            executable: Some(inputs.executable),
            stdin: inputs.stdin,
            inherited: inputs.inherited,
            capture: inputs.capture,
            cut,
            timer: None,
            kernel: KernelState::pending(),
            phase: Phase::Parked,
            finish: None,
            cause: None,
            debt: None,
            outcome: None,
            single_thread: PhantomData,
        }
    }

    /// Arms a borrowing closure guard synchronously, including unpolled use.
    pub fn drive(&mut self) -> FixedProcessDrivingLoanV1<'_> {
        FixedProcessDrivingLoanV1 {
            owner: self
        }
    }

    /// Borrows the first actual effect/drive cause without removing it.
    pub fn cause(&self) -> Option<&FixedProcessDrivenCauseV1> {
        self.cause.as_ref()
    }

    /// Borrows independent original cleanup debt.
    pub fn cleanup_debt(&self) -> Option<&FixedProcessDrivenDebtV1> {
        self.debt.as_ref()
    }

    /// Borrows the actual observed mechanics outcome, never an effect receipt.
    pub fn outcome(&self) -> Option<&FixedProcessRetainedSessionOutcome<()>> {
        self.outcome.as_ref()
    }

    /// Borrows the original reservoir; active pipe bytes settle into it on end.
    pub fn capture(&self) -> Option<&FixedProcessCaptureV1> {
        match &self.run {
            Some(run) => run.capture(),
            None => Some(&self.capture),
        }
    }

    /// Consumes the whole ended owner without dropping a live child or cause.
    ///
    /// # Errors
    /// Returns the same owner intact unless its original cleanup reached Ended.
    pub fn into_ended_parts(mut self) -> std::result::Result<FixedProcessDrivenPartsV1, Self> {
        if self.phase != Phase::Ended {
            return Err(self);
        }

        let capture = match &mut self.run {
            Some(run) => run.take_ended_capture(),
            None => Some(std::mem::take(&mut self.capture)),
        };
        let Some(capture) = capture else {
            return Err(self);
        };

        Ok(FixedProcessDrivenPartsV1 {
            capture: capture.into_retained_parts(),
            outcome: self.outcome.take(),
            cause: self.cause.take(),
            cleanup_debt: self.debt.take(),
        })
    }

    fn check_cut(&self) -> std::result::Result<(), FixedProcessDrivenCauseV1> {
        let now = uapi::boottime_nanoseconds().map_err(FixedProcessDrivenCauseV1::Clock)?;
        if now >= self.cut.0 {
            return Err(FixedProcessDrivenCauseV1::TimedOut);
        }

        Ok(())
    }

    fn initialize(&mut self) -> std::result::Result<(), FixedProcessDrivenCauseV1> {
        self.check_cut()?;
        if self.inherited.len() > super::super::MAXIMUM_INHERITED_DESCRIPTORS {
            return Err(FixedProcessDrivenCauseV1::Process(Error::invalid(
                "fixed process inherited descriptors", "exceeds the four-descriptor ceiling",
            )));
        }

        let executable = self.executable.as_ref().ok_or_else(||
            FixedProcessDrivenCauseV1::Process(
                Error::invalid("fixed process executable", "original is absent"),
            )
        )?;
        validate_executable_descriptor(executable.as_fd())
            .map_err(FixedProcessDrivenCauseV1::Process)?;
        validate_exclusive_reaping_owner().map_err(FixedProcessDrivenCauseV1::Process)?;

        self.capture.prepare_limits::<Infallible>(
            self.prepared.maximum_stdout_bytes,
            self.prepared.maximum_stderr_bytes,
        ).map_err(|error| match error {
            FixedProcessRetainedSessionError::CaptureAllocation(source) =>
                FixedProcessDrivenCauseV1::CaptureAllocation(source),
            FixedProcessRetainedSessionError::Session(
                super::FixedProcessSessionError::Process { source, .. }
            ) =>
                FixedProcessDrivenCauseV1::Process(source),
            FixedProcessRetainedSessionError::Session(
                super::FixedProcessSessionError::Cleanup(source)
            ) =>
                FixedProcessDrivenCauseV1::Process(source),
            FixedProcessRetainedSessionError::Session(
                super::FixedProcessSessionError::Exchange { source, .. }
            ) =>
                match source {},
        })?;

        self.check_cut()?;
        self.timer = Some(rustix::time::timerfd_create(
            rustix::time::TimerfdClockId::Boottime,
            rustix::time::TimerfdFlags::CLOEXEC | rustix::time::TimerfdFlags::NONBLOCK,
        ).map_err(|error| FixedProcessDrivenCauseV1::Wake(
            kernel_error("create fixed process wake", error)
        ))?);

        self.check_cut()?;
        Self::arm_timer(&self.timer, self.cut.0).map_err(FixedProcessDrivenCauseV1::Wake)?;
        self.check_cut()?;

        let inherited_borrows = self.inherited.iter().map(|fd| fd.as_fd()).collect::<Vec<_>>();
        let executable = self.executable.as_ref().ok_or_else(||
            FixedProcessDrivenCauseV1::Process(
                Error::invalid("fixed process executable", "original is absent"),
            )
        )?;
        let spawned = self.prepared.invocation.begin_from_executable_descriptor_at_cut(
            executable.as_fd(),
            self.stdin.as_ref().map(|fd| fd.as_fd()),
            &inherited_borrows,
            self.cut,
        ).map_err(FixedProcessDrivenCauseV1::Process)?;

        // Successful fork is installed before the next fallible operation.
        // Move the exact prepared reservoir; the empty parent placeholder is
        // never used as an original while run owns it. This handoff cannot fail.
        let capture = std::mem::take(&mut self.capture);
        self.run = Some(SessionRun::resident(
            spawned,
            self.prepared.maximum_stdout_bytes,
            self.prepared.maximum_stderr_bytes,
            capture,
        ));

        drop(inherited_borrows);
        drop(self.executable.take());
        drop(std::mem::take(&mut self.inherited));
        drop(self.stdin.take());

        self.check_cut()?;
        if let Some(run) = &mut self.run {
            run.initialize_retained().map_err(FixedProcessDrivenCauseV1::Process)?;
        }
        self.phase = Phase::Running;

        Ok(())
    }

    fn arm_timer(timer: &Option<OwnedFd>, endpoint: u64) -> Result<()> {
        let timer = timer.as_ref().ok_or_else(|| Error::invalid(
            "fixed process wake", "original is absent",
        ))?;

        let endpoint = rustix::event::Timespec::try_from(Duration::from_nanos(endpoint))
            .map_err(|_| Error::invalid("fixed process wake", "endpoint does not fit timespec"))?;
        let spec = rustix::time::Itimerspec {
            it_interval: rustix::event::Timespec::default(),
            it_value: endpoint,
        };
        rustix::time::timerfd_settime(timer, rustix::time::TimerfdTimerFlags::ABSTIME, &spec)
            .map_err(|error| kernel_error("arm fixed process wake", error))?;

        Ok(())
    }

    fn close(&mut self, cause: FixedProcessDrivenCauseV1) {
        if self.phase == Phase::Ended || self.phase == Phase::Debt {
            return;
        }

        if self.cause.is_none() {
            self.cause = Some(cause);
        }

        if self.finish.is_none() {
            self.finish = Some(match &self.cause {
                Some(FixedProcessDrivenCauseV1::TimedOut) => Finish::TimedOut,
                Some(FixedProcessDrivenCauseV1::OutputLimit) => Finish::OutputLimit,
                _ => Finish::Failed,
            });
        }

        self.phase = Phase::Cleaning;
        if let Some(run) = &mut self.run {
            match &self.cause {
                Some(FixedProcessDrivenCauseV1::TimedOut) => run.stop(FixedProcessStopV1::TimedOut),
                Some(FixedProcessDrivenCauseV1::OutputLimit) => {}
                Some(FixedProcessDrivenCauseV1::Unwound) => run.stop(FixedProcessStopV1::Unwound),
                _ => run.stop(FixedProcessStopV1::Error),
            }

            if let Err(source) = run.signal_driven_cleanup() {
                record_process_debt(run, &mut self.debt, source);
            }
        } else {
            self.phase = Phase::Ended;
        }
    }

    fn cleanup_once(&mut self) -> FixedProcessDrivenProgressV1 {
        let Some(run) = &mut self.run else {
            self.phase = Phase::Ended;
            return FixedProcessDrivenProgressV1::Ended;
        };

        if run.guard.armed {
            match run.poll_driven_reap() {
                Ok(Some(status)) => {
                    self.outcome = match &self.finish {
                        Some(Finish::Reaped(true)) => Some(
                            FixedProcessRetainedSessionOutcome::Completed {
                                exit_code: status.exit_code,
                                signal: status.signal,
                                exchange: (),
                            }
                        ),
                        Some(Finish::Reaped(false)) => Some(
                            FixedProcessRetainedSessionOutcome::ChildExitedBeforeExchange {
                                exit_code: status.exit_code,
                                signal: status.signal,
                            }
                        ),
                        Some(Finish::TimedOut) => Some(FixedProcessRetainedSessionOutcome::TimedOut),
                        Some(Finish::OutputLimit) => Some(FixedProcessRetainedSessionOutcome::OutputLimitExceeded),
                        _ => None,
                    };
                }
                Ok(None) => {
                    // Effect authority is already irreversibly closed. This
                    // same wake's short cleanup-only rearm is not a renewed cut.
                    let rearm = uapi::boottime_nanoseconds().and_then(|now| {
                        now.checked_add(10_000_000).ok_or_else(|| Error::invalid(
                            "fixed process cleanup wake", "endpoint overflowed",
                        ))
                    }).and_then(|endpoint| Self::arm_timer(&self.timer, endpoint));

                    if let Err(source) = rearm {
                        match &mut self.debt {
                            Some(debt) => debt.wake = Some(source),
                            None => self.debt = Some(FixedProcessDrivenDebtV1::wake(source)),
                        }
                        self.phase = Phase::Debt;
                        return FixedProcessDrivenProgressV1::Debt;
                    }

                    return FixedProcessDrivenProgressV1::Waiting;
                }
                Err(source) => {
                    record_process_debt(run, &mut self.debt, source);
                    if run.guard.armed {
                        self.phase = Phase::Debt;
                        return FixedProcessDrivenProgressV1::Debt;
                    }
                }
            }
        }

        if run.settle_driven_capture_once() {
            self.phase = Phase::Ended;
            FixedProcessDrivenProgressV1::Ended
        } else {
            FixedProcessDrivenProgressV1::Progressed
        }
    }
}

/// Owns all historical parts from the consumed ended attempt.
pub struct FixedProcessDrivenPartsV1 {
    /// Original bounded buffers, observations and additional cleanup errors.
    pub capture: FixedProcessCapturePartsV1,
    /// Actual observed mechanics outcome, if available.
    pub outcome: Option<FixedProcessRetainedSessionOutcome<()>>,
    /// First original driving cause.
    pub cause: Option<FixedProcessDrivenCauseV1>,
    /// Independent original cleanup debt.
    pub cleanup_debt: Option<FixedProcessDrivenDebtV1>,
}

/// Borrows the resident owner with cancellation armed before any poll/effect.
pub struct FixedProcessDrivingLoanV1<'a> {
    owner: &'a mut FixedProcessDrivenSessionV1,
}

impl FixedProcessDrivingLoanV1<'_> {
    /// Makes one bounded setup, shared kernel turn or cleanup observation.
    pub fn advance_once(&mut self) -> FixedProcessDrivenProgressV1 {
        match self.owner.phase {
            Phase::Parked => match self.owner.initialize() {
                Ok(()) => FixedProcessDrivenProgressV1::Progressed,
                Err(cause) => {
                    self.owner.close(cause);
                    FixedProcessDrivenProgressV1::Progressed
                }
            },
            Phase::Running => {
                // Selected driving never takes the legacy completion-before-
                // deadline shortcut. Authenticate at the genuine caller too;
                // this is only the original numeric mechanics cut.
                if let Err(cause) = self.owner.check_cut() {
                    self.owner.close(cause);
                    return FixedProcessDrivenProgressV1::Progressed;
                }

                let Some(timer) = &self.owner.timer else {
                    self.owner.close(FixedProcessDrivenCauseV1::Wake(Error::invalid(
                        "fixed process wake", "original is absent",
                    )));
                    return FixedProcessDrivenProgressV1::Progressed;
                };

                let Some(run) = &mut self.owner.run else {
                    self.owner.close(FixedProcessDrivenCauseV1::Process(Error::invalid(
                        "fixed process child", "original is absent",
                    )));
                    return FixedProcessDrivenProgressV1::Progressed;
                };

                let mut exchange: KernelExchange<'_, CapturedExchange> = KernelExchange::Captured {
                    output: Some(()),
                    timer: timer.as_fd(),
                };
                match advance_session_kernel(
                    run,
                    &mut self.owner.kernel,
                    KernelDeadline::Boottime(self.owner.cut.0),
                    &mut exchange,
                ) {
                    Ok(KernelTurn::Progressed) => FixedProcessDrivenProgressV1::Progressed,
                    Ok(KernelTurn::Waiting) => FixedProcessDrivenProgressV1::Waiting,
                    Ok(KernelTurn::Reaped(output)) => {
                        self.owner.finish = Some(Finish::Reaped(output.is_some()));
                        self.owner.phase = Phase::Cleaning;
                        run.stop(if output.is_some() { FixedProcessStopV1::Completed } else {
                            FixedProcessStopV1::ChildExitedBeforeExchange
                        });
                        if let Err(source) = run.signal_driven_cleanup() {
                            record_process_debt(run, &mut self.owner.debt, source);
                        }
                        FixedProcessDrivenProgressV1::Progressed
                    }
                    Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::TimedOut)) => {
                        self.owner.close(FixedProcessDrivenCauseV1::TimedOut);
                        FixedProcessDrivenProgressV1::Progressed
                    }
                    Ok(KernelTurn::Cancelled(_)) => {
                        self.owner.close(FixedProcessDrivenCauseV1::OutputLimit);
                        FixedProcessDrivenProgressV1::Progressed
                    }
                    Err(KernelFailure::Process(source)) => {
                        self.owner.close(FixedProcessDrivenCauseV1::Process(source));
                        FixedProcessDrivenProgressV1::Progressed
                    }
                    Err(KernelFailure::Clock(source)) => {
                        self.owner.close(FixedProcessDrivenCauseV1::Clock(source));
                        FixedProcessDrivenProgressV1::Progressed
                    }
                    Err(KernelFailure::Exchange(source)) => match source {},
                }
            }
            Phase::Cleaning => self.owner.cleanup_once(),
            Phase::Ended => FixedProcessDrivenProgressV1::Ended,
            Phase::Debt => FixedProcessDrivenProgressV1::Debt,
        }
    }

    /// Borrows at most five original descriptors for a short reactor wait.
    /// No view is returned before setup, after end or after stopped debt.
    pub fn wait_view(&self) -> Option<FixedProcessWaitViewV1<'_>> {
        let timer = self.owner.timer.as_ref()?.as_fd();
        let run = self.owner.run.as_ref()?;
        let mut descriptors = [None; 5];

        descriptors[4] = Some(timer);
        if run.guard.armed && self.owner.phase == Phase::Running
            && !self.owner.kernel.state.leader_exited
        {
            descriptors[0] = run.guard.pidfd.as_ref().map(|fd| fd.as_fd());
        }
        match self.owner.phase {
            Phase::Running => {
                if !run.stdout.closed {
                    descriptors[1] = Some(run.stdout.descriptor.as_fd());
                }
                if !run.stderr.closed {
                    descriptors[2] = Some(run.stderr.descriptor.as_fd());
                }
                descriptors[3] = run.exec_status.as_ref().map(|status| status.descriptor.as_fd());
            }
            // NOHANG Pending uses the same cleanup-only timer. Excluding a
            // continuously readable pidfd avoids a retry spin after exit.
            Phase::Cleaning if run.guard.armed => {}
            _ => return None,
        }

        Some(FixedProcessWaitViewV1 {
            descriptors,
            owner: PhantomData
        })
    }

    /// Parks an actual reactor cause once and closes before signaling.
    pub fn wait_failed(&mut self, source: std::io::Error) {
        if self.owner.phase == Phase::Cleaning {
            match &mut self.owner.debt {
                Some(debt) => debt.reactor = Some(source),
                None => self.owner.debt = Some(FixedProcessDrivenDebtV1::reactor(source)),
            }
            self.owner.phase = Phase::Debt;
        } else {
            self.owner.close(FixedProcessDrivenCauseV1::Reactor(source));
        }
    }
}

impl Drop for FixedProcessDrivingLoanV1<'_> {
    fn drop(&mut self) {
        self.owner.close(if std::thread::panicking() {
            FixedProcessDrivenCauseV1::Unwound
        } else {
            FixedProcessDrivenCauseV1::Cancelled
        });
    }
}

/// Loans only original descriptors; reactor flags cannot become kernel truth.
pub struct FixedProcessWaitViewV1<'a> {
    descriptors: [Option<BorrowedFd<'a>>; 5],
    owner: PhantomData<&'a FixedProcessDrivenSessionV1>,
}

impl<'a> FixedProcessWaitViewV1<'a> {
    /// Iterates short original borrows without extracting ownership.
    pub fn descriptors(&self) -> impl Iterator<Item = BorrowedFd<'a>> + '_ {
        self.descriptors.iter().flatten().copied()
    }
}

// Type-level unit specialization of the old engine, not a callable new mode.
// KernelExchange::Captured consumes its own unit and never invokes these methods.
struct CapturedExchange;

impl FixedProcessSessionExchange for CapturedExchange {
    type Output = ();
    type Error = Infallible;

    fn start(&mut self, _child: &FixedLiveChild<'_>, _control: BorrowedFd<'_>) ->
        std::result::Result<ExchangeStep<()>, Infallible> {
        Ok(ExchangeStep::Complete(()))
    }

    fn advance(&mut self, _child: &FixedLiveChild<'_>, _control: BorrowedFd<'_>,
        _ready: FixedProcessControlReadiness) -> std::result::Result<ExchangeStep<()>, Infallible> {
        Ok(ExchangeStep::Complete(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_cut_rejects_unbounded_values_without_sampling() {
        assert!(FixedProcessBoottimeCutV1::new(0).is_err());
        assert!(FixedProcessBoottimeCutV1::new(u64::MAX).is_err());

        let cut = FixedProcessBoottimeCutV1::new(17).unwrap();
        assert_eq!(cut.exclusive_nanoseconds(), 17);
    }

    #[test]
    fn pure_preparation_owns_transient_path_and_argument_bytes() {
        let prepared = {
            let path = std::path::PathBuf::from("/aos/fixed-helper");
            let arguments = [std::ffi::OsString::from("original-argument")];

            prepare_fixed_process_driven_invocation_v1(FixedProcessRequest {
                executable: &path,
                arguments: &arguments,
                timeout: Duration::from_secs(1),
                maximum_stdout_bytes: 32,
                maximum_stderr_bytes: 16,
            }).unwrap()
        };

        assert_eq!(prepared.invocation.executable.to_bytes(), b"/aos/fixed-helper");
        assert_eq!(prepared.invocation.arguments[0].to_bytes(), b"original-argument");
        assert_eq!(prepared.maximum_stdout_bytes, 32);
        assert_eq!(prepared.maximum_stderr_bytes, 16);
    }

    #[test]
    fn original_reactor_error_is_owned_but_diagnostics_are_redacted() {
        let cause = FixedProcessDrivenCauseV1::Reactor(std::io::Error::other("private descriptor detail"));

        assert!(!format!("{cause:?}").contains("private descriptor"));
        assert!(!format!("{cause}").contains("private descriptor"));
        assert_eq!(std::error::Error::source(&cause).unwrap().to_string(), "private descriptor detail");
    }

    #[test]
    fn cleanup_reactor_source_does_not_replace_first_process_source() {
        let process = Error::Syscall {
            operation: "first cleanup source",
            source: std::io::Error::from_raw_os_error(libc::EIO),
        };
        let mut debt = FixedProcessDrivenDebtV1::process(process);
        debt.reactor = Some(std::io::Error::from_raw_os_error(libc::ENOSPC));

        assert!(debt.process_cause().is_some());
        assert_eq!(debt.reactor_cause().unwrap().raw_os_error(), Some(libc::ENOSPC));
        assert!(std::error::Error::source(&debt).unwrap().to_string().contains("first cleanup source"));
    }
}
