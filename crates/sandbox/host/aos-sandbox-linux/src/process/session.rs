//! Event-driven exchanges with a live fixed child process.
//!
//! The session supervisor extends the fixed-process boundary with one borrowed
//! nonblocking control descriptor. It keeps the child pidfd retained, runs a
//! caller-defined nonblocking exchange, drains both output pipes concurrently,
//! and owns cancellation and reaping until the complete operation terminates.
//!
//! Synchronous control adapters and the resident output-only child module share
//! one bounded kernel-turn engine here. Legacy MONOTONIC polling and callback
//! contracts remain separate from the child's borrowed BOOTTIME driving loans.

use std::fmt;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::time::Duration;

use crate::pidfd::{PidFd, PidFdInfo};
use crate::uapi::FixedDescriptorExecRecipeV1;
use crate::{Error, Result};

use super::capture::{
    FixedProcessCaptureV1, FixedProcessRetainedSessionError,
    FixedProcessRetainedSessionOutcome, FixedProcessStopV1, SessionRun,
};
use super::{
    ChildGuard, FixedProcessOutput, FixedProcessRequest, OutputStream, PreparedInvocation,
    ProcessStatus, SpawnedProcess, kernel_error, monotonic_now, validate_exclusive_reaping_owner,
};

mod driven;
pub use driven::{
    FixedProcessBoottimeCutV1, FixedProcessDrivenCauseV1, FixedProcessDrivenDebtV1,
    FixedProcessDrivenInputsV1, FixedProcessDrivenPartsV1, FixedProcessDrivenProgressV1, FixedProcessDrivenSessionV1,
    FixedProcessDrivingLoanV1, FixedProcessPreparedInvocationV1, FixedProcessWaitViewV1,
    prepare_fixed_process_driven_invocation_v1,
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

impl<'request> FixedProcessSessionRequest<'request> {
    /// Parks a selected Nix invocation and an original monotonic cut without I/O.
    ///
    /// This move-only DATA owner authenticates no startup, approval, TPM or
    /// funding. Its caller must supply those genuine owners before driving it.
    /// The capture is borrowed from an external owner, not another field here.
    #[must_use]
    pub fn retain_nix_offline_before_monotonic_cut_v1<'capture, O, E>(
        self,
        executable: OwnedFd,
        cut: Duration,
        capture: &'capture mut FixedProcessCaptureV1,
    ) -> FixedNixOfflineSessionOwnerV1<'request, 'capture, O, E> {
        let process = self.process;
        let control = self.control;
        FixedNixOfflineSessionOwnerV1 {
            request: Some(self),
            executable: Some(executable),
            capture: Some(capture),
            process,
            control,
            cut,
            deadline: None,
            run: None,
            pending_spawn: None,
            kernel: KernelState::pending(),
            acknowledgment_exchange: None,
            terminal_exchange: None,
            outcome: None,
            first_failure: None,
            phase: NixRunPhase::Parked,
            single_thread: std::marker::PhantomData,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NixRunPhase {
    Parked,
    ExecReady,
    ReplyReady,
    Ended,
    Retired,
    Closed,
}

/// Retains one actual selected Nix child across returned errors and unwind.
///
/// It owns the same `SessionRun`, kernel state, exchange value and first typed
/// cause used by the fixed supervisor. Reply readiness precedes child retirement;
/// the genuine purpose owner must validate the still-live child and settle its
/// native obligation before sending its fixed terminal acknowledgement.
/// This !Send/!Sync owner supplies mechanics and bounded DATA, never authority,
/// physical funding, TPM/RM retirement or whole-process-tree Drain. Final Drop
/// retains the existing blocking cancellation/reap fallback.
pub struct FixedNixOfflineSessionOwnerV1<'request, 'capture, O, E> {
    request: Option<FixedProcessSessionRequest<'request>>,
    executable: Option<OwnedFd>,
    capture: Option<&'capture mut FixedProcessCaptureV1>,
    process: FixedProcessRequest<'request>,
    control: BorrowedFd<'request>,
    cut: Duration,
    deadline: Option<Duration>,
    run: Option<SessionRun<'capture>>,
    pending_spawn: Option<SpawnedProcess>,
    kernel: KernelState<O>,
    acknowledgment_exchange: Option<O>,
    terminal_exchange: Option<O>,
    outcome: Option<FixedProcessRetainedSessionOutcome<O>>,
    first_failure: Option<FixedProcessRetainedSessionError<E>>,
    phase: NixRunPhase,
    single_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl<O, E> FixedNixOfflineSessionOwnerV1<'_, '_, O, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Drives the same child to exec EOF before the first exchange callback.
    ///
    /// The genuine purpose owner must use this live borrow for its full
    /// executable, loader and startup observations before allowing HELLO.
    /// No callback, HELLO acceptance or currentness is implied by this boundary.
    ///
    /// # Errors
    /// Retains and fences the first preparation, exec, observation or cleanup
    /// failure. An absent live child or expired original cut is refused.
    pub fn prepare_live_child<X>(
        &mut self,
        exchange: &mut X,
    ) -> std::result::Result<(), &FixedProcessRetainedSessionError<E>>
    where
        X: FixedProcessSessionExchange<Output = O, Error = E>,
    {
        if self.phase != NixRunPhase::Parked {
            return Err(self.refuse());
        }

        {
            let mut operation = NixRunOperation::arm(self);
            if operation.owner.prepare_selected().is_ok()
                && operation.owner.drive_selected(exchange, CompletionBoundary::BeforeExchange).is_ok()
            {
                operation.complete();
            }
        }

        if self.phase == NixRunPhase::ExecReady {
            Ok(())
        } else {
            Err(self.refuse())
        }
    }

    /// Drives the sole supervisor to a real reply before another poll or reap.
    ///
    /// `Some` borrows the actual completed exchange value. `None` is a negative
    /// mechanical outcome and must be read through [`Self::outcome`]. The helper
    /// must remain alive awaiting the purpose-specific terminal acknowledgement.
    ///
    /// # Errors
    /// Returns the resident first validation, allocation, spawn, process,
    /// exchange or cleanup cause. Repeated, failed or interrupted driving is
    /// fenced. No actual returned run is dropped on error.
    ///
    /// # Panics
    /// Propagates callback panic after the borrowing operation fences and
    /// signals the retained child. That same run remains resident.
    pub fn run_to_reply<X>(
        &mut self,
        exchange: &mut X,
    ) -> std::result::Result<Option<&O>, &FixedProcessRetainedSessionError<E>>
    where
        X: FixedProcessSessionExchange<Output = O, Error = E>,
    {
        if self.phase != NixRunPhase::ExecReady {
            return Err(self.refuse());
        }
        {
            let mut operation = NixRunOperation::arm(self);
            if operation.owner.drive_selected(exchange, CompletionBoundary::Reply).is_ok() {
                operation.complete();
            }
        }
        if self.phase == NixRunPhase::ReplyReady {
            return Ok(self.kernel.state.exchange.as_ref());
        }
        if self.first_failure.is_none() && self.outcome.is_some() {
            return Ok(None);
        }
        Err(self.refuse())
    }

    /// Rearms the same selected run once after its first live exchange boundary.
    ///
    /// This move authenticates no acknowledgement. The genuine purpose owner
    /// must first validate its actual same-socket ACK and post-nondumpable child
    /// metadata. The next exchange uses the same run, kernel and original cut.
    /// The original first value remains resident; no launch or time is renewed.
    ///
    /// # Errors
    /// Fences reuse, missing exchange state, child exit, expired cut or an actual
    /// original observation failure. No value is removed before the slot checks.
    pub fn resume_after_acknowledgment(
        &mut self,
    ) -> std::result::Result<(), &FixedProcessRetainedSessionError<E>> {
        if self.phase != NixRunPhase::ReplyReady
            || self.acknowledgment_exchange.is_some()
            || self.kernel.state.exchange.is_none()
            || self.kernel.state.leader_exited
        {
            return Err(self.refuse());
        }

        // Fence before the actual observation. Err or caught unwind cannot
        // reopen this run; only this successful single transition does so.
        self.phase = NixRunPhase::Closed;
        if let Err(source) = self.require_selected_child() {
            self.park_process_failure(source);
            return Err(self.refuse());
        }
        self.acknowledgment_exchange = self.kernel.state.exchange.take();
        self.kernel.began = false;
        self.kernel.state.interest = None;
        self.phase = NixRunPhase::ExecReady;
        Ok(())
    }

    /// Borrows the actual first exchange value without a liveness claim.
    pub fn acknowledgment_exchange(&self) -> Option<&O> {
        self.acknowledgment_exchange.as_ref()
    }

    /// Continues the same child after the purpose owner's terminal acknowledgement.
    ///
    /// This method does not send, authenticate or infer that acknowledgement.
    /// It grants no approval; its caller owns all original live postchecks and
    /// native settlement. The existing kernel state is never restarted.
    ///
    /// # Errors
    /// Returns the first resident cause or rejects a missing reply boundary,
    /// expired original cut, premature exit, output or cleanup failure.
    ///
    /// # Panics
    /// Propagates callback panic while retaining and fencing the same run.
    pub fn finish_same_child<X>(
        &mut self,
        exchange: &mut X,
    ) -> std::result::Result<&FixedProcessRetainedSessionOutcome<O>, &FixedProcessRetainedSessionError<E>>
    where
        X: FixedProcessSessionExchange<Output = O, Error = E>,
    {
        if self.phase != NixRunPhase::ReplyReady {
            return Err(self.refuse());
        }
        {
            let mut operation = NixRunOperation::arm(self);
            if operation.owner.drive_selected(exchange, CompletionBoundary::WholeChild).is_ok() {
                operation.complete();
            }
        }
        if self.first_failure.is_some() || self.outcome.is_none() {
            return Err(self.refuse());
        }
        match self.outcome.as_ref() {
            Some(outcome) => Ok(outcome),
            None => Err(self.first_failure.get_or_insert_with(|| {
                FixedProcessRetainedSessionError::Session(process_error(nix_run_closed()))
            })),
        }
    }

    /// Borrows the same checked child at a pre-HELLO or reply boundary.
    ///
    /// # Errors
    /// Fences an absent boundary, expired cut, child exit or actual observation
    /// failure. A successful short borrow is not a timeless liveness lease.
    pub fn child(&mut self) -> std::result::Result<FixedLiveChild<'_>, &FixedProcessRetainedSessionError<E>> {
        if !matches!(self.phase, NixRunPhase::ExecReady | NixRunPhase::ReplyReady) {
            return Err(self.refuse());
        }
        let original_phase = self.phase;
        self.phase = NixRunPhase::Closed;
        let checked = self.require_selected_child();
        if let Err(source) = checked {
            self.park_process_failure(source);
            self.phase = NixRunPhase::Closed;
            return Err(self.refuse());
        }
        let identity = match (
            self.run.as_ref().and_then(|run| run.guard.pidfd.as_ref()),
            self.kernel.initial_info,
            self.deadline,
        ) {
            (Some(pidfd), Some(initial_info), Some(deadline)) => (pidfd, initial_info, deadline),
            _ => {
                self.phase = NixRunPhase::Closed;
                return Err(self.first_failure.get_or_insert_with(|| {
                    FixedProcessRetainedSessionError::Session(process_error(nix_run_closed()))
                }));
            }
        };
        let (pidfd, initial_info, deadline) = identity;
        self.phase = original_phase;
        Ok(FixedLiveChild { pidfd, initial_info, deadline })
    }

    /// Borrows the resident reply together with the same still-live child.
    ///
    /// # Errors
    /// Refuses a missing reply, expired cutoff or changed exact child. The
    /// returned pair is mechanical DATA; the purpose owner still authenticates
    /// the same socket, measured image, metadata and application frame.
    pub fn reply_and_child(
        &mut self,
    ) -> std::result::Result<(FixedLiveChild<'_>, &O), &FixedProcessRetainedSessionError<E>> {
        if self.phase != NixRunPhase::ReplyReady || self.kernel.state.exchange.is_none() {
            return Err(self.refuse());
        }
        self.phase = NixRunPhase::Closed;
        if let Err(source) = self.require_selected_child() {
            self.park_process_failure(source);
            self.phase = NixRunPhase::Closed;
            return Err(self.refuse());
        }
        match (
            self.run.as_ref().and_then(|run| run.guard.pidfd.as_ref()),
            self.kernel.initial_info, self.deadline, self.kernel.state.exchange.as_ref(),
        ) {
            (Some(pidfd), Some(initial_info), Some(deadline), Some(reply)) => {
                self.phase = NixRunPhase::ReplyReady;
                Ok((FixedLiveChild { pidfd, initial_info, deadline }, reply))
            }
            _ => {
                self.phase = NixRunPhase::Closed;
                Err(self.first_failure.get_or_insert_with(|| {
                    FixedProcessRetainedSessionError::Session(process_error(nix_run_closed()))
                }))
            }
        }
    }

    /// Borrows the actual bounded outcome without releasing original resources.
    pub fn outcome(&self) -> Option<&FixedProcessRetainedSessionOutcome<O>> {
        self.outcome.as_ref()
    }

    /// Borrows the first resident typed cause, never a fabricated currentness proof.
    pub fn failure(&self) -> Option<&FixedProcessRetainedSessionError<E>> {
        self.first_failure.as_ref()
    }

    /// Borrows original output and cleanup diagnostics while the run is retained.
    pub fn capture(&self) -> Option<&FixedProcessCaptureV1> {
        self.run.as_ref().and_then(SessionRun::capture)
            .or_else(|| self.capture.as_deref())
    }

    /// Borrows the original bounded stdout prefix, including an active run.
    /// Retirement ends this view; the external capture retains the settled bytes.
    pub fn stdout(&self) -> &[u8] {
        match &self.run {
            Some(run) if !run.stdout.bytes.is_empty() => &run.stdout.bytes,
            Some(run) => run.capture().map_or(&[], FixedProcessCaptureV1::stdout),
            None => self.capture.as_ref().map_or(&[], |capture| capture.stdout()),
        }
    }

    /// Borrows the original bounded stderr prefix, including an active run.
    /// Retirement ends this view; the external capture retains the settled bytes.
    pub fn stderr(&self) -> &[u8] {
        match &self.run {
            Some(run) if !run.stderr.bytes.is_empty() => &run.stderr.bytes,
            Some(run) => run.capture().map_or(&[], FixedProcessCaptureV1::stderr),
            None => self.capture.as_ref().map_or(&[], |capture| capture.stderr()),
        }
    }

    /// Retires only an actually completed, reaped and finitely settled run.
    ///
    /// # Errors
    /// Refuses negative, failed, interrupted or already retired owners. This
    /// mechanical retirement neither approves a native result nor proves Drain.
    pub fn retire_completed(&mut self) -> std::result::Result<(), &FixedProcessRetainedSessionError<E>> {
        if self.phase != NixRunPhase::Ended
            || self.first_failure.is_some()
            || !matches!(self.outcome, Some(FixedProcessRetainedSessionOutcome::Completed { .. }))
        {
            return Err(self.refuse());
        }
        if self.run.as_ref().is_none_or(|run| run.guard.armed) {
            return Err(self.refuse());
        }
        self.phase = NixRunPhase::Closed;
        if let Some(run) = &mut self.run {
            while !run.settle_driven_capture_once() {}
        }
        self.phase = NixRunPhase::Retired;
        self.run = None;
        Ok(())
    }

    fn prepare_selected(&mut self) -> std::result::Result<(), ()> {
        let result = (|| {
            let started = monotonic_now();
            let deadline = selected_nix_deadline(started, self.process.timeout, self.cut)?;
            self.deadline = Some(deadline);
            let request = self.request.as_ref().ok_or_else(nix_run_closed)?;
            if request.inherited.len() > super::MAXIMUM_INHERITED_DESCRIPTORS {
                return Err(Error::invalid("fixed process inherited descriptors", "exceeds the four-descriptor ceiling"));
            }
            validate_executable_descriptor(self.executable.as_ref().ok_or_else(nix_run_closed)?.as_fd())?;
            validate_session_request(request)?;
            validate_exclusive_reaping_owner()?;
            let invocation = PreparedInvocation::new(self.process)?;
            Ok(invocation)
        })();
        let invocation = match result {
            Ok(invocation) => invocation,
            Err(source) => {
                self.park_process_failure(source);
                return Err(());
            }
        };
        if let Err(source) = self.capture.as_mut().ok_or_else(nix_run_closed)
            .map_err(|source| FixedProcessRetainedSessionError::Session(process_error(source)))
            .and_then(|capture| capture.prepare(self.process))
        {
            self.first_failure = Some(source);
            return Err(());
        }
        let spawned = (|| {
            if deadline_expired(self.deadline.ok_or_else(nix_run_closed)?) {
                return Err(nix_run_expired());
            }
            let request = self.request.as_ref().ok_or_else(nix_run_closed)?;
            let inherited = request.inherited.iter().map(|fd| fd.as_fd()).collect::<Vec<_>>();
            invocation.begin_from_nix_offline_executable_descriptor(
                self.executable.as_ref().ok_or_else(nix_run_closed)?.as_fd(),
                request.stdin.as_ref().map(|fd| fd.as_fd()),
                &inherited,
            )
        })();
        self.pending_spawn = match spawned {
            Ok(spawned) => Some(spawned),
            Err(source) => {
                self.park_process_failure(source);
                return Err(());
            }
        };
        // The returned child enters a resident slot before the infallible
        // handoff. Even an internal missing-slot refusal keeps that original.
        if self.capture.is_none() || self.pending_spawn.is_none() {
            self.park_process_failure(nix_run_closed());
            return Err(());
        }
        if let (Some(capture), Some(spawned)) = (self.capture.take(), self.pending_spawn.take()) {
            self.run = Some(SessionRun::retained(spawned, self.process, capture));
        }
        drop(self.executable.take());
        if let Some(request) = self.request.take() {
            drop(request.inherited);
            drop(request.stdin);
        }
        let result = self.run.as_mut().ok_or_else(nix_run_closed)
            .and_then(SessionRun::initialize_retained);
        if let Err(source) = result {
            self.park_process_failure(source);
            self.cleanup_selected();
            return Err(());
        }
        if deadline_expired(self.deadline.unwrap_or(self.cut)) {
            self.park_process_failure(nix_run_expired());
            self.cleanup_selected();
            return Err(());
        }
        Ok(())
    }

    fn drive_selected<X>(&mut self, exchange: &mut X, boundary: CompletionBoundary) -> std::result::Result<(), ()>
    where X: FixedProcessSessionExchange<Output = O, Error = E>,
    {
        let Some(deadline) = self.deadline else {
            self.park_process_failure(nix_run_closed());
            return Err(());
        };
        let mut exchange = KernelExchange::Legacy { exchange, control: self.control, deadline };
            let turn = match &mut self.run {
                Some(run) => drive_session_kernel_until(
                    run, &mut self.kernel, KernelDeadline::Monotonic(deadline), &mut exchange, boundary,
                ),
            None => Err(KernelFailure::Process(nix_run_closed())),
        };
        match turn {
            Ok(SessionBoundaryOutcome::Boundary) => {
                self.phase = match boundary {
                    CompletionBoundary::BeforeExchange => NixRunPhase::ExecReady,
                    CompletionBoundary::Reply => NixRunPhase::ReplyReady,
                    CompletionBoundary::WholeChild => NixRunPhase::Closed,
                };
                return Ok(());
            }
            Ok(SessionBoundaryOutcome::Reaped(output)) => {
                self.terminal_exchange = output;
                let completed = self.terminal_exchange.is_some();
                let status = self.run.as_mut().ok_or_else(nix_run_closed)
                    .map_err(process_error)
                    .and_then(|run| finish_reaped_status(run, completed));
                match status {
                    Ok(status) => {
                        self.outcome = Some(match self.terminal_exchange.take() {
                            Some(exchange) => FixedProcessRetainedSessionOutcome::Completed {
                                exit_code: status.exit_code, signal: status.signal, exchange,
                            },
                            None => FixedProcessRetainedSessionOutcome::ChildExitedBeforeExchange {
                                exit_code: status.exit_code, signal: status.signal,
                            },
                        });
                        self.phase = if completed { NixRunPhase::Ended } else { NixRunPhase::Closed };
                        return Ok(());
                    }
                    Err(source) => {
                        self.first_failure = Some(FixedProcessRetainedSessionError::Session(source));
                        return Err(());
                    }
                }
            }
            Ok(SessionBoundaryOutcome::Cancelled(outcome)) => {
                self.outcome = Some(outcome);
                let timeout = matches!(self.outcome, Some(FixedProcessRetainedSessionOutcome::TimedOut));
                if let Some(run) = &mut self.run {
                    if let Err(source) = finish_cancelled_status(run, timeout) {
                        self.first_failure = Some(FixedProcessRetainedSessionError::Session(source));
                        return Err(());
                    }
                }
                self.phase = NixRunPhase::Closed;
                return Ok(());
            }
            Err(KernelFailure::Process(source) | KernelFailure::Clock(source)) => {
                self.park_process_failure(source);
                self.cleanup_selected();
                return Err(());
            }
            Err(KernelFailure::Exchange(source)) => {
                self.first_failure = Some(FixedProcessRetainedSessionError::Session(
                    FixedProcessSessionError::Exchange { source, cleanup: None },
                ));
                self.cleanup_selected();
                return Err(());
            }
        }
    }

    fn require_selected_child(&self) -> Result<()> {
        if deadline_expired(self.deadline.ok_or_else(nix_run_closed)?) {
            return Err(nix_run_expired());
        }
        let run = self.run.as_ref().ok_or_else(nix_run_closed)?;
        if !child_is_alive(&run.guard)? {
            return Err(Error::invalid("fixed Nix child", "exited before original live postchecks"));
        }
        if Some(run.guard.pidfd()?.info()?) != self.kernel.initial_info {
            return Err(Error::invalid(
                "fixed Nix child identity",
                "changed across the original live boundary",
            ));
        }
        Ok(())
    }

    fn park_process_failure(&mut self, source: Error) {
        self.first_failure.get_or_insert(FixedProcessRetainedSessionError::Session(process_error(source)));
    }

    fn cleanup_selected(&mut self) {
        if let Some(run) = &mut self.run {
            run.stop(FixedProcessStopV1::Error);
            let cleanup = run.cancel_and_reap().err();
            if cleanup.is_some() {
                run.cleanup_error_returned();
            }
            if let Some(FixedProcessRetainedSessionError::Session(
                FixedProcessSessionError::Process { cleanup: slot, .. }
                | FixedProcessSessionError::Exchange { cleanup: slot, .. },
            )) = &mut self.first_failure {
                *slot = cleanup;
            }
        }
    }

    fn refuse(&mut self) -> &FixedProcessRetainedSessionError<E> {
        self.phase = NixRunPhase::Closed;
        self.first_failure.get_or_insert_with(|| {
            FixedProcessRetainedSessionError::Session(process_error(nix_run_closed()))
        })
    }
}

struct NixRunOperation<'operation, 'request, 'capture, O, E> {
    owner: &'operation mut FixedNixOfflineSessionOwnerV1<'request, 'capture, O, E>,
    completed: bool,
}

impl<'operation, 'request, 'capture, O, E> NixRunOperation<'operation, 'request, 'capture, O, E> {
    fn arm(owner: &'operation mut FixedNixOfflineSessionOwnerV1<'request, 'capture, O, E>) -> Self {
        owner.phase = NixRunPhase::Closed;
        Self { owner, completed: false }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl<O, E> Drop for NixRunOperation<'_, '_, '_, O, E> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.owner.phase = NixRunPhase::Closed;
        if let Some(run) = &mut self.owner.run {
            if std::thread::panicking() {
                run.stop(FixedProcessStopV1::Unwound);
            }
            if let Err(source) = run.signal_driven_cleanup() {
                run.record_driven_error(source);
            }
        }
    }
}

fn selected_nix_deadline(started: Duration, timeout: Duration, cut: Duration) -> Result<Duration> {
    let relative = started.checked_add(timeout).ok_or_else(|| {
        Error::invalid("fixed process timeout", "absolute deadline overflows CLOCK_MONOTONIC duration")
    })?;
    if cut.is_zero() || started >= cut {
        return Err(nix_run_expired());
    }
    Ok(relative.min(cut))
}

fn nix_run_closed() -> Error {
    Error::invalid("fixed Nix session", "original resident operation is fenced")
}

fn nix_run_expired() -> Error {
    Error::invalid("fixed Nix session cut", "original CLOCK_MONOTONIC cut expired")
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

/// Runs the ordinary fixed path session while retaining both output streams.
///
/// This uses the same path invocation and capability inheritance as
/// [`run_fixed_process_session`]. It sets or grants no capability. A privileged
/// owner must authenticate its fixed immutable executable and confinement
/// before calling; this mechanical path boundary admits neither of them.
/// The descriptor-session APIs continue to remove child authority separately.
///
/// Capture reservations precede the ordinary spawn. Its exec confirmation and
/// initial pidfd acquisition are synchronous: the absolute deadline includes
/// that prefix but cannot preempt it. Only a returned spawn is handed into the
/// caller-held reservoir. Thereafter the same retained `SessionRun` and sole
/// supervisor own output, exchange, cancellation and exact-child reaping.
/// Owned stdin and roles close before initialization or exchange callbacks.
/// Neither captured EOF nor leader reap establishes whole-cgroup drain.
///
/// # Errors
///
/// Returns the original typed session errors for request validation, ordinary
/// spawning, observation, exchange or cleanup. Returns a typed pre-fork capture
/// reservation error for an overflowing ceiling, allocation failure or a used
/// reservoir. Caller-owned capture remains available after returned errors.
///
/// # Panics
///
/// Propagates callback panic. After the returned child is handed into the
/// retained supervisor, the same unwind guard attempts cleanup and retains
/// bounded observations. Abort, dropping capture and the synchronous spawn
/// prefix are not universal retained-custody or preemption guarantees.
pub fn run_fixed_process_session_retained_v1<X>(
    request: FixedProcessSessionRequest<'_>,
    exchange: &mut X,
    capture: &mut FixedProcessCaptureV1,
) -> std::result::Result<
    FixedProcessRetainedSessionOutcome<X::Output>,
    FixedProcessRetainedSessionError<X::Error>,
>
where
    X: FixedProcessSessionExchange,
{
    let started = monotonic_now();
    let deadline = started.checked_add(request.process.timeout).ok_or_else(|| {
        FixedProcessRetainedSessionError::Session(process_error(Error::invalid(
            "fixed process timeout",
            "absolute deadline overflows CLOCK_MONOTONIC duration",
        )))
    })?;

    validate_session_request(&request)
        .map_err(process_error)
        .map_err(FixedProcessRetainedSessionError::Session)?;
    validate_exclusive_reaping_owner()
        .map_err(process_error)
        .map_err(FixedProcessRetainedSessionError::Session)?;
    let invocation = PreparedInvocation::new(request.process)
        .map_err(process_error)
        .map_err(FixedProcessRetainedSessionError::Session)?;
    capture.prepare(request.process)?;

    let FixedProcessSessionRequest {
        process,
        stdin,
        inherited,
        control,
    } = request;
    let inherited_borrows = inherited
        .iter()
        .map(|descriptor| descriptor.as_fd())
        .collect::<Vec<_>>();
    let spawned = invocation
        .spawn(
            stdin.as_ref().map(|descriptor| descriptor.as_fd()),
            &inherited_borrows,
        )
        .map_err(process_error)
        .map_err(FixedProcessRetainedSessionError::Session)?;
    let mut run = SessionRun::retained(spawned, process, capture);

    drop(inherited_borrows);
    drop(inherited);
    drop(stdin);

    if let Err(source) = run.initialize_retained() {
        return fail_process(&mut run, source).map_err(FixedProcessRetainedSessionError::Session);
    }
    supervise_session_core(&mut run, control, deadline, exchange)
        .map_err(FixedProcessRetainedSessionError::Session)
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

/// Runs the same fixed descriptor session while retaining both output streams.
///
/// The caller owns `capture` across returned errors and callback unwind. All
/// reservations occur before fork. The original absolute deadline also covers
/// the exec-status handshake, and no callback runs before exec confirmation.
/// The request, environment, authority removal and FD roles are unchanged.
///
/// Only actual reads establish EOF. Retained bytes, exact leader wait status
/// and cleanup attempts are DATA, never process-tree drain or currentness.
/// Cleanup can block as in the existing runner. A blocking callback cannot be
/// preempted, and worker abort or dropping the reservoir loses in-memory DATA.
///
/// # Errors
///
/// Returns the original concrete session error for validation, spawning,
/// observation, exchange or cleanup failure. Rejects a previously used capture
/// or overflowing aggregate byte ceiling. Returns a typed reservation error
/// before fork if bounded capture storage cannot be allocated.
///
/// # Panics
///
/// Propagates the original callback panic. The caller-held reservoir retains
/// bounded observed output and actual cleanup diagnostics during unwinding.
pub fn run_fixed_process_session_from_executable_descriptor_retained_v1<X>(
    request: FixedProcessSessionRequest<'_>,
    executable: OwnedFd,
    exchange: &mut X,
    capture: &mut FixedProcessCaptureV1,
) -> std::result::Result<
    FixedProcessRetainedSessionOutcome<X::Output>,
    FixedProcessRetainedSessionError<X::Error>,
>
where
    X: FixedProcessSessionExchange,
{
    run_descriptor_session_retained(
        request,
        executable,
        exchange,
        capture,
        FixedDescriptorExecRecipeV1::LockedNorootV1,
    )
}

/// Runs a retained descriptor session with the closed Nix offline NNP recipe.
///
/// This route requires actual effective UID 0, exactly locked no-setuid-fixup
/// securebits (`0x0c`), and already-active no-new-privileges. The shared child engine clears
/// effective, permitted and inheritable capabilities, preserves the inherited
/// bounding set and securebits, and enables NNP before descriptor exec. It does
/// not turn this recipe into the ordinary locked-NOROOT (`0x0f`) recipe.
///
/// This is process and captured-output DATA machinery, not an offline role,
/// executable provenance, approval, TPM, currentness or process-tree drain
/// authority. The caller must independently retain and validate those owners.
/// Request bounds, empty environment, FD roles, absolute deadline, exchange and
/// output retention are identical to the ordinary retained descriptor route.
/// Cleanup can block, and a blocking exchange cannot be preempted.
///
/// # Errors
///
/// Returns the original concrete validation, reservation, spawning, observation,
/// exchange or cleanup error. Additionally rejects a parent outside the closed
/// UID/securebits/NNP recipe, preserving a failed NNP syscall's concrete cause.
/// Parent recipe rejection precedes the exec-status pipe and fork, but follows
/// the shared invocation preparation and standard output pipe setup.
///
/// # Panics
///
/// Propagates the original exchange panic. The caller-held capture retains
/// bounded observed output and cleanup diagnostics during unwinding; dropping
/// that capture or aborting the worker loses its in-memory DATA.
pub fn run_fixed_process_session_from_nix_offline_executable_descriptor_retained_v1<X>(
    request: FixedProcessSessionRequest<'_>,
    executable: OwnedFd,
    exchange: &mut X,
    capture: &mut FixedProcessCaptureV1,
) -> std::result::Result<
    FixedProcessRetainedSessionOutcome<X::Output>,
    FixedProcessRetainedSessionError<X::Error>,
>
where
    X: FixedProcessSessionExchange,
{
    run_descriptor_session_retained(
        request,
        executable,
        exchange,
        capture,
        FixedDescriptorExecRecipeV1::NixOfflineNnpV1,
    )
}

// Both public routes retain the same validation, ownership and supervision body.
fn run_descriptor_session_retained<X>(
    request: FixedProcessSessionRequest<'_>,
    executable: OwnedFd,
    exchange: &mut X,
    capture: &mut FixedProcessCaptureV1,
    recipe: FixedDescriptorExecRecipeV1,
) -> std::result::Result<
    FixedProcessRetainedSessionOutcome<X::Output>,
    FixedProcessRetainedSessionError<X::Error>,
>
where
    X: FixedProcessSessionExchange,
{
    let result = (|| {
        let started = monotonic_now();
        let deadline = started.checked_add(request.process.timeout).ok_or_else(|| {
            process_error(Error::invalid(
                "fixed process timeout",
                "absolute deadline overflows CLOCK_MONOTONIC duration",
            ))
        })?;

        if request.inherited.len() > super::MAXIMUM_INHERITED_DESCRIPTORS {
            return Err(process_error(Error::invalid(
                "fixed process inherited descriptors",
                "exceeds the four-descriptor ceiling",
            )));
        }
        validate_executable_descriptor(executable.as_fd()).map_err(process_error)?;
        validate_session_request(&request).map_err(process_error)?;
        validate_exclusive_reaping_owner().map_err(process_error)?;

        let invocation = PreparedInvocation::new(request.process).map_err(process_error)?;

        Ok((deadline, invocation))
    })()
    .map_err(FixedProcessRetainedSessionError::Session)?;

    let (deadline, invocation) = result;
    capture.prepare(request.process)?;
    let FixedProcessSessionRequest {
        process,
        stdin,
        inherited,
        control,
    } = request;
    let inherited_borrows = inherited
        .iter()
        .map(|descriptor| descriptor.as_fd())
        .collect::<Vec<_>>();
    let spawned = match recipe {
        FixedDescriptorExecRecipeV1::LockedNorootV1 => {
            invocation.begin_from_executable_descriptor(
                executable.as_fd(),
                stdin.as_ref().map(|descriptor| descriptor.as_fd()),
                &inherited_borrows,
            )
        }
        FixedDescriptorExecRecipeV1::NixOfflineNnpV1 => {
            invocation.begin_from_nix_offline_executable_descriptor(
                executable.as_fd(),
                stdin.as_ref().map(|descriptor| descriptor.as_fd()),
                &inherited_borrows,
            )
        }
    }
    .map_err(|source| FixedProcessRetainedSessionError::Session(process_error(source)))?;
    let mut run = SessionRun::retained(spawned, process, capture);

    drop(inherited_borrows);
    drop(executable);
    drop(inherited);
    drop(stdin);

    if let Err(source) = run.initialize_retained() {
        return fail_process(&mut run, source).map_err(FixedProcessRetainedSessionError::Session);
    }

    supervise_session_core(&mut run, control, deadline, exchange)
        .map_err(FixedProcessRetainedSessionError::Session)
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
    let stdout = match OutputStream::new(spawned.stdout, process.maximum_stdout_bytes) {
        Ok(stream) => stream,
        Err(source) => return fail_process_guard(&mut guard, source),
    };
    let stderr = match OutputStream::new(spawned.stderr, process.maximum_stderr_bytes) {
        Ok(stream) => stream,
        Err(source) => return fail_process_guard(&mut guard, source),
    };
    let mut run = SessionRun::legacy(guard, stdout, stderr);
    let outcome = supervise_session_core(&mut run, control, deadline, exchange)?;
    Ok(match outcome {
        FixedProcessRetainedSessionOutcome::Completed {
            exit_code,
            signal,
            exchange,
        } => {
            let process = process_output(
                ProcessStatus {
                    exit_code,
                    signal,
                },
                &mut run,
            );
            FixedProcessSessionOutcome::Completed {
                process,
                exchange,
            }
        }
        FixedProcessRetainedSessionOutcome::ChildExitedBeforeExchange {
            exit_code,
            signal,
        } => {
            FixedProcessSessionOutcome::ChildExitedBeforeExchange(
                process_output(
                    ProcessStatus {
                        exit_code,
                        signal,
                    },
                    &mut run,
                ),
            )
        }
        FixedProcessRetainedSessionOutcome::TimedOut => FixedProcessSessionOutcome::TimedOut,
        FixedProcessRetainedSessionOutcome::OutputLimitExceeded =>
            FixedProcessSessionOutcome::OutputLimitExceeded,
    })
}

struct KernelState<T> {
    state: SessionState<T>,
    initial_info: Option<PidFdInfo>,
    began: bool,
}

impl<T> KernelState<T> {
    fn pending() -> Self {
        Self {
            state: SessionState::pending(),
            initial_info: None,
            began: false,
        }
    }
}

#[derive(Clone, Copy)]
enum KernelDeadline {
    Monotonic(Duration),
    Boottime(u64),
}

impl KernelDeadline {
    fn expired(self) -> Result<bool> {
        match self {
            Self::Monotonic(deadline) => Ok(deadline_expired(deadline)),
            Self::Boottime(deadline) => Ok(crate::uapi::boottime_nanoseconds()? >= deadline),
        }
    }
}

enum KernelTurn<T> {
    Progressed,
    Waiting,
    Reaped(Option<T>),
    Cancelled(FixedProcessRetainedSessionOutcome<T>),
}

enum KernelFailure<E> {
    Process(Error),
    Clock(Error),
    Exchange(E),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CompletionBoundary {
    WholeChild,
    BeforeExchange,
    Reply,
}

enum SessionBoundaryOutcome<T> {
    Boundary,
    Reaped(Option<T>),
    Cancelled(FixedProcessRetainedSessionOutcome<T>),
}

/// Repeats the sole kernel turn; selected boundaries do not add a poll engine.
fn drive_session_kernel_until<X>(
    run: &mut SessionRun<'_>,
    kernel: &mut KernelState<X::Output>,
    deadline: KernelDeadline,
    exchange: &mut KernelExchange<'_, X>,
    boundary: CompletionBoundary,
) -> std::result::Result<SessionBoundaryOutcome<X::Output>, KernelFailure<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    loop {
        match advance_session_kernel_until(run, kernel, deadline, exchange, boundary)? {
            KernelTurn::Progressed | KernelTurn::Waiting => {
                if selected_boundary_reached(boundary, kernel, run.exec_status.is_some()) {
                    return Ok(SessionBoundaryOutcome::Boundary);
                }
            }
            KernelTurn::Reaped(output) => return Ok(SessionBoundaryOutcome::Reaped(output)),
            KernelTurn::Cancelled(outcome) => return Ok(SessionBoundaryOutcome::Cancelled(outcome)),
        }
    }
}

fn selected_boundary_reached<T>(
    boundary: CompletionBoundary,
    kernel: &KernelState<T>,
    exec_status_pending: bool,
) -> bool {
    if kernel.state.leader_exited {
        return false;
    }
    match boundary {
        CompletionBoundary::WholeChild => false,
        CompletionBoundary::BeforeExchange => {
            !exec_status_pending && kernel.initial_info.is_some() && !kernel.began
        }
        CompletionBoundary::Reply => kernel.state.exchange.is_some(),
    }
}

/// The selected captured profile has no control descriptor or callback.
enum KernelExchange<'a, X: FixedProcessSessionExchange> {
    Legacy {
        exchange: &'a mut X,
        control: BorrowedFd<'a>,
        deadline: Duration,
    },
    Captured {
        output: Option<X::Output>,
        timer: BorrowedFd<'a>,
    },
}

impl<X: FixedProcessSessionExchange> KernelExchange<'_, X> {
    fn start(
        &mut self,
        guard: &ChildGuard,
        info: Option<PidFdInfo>,
    ) -> std::result::Result<ExchangeStep<X::Output>, KernelFailure<X::Error>> {
        match self {
            Self::Legacy { exchange, control, deadline } => {
                let child = live_child(guard, info, *deadline).map_err(KernelFailure::Process)?;
                exchange.start(&child, *control).map_err(KernelFailure::Exchange)
            }
            Self::Captured { output, .. } => output.take()
                .map(ExchangeStep::Complete)
                .ok_or_else(|| KernelFailure::Process(Error::invalid(
                    "fixed process captured state", "start was already consumed",
                ))),
        }
    }

    fn advance(
        &mut self,
        guard: &ChildGuard,
        info: Option<PidFdInfo>,
        ready: FixedProcessControlReadiness,
    ) -> std::result::Result<ExchangeStep<X::Output>, KernelFailure<X::Error>> {
        match self {
            Self::Legacy { exchange, control, deadline } => {
                let child = live_child(guard, info, *deadline).map_err(KernelFailure::Process)?;
                exchange.advance(&child, *control, ready).map_err(KernelFailure::Exchange)
            }
            Self::Captured { .. } => Err(KernelFailure::Process(Error::invalid(
                "fixed process captured state", "has no control exchange",
            ))),
        }
    }

    fn poll(
        &self,
        run: &SessionRun<'_>,
        state: &SessionState<X::Output>,
    ) -> Result<SessionReadiness> {
        match self {
            Self::Legacy { control, deadline, .. } => poll_session(
                &run.guard, &run.stdout, &run.stderr, *control, state.interest,
                state.leader_exited, *deadline, run.exec_status.as_ref(),
            ),
            Self::Captured { timer, .. } => probe_captured_session(run, state.leader_exited, *timer),
        }
    }

    fn cancel_leader(&self, run: &mut SessionRun<'_>) -> Result<()> {
        match self {
            Self::Legacy { .. } => run.guard.cancel(),
            Self::Captured { .. } => run.signal_driven_cleanup(),
        }
    }
}

fn supervise_session_core<X>(
    run: &mut SessionRun<'_>,
    control: BorrowedFd<'_>,
    deadline: Duration,
    exchange: &mut X,
) -> std::result::Result<
    FixedProcessRetainedSessionOutcome<X::Output>,
    FixedProcessSessionError<X::Error>,
>
where
    X: FixedProcessSessionExchange,
{
    let mut kernel = KernelState::pending();
    let mut exchange = KernelExchange::Legacy { exchange, control, deadline };

    match drive_session_kernel_until(
        run, &mut kernel, KernelDeadline::Monotonic(deadline), &mut exchange,
        CompletionBoundary::WholeChild,
    ) {
        Ok(SessionBoundaryOutcome::Boundary) => {
            fail_process(run, nix_run_closed())
        }
        Ok(SessionBoundaryOutcome::Reaped(output)) => finish_reaped(run, output),
        Ok(SessionBoundaryOutcome::Cancelled(outcome)) => finish_cancelled(run, outcome),
        Err(KernelFailure::Process(source) | KernelFailure::Clock(source)) => fail_process(run, source),
        Err(KernelFailure::Exchange(source)) => fail_exchange(run, source),
    }
}

/// Performs one iteration of the sole child/output/exec/control engine.
/// Legacy driving immediately repeats Progressed; the resident profile yields.
fn advance_session_kernel<X>(
    run: &mut SessionRun<'_>,
    kernel: &mut KernelState<X::Output>,
    deadline: KernelDeadline,
    exchange: &mut KernelExchange<'_, X>,
) -> std::result::Result<KernelTurn<X::Output>, KernelFailure<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    advance_session_kernel_until(run, kernel, deadline, exchange, CompletionBoundary::WholeChild)
}

fn advance_session_kernel_until<X>(
    run: &mut SessionRun<'_>,
    kernel: &mut KernelState<X::Output>,
    deadline: KernelDeadline,
    exchange: &mut KernelExchange<'_, X>,
    boundary: CompletionBoundary,
) -> std::result::Result<KernelTurn<X::Output>, KernelFailure<X::Error>>
where
    X: FixedProcessSessionExchange,
{
    let KernelState { state, initial_info, began } = kernel;
    let retention = if run.retains_output() {
        OutputRetention::Prefix
    } else {
        OutputRetention::Legacy
    };

    let mut progressed = false;

    if !*began && run.exec_status.is_none() {
        if !(run.retains_output() && state.leader_exited) {
            let observed = match run.guard.pidfd().and_then(PidFd::info) {
                Ok(info) => info,
                Err(source) => return Err(KernelFailure::Process(source)),
            };
            if boundary != CompletionBoundary::WholeChild
                && initial_info.is_some_and(|original| original != observed)
            {
                return Err(KernelFailure::Process(Error::invalid(
                    "fixed Nix child identity", "changed across the original pre-HELLO boundary",
                )));
            }
            *initial_info = Some(observed);

            if deadline.expired().map_err(KernelFailure::Clock)? {
                return Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::TimedOut));
            }
            match child_is_alive(&run.guard) {
                Ok(true) => {}
                Ok(false) => state.mark_leader_exited(),
                Err(source) => return Err(KernelFailure::Process(source)),
            }
            if boundary == CompletionBoundary::BeforeExchange && !state.leader_exited {
                return Ok(KernelTurn::Progressed);
            }
            if !state.leader_exited {
                let step = exchange.start(&run.guard, *initial_info)?;
                state.apply(step);
                if deadline.expired().map_err(KernelFailure::Clock)? {
                    return Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::TimedOut));
                }
                match child_is_alive(&run.guard) {
                    Ok(true) => {}
                    Ok(false) => state.mark_leader_exited(),
                    Err(source) => return Err(KernelFailure::Process(source)),
                }
            }
            let early_exit_cleanup = if state.leader_exited {
                exchange.cancel_leader(run)
            } else {
                Ok(())
            };
            if let Err(source) = early_exit_cleanup {
                return Err(KernelFailure::Process(source));
            }
        }
        *began = true;
        progressed = true;
    }
    if boundary == CompletionBoundary::Reply && state.exchange.is_some() && !state.leader_exited {
        return Ok(KernelTurn::Progressed);
    }
    if state.leader_exited
        && run.stdout.closed
        && run.stderr.closed
        && run.exec_status.is_none()
    {
        return Ok(KernelTurn::Reaped(state.exchange.take()));
    }
    if deadline.expired().map_err(KernelFailure::Clock)? {
        return Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::TimedOut));
    }

    let ready = exchange.poll(run, state).map_err(KernelFailure::Process)?;
    progressed |= ready.has_any();

    if ready.stdout && !run.stdout.closed {
        match drain_output_once(&mut run.stdout, retention) {
            Ok(OutputDrain::Open | OutputDrain::Closed) => {}
            Ok(OutputDrain::LimitExceeded) => {
                run.limit(true);
                return Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::OutputLimitExceeded));
            }
            Err(source) => return Err(KernelFailure::Process(source)),
        }
    }
    if ready.stderr && !run.stderr.closed {
        match drain_output_once(&mut run.stderr, retention) {
            Ok(OutputDrain::Open | OutputDrain::Closed) => {}
            Ok(OutputDrain::LimitExceeded) => {
                run.limit(false);
                return Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::OutputLimitExceeded));
            }
            Err(source) => return Err(KernelFailure::Process(source)),
        }
    }
    if deadline.expired().map_err(KernelFailure::Clock)? {
        return Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::TimedOut));
    }

    if run.exec_status.is_some() {
        if ready.exec_status {
            let status = match run.exec_status.as_mut() {
                Some(status) => status.read_once(),
                None => Ok(false),
            };
            match status {
                Ok(true) => {
                    run.exec_status = None;
                    match child_is_alive(&run.guard) {
                        Ok(true) => run.exec_confirmed(),
                        Ok(false) => state.mark_leader_exited(),
                        Err(source) => return Err(KernelFailure::Process(source)),
                    }
                }
                Ok(false) => {}
                Err(source) => {
                    run.exec_failed(&source);
                    return Err(KernelFailure::Process(source));
                }
            }
        }
        if ready.leader {
            state.mark_leader_exited();
            if let Err(source) = exchange.cancel_leader(run) {
                return Err(KernelFailure::Process(source));
            }
        }
        // Exec EOF is not proof of entry if the leader died before it.
        // The same loop continues output collection without a callback.
        return Ok(if progressed { KernelTurn::Progressed } else { KernelTurn::Waiting });
    }

    if ready.leader {
        state.mark_leader_exited();
        if let Err(source) = exchange.cancel_leader(run) {
            return Err(KernelFailure::Process(source));
        }
    }
    if state.leader_exited || state.exchange.is_some() {
        return Ok(if progressed { KernelTurn::Progressed } else { KernelTurn::Waiting });
    }
    if ready.control_invalid {
        return Err(KernelFailure::Process(Error::invalid(
                "fixed process control descriptor",
                "poll reported an invalid descriptor",
            )));
    }
    if ready.control_error {
        return Err(KernelFailure::Process(Error::invalid(
                "fixed process control descriptor",
                "poll reported a terminal I/O error",
            )));
    }

    let Some(interest) = state.interest else {
        return Err(KernelFailure::Process(Error::invalid(
                "fixed process exchange state",
                "pending exchange omitted control interest",
            )));
    };
    let hup_read = ready.control_hangup && interest.includes_readable();
    let readable = ready.control_readable || hup_read;
    let writable = ready.control_writable && !ready.control_hangup;
    if readable || writable {
        if deadline.expired().map_err(KernelFailure::Clock)? {
            return Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::TimedOut));
        }
        match child_is_alive(&run.guard) {
            Ok(true) => {}
            Ok(false) => {
                state.mark_leader_exited();
                if let Err(source) = exchange.cancel_leader(run) {
                    return Err(KernelFailure::Process(source));
                }
                return Ok(KernelTurn::Progressed);
            }
            Err(source) => return Err(KernelFailure::Process(source)),
        }

        let step = exchange.advance(
            &run.guard,
            *initial_info,
            FixedProcessControlReadiness { readable, writable },
        )?;
        state.apply(step);
        if deadline.expired().map_err(KernelFailure::Clock)? {
            return Ok(KernelTurn::Cancelled(FixedProcessRetainedSessionOutcome::TimedOut));
        }
        match child_is_alive(&run.guard) {
            Ok(true) => {}
            Ok(false) => {
                state.mark_leader_exited();
                if let Err(source) = exchange.cancel_leader(run) {
                    return Err(KernelFailure::Process(source));
                }
            }
            Err(source) => return Err(KernelFailure::Process(source)),
        }
    }
    if ready.control_hangup && state.exchange.is_none() {
        return Err(KernelFailure::Process(Error::invalid(
                "fixed process control descriptor",
                "hung up before exchange completion",
            )));
    }
    Ok(if progressed { KernelTurn::Progressed } else { KernelTurn::Waiting })
}

fn live_child<'a>(
    guard: &'a ChildGuard,
    initial_info: Option<PidFdInfo>,
    deadline: Duration,
) -> Result<FixedLiveChild<'a>> {
    Ok(FixedLiveChild {
        pidfd: guard.pidfd()?,
        initial_info: initial_info.ok_or_else(|| Error::invalid(
            "fixed process exchange state",
            "initial pidfd information was not observed",
        ))?,
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
    run: &mut SessionRun<'_>,
    exchange: Option<T>,
) -> std::result::Result<FixedProcessRetainedSessionOutcome<T>, FixedProcessSessionError<E>> {
    let status = finish_reaped_status(run, exchange.is_some())?;
    Ok(match exchange {
        Some(exchange) => FixedProcessRetainedSessionOutcome::Completed {
            exit_code: status.exit_code,
            signal: status.signal,
            exchange,
        },
        None => FixedProcessRetainedSessionOutcome::ChildExitedBeforeExchange {
            exit_code: status.exit_code,
            signal: status.signal,
        },
    })
}

fn finish_reaped_status<E>(
    run: &mut SessionRun<'_>,
    completed: bool,
) -> std::result::Result<ProcessStatus, FixedProcessSessionError<E>> {
    run.stop(if completed {
        FixedProcessStopV1::Completed
    } else {
        FixedProcessStopV1::ChildExitedBeforeExchange
    });
    run
        .cancel_and_reap()
        .map_err(|source| {
            run.cleanup_error_returned();
            FixedProcessSessionError::Cleanup(source)
        })
}

fn finish_cancelled<T, E>(
    run: &mut SessionRun<'_>,
    outcome: FixedProcessRetainedSessionOutcome<T>,
) -> std::result::Result<FixedProcessRetainedSessionOutcome<T>, FixedProcessSessionError<E>> {
    finish_cancelled_status(run, matches!(outcome, FixedProcessRetainedSessionOutcome::TimedOut))?;
    Ok(outcome)
}

fn finish_cancelled_status<E>(
    run: &mut SessionRun<'_>,
    timeout: bool,
) -> std::result::Result<(), FixedProcessSessionError<E>> {
    if timeout {
        run.stop(FixedProcessStopV1::TimedOut);
    }
    run.cancel_and_reap()
        .map_err(|source| {
            run.cleanup_error_returned();
            FixedProcessSessionError::Cleanup(source)
        })?;
    Ok(())
}

fn fail_process<T, E>(
    run: &mut SessionRun<'_>,
    source: Error,
) -> std::result::Result<T, FixedProcessSessionError<E>> {
    run.stop(FixedProcessStopV1::Error);
    let cleanup = run.cancel_and_reap().err();
    if cleanup.is_some() {
        run.cleanup_error_returned();
    }
    Err(FixedProcessSessionError::Process { source, cleanup })
}

fn fail_process_guard<T, E>(
    guard: &mut ChildGuard,
    source: Error,
) -> std::result::Result<T, FixedProcessSessionError<E>> {
    let cleanup = guard.cancel_and_reap().err();
    Err(FixedProcessSessionError::Process { source, cleanup })
}

fn fail_exchange<T, E>(
    run: &mut SessionRun<'_>,
    source: E,
) -> std::result::Result<T, FixedProcessSessionError<E>> {
    run.stop(FixedProcessStopV1::Error);
    let cleanup = run.cancel_and_reap().err();
    if cleanup.is_some() {
        run.cleanup_error_returned();
    }
    Err(FixedProcessSessionError::Exchange { source, cleanup })
}

fn process_output(
    status: ProcessStatus,
    run: &mut SessionRun<'_>,
) -> FixedProcessOutput {
    FixedProcessOutput {
        exit_code: status.exit_code,
        signal: status.signal,
        stdout: std::mem::take(&mut run.stdout.bytes),
        stderr: std::mem::take(&mut run.stderr.bytes),
    }
}

enum OutputDrain {
    Open,
    Closed,
    LimitExceeded,
}

#[derive(Clone, Copy)]
enum OutputRetention {
    Legacy,
    Prefix,
}

fn drain_output_once(stream: &mut OutputStream, retention: OutputRetention) -> Result<OutputDrain> {
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
                if matches!(retention, OutputRetention::Prefix) {
                    let available = stream.maximum.saturating_sub(stream.bytes.len());
                    stream.bytes.extend_from_slice(&chunk[..available.min(count)]);
                }
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
    exec_status: bool,
    control_readable: bool,
    control_writable: bool,
    control_hangup: bool,
    control_error: bool,
    control_invalid: bool,
}

impl SessionReadiness {
    fn has_any(&self) -> bool {
        self.leader || self.stdout || self.stderr || self.exec_status
            || self.control_readable || self.control_writable || self.control_hangup
            || self.control_error || self.control_invalid
    }
}

fn poll_session(
    guard: &ChildGuard,
    stdout: &OutputStream,
    stderr: &OutputStream,
    control: BorrowedFd<'_>,
    interest: Option<FixedProcessControlInterest>,
    leader_exited: bool,
    deadline: Duration,
    exec_status: Option<&crate::uapi::FixedExecStatusReader>,
) -> Result<SessionReadiness> {
    let remaining = deadline.saturating_sub(monotonic_now());
    let timeout = rustix::event::Timespec::try_from(remaining)
        .map_err(|_| Error::invalid("fixed process timeout", "does not fit timespec"))?;
    let pidfd = guard.pidfd()?.as_fd();
    let stdout_fd = stdout.descriptor.as_fd();
    let stderr_fd = stderr.descriptor.as_fd();
    let mut descriptors = Vec::with_capacity(if exec_status.is_some() { 5 } else { 4 });
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
    let exec_index = exec_status.map(|status| {
        descriptors.push(rustix::event::PollFd::new(
            &status.descriptor,
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
        ready.leader = validate_leader_readiness(flags)?;
    }
    if let Some(index) = stdout_index {
        ready.stdout = validate_output_readiness(descriptors[index].revents())?;
    }
    if let Some(index) = stderr_index {
        ready.stderr = validate_output_readiness(descriptors[index].revents())?;
    }
    if let Some(index) = exec_index {
        ready.exec_status = validate_output_readiness(descriptors[index].revents())?;
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

fn validate_leader_readiness(flags: rustix::event::PollFlags) -> Result<bool> {
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
    Ok(flags.intersects(allowed))
}

/// Zero-time probe using only original safe borrows and the legacy validators.
/// Inactive slots borrow the same timer with empty interests, never a raw -1 FD.
fn probe_captured_session(
    run: &SessionRun<'_>,
    leader_exited: bool,
    timer: BorrowedFd<'_>,
) -> Result<SessionReadiness> {
    use rustix::event::{PollFd, PollFlags};

    let mut descriptors = std::array::from_fn::<_, 5, _>(|_| {
        PollFd::from_borrowed_fd(timer, PollFlags::empty())
    });
    if !leader_exited {
        descriptors[0] = PollFd::from_borrowed_fd(
            run.guard.pidfd()?.as_fd(), PollFlags::IN | PollFlags::RDNORM,
        );
    }
    if !run.stdout.closed {
        descriptors[1] = PollFd::from_borrowed_fd(
            run.stdout.descriptor.as_fd(), PollFlags::IN | PollFlags::HUP,
        );
    }
    if !run.stderr.closed {
        descriptors[2] = PollFd::from_borrowed_fd(
            run.stderr.descriptor.as_fd(), PollFlags::IN | PollFlags::HUP,
        );
    }
    if let Some(status) = &run.exec_status {
        descriptors[3] = PollFd::from_borrowed_fd(
            status.descriptor.as_fd(), PollFlags::IN | PollFlags::HUP,
        );
    }
    descriptors[4] = PollFd::from_borrowed_fd(timer, PollFlags::IN);
    let timeout = rustix::event::Timespec::default();
    match rustix::event::poll(&mut descriptors, Some(&timeout)) {
        Ok(_) => {}
        Err(rustix::io::Errno::INTR) => return Ok(SessionReadiness::default()),
        Err(error) => return Err(kernel_error("poll fixed process session", error)),
    }

    let mut ready = SessionReadiness::default();
    if !leader_exited {
        ready.leader = validate_leader_readiness(descriptors[0].revents())?;
    }
    if !run.stdout.closed {
        ready.stdout = validate_output_readiness(descriptors[1].revents())?;
    }
    if !run.stderr.closed {
        ready.stderr = validate_output_readiness(descriptors[2].revents())?;
    }
    if run.exec_status.is_some() {
        ready.exec_status = validate_output_readiness(descriptors[3].revents())?;
    }
    if !descriptors[4].revents().difference(PollFlags::IN).is_empty() {
        return Err(Error::MalformedKernelResponse {
            object: "fixed process deadline poll",
            message: "kernel reported invalid or unexpected readiness flags".to_owned(),
        });
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

    #[test]
    fn selected_nix_deadline_never_renews_the_original_cut() {
        let started = Duration::from_secs(10);
        let original = Duration::from_secs(12);

        assert_eq!(
            selected_nix_deadline(started, Duration::from_secs(30), original).unwrap(),
            original,
        );
        assert_eq!(
            selected_nix_deadline(started, Duration::from_secs(1), original).unwrap(),
            Duration::from_secs(11),
        );
        assert!(selected_nix_deadline(original, Duration::from_secs(30), original).is_err());
        assert!(selected_nix_deadline(started, Duration::from_secs(1), Duration::ZERO).is_err());
    }

    #[test]
    fn selected_nix_deadline_refuses_relative_overflow() {
        assert!(selected_nix_deadline(
            Duration::from_secs(1), Duration::MAX, Duration::MAX,
        ).is_err());
    }

    #[test]
    fn selected_reply_data_cannot_yield_a_legacy_or_exited_boundary() {
        let mut kernel = KernelState::<()>::pending();
        kernel.state.apply(ExchangeStep::Complete(()));

        assert!(selected_boundary_reached(CompletionBoundary::Reply, &kernel, false));
        assert!(!selected_boundary_reached(CompletionBoundary::WholeChild, &kernel, false));
        assert!(!selected_boundary_reached(CompletionBoundary::BeforeExchange, &kernel, true));

        kernel.state.mark_leader_exited();
        assert!(!selected_boundary_reached(CompletionBoundary::Reply, &kernel, false));
    }
}
