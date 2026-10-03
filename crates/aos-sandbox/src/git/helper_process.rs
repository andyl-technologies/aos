//! One-shot, nonauthorizing execution of four fixed Git inspection verbs.
//!
//! The attempt retains original images, command bytes, sealed inputs and both
//! captured streams while the shared supervisor consumes safe duplicates. A
//! directory pin establishes no protected ODB rights or exclusive writer cut.
//! This private module installs no backend, public handler or authority caller.
//!
//! Group cancellation and exact leader wait are not descendant/FD-owner drain.
//! Cleanup can outlast the deadline. Unwind retains in-memory capture only if
//! the caller keeps this owner outside the unwind scope; dropping it, SIGKILL,
//! OOM or abort is not durable custody or a quota-release receipt.

use std::convert::Infallible;
use std::fmt;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

use aos_sandbox_linux::immutable_file::{ImmutableFileError, SealedReadOnlyCredential};
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::process::{
    ExchangeStep, FixedLiveChild, FixedProcessCaptureV1, FixedProcessControlReadiness,
    FixedProcessRequest, FixedProcessRetainedSessionError, FixedProcessRetainedSessionOutcome,
    FixedProcessSessionExchange, FixedProcessSessionRequest,
    run_fixed_process_session_from_executable_descriptor_retained_v1,
};

use crate::immutable_image::git_helper::{FixedGitHelperImagesV1, GitHelperImageErrorV1};

use super::GitObjectFormatV1;

mod plan;
mod driven;
pub(super) use driven::wait_for_process_turn_v1;
pub(super) use plan::{GitHelperInspectionV1, GitHelperLimitsV1};
use plan::{GitHelperPlanErrorV1, PLAN_BYTES};

/// Holds every original and observation for one irreversible mechanical attempt.
pub(super) struct GitHelperAttemptCustodyV1<'directory> {
    images: FixedGitHelperImagesV1,
    directory: &'directory BeneathRoot,
    verb: GitHelperInspectionV1,
    format: GitObjectFormatV1,
    limits: GitHelperLimitsV1,
    input: Vec<u8>,
    plan_bytes: Option<[u8; PLAN_BYTES]>,
    plan_original: Option<SealedReadOnlyCredential>,
    input_original: Option<SealedReadOnlyCredential>,
    bookkeeping: Option<(UnixStream, UnixStream)>,
    capture: FixedProcessCaptureV1,
    attempted: bool,
    first_error: Option<GitHelperErrorV1>,
    outcome: Option<FixedProcessRetainedSessionOutcome<()>>,
    driven: Option<driven::GitDrivenPreparationV1>,
}

impl<'directory> GitHelperAttemptCustodyV1<'directory> {
    /// Assembles original custody before any fallible plan or dispatch setup.
    pub(super) fn new(
        images: FixedGitHelperImagesV1,
        directory: &'directory BeneathRoot,
        verb: GitHelperInspectionV1,
        format: GitObjectFormatV1,
        limits: GitHelperLimitsV1,
        input: Vec<u8>,
    ) -> Self {
        Self {
            images,
            directory,
            verb,
            format,
            limits,
            input,
            plan_bytes: None,
            plan_original: None,
            input_original: None,
            bookkeeping: None,
            capture: FixedProcessCaptureV1::new(),
            attempted: false,
            first_error: None,
            outcome: None,
            driven: None,
        }
    }

    /// Dispatches at most once and leaves all returned DATA/error custody here.
    ///
    /// An Ok reports an observed supervisor outcome, not exit-zero success,
    /// protected validation, a Git-stage receipt or complete descendant drain.
    /// A second call cannot revalidate or redispatch even after an unwind.
    pub(super) fn run_once(&mut self) -> Result<(), &GitHelperErrorV1> {
        if !claim_attempt(&mut self.attempted) {
            return Err(self.first_error.as_ref().unwrap_or(&ALREADY_ATTEMPTED));
        }

        match self.run_original() {
            Ok(outcome) => {
                self.outcome = Some(outcome);
                Ok(())
            }
            Err(error) => {
                let retained = self.first_error.insert(error);
                Err(retained)
            }
        }
    }

    fn prepare_originals(
        &mut self,
        cut: Option<aos_sandbox_linux::process::FixedProcessBoottimeCutV1>,
    ) -> Result<(), GitHelperErrorV1> {
        driven::check_cut(cut)?;
        self.images.recheck().map_err(GitHelperErrorV1::Image)?;
        let bytes = plan::encode(
            self.verb,
            self.format,
            self.limits,
            self.input.len(),
            self.images.git_verity(),
            self.images.helper_verity(),
        )
        .map_err(GitHelperErrorV1::Plan)?;
        self.plan_bytes = Some(bytes);

        driven::check_cut(cut)?;
        let plan_original = SealedReadOnlyCredential::create(
            "aos-git-helper-plan-v1",
            &bytes,
            PLAN_BYTES,
        )
        .map_err(GitHelperErrorV1::Sealed)?;
        self.plan_original = Some(plan_original);

        if !self.input.is_empty() {
            driven::check_cut(cut)?;
            let input_original = SealedReadOnlyCredential::create(
                "aos-git-helper-input-v1",
                &self.input,
                self.input.len(),
            )
            .map_err(GitHelperErrorV1::Sealed)?;
            self.input_original = Some(input_original);
        }

        Ok(())
    }

    fn run_original(&mut self) -> Result<FixedProcessRetainedSessionOutcome<()>, GitHelperErrorV1> {
        self.prepare_originals(None)?;

        // Neither endpoint is delivered to the child or used as an ingress,
        // acknowledgement or authority carrier. The sole supervisor requires a
        // nonblocking control slot even for this immediate-complete exchange.
        let (control, idle) = UnixStream::pair().map_err(GitHelperErrorV1::Io)?;
        self.bookkeeping = Some((control, idle));
        let (control, idle) = self.bookkeeping.as_ref().ok_or(GitHelperErrorV1::Internal)?;
        control.set_nonblocking(true).map_err(GitHelperErrorV1::Io)?;
        idle.set_nonblocking(true).map_err(GitHelperErrorV1::Io)?;

        let plan_original = self.plan_original.as_ref().ok_or(GitHelperErrorV1::Internal)?;
        let mut inherited = Vec::new();
        inherited.try_reserve_exact(3).map_err(GitHelperErrorV1::Allocation)?;
        inherited.push(duplicate(plan_original.as_fd())?);
        inherited.push(duplicate(self.directory.as_fd())?);
        inherited.push(self.images.duplicate_git().map_err(GitHelperErrorV1::Image)?);
        let stdin = self.input_original.as_ref()
            .map(|original| duplicate(original.as_fd()))
            .transpose()?;
        let executable = self.images.duplicate_helper().map_err(GitHelperErrorV1::Image)?;

        // Exactly three roles place the executable at FD6 in the existing
        // audited runner. E0 closes roles3..6 on its same-process Git exec.
        self.images.recheck().map_err(GitHelperErrorV1::Image)?;
        let request = FixedProcessSessionRequest {
            process: FixedProcessRequest {
                executable: self.images.helper_path(),
                arguments: &[],
                timeout: self.limits.timeout,
                maximum_stdout_bytes: self.limits.maximum_output_bytes,
                maximum_stderr_bytes: self.limits.maximum_stderr_bytes,
            },
            stdin,
            inherited,
            control: control.as_fd(),
        };
        let outcome = run_fixed_process_session_from_executable_descriptor_retained_v1(
            request,
            executable,
            &mut InspectionExchange,
            &mut self.capture,
        )
        .map_err(GitHelperErrorV1::Supervisor)?;

        // No post-return fallible image check discards the original outcome.
        // Capture records helper entry, not protected proof of the Git exec.
        Ok(outcome)
    }

    pub(super) fn capture(&self) -> &FixedProcessCaptureV1 {
        &self.capture
    }

    pub(super) fn outcome(&self) -> Option<&FixedProcessRetainedSessionOutcome<()>> {
        self.outcome.as_ref()
    }

    pub(super) fn first_error(&self) -> Option<&GitHelperErrorV1> {
        self.first_error.as_ref()
    }

    pub(super) fn original_input(&self) -> &[u8] {
        &self.input
    }

    pub(super) fn original_plan(&self) -> Option<&[u8; PLAN_BYTES]> {
        self.plan_bytes.as_ref()
    }
}

fn duplicate(descriptor: BorrowedFd<'_>) -> Result<OwnedFd, GitHelperErrorV1> {
    descriptor.try_clone_to_owned().map_err(GitHelperErrorV1::Io)
}

/// Latches before fallible setup and has no reset or currentness transition.
fn claim_attempt(attempted: &mut bool) -> bool {
    !std::mem::replace(attempted, true)
}

/// Completes bookkeeping only; never authenticates a role or process-stage ack.
struct InspectionExchange;

impl FixedProcessSessionExchange for InspectionExchange {
    type Output = ();
    type Error = Infallible;

    fn start(
        &mut self,
        _child: &FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
    ) -> Result<ExchangeStep<()>, Infallible> {
        Ok(ExchangeStep::Complete(()))
    }

    fn advance(
        &mut self,
        _child: &FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
        _readiness: FixedProcessControlReadiness,
    ) -> Result<ExchangeStep<()>, Infallible> {
        Ok(ExchangeStep::Complete(()))
    }
}

static ALREADY_ATTEMPTED: GitHelperErrorV1 = GitHelperErrorV1::AlreadyAttempted;

/// Owns the first available nested cause without exposing sensitive diagnostics.
#[derive(thiserror::Error)]
pub(super) enum GitHelperErrorV1 {
    #[error("Git helper attempt already ended or began")]
    AlreadyAttempted,
    #[error("Git helper retained image failed")]
    Image(#[source] GitHelperImageErrorV1),
    #[error("Git helper mechanical plan refused")]
    Plan(#[source] GitHelperPlanErrorV1),
    #[error("Git helper sealed original failed")]
    Sealed(#[source] ImmutableFileError),
    #[error("Git helper descriptor or bookkeeping failed")]
    Io(#[source] std::io::Error),
    #[error("Git helper role allocation failed")]
    Allocation(#[source] std::collections::TryReserveError),
    #[error("Git helper original mechanical clock or preparation failed")]
    Process(#[source] aos_sandbox_linux::Error),
    #[error("Git helper original mechanical clock or cut failed")]
    Clock(#[source] aos_sandbox_linux::Error),
    #[error("Git helper retained supervisor failed")]
    Supervisor(#[source] FixedProcessRetainedSessionError<Infallible>),
    #[error("Git helper private staging invariant failed")]
    Internal,
}

impl fmt::Debug for GitHelperErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_error_diagnostics_do_not_dump_nested_details() {
        let error = GitHelperErrorV1::Io(std::io::Error::other("private input and descriptor detail"));

        assert!(!format!("{error:?}").contains("private input"));
        assert!(!format!("{error}").contains("private input"));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn empty_capture_has_no_execution_or_drain_claim() {
        let capture = FixedProcessCaptureV1::new();

        assert!(capture.stdout().is_empty());
        assert!(capture.stderr().is_empty());
        assert!(!capture.observation().reaped());
        assert_eq!(
            capture.observation().dispatch(),
            aos_sandbox_linux::process::FixedProcessDispatchV1::NoChildProduced,
        );
    }

    #[test]
    fn dispatch_latch_never_reopens_after_setup_or_observation() {
        let mut attempted = false;

        assert!(claim_attempt(&mut attempted));
        assert!(attempted);
        assert!(!claim_attempt(&mut attempted));
        assert!(!claim_attempt(&mut attempted));
    }
}
