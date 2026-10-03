//! Borrowed reactor driving of the same output-only fixed helper attempt.
//!
//! Returned images, sealed originals and every partial descriptor input stay
//! in the existing parent before later gates. A synchronous future factory
//! arms cancellation before handing out even an unpolled future. No Gateway
//! caller, Git backend, Source effect or funded drain is installed here.

use std::future::{Future, poll_fn};
use std::os::fd::{AsFd as _, OwnedFd};
use std::task::Poll;

use aos_sandbox_linux::process::{
    FixedProcessBoottimeCutV1, FixedProcessCaptureV1, FixedProcessDrivenCauseV1,
    FixedProcessDrivenDebtV1, FixedProcessDrivenInputsV1, FixedProcessDrivenProgressV1,
    FixedProcessDrivenSessionV1, FixedProcessPreparedInvocationV1, FixedProcessRequest,
    FixedProcessWaitViewV1, prepare_fixed_process_driven_invocation_v1,
};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use super::{GitHelperAttemptCustodyV1, GitHelperErrorV1, claim_attempt, duplicate};

/// Partial original slots, installed before the first selected setup gate.
pub(super) struct GitDrivenPreparationV1 {
    cut: FixedProcessBoottimeCutV1,
    prepared: Option<FixedProcessPreparedInvocationV1>,
    executable: Option<OwnedFd>,
    stdin: Option<OwnedFd>,
    inherited: Vec<OwnedFd>,
    session: Option<FixedProcessDrivenSessionV1>,
    interrupted: Option<GitDrivenInterruptionV1>,
}

#[derive(Clone, Copy, Debug)]
enum GitDrivenInterruptionV1 {
    Cancelled,
    Unwound
}

/// Reports failure while the original cause and capture stay in the parent.
#[derive(Clone, Copy, Debug)]
pub(in crate::git) struct GitHelperDrivenFailedV1;

/// Borrows genuine resident causes; interruption does not invent an IO source.
pub(in crate::git) enum GitHelperDrivenCauseV1<'a> {
    /// Original setup failure owned in the shared attempt.
    Setup(&'a GitHelperErrorV1),
    /// Original lower engine, clock, wake or reactor cause.
    Drive(&'a FixedProcessDrivenCauseV1),
    /// Borrowing cancellation with no nested actual error object.
    Cancelled,
    /// Original panic interruption, not a converted panic source.
    Unwound,
}

impl GitDrivenPreparationV1 {
    fn new(cut: FixedProcessBoottimeCutV1) -> Self {
        Self {
            cut,
            prepared: None,
            executable: None,
            stdin: None,
            inherited: Vec::new(),
            session: None,
            interrupted: None,
        }
    }
}

impl GitHelperAttemptCustodyV1<'_> {
    /// Creates one prearmed output-only driving future, not Git authorization.
    /// The existing E0 inspection plan/limits remain the only helper recipe.
    /// This convenience future has no protected caller gate and must not be
    /// treated as an authorized Git effect driver. A later genuine caller uses
    /// lower advance_once plus the shared wait adapter with its own bookends.
    pub(in crate::git) fn drive_once(
        &mut self,
        cut: FixedProcessBoottimeCutV1,
    ) -> impl Future<Output = Result<(), GitHelperDrivenFailedV1>> + '_ {
        let accepted = claim_attempt(&mut self.attempted);
        if accepted {
            self.driven = Some(GitDrivenPreparationV1::new(cut));
        }

        let mut guard = GitDrivingGuardV1 {
            attempt: self,
            armed: accepted
        };

        async move {
            if !accepted {
                return Err(GitHelperDrivenFailedV1);
            }

            if let Err(error) = guard.attempt.prepare_driven() {
                // First failure is resident before guard disarm/return. Every
                // partial original slot remains in the same parent.
                if guard.attempt.first_error.is_none() {
                    guard.attempt.first_error = Some(error);
                }
                guard.armed = false;

                return Err(GitHelperDrivenFailedV1);
            }

            let result = {
                let Some(state) = &mut guard.attempt.driven else {
                    return Err(GitHelperDrivenFailedV1);
                };
                let Some(session) = &mut state.session else {
                    return Err(GitHelperDrivenFailedV1);
                };

                let mut loan = session.drive();
                loop {
                    match loan.advance_once() {
                        FixedProcessDrivenProgressV1::Progressed => tokio::task::yield_now().await,
                        FixedProcessDrivenProgressV1::Waiting => {
                            let Some(view) = loan.wait_view() else {
                                // Closed constructors make this unavailable
                                // only after loss of an original wait owner.
                                return Err(GitHelperDrivenFailedV1);
                            };
                            let wait = wait_for_process_turn_v1(view).await;
                            if let Err(source) = wait {
                                loan.wait_failed(source);
                            }
                        }
                        FixedProcessDrivenProgressV1::Ended => break Ok(()),
                        FixedProcessDrivenProgressV1::Debt => break Err(GitHelperDrivenFailedV1),
                    }
                }
            };

            guard.armed = false;
            result?;

            match guard.attempt.driven.as_ref()
                .and_then(|state| state.session.as_ref())
            {
                Some(session) if session.cause().is_none()
                    && session.cleanup_debt().is_none() => Ok(()),
                _ => Err(GitHelperDrivenFailedV1),
            }
        }
    }

    fn prepare_driven(&mut self) -> Result<(), GitHelperErrorV1> {
        let cut = self.driven.as_ref().ok_or(GitHelperErrorV1::Internal)?.cut;
        self.prepare_originals(Some(cut))?;

        check_cut(Some(cut))?;
        let prepared = prepare_fixed_process_driven_invocation_v1(FixedProcessRequest {
            executable: self.images.helper_path(),
            arguments: &[],
            timeout: self.limits.timeout,
            maximum_stdout_bytes: self.limits.maximum_output_bytes,
            maximum_stderr_bytes: self.limits.maximum_stderr_bytes,
        }).map_err(GitHelperErrorV1::Process)?;
        let state = self.driven.as_mut().ok_or(GitHelperErrorV1::Internal)?;
        state.prepared = Some(prepared);

        // The resident partial vector owns each successful safe duplicate
        // before the next duplication/image gate. These are the same three
        // ordinary roles, not new credentials, descriptor admission or rights.
        state.inherited.try_reserve_exact(3).map_err(GitHelperErrorV1::Allocation)?;

        check_cut(Some(cut))?;
        let plan = self.plan_original.as_ref().ok_or(GitHelperErrorV1::Internal)?;
        state.inherited.push(duplicate(plan.as_fd())?);

        check_cut(Some(cut))?;
        state.inherited.push(duplicate(self.directory.as_fd())?);

        check_cut(Some(cut))?;
        state.inherited.push(self.images.duplicate_git().map_err(GitHelperErrorV1::Image)?);

        check_cut(Some(cut))?;
        state.stdin = self.input_original.as_ref()
            .map(|original| duplicate(original.as_fd())).transpose()?;

        check_cut(Some(cut))?;
        state.executable = Some(self.images.duplicate_helper().map_err(GitHelperErrorV1::Image)?);

        check_cut(Some(cut))?;
        self.images.recheck().map_err(GitHelperErrorV1::Image)?;

        // Closed slots have all been filled. No fallible operation follows
        // taking the executable/prepared inputs and parking the original.
        if state.prepared.is_none() || state.executable.is_none() {
            return Err(GitHelperErrorV1::Internal);
        }

        let (Some(prepared), Some(executable)) = (state.prepared.take(), state.executable.take()) else {
            return Err(GitHelperErrorV1::Internal);
        };

        state.session = Some(FixedProcessDrivenSessionV1::park(
            prepared,
            FixedProcessDrivenInputsV1 {
                executable,
                stdin: state.stdin.take(),
                inherited: std::mem::take(&mut state.inherited),
                capture: std::mem::take(&mut self.capture),
            },
            cut,
        ));

        Ok(())
    }

    /// Borrows the same first setup/drive cause, never a synthesized IO error.
    pub(in crate::git) fn driven_cause(&self) -> Option<GitHelperDrivenCauseV1<'_>> {
        if let Some(error) = &self.first_error {
            return Some(GitHelperDrivenCauseV1::Setup(error));
        }

        let state = self.driven.as_ref()?;
        if let Some(cause) = state.session.as_ref().and_then(|session| session.cause()) {
            return Some(GitHelperDrivenCauseV1::Drive(cause));
        }

        state.interrupted.map(|cause| match cause {
            GitDrivenInterruptionV1::Cancelled => GitHelperDrivenCauseV1::Cancelled,
            GitDrivenInterruptionV1::Unwound => GitHelperDrivenCauseV1::Unwound,
        })
    }

    /// Borrows whole original lower capture DATA without copying output.
    pub(in crate::git) fn driven_capture(&self) -> Option<&FixedProcessCaptureV1> {
        self.driven.as_ref()?.session.as_ref()?.capture()
    }

    /// Borrows independent original lower cleanup debt.
    pub(in crate::git) fn driven_cleanup_debt(&self) -> Option<&FixedProcessDrivenDebtV1> {
        self.driven.as_ref()?.session.as_ref()?.cleanup_debt()
    }
}

struct GitDrivingGuardV1<'a, 'directory> {
    attempt: &'a mut GitHelperAttemptCustodyV1<'directory>,
    armed: bool,
}

impl Drop for GitDrivingGuardV1<'_, '_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        if let Some(state) = &mut self.attempt.driven {
            if state.interrupted.is_none() {
                state.interrupted = Some(if std::thread::panicking() {
                    GitDrivenInterruptionV1::Unwound
                } else {
                    GitDrivenInterruptionV1::Cancelled
                });
            }

            if let Some(session) = &mut state.session {
                // Negative-only closure also covers a parked unpolled session.
                // It never extracts/destroys the resident or blocks on reap.
                drop(session.drive());
            }
        }
    }
}

pub(super) fn check_cut(cut: Option<FixedProcessBoottimeCutV1>) -> Result<(), GitHelperErrorV1> {
    if let Some(cut) = cut {
        cut.check().map_err(GitHelperErrorV1::Clock)?;
    }

    Ok(())
}

/// Registers only short original borrows; all registrations drop on return or
/// cancellation before the lower owner can advance. Cached flags are wake DATA.
pub(in crate::git) async fn wait_for_process_turn_v1(
    view: FixedProcessWaitViewV1<'_>,
) -> std::io::Result<()> {
    tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
    let mut descriptors = Vec::new();
    descriptors.try_reserve_exact(5).map_err(std::io::Error::other)?;

    for descriptor in view.descriptors() {
        descriptors.push(AsyncFd::with_interest(descriptor, Interest::READABLE)?);
    }

    poll_fn(|context| {
        for descriptor in &descriptors {
            match descriptor.poll_read_ready(context) {
                Poll::Ready(Ok(guard)) => {
                    drop(guard);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(source)) => return Poll::Ready(Err(source)),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_preparation_has_no_selected_clock_check() {
        assert!(check_cut(None).is_ok());
    }
}
