//! Submission preflight and worker panic reconciliation.

use super::*;

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    /// Performs replay/conflict and epoch checks before semantic admission.
    ///
    /// A caller may release actor ownership while evaluating [`Self::admission_validator`]
    /// after this method returns [`SubmitPreflight::NeedsValidation`]. The final
    /// submit method rechecks assignment identity after reacquiring ownership.
    pub(crate) fn preflight_submit(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitPreflight, LocalExecutorError<L::Error>> {
        if let Some(response) = self.assignment_response(request)? {
            return Ok(SubmitPreflight::Resolved(response));
        }
        if request.daemon_epoch() != self.daemon_epoch {
            return self
                .persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Unauthorized,
                    },
                )
                .map(SubmitPreflight::Resolved);
        }
        Ok(SubmitPreflight::NeedsValidation)
    }

    /// Completes assignment admission after out-of-actor semantic validation.
    pub(crate) fn submit_after_validation(
        &mut self,
        request: &SubmitAttemptRequest,
        validation: Result<ValidatedSubmitAdmission, ExecutorRejection>,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        if let Some(response) = self.assignment_response(request)? {
            return Ok(response);
        }
        if request.daemon_epoch() != self.daemon_epoch {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Unauthorized,
                },
            );
        }
        let admission = match validation {
            Ok(admission) => admission,
            Err(reason) => {
                return self
                    .persist_response(request, SubmitAttemptDisposition::Rejected { reason });
            }
        };
        self.submit_admitted(request, admission)
    }

    /// Reconciles a caught worker panic after its linear token was unwound.
    ///
    /// Only the fixed worker owner calls this with the execution identity and
    /// attempt key captured before dispatch. The method marks physical worker
    /// ownership finished before durable cancellation so capacity cannot remain
    /// charged to an execution whose thread has already stopped.
    pub(crate) fn reconcile_panicked_worker(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
    ) -> Result<CancellationOutcome, LocalExecutorError<L::Error>> {
        if let Some(active) = self.active.get_mut(&execution) {
            if AttemptExecutionKey::for_request(&active.request) != key {
                return Err(LocalExecutorError::LedgerInvariant {
                    reason: "panicked worker execution basis does not match active reservation",
                });
            }
            active.cancellation.cancel();
            active.worker_in_flight = false;
        }
        self.cancel_execution(key, execution)
    }
}
