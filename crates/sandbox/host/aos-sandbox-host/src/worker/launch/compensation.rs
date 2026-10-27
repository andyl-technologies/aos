//! Lends only prearmed negative cleanup on the same consumed Launch.
//!
//! The original failure, request, native prefixes and financial debt remain
//! resident. This borrower cannot start, promote, reset or settle the Launch.

use super::*;
use crate::state::transition::GuardianLaunchPhase;

/// Exclusively borrows the original's finite, already-paid cleanup suffix.
#[must_use = "the original failure and entered native cleanup remain resident"]
pub(crate) struct HostLaunchCompensationLoanV1<'borrow, 'call, 'original> {
    receiving: &'borrow mut HostLaunchWorkerReceivingV2<'call, 'original>,
    scope: (super::super::HostRuntimeIdentity, [u8; 32]),
}

// Only this child's actual loan may create a negative call. Its fields are
// private even to the parent worker module; DATA cannot select the obligation.
#[derive(Clone, Copy)]
pub(super) struct CompensationCallV1 {
    request: RequestIdentity,
    scope: (super::super::HostRuntimeIdentity, [u8; 32]),
}

impl CompensationCallV1 {
    pub(super) async fn require_v1(
        &self,
        receiving: &HostLaunchWorkerReceivingV2<'_, '_>,
        call: HostSystemdCallV2,
    ) -> Result<()> {
        if !matches!(
            call,
            HostSystemdCallV2::ExactObserve
                | HostSystemdCallV2::PostUnrefObserve
                | HostSystemdCallV2::ExactStop
        ) || self.request != identity(receiving.request)
            || tokio::time::Instant::now() >= receiving.deadline
        {
            return Err(closed(
                "negative call differs from its original finite programme",
            ));
        }
        let original = receiving.original.lock().await;
        if original.request != self.request
            || !original.compensation_entered
            || original.compensation_result.is_some()
            || original.compensation_scope != Some(self.scope)
            || !original
                .compensation_prearm
                .is_some_and(|paid| paid.request == self.request && paid.compensation_prearm)
        {
            return Err(closed(
                "negative call lost its resident worker/prearm association",
            ));
        }
        let phase = HostLaunchWorkerPhaseV4 {
            request: self.request,
            current_native_files: original
                .current_native_files_v4()?
                .checked_add(original.sdk_interval_files_v4(call)?)
                .ok_or(HostError::ResourceExhausted)?,
            compensation_prearm: false,
        };
        receiving
            .receiving
            .require_launch_compensation_phase_v1(receiving.request, &phase)
    }
}

impl<'call, 'original> HostLaunchWorkerReceivingV2<'call, 'original> {
    /// Borrows the original failed Launch without reopening a healthy port.
    ///
    /// # Errors
    /// Refuses another durable attempt, absent successful prearm, expired local
    /// horizon, wrong scope, reentry or a foreign consumed financial original.
    pub(crate) async fn borrow_compensation_once_v1<'borrow>(
        &'borrow mut self,
        scope: &super::super::HostRuntimeIdentity,
        binding: [u8; 32],
        phase: &GuardianLaunchPhase,
    ) -> Result<HostLaunchCompensationLoanV1<'borrow, 'call, 'original>> {
        // The verification failure being handled follows the original payload
        // start. It cannot manufacture a negative owner for an unrelated phase.
        if !matches!(phase, GuardianLaunchPhase::PayloadStartIssued { .. })
            || tokio::time::Instant::now() >= self.deadline
        {
            return Err(closed(
                "negative cleanup lacks its original payload-start boundary",
            ));
        }
        {
            let mut original = self.original.lock().await;
            let paid = original
                .compensation_prearm
                .as_ref()
                .ok_or_else(|| closed("negative cleanup has no earlier successful prearm"))?;
            if original.request != identity(self.request)
                || original.schedule.is_resident_stop_v4()
                || original.compensation_entered
                || original.compensation_scope != Some((*scope, binding))
                || paid.request != identity(self.request)
                || !paid.compensation_prearm
            {
                return Err(closed(
                    "negative cleanup differs from its original worker scope",
                ));
            }
            let actual = HostLaunchWorkerPhaseV4 {
                request: original.request,
                current_native_files: original.current_native_files_v4()?,
                compensation_prearm: false,
            };
            self.receiving
                .require_launch_compensation_phase_v1(self.request, &actual)?;
            original.compensation_entered = true;
        }
        Ok(HostLaunchCompensationLoanV1 {
            receiving: self,
            scope: (*scope, binding),
        })
    }
}

impl HostLaunchCompensationLoanV1<'_, '_, '_> {
    fn call_v1(&self) -> CompensationCallV1 {
        CompensationCallV1 {
            request: identity(self.receiving.request),
            scope: self.scope,
        }
    }

    /// Observes an original role through the same bounded SDK/absence engine.
    ///
    /// # Errors
    /// Retains and refuses scope, horizon, earlier-prearm, SDK or native errors.
    pub(crate) async fn observe_v1(
        &mut self,
        worker: &super::super::RetainedPayloadWorkerV1<'_>,
        scope: &super::super::HostRuntimeIdentity,
        role: aos_systemd_client::ExactUnitRole,
        post_unref: bool,
    ) -> Result<super::super::GuardianObservation> {
        if *scope != self.scope.0 {
            return Err(closed("negative observation scope differs"));
        }
        let call = self.call_v1();
        self.receiving
            .observe_exact_kind_v3(worker.worker, scope, role, None, post_unref, Some(call))
            .await
    }

    /// Stops only the reducer's exact original binding and invocation.
    ///
    /// # Errors
    /// Refuses foreign scope, unpaid/exhausted entry, expired original clock or
    /// SDK/native uncertainty, preserving all actual prefixes and owed posts.
    pub(crate) async fn stop_v1(
        &mut self,
        worker: &super::super::RetainedPayloadWorkerV1<'_>,
        scope: &super::super::HostRuntimeIdentity,
        role: aos_systemd_client::ExactUnitRole,
        binding: [u8; 32],
        invocation: [u8; 16],
    ) -> Result<super::super::ExactWorkerStopOutcome> {
        if (*scope, binding) != self.scope {
            return Err(closed("negative Stop scope/binding differs"));
        }
        let call = self.call_v1();
        self.receiving
            .stop_exact_unit_engine_v1(
                worker,
                scope,
                role,
                binding,
                invocation,
                CallObligationV2::Compensation(call),
            )
            .await
    }

    /// Compares retained custody before the genuine reducer's negative write.
    ///
    /// # Errors
    /// Refuses reentry, changed original scope or lost paid native association.
    pub(crate) async fn require_terminal_v1(
        &self,
        scope: &super::super::HostRuntimeIdentity,
        binding: [u8; 32],
    ) -> Result<()> {
        if (*scope, binding) != self.scope {
            return Err(closed("negative terminal scope differs"));
        }
        // No new receiver is constructed: compare the actual retained files to
        // the same paid ceiling after all entered rows have run their posts.
        let original = self.receiving.original.lock().await;
        if original.compensation_result.is_some()
            || !original.compensation_entered
            || original.compensation_scope != Some(self.scope)
        {
            return Err(closed("negative terminal is absent or already completed"));
        }
        let actual = HostLaunchWorkerPhaseV4 {
            request: original.request,
            current_native_files: original.current_native_files_v4()?,
            compensation_prearm: false,
        };
        self.receiving
            .receiving
            .require_launch_compensation_phase_v1(self.receiving.request, &actual)
    }

    /// Parks the cleanup result without settling or replacing the first cause.
    pub(crate) async fn finish_once_v1(self, result: Result<()>) {
        let mut original = self.receiving.original.lock().await;
        if original.compensation_result.is_none() {
            original.compensation_result = Some(result);
        }
    }
}

/// Binds a diagnostic selection to the genuine failed receiving original.
///
/// This private-constructor affinity lends no effect, capacity or completion.
/// It shares only the existing worker's weak identity and exact request.
pub(crate) struct HostLaunchVerificationAffinityV1 {
    request: RequestIdentity,
    worker: Weak<Mutex<HostLaunchWorkerOriginalV2>>,
    original_failure: bool,
}

impl HostLaunchVerificationAffinityV1 {
    /// Compares the actual retained Stage without observing or adopting it.
    pub(crate) fn matches_worker_v1(
        &self,
        worker: &Arc<Mutex<HostLaunchWorkerOriginalV2>>,
        request: RequestIdentity,
    ) -> bool {
        self.request == request && self.worker.ptr_eq(&Arc::downgrade(worker))
    }

    /// Reports only the same Source owner's failure at the causal frontier.
    pub(crate) fn original_failure_selected_v1(&self) -> bool {
        self.original_failure
    }
}

impl HostLaunchWorkerReceivingV2<'_, '_> {
    /// Captures only the actual verification failure's diagnostic association.
    ///
    /// # Errors
    /// Refuses another request, absent original scope, an already entered
    /// cleanup or lost consumed-flight custody; it creates no cleanup permit.
    pub(crate) fn capture_verification_affinity_v1(
        &self,
        scope: &super::super::HostRuntimeIdentity,
        binding: [u8; 32],
    ) -> Result<HostLaunchVerificationAffinityV1> {
        self.receiving
            .require_launch_readonly_post_request_v2(self.request)?;
        let original = self
            .original
            .try_lock()
            .map_err(|_| closed("verification diagnostic original is borrowed"))?;
        if original.request != identity(self.request)
            || original.schedule.is_resident_stop_v4()
            || original.compensation_scope != Some((*scope, binding))
            || original.compensation_entered
        {
            return Err(closed(
                "verification diagnostic has no same original worker",
            ));
        }
        Ok(HostLaunchVerificationAffinityV1 {
            request: original.request,
            worker: Arc::downgrade(&self.original),
            original_failure: self
                .receiving
                .component_report_original_failure_entered_v2(),
        })
    }
}
