//! Fences one physical attempt under the actual deployment publisher invocation.
//!
//! The sole constructor borrows genuine Origins and their original startup.
//! Every use rechecks the existing image, credential, PID1 service and cgroup
//! engines. The retained kernel population monitor grants neither retirement
//! authority nor a way to wait for this live publisher's own group to empty.
//!
//! ```text
//! original startup: Idle -> Held -> Ended | Failed
//!                                 no reset or second physical claim
//! ```

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use aos_sandbox_linux::cgroup::{CgroupPopulationMonitor, CgroupPopulationState};
use aos_sandbox_linux::pidfd::PidFd;

use super::{
    ProductionRuntimeDeploymentStartupV1, RuntimeDeploymentComparisonErrorV1,
    RuntimeDeploymentComparisonOriginsV1, RuntimeDeploymentStartupErrorV1,
};

/// Reports a physical-invocation refusal with its first retained typed cause.
///
/// Cloning this diagnostic shares only the error, never the invocation lease.
#[derive(Clone, Debug)]
pub struct HostPhysicalInvocationErrorV1 {
    cause: Arc<InvocationFailureV1>,
}

impl fmt::Display for HostPhysicalInvocationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("deployment physical invocation is unavailable")
    }
}

impl Error for HostPhysicalInvocationErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

#[derive(Debug, thiserror::Error)]
enum InvocationFailureV1 {
    #[error("deployment original startup differs")]
    Startup(#[source] RuntimeDeploymentStartupErrorV1),
    #[error("deployment original genesis custody differs")]
    Origins(#[source] RuntimeDeploymentComparisonErrorV1),
    #[error("deployment original population monitor failed")]
    Population(#[source] aos_sandbox_linux::Error),
    #[error("deployment publisher is not in its original populated lifetime")]
    NotPopulated,
    #[error("deployment physical invocation is already held")]
    AlreadyHeld,
    #[error("deployment physical invocation has ended")]
    Ended,
    #[error("deployment physical invocation did not complete its check")]
    Unfinished,
    #[error("deployment physical invocation state was poisoned")]
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvocationPhaseV1 {
    Idle,
    Held,
    Ended,
    Failed,
}

struct InvocationStateV1 {
    phase: InvocationPhaseV1,
    first_failure: Option<Arc<InvocationFailureV1>>,
}

/// Lives only on the genuine captured startup; no caller can manufacture it.
pub(super) struct HostPhysicalInvocationStateV1 {
    state: Mutex<InvocationStateV1>,
}

impl HostPhysicalInvocationStateV1 {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(InvocationStateV1 {
                phase: InvocationPhaseV1::Idle,
                first_failure: None,
            }),
        }
    }

    fn claim(&self) -> Result<InvocationClaimV1<'_>, HostPhysicalInvocationErrorV1> {
        let mut state = self.lock();
        if state.phase != InvocationPhaseV1::Idle {
            return Err(unavailable(&state));
        }

        // This transition precedes all original rechecks and kernel opens.
        // No fallible work separates Held from its stack-owned cleanup guard.
        state.phase = InvocationPhaseV1::Held;
        Ok(InvocationClaimV1 {
            owner: self,
            healthy: false,
        })
    }

    fn require_held(&self) -> Result<(), HostPhysicalInvocationErrorV1> {
        let state = self.lock();
        if state.phase != InvocationPhaseV1::Held {
            return Err(unavailable(&state));
        }
        Ok(())
    }

    fn fail(&self, cause: InvocationFailureV1) -> HostPhysicalInvocationErrorV1 {
        let mut state = self.lock();
        // Close the shared original before retaining/returning diagnostics.
        state.phase = InvocationPhaseV1::Failed;
        let cause = state.first_failure.get_or_insert_with(|| Arc::new(cause));
        HostPhysicalInvocationErrorV1 {
            cause: Arc::clone(cause),
        }
    }

    fn end(&self) {
        let mut state = self.lock();
        if state.phase == InvocationPhaseV1::Held {
            state.phase = InvocationPhaseV1::Ended;
        }
    }

    fn lock(&self) -> MutexGuard<'_, InvocationStateV1> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                // Recover only to fence and preserve diagnostics, never to
                // resume an invocation or turn a poisoned state back to Idle.
                let mut state = poisoned.into_inner();
                state.phase = InvocationPhaseV1::Failed;
                state.first_failure
                    .get_or_insert_with(|| Arc::new(InvocationFailureV1::Poisoned));
                state
            }
        }
    }
}

fn unavailable(state: &InvocationStateV1) -> HostPhysicalInvocationErrorV1 {
    if let Some(cause) = &state.first_failure {
        return HostPhysicalInvocationErrorV1 {
            cause: Arc::clone(cause),
        };
    }

    let cause = match state.phase {
        InvocationPhaseV1::Idle | InvocationPhaseV1::Failed => InvocationFailureV1::Unfinished,
        InvocationPhaseV1::Held => InvocationFailureV1::AlreadyHeld,
        InvocationPhaseV1::Ended => InvocationFailureV1::Ended,
    };
    HostPhysicalInvocationErrorV1 {
        cause: Arc::new(cause),
    }
}

struct InvocationClaimV1<'startup> {
    owner: &'startup HostPhysicalInvocationStateV1,
    healthy: bool,
}

impl<'startup> InvocationClaimV1<'startup> {
    fn complete_claim<T>(
        &mut self,
        result: Result<T, InvocationFailureV1>,
    ) -> Result<T, HostPhysicalInvocationErrorV1> {
        match result {
            Ok(value) => {
                self.healthy = true;
                Ok(value)
            }
            Err(cause) => Err(self.owner.fail(cause)),
        }
    }

    fn begin(
        &mut self,
    ) -> Result<InvocationOperationV1<'_, 'startup>, HostPhysicalInvocationErrorV1> {
        self.owner.require_held()?;
        if !self.healthy {
            return Err(self.owner.fail(InvocationFailureV1::Unfinished));
        }

        self.healthy = false;
        Ok(InvocationOperationV1 {
            claim: self,
            complete: false,
        })
    }
}

impl Drop for InvocationClaimV1<'_> {
    fn drop(&mut self) {
        if self.healthy {
            self.owner.end();
        } else {
            self.owner.fail(InvocationFailureV1::Unfinished);
        }
    }
}

struct InvocationOperationV1<'claim, 'startup> {
    claim: &'claim mut InvocationClaimV1<'startup>,
    complete: bool,
}

impl InvocationOperationV1<'_, '_> {
    fn finish<T>(
        mut self,
        result: Result<T, InvocationFailureV1>,
    ) -> Result<T, HostPhysicalInvocationErrorV1> {
        let result = self.claim.complete_claim(result);
        self.complete = true;
        result
    }
}

impl Drop for InvocationOperationV1<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            // This guard runs even when a caller catches the check's unwind
            // and keeps the lease alive. No later claim can reuse the startup.
            self.claim.owner.fail(InvocationFailureV1::Unfinished);
        }
    }
}

/// Borrows one genuine startup invocation and its original population monitor.
///
/// This move-only prerequisite has no scalar, descriptor, proof or callback
/// constructor. Drop permanently ends the same invocation. Failed or interrupted
/// checks retain their first typed cause. No operation writes, seeds or extends
/// NV, kills a population, grants a floor or authorizes another activation.
/// The terminal publisher and installed PID1 ordering remain separate work.
#[must_use = "retain the original one-shot invocation through the physical owner"]
pub struct HostPhysicalInvocationLeaseV1<'origin, 'startup> {
    // Field drop order fences the shared original before releasing the monitor.
    claim: InvocationClaimV1<'origin>,
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    startup: &'origin ProductionRuntimeDeploymentStartupV1,
    population: CgroupPopulationMonitor,
}

impl<'origin, 'startup> HostPhysicalInvocationLeaseV1<'origin, 'startup> {
    pub(super) fn claim(
        origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    ) -> Result<Self, HostPhysicalInvocationErrorV1> {
        let startup = origins.host_physical_invocation_startup();
        let mut claim = startup.host_physical_invocation_state().claim()?;
        let result = (|| {
            recheck_originals(origins, startup)?;
            let population = startup
                .retain_host_invocation_population()
                .map_err(InvocationFailureV1::Population)?;
            require_populated(&population)?;
            recheck_originals(origins, startup)?;
            require_populated(&population)?;
            Ok(population)
        })();
        let population = claim.complete_claim(result)?;

        Ok(Self {
            claim,
            origins,
            startup,
            population,
        })
    }

    /// Rechecks the same actual invocation, originals and recursive population.
    ///
    /// Empty or retired observations refuse this still-live publisher; they
    /// cannot become a local Drained proof, retry or restart permit.
    ///
    /// # Errors
    ///
    /// Rejects a terminal lease, original startup/genesis drift, failed kernel
    /// observation or a population inconsistent with the retained live owner.
    /// Failure permanently fences every physical claim from the same startup.
    pub fn recheck(&mut self) -> Result<(), HostPhysicalInvocationErrorV1> {
        let origins = self.origins;
        let startup = self.startup;
        let population = &self.population;
        let operation = self.claim.begin()?;
        let result = (|| {
            recheck_originals(origins, startup)?;
            require_populated(population)?;
            recheck_originals(origins, startup)?;
            require_populated(population)
        })();
        operation.finish(result)
    }

    /// Joins a retained child's actual parent and exact original cgroup.
    ///
    /// This adds no image, MAC, credential or TPM/session authentication for
    /// the child. The separate fixed helper owner still performs those checks.
    ///
    /// # Errors
    ///
    /// Rejects original drift, a stale or foreign child, another parent/cgroup
    /// or failed population readback, permanently fencing this invocation.
    pub fn require_child(&mut self, child: &PidFd) -> Result<(), HostPhysicalInvocationErrorV1> {
        let origins = self.origins;
        let startup = self.startup;
        let population = &self.population;
        let operation = self.claim.begin()?;
        let result = (|| {
            recheck_originals(origins, startup)?;
            require_populated(population)?;
            startup.require_child(child).map_err(InvocationFailureV1::Startup)?;
            recheck_originals(origins, startup)?;
            require_populated(population)
        })();
        operation.finish(result)
    }
}

fn recheck_originals(
    origins: &RuntimeDeploymentComparisonOriginsV1<'_>,
    startup: &ProductionRuntimeDeploymentStartupV1,
) -> Result<(), InvocationFailureV1> {
    // Preserve the actual startup cause before the existing genesis engine's
    // narrower provisioning error; reuse both engines rather than reparse.
    startup.recheck().map_err(InvocationFailureV1::Startup)?;
    origins.recheck().map_err(InvocationFailureV1::Origins)
}

fn require_populated(population: &CgroupPopulationMonitor) -> Result<(), InvocationFailureV1> {
    let state = population.state().map_err(InvocationFailureV1::Population)?;
    require_populated_state(state)
}

fn require_populated_state(state: CgroupPopulationState) -> Result<(), InvocationFailureV1> {
    match state {
        CgroupPopulationState::Populated => Ok(()),
        CgroupPopulationState::Empty | CgroupPopulationState::Retired => {
            Err(InvocationFailureV1::NotPopulated)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    // These exercise only the private latch and typed observation predicate.
    // No startup, Origins, pidfd, cgroup or positive physical lease is fabricated.
    #[test]
    fn unrun_same_original_claim_is_one_shot_before_fallible_admission() {
        let owner = HostPhysicalInvocationStateV1::new();
        let mut claim = owner.claim().expect("initial private claim");
        assert_eq!(owner.lock().phase, InvocationPhaseV1::Held);

        let repeated = owner.claim().err().expect("same original already held");
        assert!(matches!(
            repeated.cause.as_ref(),
            InvocationFailureV1::AlreadyHeld,
        ));
        claim.complete_claim(Ok(())).expect("inert claim completion");
        drop(claim);

        assert_eq!(owner.lock().phase, InvocationPhaseV1::Ended);
        let ended = owner.claim().err().expect("ended original cannot reopen");
        assert!(matches!(ended.cause.as_ref(), InvocationFailureV1::Ended));
    }

    #[test]
    fn unrun_incomplete_initial_claim_drop_permanently_fails_the_original() {
        let owner = HostPhysicalInvocationStateV1::new();
        drop(owner.claim().expect("initial private claim"));

        assert_eq!(owner.lock().phase, InvocationPhaseV1::Failed);
        let error = owner.claim().err().expect("original remains failed");
        assert!(matches!(
            error.cause.as_ref(),
            InvocationFailureV1::Unfinished,
        ));
    }

    #[test]
    fn unrun_first_startup_failure_survives_later_failure_and_drop() {
        let owner = HostPhysicalInvocationStateV1::new();
        let mut claim = owner.claim().expect("initial private claim");

        let first = claim
            .complete_claim::<()>(Err(InvocationFailureV1::Startup(
                RuntimeDeploymentStartupErrorV1::Image,
            )))
            .expect_err("inert typed refusal");
        let later = owner.fail(InvocationFailureV1::NotPopulated);
        assert!(Arc::ptr_eq(&first.cause, &later.cause));
        assert!(matches!(
            first.cause.as_ref(),
            InvocationFailureV1::Startup(RuntimeDeploymentStartupErrorV1::Image),
        ));
        assert!(
            first.source()
                .and_then(|cause| cause.source())
                .is_some_and(|cause| cause.is::<RuntimeDeploymentStartupErrorV1>()),
        );

        drop(claim);
        let refused = owner.claim().err().expect("failed original cannot reopen");
        assert!(Arc::ptr_eq(&first.cause, &refused.cause));
    }

    #[test]
    fn unrun_population_kernel_cause_is_retained_without_string_erasure() {
        let owner = HostPhysicalInvocationStateV1::new();
        let mut claim = owner.claim().expect("initial private claim");
        claim.complete_claim(Ok(())).expect("inert claim completion");

        let first = claim
            .begin()
            .expect("begin inert check")
            .finish::<()>(Err(InvocationFailureV1::Population(
                aos_sandbox_linux::Error::DeadlineExceeded {
                    operation: "inert population observation",
                },
            )))
            .expect_err("inert kernel refusal");
        assert!(
            first.source()
                .and_then(|cause| cause.source())
                .is_some_and(|cause| cause.is::<aos_sandbox_linux::Error>()),
        );
        let later = claim.begin().err().expect("no retry after failure");
        assert!(Arc::ptr_eq(&first.cause, &later.cause));
        assert_eq!(owner.lock().phase, InvocationPhaseV1::Failed);
    }

    #[test]
    fn unrun_successful_checks_keep_only_the_same_held_claim() {
        let owner = HostPhysicalInvocationStateV1::new();
        let mut claim = owner.claim().expect("initial private claim");
        claim.complete_claim(Ok(())).expect("inert claim completion");

        for _ in 0..2 {
            claim.begin()
                .expect("same held check")
                .finish(Ok(()))
                .expect("inert successful check");
            assert_eq!(owner.lock().phase, InvocationPhaseV1::Held);
            assert!(owner.claim().is_err());
        }

        drop(claim);
        assert_eq!(owner.lock().phase, InvocationPhaseV1::Ended);
        assert!(owner.claim().is_err());
    }

    #[test]
    fn unrun_incomplete_operation_drop_fences_a_still_retained_claim() {
        let owner = HostPhysicalInvocationStateV1::new();
        let mut claim = owner.claim().expect("initial private claim");
        claim.complete_claim(Ok(())).expect("inert claim completion");

        drop(claim.begin().expect("begin inert check"));
        assert_eq!(owner.lock().phase, InvocationPhaseV1::Failed);
        let first = claim.begin().err().expect("no retained-claim retry");
        assert!(matches!(
            first.cause.as_ref(),
            InvocationFailureV1::Unfinished,
        ));
        let repeated = owner.claim().err().expect("no new original claim");
        assert!(Arc::ptr_eq(&first.cause, &repeated.cause));
    }

    #[test]
    fn unrun_caught_operation_unwind_fences_before_the_lease_is_dropped() {
        let owner = HostPhysicalInvocationStateV1::new();
        let mut claim = owner.claim().expect("initial private claim");
        claim.complete_claim(Ok(())).expect("inert claim completion");

        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _operation = claim.begin().expect("begin inert check");
            panic!("inert interrupted check");
        }));
        assert!(unwind.is_err());
        assert_eq!(owner.lock().phase, InvocationPhaseV1::Failed);
        assert!(claim.begin().is_err());
        assert!(owner.claim().is_err());
    }

    #[test]
    fn unrun_poison_recovery_is_only_a_permanent_failure_fence() {
        let owner = HostPhysicalInvocationStateV1::new();
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _state = owner.state.lock().expect("inert state lock");
            panic!("inert poisoned state");
        }));
        assert!(unwind.is_err());

        let first = owner.claim().err().expect("poison cannot admit a claim");
        assert_eq!(owner.lock().phase, InvocationPhaseV1::Failed);
        assert!(matches!(first.cause.as_ref(), InvocationFailureV1::Poisoned));
        let later = owner.claim().err().expect("poison never resets");
        assert!(Arc::ptr_eq(&first.cause, &later.cause));
    }

    #[test]
    fn unrun_empty_or_retired_state_never_mints_local_drain_or_retry() {
        assert!(require_populated_state(CgroupPopulationState::Populated).is_ok());
        for state in [CgroupPopulationState::Empty, CgroupPopulationState::Retired] {
            assert!(matches!(
                require_populated_state(state),
                Err(InvocationFailureV1::NotPopulated),
            ));
        }
    }
}
