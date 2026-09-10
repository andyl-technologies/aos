//! Pure lifecycle-worker ordering and freshness gates.
//!
//! This module models control-flow authority only. A step token does not prove
//! that Linux accepted a mutation or that a postcondition was observed. The
//! future fixed worker may acknowledge success only after its exact mutation
//! routine returns successfully, and the broker must still obtain trusted
//! post-effect observation before committing lifecycle state.

use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

use crate::NetworkAdmissionError;
use crate::authorization::NetworkAuthorityV1;
use crate::kernel_plan::NetworkKernelPlanV1;
use crate::namespace_catalog::{
    NetworkNamespaceIdentityV1, NetworkNamespaceLifecycleActionV1, NetworkNamespaceObservedStateV1,
};
use crate::worker_protocol::{NetworkWorkerProtocolError, check_freshness};
use crate::worker_replay::NetworkWorkerReplayLedger;

use super::AuthenticatedNetworkLifecycleWorkerDispatchV1;

/// Names one ordered, separately freshness-gated worker kernel operation.
///
/// Broker-owned systemd custody and namespace-pin teardown are intentionally
/// absent. A future broker may authorize those only after trusted observation
/// proves exact kernel-object absence, while retaining namespace custody until
/// pin cleanup is complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkLifecycleExecutionStepV1 {
    /// Confirms both veth ends remain down before activation work begins.
    EnsureLinksDown,
    /// Installs the exact new lease tuple while the data path remains down.
    ArmLeaseGate,
    /// Replaces the current lease tuple as one atomic map update.
    ReplaceLeaseGateAtomically,
    /// Applies the complete plan-derived IPv4 and IPv6 address pairs.
    ConfigureExactAddressPairs,
    /// Applies the complete plan-derived IPv4 and IPv6 routes.
    ConfigureExactRoutes,
    /// Applies the complete plan-derived permanent IPv6 neighbor set.
    ConfigureExactPermanentNeighbors,
    /// Verifies the exact plan configuration before activation or containment.
    VerifyExactPlanConfiguration,
    /// Raises both exact veth ends only after all prior activation steps.
    RaiseLinks,
    /// Lowers both exact veth ends before containment or cleanup continues.
    LowerLinks,
    /// Restores the lease gate to local default-drop state.
    DisarmLeaseGate,
    /// Removes only the exact plan-owned links, rules, maps, and policy objects.
    RemoveOwnedNetworkObjects,
    /// Verifies exact kernel-object absence without authorizing broker teardown.
    VerifyKernelOwnedObjectsAbsent,
}

impl AuthenticatedNetworkLifecycleWorkerDispatchV1 {
    /// Claims the attempt under two fresh authority checks.
    ///
    /// A claim remains consumed if the second check fails. No target, plan, or
    /// execution step is exposed before both checks complete.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::Authority`] for stale or expired
    /// authority, including an attempted renewal after its prior gate expired.
    /// Returns [`NetworkWorkerProtocolError::Replay`] or
    /// [`NetworkWorkerProtocolError::ReplayStore`] for replay-ledger failure.
    pub fn authorize_execution<C, F>(
        self,
        authority: &NetworkAuthorityV1,
        replay: &mut NetworkWorkerReplayLedger,
        trusted_current_fence: &mut C,
        trusted_clock: &mut F,
    ) -> Result<NetworkLifecycleExecutionAuthorizationV1, NetworkWorkerProtocolError>
    where
        C: FnMut() -> Result<Vec<u8>, NetworkAdmissionError>,
        F: FnMut() -> Result<RawPairedClockSample, NetworkAdmissionError>,
    {
        check_execution_freshness(authority, &self, trusted_current_fence, trusted_clock)?;
        let dispatch_digest =
            ObjectDigest::from_bytes(Sha256::digest(&self.request.dispatch).into());
        replay.claim(
            self.request.request_id,
            self.request.effect_digest,
            self.request.kernel_plan.digest(),
            dispatch_digest,
        )?;
        check_execution_freshness(authority, &self, trusted_current_fence, trusted_clock)?;

        Ok(NetworkLifecycleExecutionAuthorizationV1 {
            authenticated: self,
            next_step: 0,
            pending_step: None,
            poisoned: false,
        })
    }
}

/// Owns one replay-claimed lifecycle attempt and its exact pending step.
///
/// Issuing a token records that step as pending before returning it. Only the
/// token's explicit successful completion advances the cursor. Dropping or
/// failing a token poisons the attempt; forgetting it leaves the pending step
/// in place, so no later step can be issued.
pub struct NetworkLifecycleExecutionAuthorizationV1 {
    authenticated: AuthenticatedNetworkLifecycleWorkerDispatchV1,
    next_step: usize,
    pending_step: Option<usize>,
    poisoned: bool,
}

impl NetworkLifecycleExecutionAuthorizationV1 {
    /// Authorizes the next exact step after another fresh authority check.
    ///
    /// The returned token must be completed explicitly. It is never safe to
    /// infer kernel success from token issuance or destruction.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::Authority`] when current authority
    /// or effect time changed, or when a renewal's prior gate is expired.
    /// Returns [`NetworkWorkerProtocolError::ExecutionPoisoned`] after a prior
    /// step failed, was dropped, or remains pending.
    pub fn authorize_next_step<'a, C, F>(
        &'a mut self,
        authority: &NetworkAuthorityV1,
        trusted_current_fence: &mut C,
        trusted_clock: &mut F,
    ) -> Result<Option<NetworkLifecycleAuthorizedStepV1<'a>>, NetworkWorkerProtocolError>
    where
        C: FnMut() -> Result<Vec<u8>, NetworkAdmissionError>,
        F: FnMut() -> Result<RawPairedClockSample, NetworkAdmissionError>,
    {
        if self.poisoned || self.pending_step.is_some() {
            self.poisoned = true;
            return Err(NetworkWorkerProtocolError::ExecutionPoisoned);
        }

        let steps = execution_steps(self.authenticated.request.context.action);
        let Some(step) = steps.get(self.next_step).copied() else {
            return Ok(None);
        };
        if let Err(error) = check_execution_freshness(
            authority,
            &self.authenticated,
            trusted_current_fence,
            trusted_clock,
        ) {
            self.poisoned = true;
            return Err(error);
        }

        // The state becomes non-advancing before caller code can see the token.
        self.pending_step = Some(self.next_step);
        Ok(Some(NetworkLifecycleAuthorizedStepV1 {
            step,
            step_index: self.next_step,
            authorization: self,
            resolved: false,
        }))
    }

    /// Reports whether every worker step completed without poison.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.poisoned
            && self.pending_step.is_none()
            && self.next_step == execution_steps(self.authenticated.request.context.action).len()
    }

    /// Reports whether this attempt can never issue another step.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

/// Carries control-flow authority for one exact pending worker step.
///
/// This token is not a kernel postcondition proof. The fixed worker must invoke
/// [`Self::complete_success`] only after the named operation succeeds.
#[must_use = "dropping a pending lifecycle step permanently poisons the attempt"]
pub struct NetworkLifecycleAuthorizedStepV1<'a> {
    step: NetworkLifecycleExecutionStepV1,
    step_index: usize,
    authorization: &'a mut NetworkLifecycleExecutionAuthorizationV1,
    resolved: bool,
}

impl NetworkLifecycleAuthorizedStepV1<'_> {
    /// Returns the one operation authorized by this pending token.
    #[must_use]
    pub const fn step(&self) -> NetworkLifecycleExecutionStepV1 {
        self.step
    }

    /// Returns the exact canonical plan admitted with the durable effect.
    #[must_use]
    pub const fn kernel_plan(&self) -> &NetworkKernelPlanV1 {
        &self.authorization.authenticated.request.kernel_plan
    }

    /// Returns the exact retained target namespace identity.
    #[must_use]
    pub const fn target_namespace(&self) -> NetworkNamespaceIdentityV1 {
        self.authorization
            .authenticated
            .request
            .context
            .authority
            .identity
    }

    /// Returns the closed lifecycle action shared by every step.
    #[must_use]
    pub const fn action(&self) -> NetworkNamespaceLifecycleActionV1 {
        self.authorization.authenticated.request.context.action
    }

    /// Returns the exact desired post-effect state.
    #[must_use]
    pub const fn desired_state(&self) -> NetworkNamespaceObservedStateV1 {
        self.authorization
            .authenticated
            .request
            .context
            .desired_state
    }

    /// Acknowledges successful completion under a post-step freshness check.
    ///
    /// This advances exactly the pending step. It does not attest a Linux
    /// postcondition; the caller is responsible for invoking it only after the
    /// fixed mutation implementation reports success.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::Authority`] when authority became
    /// stale during the operation, permanently poisoning this attempt. Returns
    /// [`NetworkWorkerProtocolError::ExecutionPoisoned`] if the token no longer
    /// names the exact pending cursor.
    pub fn complete_success<C, F>(
        mut self,
        authority: &NetworkAuthorityV1,
        trusted_current_fence: &mut C,
        trusted_clock: &mut F,
    ) -> Result<(), NetworkWorkerProtocolError>
    where
        C: FnMut() -> Result<Vec<u8>, NetworkAdmissionError>,
        F: FnMut() -> Result<RawPairedClockSample, NetworkAdmissionError>,
    {
        if self.authorization.poisoned
            || self.authorization.pending_step != Some(self.step_index)
            || self.authorization.next_step != self.step_index
        {
            self.poison();
            return Err(NetworkWorkerProtocolError::ExecutionPoisoned);
        }
        if let Err(error) = check_execution_freshness(
            authority,
            &self.authorization.authenticated,
            trusted_current_fence,
            trusted_clock,
        ) {
            self.poison();
            return Err(error);
        }

        self.authorization.next_step += 1;
        self.authorization.pending_step = None;
        self.resolved = true;
        Ok(())
    }

    /// Records mutation failure and permanently poisons the attempt.
    pub fn fail(mut self) {
        self.poison();
    }

    fn poison(&mut self) {
        self.authorization.poisoned = true;
        self.authorization.pending_step = None;
        self.resolved = true;
    }
}

impl Drop for NetworkLifecycleAuthorizedStepV1<'_> {
    fn drop(&mut self) {
        if !self.resolved {
            self.poison();
        }
    }
}

fn check_execution_freshness<C, F>(
    authority: &NetworkAuthorityV1,
    authenticated: &AuthenticatedNetworkLifecycleWorkerDispatchV1,
    trusted_current_fence: &mut C,
    trusted_clock: &mut F,
) -> Result<(), NetworkWorkerProtocolError>
where
    C: FnMut() -> Result<Vec<u8>, NetworkAdmissionError>,
    F: FnMut() -> Result<RawPairedClockSample, NetworkAdmissionError>,
{
    let trusted_current_fence =
        trusted_current_fence().map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let reopened_current = authority
        .open_fence(
            &authenticated.request.context.sandbox_id,
            &trusted_current_fence,
        )
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    if trusted_current_fence != authenticated.request.current_fence
        || reopened_current != authenticated.current_fence
    {
        return Err(NetworkWorkerProtocolError::Authority);
    }

    let mut observed_clock = None;
    check_freshness(
        authority,
        &authenticated.current_fence,
        &authenticated.effect,
        &mut || {
            let clock = trusted_clock()?;
            observed_clock = Some(clock);
            Ok(clock)
        },
    )?;
    if authenticated.request.context.action == NetworkNamespaceLifecycleActionV1::Renew {
        let prior_deadline = authenticated
            .request
            .context
            .authority
            .observed_state
            .lease()
            .map(|(_, _, deadline)| deadline)
            .ok_or(NetworkWorkerProtocolError::Authority)?;
        if observed_clock.is_none_or(|clock| clock.boottime_nanoseconds() >= prior_deadline) {
            return Err(NetworkWorkerProtocolError::Authority);
        }
    }
    Ok(())
}

fn execution_steps(
    action: NetworkNamespaceLifecycleActionV1,
) -> &'static [NetworkLifecycleExecutionStepV1] {
    use NetworkLifecycleExecutionStepV1 as Step;

    match action {
        NetworkNamespaceLifecycleActionV1::Arm => &[
            Step::EnsureLinksDown,
            Step::ArmLeaseGate,
            Step::ConfigureExactAddressPairs,
            Step::ConfigureExactRoutes,
            Step::ConfigureExactPermanentNeighbors,
            Step::VerifyExactPlanConfiguration,
            Step::RaiseLinks,
        ],
        NetworkNamespaceLifecycleActionV1::Renew => &[Step::ReplaceLeaseGateAtomically],
        NetworkNamespaceLifecycleActionV1::Disarm => &[
            Step::LowerLinks,
            Step::DisarmLeaseGate,
            Step::ConfigureExactAddressPairs,
            Step::ConfigureExactRoutes,
            Step::ConfigureExactPermanentNeighbors,
            Step::VerifyExactPlanConfiguration,
        ],
        NetworkNamespaceLifecycleActionV1::Destroy => &[
            Step::LowerLinks,
            Step::RemoveOwnedNetworkObjects,
            Step::VerifyKernelOwnedObjectsAbsent,
        ],
        NetworkNamespaceLifecycleActionV1::Fence => &[],
    }
}
