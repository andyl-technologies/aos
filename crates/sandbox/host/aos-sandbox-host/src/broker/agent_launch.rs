//! Protected guest-agent custody for one Guardian-first payload attempt.
//!
//! The fixed runtime owner, signing seed, and attach trust are opened only
//! after Host has accepted a signed launch and resolved the Storage-authenticated
//! guest root. No private socket can be recovered after a process restart.

use std::time::{Duration, Instant};

use aos_sandbox_controller_domain::runtime_execution::DormantRuntimeExecutionOwnerV1;
use aos_sandbox_guest_protocol::guest_root_publication::CONCRETE_GUEST_FEATURE_MASK_V1;
use aos_sandbox_guest_protocol::{AgentFeatureSetV1, AgentFeatureV1};
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::ValidatedAssignmentFence;

use super::HostBroker;
use crate::live_agent::{
    HostAgentLaunchHandoffV1, HostAgentLiveSessionV1, HostAgentPendingSessionV1,
    HostAgentProtectedAttachTrustV1, HostAgentProtectedSeedV1,
};
use crate::plan::{HostCatalog, PreparedLaunch};
use crate::state::HostStateStore;
use crate::state::transition::GuardianAttempt;
use crate::worker::HostWorker;
use crate::{HostError, Result};

const AGENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn agent_replay_is_quarantined(attempt: Option<GuardianAttempt<'_>>) -> bool {
    attempt.is_some_and(|attempt| attempt.agent_required)
}

impl<C, S, W> HostBroker<C, S, W>
where
    C: HostCatalog,
    S: HostStateStore,
    W: HostWorker,
{
    pub(super) fn prepare_protected_agent_payload(
        &self,
        fence: &ValidatedAssignmentFence,
        payload: PreparedLaunch,
    ) -> Result<(PreparedLaunch, HostAgentPendingSessionV1)> {
        let package_binding = payload.guest_package_binding().ok_or_else(|| {
            HostError::InvalidPlan("guest root lacks authenticated package identity".to_owned())
        })?;
        if payload.guest_feature_mask() != Some(CONCRETE_GUEST_FEATURE_MASK_V1) {
            return Err(HostError::InvalidPlan(
                "guest root lacks the fixed agent feature profile".to_owned(),
            ));
        }

        let mut owner = DormantRuntimeExecutionOwnerV1::open()
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let claim = owner
            .claim()
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let seed = HostAgentProtectedSeedV1::open_for_claim(&claim)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let attach_trust = HostAgentProtectedAttachTrustV1::open_for_claim(&claim)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let record = seed
            .launch_record(
                fixed_guest_features()?,
                ObjectDigest::from_bytes(package_binding),
            )
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let handoff = HostAgentLaunchHandoffV1::prepare(&claim, fence, record, attach_trust)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        handoff
            .bind_prepared_launch(&claim, fence, payload)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))
    }

    pub(super) fn prepare_protected_agent_payload_receiving_v2(
        &self,
        fence: &ValidatedAssignmentFence,
        receiving: &crate::plan::HostExecutionReceivingLoanV2<'_>,
    ) -> Result<()> {
        receiving.require_launch_current_v2()?;
        let stage = self.launch_original.as_ref()
            .ok_or(HostError::Fence("Host launch resident capsule is absent"))?;
        let mut stage = stage.lock().map_err(|_| HostError::Fence("Host launch capsule is poisoned"))?;
        let super::launch_handoff::HostLaunchOriginalV2 { owner, owner_error, setup, prepared_payload, .. } = &mut *stage;
        let claim = match owner.as_mut().ok_or(HostError::Fence("Host launch native owner is absent"))?.claim() {
            Ok(claim) => claim,
            Err(error) => { *owner_error = Some(error); return Err(HostError::Fence("Host launch native claim failed")); }
        };
        let setup = setup.as_mut().ok_or(HostError::Fence("Host launch setup destination is absent"))?;
        setup.prepare_once(&claim, fence, prepared_payload, fixed_guest_features()?, receiving)
            .map_err(|_| HostError::Fence("Host launch native Agent setup failed; originals retained"))?;
        let payload = setup.take_prepared_once()
            .map_err(|_| HostError::Fence("Host launch prepared payload is absent"))?;
        *prepared_payload = Some(payload);
        Ok(())
    }

    pub(super) fn authenticate_protected_agent_receiving_v2(&self, request: &[u8; 16]) -> Result<()> {
        if !self.launch_is_entered_v2(request) { return Err(HostError::AgentLaunchQuarantined); }
        let stage = self.launch_original.as_ref()
            .ok_or(HostError::Fence("Host launch resident capsule is absent"))?;
        let mut stage = stage.lock().map_err(|_| HostError::Fence("Host launch capsule is poisoned"))?;
        let result = (|| {
        stage.observe_names_once_v2(0)?;
        let super::launch_handoff::HostLaunchOriginalV2 { owner, owner_error, setup, clock, deadline, .. } = &mut *stage;
        let clock = clock.as_mut().ok_or(HostError::Fence("Host launch retained clock is absent"))?;
        let deadline = clock.deadline(*deadline)?;
        let local_limit = Instant::now().checked_add(AGENT_HANDSHAKE_TIMEOUT)
            .ok_or(HostError::Fence("Host launch handshake timeout overflows"))?;
        let claim = match owner.as_mut().ok_or(HostError::Fence("Host launch native owner is absent"))?.claim() {
            Ok(claim) => claim,
            Err(error) => { *owner_error = Some(error); return Err(HostError::Fence("Host launch native claim failed")); }
        };
        // The Stage is already locked. Borrow its disjoint clock directly;
        // reacquiring this mutex from the native callback would deadlock.
        let mut before_native_write = || {
            clock.sample_handshake_write_v3()
                .map_err(|_| crate::live_agent::HostAgentLiveErrorV1::RecoveryRequired)
        };
        setup.as_mut().ok_or(HostError::Fence("Host launch Agent setup is absent"))?
            .authenticate_once(&claim, deadline.min(local_limit), &mut before_native_write)
            .map_err(|_| HostError::Fence("Host launch Agent authentication failed; originals retained"))
        })();
        if result.is_err() {
            stage.first.get_or_insert(super::launch_handoff::LaunchFirstV2::Primary);
        }
        stage.agent_authentication = Some(result);
        if !matches!(stage.agent_authentication, Some(Ok(()))) {
            return Err(HostError::Fence("Host launch authentication frontier failed; actual cause retained"));
        }
        Ok(())
    }

    pub(super) fn take_completed_launch_agent_v2(&mut self, request: &[u8; 16])
        -> Result<Option<HostAgentLiveSessionV1>>
    {
        let Some(stage) = self.launch_original.as_ref() else { return Ok(None); };
        let mut stage = stage.lock().map_err(|_| HostError::Fence("Host launch capsule is poisoned"))?;
        if &stage.request.0 != request || stage.authenticated_sent {
            return Err(HostError::AgentLaunchQuarantined);
        }
        let complete = self.state.guardian_attempt(request).is_some_and(|attempt|
            matches!(attempt.phase, crate::state::transition::GuardianLaunchPhase::Complete { .. }));
        if !complete { return Ok(None); }
        let setup = stage.setup.as_mut().ok_or(HostError::AgentLaunchQuarantined)?;
        Ok(setup.authenticated.take())
    }

    pub(super) fn authenticate_protected_agent(
        pending: HostAgentPendingSessionV1,
    ) -> Result<HostAgentLiveSessionV1> {
        let mut owner = DormantRuntimeExecutionOwnerV1::open()
            .map_err(|error| HostError::State(error.to_string()))?;
        let claim = owner
            .claim()
            .map_err(|error| HostError::State(error.to_string()))?;
        let deadline = Instant::now()
            .checked_add(AGENT_HANDSHAKE_TIMEOUT)
            .ok_or_else(|| HostError::State("agent handshake deadline overflow".to_owned()))?;
        pending
            .authenticate(&claim, deadline)
            .map_err(|error| HostError::Worker(error.to_string()))
    }
}

pub(crate) fn fixed_guest_features() -> Result<AgentFeatureSetV1> {
    AgentFeatureSetV1::new(vec![
        AgentFeatureV1::Readiness,
        AgentFeatureV1::ExecutionHandoff,
        AgentFeatureV1::ExecutionObservation,
        AgentFeatureV1::TerminalResize,
        AgentFeatureV1::ExecutionSignal,
        AgentFeatureV1::Quiesce,
    ])
    .map_err(|error| HostError::InvalidPlan(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_agent_features_match_the_published_guest_root() {
        let features = fixed_guest_features().unwrap();
        let mask = features.as_slice().iter().fold(0_u16, |mask, feature| {
            mask | (1_u16 << (*feature as u8 - 1))
        });

        assert_eq!(mask, CONCRETE_GUEST_FEATURE_MASK_V1);
        assert!(!features.contains(AgentFeatureV1::RuntimeArgumentObservation));
    }

    #[test]
    fn unretained_agent_attempt_never_authorizes_a_replayed_start() {
        use crate::state::transition::GuardianLaunchPhase;

        let phase = GuardianLaunchPhase::PayloadStartIssued {
            guardian_invocation: [8; 16],
        };
        let attempt = GuardianAttempt {
            binding: [1; 32],
            broker_plan: &[],
            broker_plan_signature: &[],
            ownership_lease: &[],
            ownership_lease_signature: &[],
            agent_required: true,
            phase: &phase,
        };

        assert!(agent_replay_is_quarantined(Some(attempt)));
        assert!(!agent_replay_is_quarantined(None));
    }
}
