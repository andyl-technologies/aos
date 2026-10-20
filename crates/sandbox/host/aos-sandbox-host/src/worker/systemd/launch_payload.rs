//! Dispatches the shared bound-payload recipe through a genuine Launch loan.
//!
//! This adapter owns no client, account or replacement native pins. Every SDK
//! and native prefix enters the already paid same-request resident worker. The
//! existing readback parks each actual returned owner before its next check.

use super::*;
use crate::worker::launch::HostLaunchWorkerReceivingV2;

pub(in crate::worker) struct LaunchPayloadWorkerV3<'worker, 'call, 'flight, 'original> {
    worker: &'worker SystemdOneShotWorker,
    receiving: &'call mut HostLaunchWorkerReceivingV2<'flight, 'original>,
}

impl LaunchPayloadWorkerV3<'_, '_, '_, '_> {
    async fn observe_bound_payload(&mut self, identity: &HostRuntimeIdentity) -> Result<GuardianObservation> {
        self.receiving.observe_payload_entry_v3(self.worker, identity).await
    }

    async fn observe_with_client(&mut self, _unused: &(), identity: &HostRuntimeIdentity) -> Result<WorkerObservation> {
        self.receiving.observe_sandbox_v2(self.worker, identity).await
    }

    async fn submit_payload_v3(
        &mut self,
        spec: &SandboxUnitSpec,
        identity: &HostRuntimeIdentity,
        guardian: ExactUnitTarget,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<crate::worker::launch::PayloadSubmissionV3> {
        self.receiving.submit_payload_v3(self.worker, spec, identity, guardian, before_effect).await
    }

    async fn verify_supervisor_v3(
        &mut self,
        pins: &LaunchPins,
        leader: &PinnedLeader,
        policy: PayloadRootContinuityPolicyV1,
    ) -> Result<PinnedPayloadLeader> {
        let original = self.receiving.verify_supervisor_v2(self.worker, pins, leader, policy).await?;
        let inspection = original.lock().await.inspection().cloned()
            .ok_or_else(|| resident_readback_missing("same supervisor payload inspection"))?;
        // This is an exclusive move from the actual successful quiescence
        // owner. The caller immediately parks the pins on the same readback.
        let completed = inspection.lock().await.take_payload_once()
            .ok_or_else(|| resident_readback_missing("completed actual payload pins"))?;
        Ok(completed)
    }

    async fn snapshot_v3(
        &mut self, pins: &LaunchPins, leader: &PinnedLeader, payload: &PinnedPayloadLeader,
    ) -> Result<RuntimeProofSnapshot> {
        self.receiving.runtime_snapshot_v2(pins, leader, payload).await
    }

    async fn shifted_v3(
        &mut self, identity: &HostRuntimeIdentity, spec: &SandboxUnitSpec,
        invocation: [u8; 16], leader: &PinnedLeader, payload: &PinnedPayloadLeader,
        proof: &RuntimeProofSnapshot,
    ) -> Result<VerifiedShiftedPayloadInspectionV1> {
        self.receiving.inspect_shifted_v2(identity, spec, invocation, leader, payload, proof).await
    }

    fn capture_service_limits(&self, spec: &SandboxUnitSpec, state: &mut BoundPayloadReadbackV1) -> Result<()> {
        self.worker.capture_service_limits(spec, state)
    }

    fn recheck_service_limits(&self, spec: &SandboxUnitSpec, state: &mut BoundPayloadReadbackV1) -> Result<()> {
        self.worker.recheck_service_limits(spec, state)
    }
}

impl RetainedPayloadWorkerV1<'_> {
    pub(crate) async fn start_launch_v3(
        &self,
        spec: &SandboxUnitSpec,
        pins: &LaunchPins,
        identity: &HostRuntimeIdentity,
        guardian_invocation_id: [u8; 16],
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
        state: &mut BoundPayloadReadbackV1,
        receiving: &mut HostLaunchWorkerReceivingV2<'_, '_>,
    ) -> Result<()> {
        if state.limit_native.is_none() {
            return Err(resident_readback_missing("genuine Launch limit original"));
        }
        begin_resident_readback(state)?;
        let mut worker = LaunchPayloadWorkerV3 {
            worker: self.worker,
            receiving: &mut *receiving,
        };
        let result = async {
            start_bound_payload_recipe!(worker, spec, pins, identity, guardian_invocation_id,
                before_effect, Launch, state)
        }.await;
        drop(worker);
        finish_resident_readback(state, result)?;
        receiving.complete_ready_limit_point_v4(state).await
    }

    pub(crate) async fn prove_launch_v3(
        &self,
        spec: &SandboxUnitSpec,
        pins: &LaunchPins,
        identity: &HostRuntimeIdentity,
        state: &mut BoundPayloadReadbackV1,
        receiving: &mut HostLaunchWorkerReceivingV2<'_, '_>,
    ) -> Result<()> {
        if state.limit_native.is_none() {
            return Err(resident_readback_missing("genuine Launch limit original"));
        }
        begin_resident_readback(state)?;
        let mut worker = LaunchPayloadWorkerV3 {
            worker: self.worker,
            receiving: &mut *receiving,
        };
        let result = async {
            prove_bound_payload_recipe!(worker, spec, pins, identity, Launch, state)
        }.await;
        drop(worker);
        finish_resident_readback(state, result)?;
        receiving.complete_ready_limit_point_v4(state).await
    }
}
