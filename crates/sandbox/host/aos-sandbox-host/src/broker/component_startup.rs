//! Binds the normal donated-report channel to one real admitted Host Launch.

use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use crate::state::transition::DurableExecution;
use crate::{HostError, Result};

pub(crate) struct ComponentStartupReportScopeV2 {
    challenge: [u8; 200],
    request: ([u8; 16], [u8; 32], [u8; 32]),
    boot: [u8; 16],
    cutoff: u64,
}

impl ComponentStartupReportScopeV2 {
    pub(in crate::broker) fn from_actual_launch_v2(
        request: &AuthenticatedBrokerMethodRequestV1,
        runtime: &aos_sandbox_protocol::ValidatedRuntimeRequest,
        setup: &crate::live_agent::launch_original::HostAgentLaunchOriginalV2,
        execution: &DurableExecution,
        boot: [u8; 16],
        cutoff: u64,
    ) -> Result<Self> {
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || request.request_id() != *runtime.header().request_id()
            || boot == [0; 16] || cutoff == 0
        { return Err(HostError::Fence("component report differs from the actual Host Launch")); }
        let channel = setup.component_report_channel_v2()?;
        let binding = execution.guardian_binding().ok_or(HostError::AgentLaunchQuarantined)?;
        let fence = runtime.fence();
        let mut challenge = [0; 200];
        challenge[..8].copy_from_slice(b"AOSNHR01");
        challenge[8..10].copy_from_slice(&1_u16.to_be_bytes());
        challenge[12..16].copy_from_slice(&200_u32.to_be_bytes());
        challenge[16..48].copy_from_slice(&channel);
        challenge[48..80].copy_from_slice(&request.signed_request_digest());
        challenge[80..112].copy_from_slice(&binding);
        challenge[112..128].copy_from_slice(fence.sandbox_id());
        challenge[128..144].copy_from_slice(fence.incarnation_id());
        challenge[144..152].copy_from_slice(&fence.assignment_epoch().to_be_bytes());
        challenge[152..160].copy_from_slice(&fence.desired_generation().to_be_bytes());
        challenge[176..192].copy_from_slice(&boot);
        challenge[192..200].copy_from_slice(&cutoff.to_be_bytes());
        Ok(Self { challenge, request: (request.request_id(), request.session_binding(),
            request.signed_request_digest()), boot, cutoff })
    }

    pub(crate) fn challenge_v2(&self) -> &[u8; 200] { &self.challenge }
    pub(crate) fn boot_v2(&self) -> [u8; 16] { self.boot }
    pub(crate) fn request_v2(&self) -> ([u8; 16], [u8; 32], [u8; 32]) { self.request }

    pub(crate) fn require_request_v2(&self, request: &AuthenticatedBrokerMethodRequestV1) -> Result<()> {
        if self.request != (request.request_id(), request.session_binding(), request.signed_request_digest()) {
            return Err(HostError::Fence("component startup report belongs to another request"));
        }
        Ok(())
    }

    pub(crate) fn require_deadline_v2(&self) -> Result<()> {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let nanos = u64::try_from(now.tv_sec).ok().and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|base| u64::try_from(now.tv_nsec).ok().and_then(|fraction| base.checked_add(fraction)))
            .ok_or(HostError::Fence("component report clock is invalid"))?;
        if nanos >= self.cutoff { return Err(HostError::Fence("component report original Launch cutoff expired")); }
        Ok(())
    }
}
