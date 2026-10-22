//! Prepares the installed component backend without claiming physical readiness.
//!
//! Only the completed paid component Phase0 original supplies package/MAC/startup
//! provenance. An authenticated normal Host Launch still owns every effect and
//! must produce the actual shifted-payload, supervisor-policy and Agent proofs.

use std::time::Duration;
use std::os::fd::AsFd as _;

use crate::plan::{HostExecutionReceivingLoanV2, NspawnConfig, PreparedLaunch};
use crate::worker::BoundPayloadVerification;
use crate::Result;

pub(crate) struct HostComponentBackendPreparationV2 {
    original: super::component_phase0::HostComponentPhase0OriginalV2,
}

impl HostComponentBackendPreparationV2 {
    pub(crate) fn retain_completed_v2(
        original: super::component_phase0::HostComponentPhase0OriginalV2,
    ) -> Self {
        // The caller checks the actual same-startup completed original before
        // the exclusive move. Keeping it whole preserves native first causes.
        Self { original }
    }

    pub(crate) fn require_receiving_v2(
        &self,
        receiving: &HostExecutionReceivingLoanV2<'_>,
    ) -> Result<()> {
        receiving.require_component_backend_origin_v2(&self.original)
    }

    pub(crate) fn revalidate_compilation_v2(
        &self,
        native: Option<&mut crate::plan::readiness::NspawnRevalidationOriginalV2>,
    ) -> Result<()> {
        let phase0 = self.original.phase0_v2()?;
        phase0.readiness.revalidate_preparation_v2(native)
    }

    pub(crate) fn executable_pin(&self) -> Result<std::os::fd::BorrowedFd<'_>> {
        Ok(self.original.phase0_v2()?.readiness.canary_original_binding().executable_pin.as_fd())
    }

    pub(crate) fn executable_pin_arc(&self) -> Result<&std::sync::Arc<std::os::fd::OwnedFd>> {
        Ok(&self.original.phase0_v2()?.readiness.canary_original_binding().executable_pin)
    }

    pub(crate) fn programs_v2(&self) -> Result<&[u8]> {
        self.original.programs_v2()
    }

    pub(crate) fn verify_policy_v2(
        &self,
        payload: &PreparedLaunch,
        supervisor_pid: u32,
        values: &[aos_systemd_client::OwnedValue],
    ) -> Result<crate::plan::VerifiedLiveSupervisorPolicyV1> {
        let phase0 = self.original.phase0_v2()?;
        phase0.packaged.verify_supervisor_policy_data_v2(
            &phase0.readiness, payload.spec(), supervisor_pid, values,
        )
    }

    pub(crate) fn complete_physical_v2(
        &self,
        payload: &PreparedLaunch,
        proof: &BoundPayloadVerification,
        live: &crate::plan::VerifiedLiveSupervisorPolicyV1,
        agent: &crate::live_agent::launch_original::HostAgentLaunchOriginalV2,
        report: &crate::worker::HostComponentStartupReportOriginalV2,
    ) -> Result<NspawnConfig> {
        agent.require_completed_backend_handshake_v2()?;
        report.require_verified_v2(proof)?;
        let phase0 = self.original.phase0_v2()?;
        let readiness = phase0.readiness.complete_component_physical_payload_v2(
            &phase0.packaged, live, payload, proof, phase0.policy_digest,
        )?;
        // Uses the existing real readiness constructor; a Phase0 owner alone
        // never enters this method's physical conjunction.
        Ok(NspawnConfig {
            readiness,
            timeout_start: Duration::from_secs(30),
            timeout_stop: Duration::from_secs(30),
            #[cfg(all(test, feature = "kernel-tests"))]
            kernel_guest_fixture: None,
        })
    }
}

/// Retains one real physical completion and its final executable bookend.
pub(crate) struct HostComponentBackendCompletionV2 {
    revalidation: Option<crate::plan::readiness::NspawnRevalidationOriginalV2>,
    completed: Option<Result<NspawnConfig>>,
}

impl HostComponentBackendCompletionV2 {
    pub(crate) fn new() -> Self {
        Self {
            revalidation: Some(crate::plan::readiness::NspawnRevalidationOriginalV2::new()),
            completed: None,
        }
    }

    pub(crate) fn receiving_demand_v2() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(crate::plan::readiness::NspawnRevalidationOriginalV2::requested_bytes_v2()?)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, 1)
            .with(D::MetadataEntries, 1))
    }

    pub(crate) fn complete_once_v2(
        &mut self,
        preparation: &HostComponentBackendPreparationV2,
        payload: &PreparedLaunch,
        proof: &BoundPayloadVerification,
        live: &crate::plan::VerifiedLiveSupervisorPolicyV1,
        agent: &crate::live_agent::launch_original::HostAgentLaunchOriginalV2,
        report: &crate::worker::HostComponentStartupReportOriginalV2,
    ) -> Result<()> {
        if self.completed.is_some() {
            return Err(crate::HostError::Fence("component physical completion was already entered"));
        }
        self.completed = Some((|| {
            let config = preparation.complete_physical_v2(payload, proof, live, agent, report)?;
            let revalidation = self.revalidation.as_mut()
                .ok_or(crate::HostError::Fence("component final native bookend is absent"))?;
            config.readiness.revalidate_for_nspawn_engine_v2(Some(revalidation))?;
            Ok(config)
        })());
        if !matches!(self.completed, Some(Ok(_))) {
            return Err(crate::HostError::Fence("component physical completion failed; originals retained"));
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.revalidation.as_ref().and_then(|native| native.failure())
            .or_else(|| self.completed.as_ref()?.as_ref().err()
            .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    pub(crate) fn take_completed_after_posts_v2(&mut self) -> Result<NspawnConfig> {
        if !matches!(self.completed, Some(Ok(_))) {
            return Err(crate::HostError::Fence("component completion is not positive"));
        }
        let Some(Ok(config)) = self.completed.take() else { std::process::abort(); };
        // The sole broker caller has completed its independently owed native
        // after before this move. Positive fixed boot/hash scratch has no later
        // user; failed prefixes never reach this physical disposal boundary.
        drop(self.revalidation.take());
        Ok(config)
    }
}
