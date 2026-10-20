//! Lends only the genuine Host stage to the sole resource-opening engine.

use crate::journal::JournalError;
use crate::normal_root::RootHostLaunchStageReceivingV1;
use crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1;
use crate::policy_compiler::root_resource_opening::{
    OpeningQueryV2, OpeningReceivingV2, RootResourceOpeningOriginalV2,
};
use aos_sandbox_core::RawPairedClockSample;
use std::error::Error;

#[derive(Default)]
pub(crate) struct RootHostLaunchOpeningOriginalV2 {
    original: RootResourceOpeningOriginalV2,
}

impl RootHostLaunchOpeningOriginalV2 {
    pub(in crate::policy_compiler) fn admit_query_once_v1(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        server_bytes: usize,
    ) -> Result<(), JournalError> {
        self.original
            .admit_query_once_v1(OpeningReceivingV2::Host(stage), server_bytes)
    }

    pub(in crate::policy_compiler) fn observe_query_once_v1(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), JournalError> {
        self.original.observe_query_once_v1(bytes)
    }

    pub(in crate::policy_compiler) fn admit_subject_once_v1(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        owner_bytes: usize,
    ) -> Result<(), JournalError> {
        self.original
            .admit_subject_once_v1(OpeningReceivingV2::Host(stage), owner_bytes)
    }

    pub(crate) fn require_paid_chunk_peak_v1(&self) -> Result<(), JournalError> {
        self.original.require_paid_chunk_peak_v1()
    }

    pub(crate) fn current_cutoff_v1(&self) -> Result<u64, JournalError> {
        self.original.current_cutoff_v1()
    }

    pub(crate) fn require_current_clock_v1(
        &self,
        sample: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.original.require_current_clock_v1(sample)
    }

    pub(in crate::policy_compiler) fn horizon_v1(
        &self,
    ) -> Result<RootContinuationHorizonDataV1, JournalError> {
        self.original.horizon_v1()
    }

    pub(in crate::policy_compiler) fn query_v1(
        &self,
    ) -> Result<
        aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostLaunchQueryDataV1,
        JournalError,
    > {
        match self.original.query_v1()? {
            OpeningQueryV2::Host(value) => Ok(value),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(in crate::policy_compiler) fn root_sample_v1(
        &self,
    ) -> Result<RawPairedClockSample, JournalError> {
        self.original.root_sample_v1()
    }

    pub(in crate::policy_compiler) fn root_nonce_v1(&self) -> Result<[u8; 16], JournalError> {
        self.original.root_nonce_v1()
    }

    pub(in crate::policy_compiler) fn funding_failed_v1(&self) -> bool {
        self.original.funding_failed_v1()
    }

    pub(in crate::policy_compiler) fn tighten_host_inputs_once_v2(
        &mut self,
        source: &crate::policy_compiler::public_start_source::CurrentAcceptedStartProjectSourceV2,
        policy: &crate::policy_compiler::continuation_policy::RootHostLaunchPolicyOriginalV1,
        lease: &aos_sandbox_ownership_protocol::SignedOwnershipLease,
    ) -> Result<(), JournalError> {
        self.original
            .tighten_host_inputs_once_v2(source, policy, lease)
    }

    pub(in crate::policy_compiler) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}
