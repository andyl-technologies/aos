//! Lends only the genuine Apply stage to the sole resource-opening engine.

use std::error::Error;
use aos_sandbox_model::RawPairedClockSample;
use crate::journal::JournalError;
use crate::normal_root::RootApplyStageReceivingV1;
use crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1;
use crate::policy_compiler::root_resource_opening::{RootResourceOpeningOriginalV2, OpeningReceivingV2, OpeningQueryV2};

#[derive(Default)]
pub(crate) struct RootStorageApplyOpeningOriginalV1 {
    original: RootResourceOpeningOriginalV2,
}

impl RootStorageApplyOpeningOriginalV1 {
    pub(in crate::policy_compiler) fn admit_query_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>, server_bytes: usize) -> Result<(), JournalError> {
        self.original.admit_query_once_v1(OpeningReceivingV2::Apply(stage), server_bytes)
    }

    pub(in crate::policy_compiler) fn observe_query_once_v1(&mut self, bytes: &[u8]) -> Result<(), JournalError> {
        self.original.observe_query_once_v1(bytes)
    }

    pub(in crate::policy_compiler) fn admit_subject_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>, owner_bytes: usize) -> Result<(), JournalError> {
        self.original.admit_subject_once_v1(OpeningReceivingV2::Apply(stage), owner_bytes)
    }

    pub(crate) fn require_paid_chunk_peak_v1(&self) -> Result<(), JournalError> {
        self.original.require_paid_chunk_peak_v1()
    }

    pub(crate) fn current_cutoff_v1(&self) -> Result<u64, JournalError> {
        self.original.current_cutoff_v1()
    }

    pub(crate) fn require_current_clock_v1(&self, sample: RawPairedClockSample) -> Result<(), JournalError> {
        self.original.require_current_clock_v1(sample)
    }

    pub(in crate::policy_compiler) fn horizon_v1(&self) -> Result<RootContinuationHorizonDataV1, JournalError> {
        self.original.horizon_v1()
    }

    pub(in crate::policy_compiler) fn query_v1(&self) -> Result<aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::StorageApplyQueryDataV1, JournalError> {
        match self.original.query_v1()? { OpeningQueryV2::Apply(value) => Ok(value), _ => Err(JournalError::ProtectedBoundary) }
    }

    pub(in crate::policy_compiler) fn root_sample_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.original.root_sample_v1()
    }

    pub(in crate::policy_compiler) fn root_nonce_v1(&self) -> Result<[u8; 16], JournalError> {
        self.original.root_nonce_v1()
    }

    pub(in crate::policy_compiler) fn funding_failed_v1(&self) -> bool {
        self.original.funding_failed_v1()
    }

    pub(in crate::policy_compiler) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

impl RootStorageApplyOpeningOriginalV1 {
    pub(super) fn tighten_inputs_once_v1(&mut self,
        inputs: &crate::policy_compiler::provisioning_current::apply_inputs::RootApplyInputsOriginalV1,
        policy: &crate::policy_compiler::continuation_policy::RootApplyPolicyOriginalV1,
    ) -> Result<(), JournalError> {
        self.original.tighten_inputs_once_v1(inputs, policy)
    }
}

#[cfg(test)]
const ROOT_APPLY_MAXIMUM_FLIGHT_NS: u64 = 65_000_000_000;

#[cfg(test)]
fn query_sample_cutoff_data_v1(
    query: aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::StorageApplyQueryDataV1,
    sample: RawPairedClockSample,
) -> Result<u64, JournalError> {
    crate::policy_compiler::root_resource_opening::query_sample_cutoff_v2(OpeningQueryV2::Apply(query), sample)
}
#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::StorageApplyQueryDataV1;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(boot: [u8;16], boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([1;16]).unwrap(),
            boot, 100, boottime).unwrap()
    }

    fn query(cutoff: u64) -> StorageApplyQueryDataV1 {
        StorageApplyQueryDataV1 { controller_nonce: [2;16], original_boot: [3;16],
            original_boottime_ns: 1, original_cutoff_ns: cutoff, subject_bytes: 1,
            subject_digest: [4;32], controller_next: 1, controller_end: 1 }
    }

    #[test]
    fn fresh_root_horizon_only_tightens_the_unchanged_original() {
        let first = sample([3;16], 10);

        assert_eq!(query_sample_cutoff_data_v1(query(20), first).unwrap(), 20);
        assert_eq!(query_sample_cutoff_data_v1(query(u64::MAX), first).unwrap(),
            10 + ROOT_APPLY_MAXIMUM_FLIGHT_NS);
    }

    #[test]
    fn expired_or_different_boot_query_never_gets_a_new_deadline() {
        assert!(query_sample_cutoff_data_v1(query(10), sample([3;16], 10)).is_err());
        assert!(query_sample_cutoff_data_v1(query(20), sample([8;16], 10)).is_err());
        assert!(query_sample_cutoff_data_v1(query(20), sample([3;16], 0)).is_err());
    }
}
