//! Lends the already-paid Execution purpose to the common Root opening engine.

use super::*;
use crate::policy_compiler::root_resource_opening::{
    OpeningQueryV2, OpeningReceivingV2, RootResourceOpeningOriginalV2,
};

#[derive(Default)]
pub(crate) struct RootExecutionNoApplyOpeningOriginalV2 {
    original: RootResourceOpeningOriginalV2,
}

impl RootExecutionNoApplyOpeningOriginalV2 {
    pub(super) fn admit_query(
        &mut self,
        stage: &mut crate::normal_root::RootExecutionNoApplyStageReceivingV2<'_, '_>,
    ) -> Result<(), JournalError> {
        self.original.admit_query_once_v1(
            OpeningReceivingV2::ExecutionNoApply(stage),
            size_of::<Native>(),
        )
    }

    pub(super) fn observe_query(&mut self, bytes: &[u8]) -> Result<(), JournalError> {
        self.original.observe_query_once_v1(bytes)
    }

    pub(super) fn admit_subject(
        &mut self,
        stage: &mut crate::normal_root::RootExecutionNoApplyStageReceivingV2<'_, '_>,
    ) -> Result<(), JournalError> {
        self.original.admit_subject_once_v1(
            OpeningReceivingV2::ExecutionNoApply(stage),
            size_of::<Native>(),
        )
    }

    pub(super) fn query(&self) -> Result<ExchangeQueryV2, JournalError> {
        match self.original.query_v1()? {
            OpeningQueryV2::ExecutionNoApply(query) => Ok(ExchangeQueryV2::Active(query)),
            OpeningQueryV2::ExecutionAcquisition(query) => Ok(ExchangeQueryV2::Acquisition(query)),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn tighten_acquisition_policy(
        &mut self,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
    ) -> Result<(), JournalError> {
        self.original
            .tighten_execution_acquisition_policy_once_v2(policy)
    }

    pub(super) fn narrow_acquisition_wall(&mut self, expiry: i64) -> Result<(), JournalError> {
        self.original
            .narrow_execution_acquisition_wall_once_v2(expiry)
    }

    pub(super) fn tighten(
        &mut self,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        lease: CurrentHostNoApplyLeaseDataV2,
    ) -> Result<(), JournalError> {
        self.original
            .tighten_execution_inputs_once_v2(policy, lease)
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

    pub(crate) fn require_paid_chunk_peak_v1(&self) -> Result<(), JournalError> {
        self.original.require_paid_chunk_peak_v1()
    }

    pub(super) fn horizon(&self) -> Result<RootContinuationHorizonDataV1, JournalError> {
        self.original.horizon_v1()
    }

    pub(super) fn sample(&self) -> Result<RawPairedClockSample, JournalError> {
        self.original.root_sample_v1()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

// Both variants preserve their actual wire purpose; Acquisition has no C cut.
#[derive(Clone, Copy)]
pub(super) enum ExchangeQueryV2 {
    Active(ExecutionNoApplyQueryDataV2),
    Acquisition(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::ExecutionNoApplyAcquisitionQueryDataV2),
}

impl ExchangeQueryV2 {
    pub(super) fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        match self {
            Self::Active(query) => query.digest_v2(),
            Self::Acquisition(query) => query.digest_v2(),
        }
    }

    pub(super) fn cutoff(self) -> u64 {
        match self {
            Self::Active(query) => query.original_cutoff_ns,
            Self::Acquisition(query) => query.original_cutoff_ns,
        }
    }

    pub(super) fn subject_bytes(self) -> u64 {
        match self {
            Self::Active(query) => query.subject_bytes,
            Self::Acquisition(query) => query.subject_bytes,
        }
    }
}
