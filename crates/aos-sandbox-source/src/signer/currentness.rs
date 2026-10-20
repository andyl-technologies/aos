//! Keeps the Source task-subject policy over shared retained sampling.

use std::error::Error;
use aos_sandbox_core::{AccountingError, ResourceVector};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::{CurrentSelfPidFdCustodyV1, PidFdInfo, PidFdProcessIdentity};
use super::SourceReceivingClosedV1;
use aos_sandbox_broker::receiving::receiving_limits::ReceivingContainmentReadbackV1;
use aos_sandbox_broker::receiving::FixedServiceCurrentnessSampleV1;

#[derive(Default)]
pub(super) struct SourceCurrentnessSampleV1(FixedServiceCurrentnessSampleV1<SourceReceivingClosedV1>);

impl SourceCurrentnessSampleV1 {
    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        FixedServiceCurrentnessSampleV1::<SourceReceivingClosedV1>::dynamic_demand()
    }

    pub(super) fn observe_once(
        &mut self,
        process: &mut CurrentSelfPidFdCustodyV1,
        anchor: &RetainedCgroupAnchor,
        limits: &ReceivingContainmentReadbackV1,
        initial_info: PidFdInfo,
        initial_identity: PidFdProcessIdentity,
    ) -> Result<(), SourceReceivingClosedV1> {
        self.0.observe_once(process, anchor, limits, initial_info, initial_identity,
            Some(b"system_u:system_r:aos_sandbox_source_signer_t"), true)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.0.failure()
    }
}
