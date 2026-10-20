//! Keeps the actual completed Recover native association for cleanup funding.
//!
//! This private owner is financial provenance only. Core must independently
//! hold its actual accepted Recover, current capability/policy, desired-absent
//! exact old Stop and protected Source parent. No public DATA constructor or
//! conversion to ordinary recovered enrollment exists.

use super::*;
use aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1;

pub(in crate::controller_receiving) struct RecoveredStopCleanupAssociationOriginalV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    _turn: Arc<std::sync::atomic::AtomicBool>,
    data: RecoveredHostStopCleanupAssociationDataV1,
}

impl RecoveredStopCleanupAssociationOriginalV1 {
    pub(in crate::controller_receiving) fn require_same_v1(&self,
        original: &Arc<ControllerReceivingOriginalV1>, identity: &Arc<ControllerWriterIdentityV1>,
        data: RecoveredHostStopCleanupAssociationDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !Arc::ptr_eq(&self.original, original) || !Arc::ptr_eq(&self.identity, identity)
            || self.data != data
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) const fn data_v1(&self)
        -> RecoveredHostStopCleanupAssociationDataV1 { self.data }
}

impl ControllerOperatorRecoverReceivingV1 {
    pub(in crate::controller_receiving) fn completed_cleanup_association_v1<P>(&self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, data: RecoveredHostStopCleanupAssociationDataV1,
    ) -> Result<RecoveredStopCleanupAssociationOriginalV1, ControllerBankLaunchErrorV1> {
        self.require_completed_original_v1(writer, launch, profile)?;
        data.encode_v1()?;
        Ok(RecoveredStopCleanupAssociationOriginalV1 {
            original: Arc::clone(&self.native.original), identity: Arc::clone(&self.native.identity),
            _turn: Arc::clone(self.native.turn_identity.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?),
            data,
        })
    }
}
