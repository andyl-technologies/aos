//! Shares the two actual cleanup predecessor comparisons in the existing reader.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum ResourceReadContinuationV4 {
    Apply(super::super::admission::DeleteApplyResourceBindingDataV3, DeleteRootFreshFrameDataV2),
    Network(super::super::admission::DeleteNetworkResourceBindingDataV4, DeleteRootFreshFrameDataV2),
    Mount(super::super::admission::DeleteMountResourceBindingDataV4, DeleteRootFreshFrameDataV2),
}

impl ResourceReadContinuationV4 {
    pub(super) fn purpose(self) -> DeleteResourcePurposeV3 {
        match self { Self::Apply(..) => DeleteResourcePurposeV3::Apply7,
            Self::Network(..) => DeleteResourcePurposeV3::Network9,
            Self::Mount(..) => DeleteResourcePurposeV3::MountReap62 }
    }

    pub(super) fn frame(self) -> DeleteRootFreshFrameDataV2 {
        match self { Self::Apply(_, frame) | Self::Network(_, frame) | Self::Mount(_, frame) => frame }
    }

    pub(super) fn require_context(self, context: DeleteRootResourceContextDataV2,
        frame: DeleteRootFreshFrameDataV2,
    ) -> Result<RawPairedClockSample, DeleteRootResourceWireErrorV2> {
        Ok(match self {
            Self::Apply(binding, _) => {
                context.require_preparation_current_v3(frame, binding.current, binding.current.draft, context.lease)?;
                binding.sender_before
            }
            Self::Network(binding, _) => {
                context.require_network_predecessor_v4(frame, binding.predecessor,
                    binding.predecessor.current.draft, context.lease)?;
                binding.before
            }
            Self::Mount(binding, _) => {
                context.require_cleanup_current_v4(frame, binding.current, binding.approved9, context.lease)?;
                binding.before
            }
        })
    }

    pub(super) fn require_approval(self, approval: DeleteRootPreparatoryApprovalDataV3,
        frame: DeleteRootFreshFrameDataV2, challenge: DeleteRootChallengeDataV2,
        initial: DeleteRootInitialAckDataV3, draft: DeleteRootResourceDraftDataV2<'_>,
        signed: aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourceSignedDataV2<'_>,
    ) -> Result<(), DeleteRootResourceWireErrorV2> {
        match self {
            Self::Apply(binding, _) => approval.require_apply_exchange_v3(frame, challenge, initial,
                binding.current, binding.current.draft, draft, signed),
            Self::Network(binding, _) => approval.require_network_exchange_v4(frame, challenge, initial,
                binding.predecessor, binding.predecessor.current.draft, draft, signed),
            Self::Mount(binding, _) => approval.require_mount_exchange_v4(frame, challenge, initial,
                binding.current, binding.approved9, draft, signed),
        }
    }
}
