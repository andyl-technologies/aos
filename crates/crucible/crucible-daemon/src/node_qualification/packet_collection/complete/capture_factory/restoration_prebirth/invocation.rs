//! Projects full prebirth archive provenance without moving or renewing tickets.

use super::*;
use crucible_engine::node_contract::RuntimeError;
use crucible_node_transport::reference_packet::service::{
    PacketNative5SourceLaunch, native_startup::PacketNativeInvocationPurposeData,
};

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn original_native_invocation_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        plan: &InstalledConformancePlan,
        launches: &[PacketNative5SourceLaunch; 3],
    ) -> Result<[PacketNativeInvocationPurposeData; 3], RuntimeError> {
        self.authenticate_native_startup_target_precredit_data(authority, plan)?;
        let member = |index: usize| -> Result<PacketNativeInvocationPurposeData, RuntimeError> {
            let ticket = self.native[index]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let owner = ticket.owner()?;
            let source = authority.roster().sources[index].installation();
            if owner.owner != source.owner.owner.id
                || owner.participants != source.owner.owner.participant_ids
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            // The capsule's opaque Source issued these exact tickets. Full
            // references, owner and actual fresh target remain independently bound.
            PacketNativeInvocationPurposeData::restoration_target_data(
                &launches[index],
                ticket.runtime_object()?,
                &owner.state,
                &owner.owner,
            )
            .map_err(|_| RuntimeError::ForeignAuthority)
        };
        let result = [member(0)?, member(1)?, member(2)?];
        self.authenticate_native_startup_target_precredit_data(authority, plan)?;
        Ok(result)
    }
}
