//! Reborrows the original Initial for the actual native NoApply peer.
//!
//! The enclosing receiving guard owns the same L/U interval. Native code owns
//! the complete purpose/admission ledger; this child supplies no callback,
//! completed DATA or replacement financial handle.

use aos_sandbox_model::ResourceVector;
use aos_sandbox_policy::native::{
    RootNoApplyControllerPeerOriginalV2 as Peer, RootNoApplyStageDataV2,
};

use super::{RootContinuationDemandV1, RootReceivingOriginalV1};
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};

impl RootReceivingOriginalV1 {
    pub(crate) fn native_no_apply_bridge_control_bytes_v2() -> Option<usize> {
        use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootSelectedStartupBorrowV1};
        use aos_sandbox_policy::native::RootCompletedPolicyListenerOriginalV1;
        use std::mem::size_of;

        let prepare = size_of::<(&mut Self, &ProductionNormalRootStartupV1, ResourceVector)>()
            .checked_add(size_of::<Result<Peer<'static>, Error>>())?
            .checked_mul(2)?
            .checked_add(size_of::<&RootCompletedPolicyListenerOriginalV1>().checked_mul(2)?)?
            .checked_add(
                size_of::<Result<&RootCompletedPolicyListenerOriginalV1, Error>>()
                    .checked_mul(2)?,
            )?
            .checked_add(size_of::<RootSelectedStartupBorrowV1<'static>>().checked_mul(2)?)?
            .checked_add(
                size_of::<Result<RootSelectedStartupBorrowV1<'static>, RootObservationErrorV1>>()
                    .checked_mul(2)?,
            )?;
        let admission = size_of::<(
            &mut Self,
            &mut Peer<'static>,
            RootNoApplyStageDataV2,
            RootContinuationDemandV1,
        )>()
        .checked_add(size_of::<Result<(), Error>>())?
        .checked_mul(2)?
        .checked_add(size_of::<RootContinuationDemandV1>().checked_mul(2)?)?
        .checked_add(size_of::<(ResourceVector, ResourceVector)>().checked_mul(2)?)?;
        let node = size_of::<(&Self, &Peer<'static>)>()
            .checked_add(size_of::<Result<[u8; 16], Error>>())?
            .checked_mul(2)?
            .checked_add(size_of::<[u8; 16]>().checked_mul(4)?)?
            .checked_add(size_of::<Result<[u8; 16], Error>>().checked_mul(2)?)?;
        let owed = size_of::<(&mut Self, &mut Peer<'static>)>()
            .checked_add(size_of::<Result<(), Error>>())?
            .checked_mul(6)?;
        prepare
            .checked_add(admission)?
            .checked_add(node)?
            .checked_add(owed)
    }

    pub(crate) fn prepare_native_no_apply_peer_v2<'startup>(
        &mut self,
        startup: &'startup ProductionNormalRootStartupV1,
        upper_geometry: ResourceVector,
    ) -> Result<Peer<'startup>, Error> {
        self.require_active_policy_flight_v1()?;
        let completed = self
            .native_completed_listener
            .as_ref()
            .ok_or(Error::Service)?;
        let selected = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()
            .map_err(|_| Error::Service)?;
        Ok(Peer::prepare_once_v2(
            completed,
            &mut self.activation,
            selected,
            upper_geometry,
        ))
    }

    pub(crate) fn admit_native_no_apply_stage_v2(
        &mut self,
        peer: &mut Peer<'_>,
        stage: RootNoApplyStageDataV2,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.require_active_policy_flight_v1()?;
        let (demand, baseline) = demand.into_parts_data_v1();
        peer.admit_stage_once_v2(&mut self.activation, stage, demand, baseline)
            .map_err(|_| Error::Service)
    }

    pub(crate) fn native_no_apply_node_data_v2(&self, peer: &Peer<'_>) -> Result<[u8; 16], Error> {
        let original = self.current_enrolled_node_data_v1()?;
        let actual = peer
            .enrolled_node_data_v2(&self.activation)
            .map_err(|_| Error::Service)?;
        if original != actual {
            return Err(Error::Service);
        }
        Ok(actual)
    }

    // These are prearmed obligations; no healthy upper entry suppresses them.
    pub(crate) fn finish_native_no_apply_capture_post_v2(
        &mut self,
        peer: &mut Peer<'_>,
    ) -> Result<(), Error> {
        peer.finish_capture_post_once_v2(&mut self.activation)
            .map_err(Into::into)
    }

    pub(crate) fn begin_native_no_apply_final_post_v2(
        &mut self,
        peer: &mut Peer<'_>,
    ) -> Result<(), Error> {
        peer.begin_final_post_once_v2(&mut self.activation)
            .map_err(Into::into)
    }

    pub(crate) fn finish_native_no_apply_final_post_v2(
        &mut self,
        peer: &mut Peer<'_>,
    ) -> Result<(), Error> {
        peer.finish_final_post_once_v2(&mut self.activation)
            .map_err(Into::into)
    }
}
