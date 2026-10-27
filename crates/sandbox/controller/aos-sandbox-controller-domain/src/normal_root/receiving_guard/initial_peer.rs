//! Keeps initial peer preparation and owed posts in their original L/U slots.

use super::RootReceivingGuardV1;
use crate::normal_root::{
    NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1, RootControllerPeerReceivingV1,
};

impl RootReceivingGuardV1<'_> {
    pub(crate) fn park_initial_controller_peer_once_v1<'startup>(
        &mut self,
        startup: &'startup ProductionNormalRootStartupV1,
    ) -> Result<RootControllerPeerReceivingV1<'startup>, Error> {
        self.original.park_initial_controller_peer_once_v1(startup)
    }

    pub(crate) fn prepare_initial_controller_peer_once_v1(
        &mut self,
        peer: &mut RootControllerPeerReceivingV1<'_>,
    ) -> Result<(), Error> {
        self.original.prepare_initial_controller_peer_once_v1(
            peer.startup_original_mut_v1()?,
            &self.mutation,
        )
    }

    pub(crate) fn finish_initial_controller_post_once_v1(
        &mut self,
        peer: &mut RootControllerPeerReceivingV1<'_>,
    ) -> Result<(), Error> {
        self.original
            .finish_initial_controller_post_once_v1(peer.startup_original_mut_v1()?, &self.mutation)
    }

    pub(crate) fn complete_initial_controller_peer_once_v1(
        &mut self,
        peer: &mut RootControllerPeerReceivingV1<'_>,
    ) -> Result<(), Error> {
        self.original
            .complete_initial_controller_peer_once_v1(peer.startup_original_mut_v1()?)
    }

    pub(crate) fn initial_peer_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<(&mut Self, &ProductionNormalRootStartupV1)>().checked_mul(3)?
            .checked_add(crate::controller_resource_reservation::RootReceivingOriginalV1::initial_peer_control_bytes_v1()?)?
            .checked_add(size_of::<(&mut Self, &mut RootControllerPeerReceivingV1<'_>)>().checked_mul(9)?)?
            .checked_add(size_of::<Result<RootControllerPeerReceivingV1<'_>, Error>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), Error>>().checked_mul(9)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}
