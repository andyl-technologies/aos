//! Lends the private live completed Capture checkpoint before dynamic admission.
//!
//! This lender supplies frozen correspondence DATA for a prequote geometry
//! walk without allocating native-read scratch. A live current-checkpoint loan
//! must separately hold the actual same-Source read token and native fences.
//! The admitted path still verifies full Source/native/MAC evidence.

use super::super::{bridge::CaptureAdminBridge, owner::CaptureOnceOwner};
use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association::OriginalAckPeerAssociation;
use crucible_node_transport::client::OriginalCanonicalBlobAckEmitter;
use std::{cell::Ref, mem::size_of};

impl PacketCompleteSemanticSource {
    /// Lends a genuine completed Capture's unchanged pre-upload checkpoint.
    ///
    /// The callback receives measurement, underlying-model reference, actual
    /// saved prefix frontier and actual completed final frontier. It may select
    /// only the independently frozen typed predecessor at that exact prefix.
    /// These facts may price geometry before native-read scratch is allocated.
    /// Any actual live checkpoint loan must additionally hold and recheck the
    /// real same-Source read token/claim and native/current chooser fences.
    /// These identities issue no admission rights. No historical DTO, old
    /// Observe currency or signature-presence template
    /// can construct the private completed owners borrowed here.
    ///
    /// # Errors
    /// Refuses a foreign actor/Source/Controller/World, borrowed or incomplete
    /// owner, changed actual SDK pair/content or advanced final frontier. Both
    /// current fences are checked even when the callback refuses.
    pub(crate) fn with_original_frozen_restored_capture_checkpoint17_cache_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        inspect: impl FnOnce(&ContentRef, &ContentRef, U64, U64) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let capture = original
            .restored_capture
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;

        // This getter requires both the actual Source Capture once owner and
        // its native-confirmed post-confirmation owner to be Complete.
        let bridge = capture.current_bridge_data()?;
        bridge.authenticate_completed_cache17_data(self, controller, emitter, world)?;
        let (measurement, model, prefix_frontier) = bridge.pre_checkpoint_identity_data();
        let (_, _, final_frontier) = bridge.checkpoint_identity_data();
        let result = inspect(measurement, model, prefix_frontier, final_frontier);
        bridge.authenticate_completed_cache17_data(self, controller, emitter, world)?;
        self.storage_origin_with_error::<RuntimeError>()?;
        result
    }

    /// Reports fixed lender scratch; callback and caller fences remain separate.
    pub(crate) fn original_frozen_restored_capture_checkpoint17_cache_counter_scratch_data() -> usize
    {
        CaptureAdminBridge::completed_cache17_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CnpController>()
            + size_of::<&WorldActivation>()
            + size_of::<Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<
                Result<Ref<'static, Option<OriginalAckPeerAssociation>>, std::cell::BorrowError>,
            >()
            + size_of::<Ref<'static, CaptureOnceOwner>>()
            + size_of::<Result<Ref<'static, CaptureOnceOwner>, std::cell::BorrowError>>()
            + size_of::<&OriginalAckPeerAssociation>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&CaptureAdminBridge>()
            + size_of::<Result<&CaptureAdminBridge, RuntimeError>>()
            + size_of::<(&ContentRef, &ContentRef, U64)>() * 2
            + size_of::<&ContentRef>() * 2
            + size_of::<U64>() * 2
            + size_of::<Result<(), RuntimeError>>() * 3
    }
}
