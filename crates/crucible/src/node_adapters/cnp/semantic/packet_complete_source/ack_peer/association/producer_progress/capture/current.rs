//! Selects the actual retained Capture frontier without reviving old Observe.
//!
//! The owning current-proof chooser compares every completed branch's saved SDK
//! frontier first. It authenticates only the unique newest branch and never
//! falls back to an older proof after a currentness or signature refusal.

use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_contract::{RuntimeError, WorldActivation},
};
use crucible_node_contract::{ContentRef, U64};
use crucible_node_provider::client::CnpController;

impl PacketCompleteSemanticSource {
    /// Returns the actual completed Capture frontier as comparison DATA.
    ///
    /// An unused Capture has no candidate. An in-flight or failed Capture
    /// refuses the whole current read; it cannot make the prior Observe current.
    pub(crate) fn original_restored_capture_checkpoint_frontier_data(
        &self,
    ) -> Result<Option<U64>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let capture = original
            .restored_capture
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !capture.is_used_data() {
            return Ok(None);
        }
        let bridge = capture.current_bridge_data()?;
        Ok(Some(bridge.checkpoint_identity_data().2))
    }

    /// Lends the unique selected completed Capture proof under its owning read.
    ///
    /// The caller already holds the same original SourceRead and independently
    /// authenticates its real World/current native checkpoint. This method
    /// repeats the exact completed SDK pair, saved bridge MAC, original creator
    /// and immutable model correspondence before lending borrowed identities.
    pub(crate) fn with_original_restored_capture_checkpoint_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        inspect: impl FnOnce(&ContentRef, &ContentRef, U64) -> Result<R, RuntimeError>,
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
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let capture = original
            .restored_capture
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let bridge = capture.current_bridge_data()?;
        bridge.authenticate_current_data(self, controller, emitter, world, key)?;
        let (measurement, model, frontier) = bridge.checkpoint_identity_data();
        let result = inspect(measurement, model, frontier)?;
        bridge.authenticate_current_data(self, controller, emitter, world, key)?;
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(result)
    }
}

impl PacketCompleteSemanticSource {
    /// Lends the unchanged typed pre-Capture checkpoint under its real bridge.
    ///
    /// The bridge proves the actual current completed Capture frontier. Its
    /// saved pre-upload frontier locates the independently retained typed owner
    /// without requiring that older SDK pair to remain current after uploads.
    /// The historical lender checks exact native/Source/journal correspondence;
    /// the same current bridge is checked again after the callback.
    ///
    /// # Errors
    /// Refuses a failed/currentness mismatch, missing or ambiguous retained typed
    /// origin, changed full checkpoint references, private MAC or caller failure.
    pub(crate) fn with_original_restored_capture_typed_checkpoint_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        inspect: impl FnOnce(
            &crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
            &crucible_node_provider::reference_packet::control::PacketNative5UnderlyingRecord,
            &ContentRef,
            U64,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.with_original_restored_capture_checkpoint_data(
            controller,
            world,
            key,
            |measurement, model, frontier| {
                let prefix_frontier = {
                    let association = self
                        .ack_peer_association
                        .try_borrow()
                        .map_err(|_| RuntimeError::OwnerBusy)?;
                    let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
                    let capture = original
                        .restored_capture
                        .try_borrow()
                        .map_err(|_| RuntimeError::OwnerBusy)?;
                    let (original_measurement, original_model, prefix_frontier) = capture
                        .current_bridge_data()?
                        .pre_checkpoint_identity_data();
                    if original_measurement != measurement || original_model != model {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                    prefix_frontier
                };
                self.with_original_retained_checkpoint17_at_frontier_data(
                    controller,
                    world,
                    key,
                    measurement,
                    model,
                    prefix_frontier,
                    |record, underlying| inspect(record, underlying, measurement, frontier),
                )
            },
        )
    }
}

#[path = "current/precredit.rs"]
mod precredit;
