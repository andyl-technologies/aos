//! Joins the complete administrative bridge to actual SDK and native history.
//!
//! This bridge authenticates the unchanged pre-Capture checkpoint at the actual
//! advanced completion frontier. It cannot make an older Observe current, create
//! a Source loan, reconstruct a grant, or substitute for signed archive ancestry.

use super::producer_fields::{field, object, read};
use crate::node_contract::{RuntimeError, SavedRuntimeActivation};
use crucible_node_format::{ContentRef, U64};
use crucible_node_transport::{
    protocol_snapshot::{
        current_controller17::{
            ValidatedControllerSettledHistory17, ValidatedHistoricalRestoredSettledCapture17,
        },
        restored_settled17::SealedHistoricalRestoredSettledNative17,
    },
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::complete_restore::PacketNativeRestoredRecord,
    },
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;

/// Retains the checked advanced frontier independently of the unchanged model.
pub(crate) struct OriginalSourceRestoredCaptureAdminBridgeHistory17Read {
    sdk: ValidatedHistoricalRestoredSettledCapture17,
}

impl OriginalSourceRestoredCaptureAdminBridgeHistory17Read {
    /// Authenticates one actual completed bridge under this same Source history.
    ///
    /// The parent selects the exact independently verified checkpoint at the
    /// saved pre-upload frontier. It retains all raw/DOM history and admits both
    /// SDK typed parsing and bounded proof/Source serialization before entry.
    ///
    /// # Errors
    /// Refuses a partial bridge, changed checkpoint/frontier/world, unequal real
    /// Capture/confirmation pairs, unavailable native history, a broken Source
    /// MAC, or an absent native/current model correspondence.
    pub(crate) fn validate_data(
        history: &Value,
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        world: &SavedRuntimeActivation,
        checkpoint: (
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &ContentRef,
            U64,
        ),
        maximum_transcript: usize,
    ) -> Result<Self, RuntimeError> {
        let bridge = object(
            history,
            &[
                "schema",
                "world",
                "measurement",
                "model",
                "native_after",
                "capture_request",
                "capture_id",
                "capture_operation",
                "prefix_frontier",
                "frontier",
                "signature",
            ],
        )?;
        if field(bridge, "schema")?.as_str()
            != Some("source-private.source-restored-capture-admin-bridge/17")
        {
            return Err(invalid());
        }
        let sdk = ValidatedHistoricalRestoredSettledCapture17::validate_data(controller)
            .map_err(|_| invalid())?;
        let request = sdk.request_data();
        let receipt = sdk.receipt_data();
        let prefix_frontier: U64 = read(field(bridge, "prefix_frontier")?)?;
        let frontier: U64 = read(field(bridge, "frontier")?)?;
        let signature: [u8; 32] = read(field(bridge, "signature")?)?;
        if field(bridge, "world")?
            != &serde_json::to_value(BridgeWorld17(world)).map_err(|_| invalid())?
            || field(bridge, "measurement")?
                != &serde_json::to_value(checkpoint.2).map_err(|_| invalid())?
            || field(bridge, "model")?
                != &serde_json::to_value(&checkpoint.0.native_receipt.native_record)
                    .map_err(|_| invalid())?
            || field(bridge, "native_after")?
                != &serde_json::to_value(&receipt.native_after_ref).map_err(|_| invalid())?
            || field(bridge, "capture_request")?
                != &serde_json::to_value(&sdk.confirmation_request_data().settled_capture_request)
                    .map_err(|_| invalid())?
            || field(bridge, "capture_id")?
                != &serde_json::to_value(&request.capture.capture_id).map_err(|_| invalid())?
            || field(bridge, "capture_operation")?
                != &serde_json::to_value(&request.capture_operation).map_err(|_| invalid())?
            || request.current_record != *checkpoint.2
            || request.current_model != checkpoint.0.native_receipt.native_record
            || prefix_frontier != checkpoint.3
            || prefix_frontier != sdk.prefix_frontier_data()
            || frontier != sdk.frontier_data()
            || prefix_frontier >= frontier
        {
            return Err(invalid());
        }
        native
            .authenticate_restored_capture_history_data(&sdk, controller)
            .map_err(|_| invalid())?;
        native
            .authenticate_current_checkpoint_data(checkpoint.0, checkpoint.1, checkpoint.2)
            .map_err(|_| invalid())?;
        let (capture, terminal, _) = sdk.capture_pair_data();
        let (confirmation, final_terminal, _) = sdk.confirmation_pair_data();
        let mut verifier = native
            .restored_capture_bridge_history_verifier_data(maximum_transcript)
            .map_err(|_| invalid())?;
        serde_json::to_writer(
            &mut verifier,
            &(
                BridgeWorld17(world),
                checkpoint.2,
                &checkpoint.0.native_receipt.native_record,
                &receipt.native_after_ref,
                &sdk.confirmation_request_data().settled_capture_request,
                &request.capture.capture_id,
                &request.capture_operation,
                prefix_frontier,
                frontier,
                capture,
                terminal,
                confirmation,
                final_terminal,
            ),
        )
        .map_err(|_| invalid())?;
        verifier.verify_data(&signature).map_err(|_| invalid())?;
        Ok(Self { sdk })
    }

    /// Returns the actual pre-upload checkpoint identity without claiming currency.
    pub(crate) fn prefix_checkpoint_data(&self) -> (&ContentRef, &ContentRef, U64) {
        (
            &self.sdk.request_data().current_record,
            &self.sdk.request_data().current_model,
            self.sdk.prefix_frontier_data(),
        )
    }

    /// Returns the actual final advanced frontier after confirmation/evidence.
    pub(crate) fn completed_frontier_data(&self) -> U64 {
        self.sdk.frontier_data()
    }

    /// Borrows the private checked actual SDK pair for the whole Source reader.
    pub(crate) fn sdk_data(&self) -> &ValidatedHistoricalRestoredSettledCapture17 {
        &self.sdk
    }

    /// Counts all independently retained typed SDK result backing.
    ///
    /// # Errors
    /// Refuses exhaustive traversal, checked overflow, or exceeded admission.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let facts = self
            .sdk
            .retained_metadata_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        crate::node_adapters::cnp::PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(&facts, maximum)?
            .checked_add(std::mem::size_of::<Self>()).filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }
}

struct BridgeWorld17<'a>(&'a SavedRuntimeActivation);

impl Serialize for BridgeWorld17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let SavedRuntimeActivation {
            generation,
            activation_id,
            world_binding_hash,
            owners,
            boundary,
        } = self.0;
        let mut fields = serializer.serialize_struct("SourceCaptureBridgeWorld17", 5)?;
        fields.serialize_field("generation", generation)?;
        fields.serialize_field("activation_id", activation_id)?;
        fields.serialize_field("world_binding_hash", world_binding_hash)?;
        fields.serialize_field("owners", owners)?;
        fields.serialize_field("boundary", boundary)?;
        fields.end()
    }
}

fn invalid() -> RuntimeError {
    RuntimeError::InvalidReceipt
}
