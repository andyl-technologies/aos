//! Retains the sole decoded Controller inventory and its exact signed body.
//!
//! These immutable models remain DATA. A genuine native caller must join the
//! same request/body commitment, journal original and complete live interval.

use super::super::{AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1};
use crate::ProtocolValidationError;
use aos_proto::aos::sandbox::local::v1::{BrokerMethod, InventoryRuntimeResponse, InventoryStorageResourcesResponse};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

/// Contains the complete method-selected inventory produced by its sole decoder.
#[doc(hidden)]
pub enum ControllerInventoryModelDataV2 {
    /// Complete Host known rows and the separately validated native companion.
    Host(InventoryRuntimeResponse),
    /// Complete Mount destination slots, resources and physical anchors.
    Mount(crate::ValidatedDestinationSlotInventory),
    /// Complete Storage launch and lifecycle graph, retaining its raw model.
    Storage(crate::ValidatedStorageInventory, InventoryStorageResourcesResponse),
    /// Complete Network resources and namespace identities.
    Network(crate::ValidatedNetworkInventory),
}

/// Binds an immutable decoded inventory to the exact body that produced it.
///
/// The private fields prevent substitution of a caller-built empty inventory
/// for a different native query body. This creates no native or read authority.
#[doc(hidden)]
pub struct ControllerInventoryDecodedOriginalV2 {
    body_digest: [u8; 32],
    method: BrokerMethod,
    model: ControllerInventoryModelDataV2,
}

impl ControllerInventoryDecodedOriginalV2 {
    /// Borrows the complete model without decoding or copying it again.
    pub const fn model_v2(&self) -> &ControllerInventoryModelDataV2 { &self.model }

    /// Returns the exact method-body digest as non-authorizing comparison DATA.
    pub const fn body_digest_v2(&self) -> [u8; 32] { self.body_digest }

    /// Returns the exact authenticated method used by this decoder.
    pub const fn method_v2(&self) -> BrokerMethod { self.method }
}

/// Decodes one authenticated inventory through its sole existing body parser.
///
/// Native custody, signed history currentness and payment remain mandatory at
/// the actual caller. A successful pure decoder cannot manufacture that proof.
///
/// # Errors
/// Refuses non-success, another method, malformed or oversized canonical data,
/// invalid model relations, unknown fields or exhausted schema bounds.
#[doc(hidden)]
pub fn decode_controller_inventory_model_v2(outcome: &AuthenticatedBrokerMethodOutcomeV1)
    -> Result<ControllerInventoryDecodedOriginalV2, ProtocolValidationError> {
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(ProtocolValidationError::InvalidField("successful Delete Inventory"));
    };
    let maximum = outcome.request().maximum_response_bytes();
    let model = match outcome.request().method() {
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME =>
            InventoryRuntimeResponse::decode_from_slice(exact_body)
                .map(ControllerInventoryModelDataV2::Host)
                .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string())),
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS =>
            crate::decode_destination_slot_inventory_response(exact_body, maximum).map(ControllerInventoryModelDataV2::Mount),
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES =>
            crate::decode_storage_resource_inventory_response_with_model(exact_body, maximum)
                .map(|(validated, model)| ControllerInventoryModelDataV2::Storage(validated, model)),
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES =>
            crate::decode_network_resource_inventory_response(exact_body, maximum).map(ControllerInventoryModelDataV2::Network),
        _ => Err(ProtocolValidationError::InvalidField("Delete Inventory method")),
    }?;
    Ok(ControllerInventoryDecodedOriginalV2 { body_digest: Sha256::digest(exact_body).into(),
        method: outcome.request().method(), model })
}
