//! Defines inert data for an explicitly selected native-after confirmation.
//!
//! The extension is carried only by a correlated Poll request and response.
//! Decoding these records supplies no source ticket, original owner or adopter.
//! The actual endpoint and source validate the same retained Capture, its three
//! transferred objects, issued after owner and the complete confirmation suffix.

use crate::ProviderError;
use crucible_node_format::{ContentRef, HashRef, Id, U64, Validate};
use serde::{Deserialize, Serialize};

/// Names the separately negotiated request/response confirmation feature.
pub const PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE: &str =
    "source-owned.packet-native-after-confirmation/5";

/// Names the envelope extension carrying the source-selected confirmation.
pub const PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION: &str =
    PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE;

/// Binds a confirmation request to one original completed Capture.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeAfterConfirmationRequest {
    /// Names this closed request grammar.
    pub schema: String,
    /// Identifies the original Capture request retained in both endpoint journals.
    pub capture_request_id: Id,
    /// Commits to the normative original request identity; literal sequence remains separately journaled.
    pub capture_request_hash: HashRef,
    /// Identifies the unchanged original Capture operation.
    pub capture_operation_id: Id,
    /// Commits to the actual final postsequence Capture response bytes.
    pub capture_terminal_hash: HashRef,
    /// Retains the actual terminal provider sequence assigned after all three ACKs.
    pub capture_terminal_sequence: U64,
    /// Names the original whole native snapshot transferred before Capture completion.
    pub native_snapshot_ref: ContentRef,
    /// Names the separately transferred complete Control snapshot.
    pub native_control_ref: ContentRef,
    /// Names the separately transferred unchanged-cut anchor.
    pub native_anchor_ref: ContentRef,
}

/// Binds one actual after body to the same original Capture and confirmation.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeAfterConfirmationReceipt {
    /// Names this closed response grammar.
    pub schema: String,
    /// Retains the exact original request conjunction.
    pub capture: PacketNativeAfterConfirmationRequest,
    /// Names the actual frozen after body exported before this Poll response.
    pub native_after_ref: ContentRef,
    /// Reports the actual independent after Vec capacity for source accounting.
    pub native_after_capacity: U64,
}

impl PacketNativeAfterConfirmationRequest {
    /// Checks closed data grammar without authenticating any original owner.
    ///
    /// # Errors
    /// Refuses another schema, invalid identifiers/references, wrong request
    /// identity domain, absent terminal sequence or aliased Capture objects.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.capture_request_id.validate()?;
        self.capture_operation_id.validate()?;
        self.capture_request_hash.validate()?;
        self.capture_terminal_hash.validate()?;
        self.native_snapshot_ref.validate()?;
        self.native_control_ref.validate()?;
        self.native_anchor_ref.validate()?;
        if self.schema != "source-owned.packet-native-after-confirmation-request/5"
            || self.capture_request_hash.domain != "cnp.request.v1"
            || self.capture_terminal_hash.domain != "source-owned.packet-native-capture-terminal/5"
            || self.capture_terminal_sequence.get() == 0
            || self.native_snapshot_ref == self.native_control_ref
            || self.native_snapshot_ref == self.native_anchor_ref
            || self.native_control_ref == self.native_anchor_ref
        {
            return Err(ProviderError::Correlation(
                "native-after confirmation request grammar",
            ));
        }
        Ok(())
    }
}

impl PacketNativeAfterConfirmationReceipt {
    /// Checks a closed receipt shape without granting capture or restoration.
    ///
    /// # Errors
    /// Refuses invalid request data, another schema, invalid after reference,
    /// capacity below actual body length or aliasing with any Capture object.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.capture.validate_data()?;
        self.native_after_ref.validate()?;
        if self.schema != "source-owned.packet-native-after-confirmation-receipt/5"
            || self.native_after_capacity.get() < self.native_after_ref.length.get()
            || self.native_after_ref == self.capture.native_snapshot_ref
            || self.native_after_ref == self.capture.native_control_ref
            || self.native_after_ref == self.capture.native_anchor_ref
        {
            return Err(ProviderError::Correlation(
                "native-after confirmation receipt grammar",
            ));
        }
        Ok(())
    }
}

mod contract;
mod selection;
pub use contract::{native_after_confirmation_contract, native_after_confirmation_schema};
pub use selection::PacketNative5ConfirmationSelection;

pub(crate) use contract::native_after_confirmation_contract_storage_data;
