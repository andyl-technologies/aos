//! Defines model-absent bootstrap ACK18 DATA and exact assignment framing.
//!
//! ```text
//! assigned native_import18_bootstrap.extensions = {bootstrap-ack-proof18: proof}
//! correlated response.extensions = {bootstrap-ack-receipt18: receipt}
//! receipt.state = "bootstrap_only"
//! ```
//!
//! The native and Source issuers independently lend the same original private
//! birth, complete SourceBinding18, selected definitions, kernel identities,
//! registrations, literal Hello pair, recipe and initial row. These DATA helpers
//! cannot create those owners, a model, ordinary admission, Ready or a frontier.

use super::*;
use crate::envelope::{MessageKind, Method};
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;

mod projection;
pub use projection::{
    PacketNativeImport18BootstrapAckProjectionData,
    native_import18_bootstrap_ack_constructor_transient_data,
    native_import18_bootstrap_ack_counter_scratch_data,
    native_import18_bootstrap_ack_projection_data,
};

mod crypto;
pub use crypto::{
    native_import18_bootstrap_ack_context_digest_data, native_import18_bootstrap_ack_proof_data,
    native_import18_bootstrap_ack_receipt_data, verify_native_import18_bootstrap_ack_proof_data,
    verify_native_import18_bootstrap_ack_receipt_data,
};

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import18::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_FEATURE;
/// Names the closed profile-specific request grammar.
pub const NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA: &str =
    "source-owned.packet-native-import-bootstrap-request/18";
/// Names the closed bootstrap-only result grammar.
pub const NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA: &str =
    "source-owned.packet-native-import-bootstrap-result/18";

/// Requests the same genuine initial bootstrap without ordinary realization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18BootstrapRequest {
    /// Selects only the new profile method's exact request grammar.
    pub schema: String,
    /// Binds the actual immutable Source/native recipe occurrence.
    pub recipe_identity: Bytes,
    /// Binds the independently derived same initial escrow.
    pub initial_funding: PacketNativeStartupAllocationRow,
}

/// Reports only completion of the original bootstrap authentication method.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18BootstrapResult {
    /// Selects only the new profile method's exact result grammar.
    pub schema: String,
    /// Never claims realized, admitted, model-installed or Ready status.
    pub state: PacketNativeImport18BootstrapAckState,
    /// Preserves the same immutable recipe identity.
    pub recipe_identity: Bytes,
    /// Preserves the same independently derived original initial row.
    pub initial_funding: PacketNativeStartupAllocationRow,
}

impl PacketNativeImport18BootstrapRequest {
    /// Checks the complete request DATA without issuing bootstrap ownership.
    ///
    /// # Errors
    /// Refuses another schema, digest width or invalid initial row.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA {
            return Err(invalid());
        }
        digest32(&self.recipe_identity)?;
        self.initial_funding.requested_peak_data()?;
        Ok(())
    }
}

impl PacketNativeImport18BootstrapResult {
    /// Checks exact bootstrap-only result correspondence with its actual request.
    ///
    /// # Errors
    /// Refuses another schema/state/recipe/row or malformed original DATA.
    pub fn authenticate_request_data(
        &self,
        request: &PacketNativeImport18BootstrapRequest,
    ) -> Result<(), ProviderError> {
        request.validate_data()?;
        if self.schema != NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA
            || self.state != PacketNativeImport18BootstrapAckState::BootstrapOnly
            || self.recipe_identity != request.recipe_identity
            || self.initial_funding != request.initial_funding
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import18::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF;
pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import18::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT;
/// Names the complete bootstrap-only context grammar.
pub const NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT: &str =
    "source-owned.packet-native-import-bootstrap-ack-context/18";

/// Retains complete independently derived original bootstrap bindings.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18BootstrapAckContext {
    /// Selects the exact new context grammar.
    pub schema: String,
    /// Selects the shared BLAKE3 keyed-canonical algorithm.
    pub algorithm: String,
    /// Binds complete SourceBinding18 and original birth/private-launch/Host association.
    pub source_birth: Bytes,
    /// Binds both actual PID, UID and measured executable identities.
    pub kernel_binding: Bytes,
    /// Binds the complete immutable selected policy and full definitions.
    pub policy_binding: Bytes,
    /// Binds the actual complete Host registration and connection identity.
    pub host_registration: Bytes,
    /// Binds the actual complete native registration and connection identity.
    pub native_registration: Bytes,
    /// Binds the complete literal Host-to-native Hello frame including its header.
    pub hello_request: Bytes,
    /// Binds the complete literal native-to-Host Hello frame including its header.
    pub hello_response: Bytes,
    /// Binds the same actual assigned bootstrap request, removing only proof18.
    pub assigned_request: Bytes,
    /// Binds the actual retained same-lease immutable full recipe identity.
    pub recipe_identity: Bytes,
    /// Binds the independently derived initial row without issuing its allowance.
    pub initial_funding: PacketNativeStartupAllocationRow,
}

/// Retains the distinct Source bootstrap proof without ordinary admission semantics.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18BootstrapAckProof {
    /// Selects only the new request-proof grammar.
    pub schema: String,
    /// Selects the shared keyed-canonical algorithm.
    pub algorithm: String,
    /// Binds the complete independent context.
    pub context_digest: Bytes,
    /// Contains the distinct-domain Source MAC.
    pub mac: Bytes,
}

/// States the limited result of the new original bootstrap occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNativeImport18BootstrapAckState {
    /// Authenticates the bootstrap occurrence without installing or opening a model.
    BootstrapOnly,
}

/// Retains a native bootstrap-only terminal, never an ordinary Admit receipt.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18BootstrapAckReceipt {
    /// Selects only the new receipt grammar.
    pub schema: String,
    /// Selects the shared keyed-canonical algorithm.
    pub algorithm: String,
    /// Explicitly limits this receipt to the original bootstrap occurrence.
    pub state: PacketNativeImport18BootstrapAckState,
    /// Binds the complete independently reconstructed context.
    pub context_digest: Bytes,
    /// Binds the exact same assigned response, removing only receipt18.
    pub assigned_response: Bytes,
    /// Contains the distinct-domain native MAC.
    pub mac: Bytes,
}

impl PacketNativeImport18BootstrapAckContext {
    /// Checks the exact context grammar and nine fixed digest widths.
    ///
    /// # Errors
    /// Refuses another schema/algorithm, digest width, or incomplete initial row.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(invalid());
        }
        for digest in [
            &self.source_birth,
            &self.kernel_binding,
            &self.policy_binding,
            &self.host_registration,
            &self.native_registration,
            &self.hello_request,
            &self.hello_response,
            &self.assigned_request,
            &self.recipe_identity,
        ] {
            digest32(digest)?;
        }
        self.initial_funding.requested_peak_data()?;
        Ok(())
    }
}

impl PacketNativeImport18BootstrapAckProof {
    /// Checks the new proof grammar without authenticating a Source occurrence.
    ///
    /// # Errors
    /// Refuses another schema, algorithm or digest/MAC width.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(invalid());
        }
        digest32(&self.context_digest)?;
        digest32(&self.mac)?;
        Ok(())
    }
}

impl PacketNativeImport18BootstrapAckReceipt {
    /// Checks the exact bootstrap-only receipt grammar without granting a frontier.
    ///
    /// # Errors
    /// Refuses another schema, algorithm, state spelling or digest/MAC width.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
            || self.state != PacketNativeImport18BootstrapAckState::BootstrapOnly
        {
            return Err(invalid());
        }
        digest32(&self.context_digest)?;
        digest32(&self.assigned_response)?;
        digest32(&self.mac)?;
        Ok(())
    }
}

/// Hashes the complete same bootstrap assignment after removing only proof18.
///
/// The proof may be absent in the actual SDK signing slot. Every other extension
/// refuses, including ACK5 and import17/18 Prepare keys. This does not reserve a
/// Session original or issue native bootstrap permission.
///
/// # Errors
/// Refuses a different message/method/body, malformed Envelope, foreign key or
/// failure to canonicalize within the independently supplied actual frame bound.
pub fn native_import18_bootstrap_ack_assigned_request_digest(
    original: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.message != MessageKind::Request
        || original.method != Method::NativeImport18Bootstrap
        || original
            .extensions
            .keys()
            .any(|key| key != NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
    {
        return Err(invalid());
    }
    let request: PacketNativeImport18BootstrapRequest =
        serde_json::from_value(serde_json::Value::Object(original.body.clone()))
            .map_err(ContractError::from)?;
    request.validate_data()?;
    assigned_digest(
        original,
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,
        maximum_frame_bytes,
    )
}

/// Hashes the exact correlated bootstrap response after removing only receipt18.
///
/// # Errors
/// Refuses a missing request proof, another response, extra extension, failure to canonicalize within the actual frame bound.
pub fn native_import18_bootstrap_ack_assigned_response_digest(
    original: &Envelope,
    response: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    native_import18_bootstrap_ack_assigned_request_digest(original, maximum_frame_bytes)?;
    if !original
        .extensions
        .contains_key(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
        || response
            .extensions
            .keys()
            .any(|key| key != NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT)
    {
        return Err(invalid());
    }
    response.validate()?;
    original.matches_response(response)?;
    // The actual dedicated profile body parser retains and checks the typed
    // completed bootstrap18 result before interpreting this distinct receipt.
    // Ordinary Admit results are outside this method's grammar.
    assigned_digest(
        response,
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT,
        maximum_frame_bytes,
    )
}

fn assigned_digest(
    original: &Envelope,
    excluded: &str,
    maximum: usize,
) -> Result<[u8; 32], ProviderError> {
    let mut value = serde_json::to_value(original).map_err(ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove(excluded);
    let bytes = bounded(&value, maximum)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

#[cfg(test)]
#[path = "bootstrap_ack/tests.rs"]
mod tests;

mod body;
pub use body::{
    PacketNativeImport18BootstrapReceivedBody, PacketNativeImport18BootstrapResponseBody,
    native_import18_bootstrap_request_body_data, native_import18_bootstrap_response_body_data,
};

mod operands;
pub use operands::{
    PacketNativeImport18BootstrapBirthView, PacketNativeImport18BootstrapDefinitionsView,
    PacketNativeImport18BootstrapKernelView, PacketNativeImport18BootstrapNegotiatedView,
    PacketNativeImport18BootstrapPolicyView, PacketNativeImport18BootstrapProcessView,
    native_import18_bootstrap_birth_wire_data, native_import18_bootstrap_kernel_wire_data,
    native_import18_bootstrap_operands_counter_scratch_data,
    native_import18_bootstrap_policy_wire_data,
};

pub(in crate::reference_packet) use operands::{
    native_import18_bootstrap_birth_serialization_data,
    native_import18_bootstrap_kernel_serialization_data,
    native_import18_bootstrap_policy_serialization_data,
};

mod source_retention;
pub use source_retention::{
    PacketNativeImport18BootstrapRetainedData,
    native_import18_bootstrap_retention_counter_scratch_data,
};
