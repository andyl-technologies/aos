//! Defines the separately funded Source-signed pre-content upload boundary.
//!
//! ```text
//! BlobBegin.extensions[activation-upload/1] = {request,proof}
//! request = {schema,scope,role,coordinator,manifest,chunk_bytes,
//!            maximum_requests,native_allocation}
//! MAC context = {request,assigned_request}; only own proof is excluded.
//! ```
//!
//! A decoded request or MAC alone creates no native grant. The live native
//! target must authenticate the same Commit, completed Arm, connection, Source
//! scope and sticky ordinal before admitting content storage. Both uploads
//! finish before the final WorldActivate assignment is reserved or signed.

use super::*;
#[cfg(test)]
use crate::envelope::{Envelope, MessageKind};
#[cfg(test)]
use crucible_node_format::{ContractError, canonical};

mod contract;
mod crypto;
mod projection;
pub(super) mod storage;
pub use contract::{
    authenticate_restoration_activation_upload_schema_data,
    restoration_activation_upload_contract_data, restoration_activation_upload_schema,
    restoration_activation_upload_schema_counter_scratch_data,
};
pub use crypto::{
    maximum_restoration_activation_upload_proof_encoded_bytes_data,
    restoration_activation_upload_assigned_request_digest,
    restoration_activation_upload_context_digest_data, restoration_activation_upload_proof_data,
    verify_restoration_activation_upload_proof_data,
};
pub(crate) use storage::original_native_restoration_activation_upload_required_storage_data;

/// Names the explicitly negotiated upload-begin schema and envelope extension.
pub const PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE: &str =
    "source-owned.packet-restoration-activation-upload/1";

/// Identifies one exact immutable body without permitting an upload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketRestorationActivationUploadRole {
    /// Selects the complete genuine prepared restored coordinator first.
    Coordinator,
    /// Selects the complete world manifest after coordinator completion.
    Manifest,
}

impl PacketRestorationActivationUploadRole {
    /// Returns this closed upload's retained ordinal.
    pub const fn ordinal_data(self) -> usize {
        match self {
            Self::Coordinator => 0,
            Self::Manifest => 1,
        }
    }
}

/// Binds one actual BlobBegin to both complete future world content originals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationUploadRequest {
    /// Selects exactly the separate upload-begin edition one.
    pub schema: String,
    /// Retains the same authenticated World phase Source/target/Commit scope.
    pub scope: PacketRestorationActivationScope,
    /// Selects one fixed ordinal; it cannot select arbitrary content.
    pub role: PacketRestorationActivationUploadRole,
    /// Binds the complete actual prepared coordinator bytes.
    pub coordinator: ContentRef,
    /// Binds the complete actual activation manifest bytes.
    pub manifest: ContentRef,
    /// Retains the unchanged actual negotiated frame ceiling.
    pub maximum_frame_bytes: U64,
    /// Fixes the nonzero chunk width before the bounded effect loop.
    pub chunk_bytes: U64,
    /// Fixes the exact Begin/Chunk/Finish request population for this role.
    pub maximum_requests: U64,
    /// Funds this independent upload owner, not Commit or final activation.
    pub native_allocation: PacketRestorationActivationAllocationRow,
}

impl PacketRestorationActivationUploadRequest {
    /// Borrows the exact full content identity permitted by this ordinal.
    pub const fn content_ref_data(&self) -> &ContentRef {
        match self.role {
            PacketRestorationActivationUploadRole::Coordinator => &self.coordinator,
            PacketRestorationActivationUploadRole::Manifest => &self.manifest,
        }
    }

    /// Checks the closed finite upload population without granting any effects.
    ///
    /// # Errors
    /// Refuses another schema, invalid or identical contents, invalid common
    /// scope/row, zero or oversized chunk, nonexact loop count or artifact cap.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE
            || self.maximum_frame_bytes.get() == 0
            || self.maximum_frame_bytes.get() > 65_536
            || self.chunk_bytes.get() == 0
            || self.chunk_bytes.get() > 4096
            || self.coordinator.media_type != "application/json"
            || self.manifest.media_type != "application/json"
            || self.coordinator == self.manifest
            || self.coordinator.length.get() == 0
            || self.coordinator.length.get() > 131_072
            || self.manifest.length.get() > 16_384
            || self.manifest.length.get() == 0
            || self.maximum_requests.get() > 4096
            || self.maximum_requests.get()
                != self
                    .content_ref_data()
                    .length
                    .get()
                    .div_ceil(self.chunk_bytes.get())
                    .checked_add(2)
                    .ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        self.coordinator.validate()?;
        self.manifest.validate()?;
        // The borrowed common grammar constructs no synthetic phase owner.
        super::validate_scope_data(&self.scope)?;
        self.native_allocation.requested_bytes_data()?;
        crate::connection::serialized_credit(self, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
        Ok(())
    }
}

/// Binds upload MAC data to the complete actual assigned BlobBegin envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationUploadContext {
    /// Retains the full exact upload scope/ordinal/limits/ref/row body.
    pub request: PacketRestorationActivationUploadRequest,
    /// Retains the full assigned-envelope projection, excluding only own proof.
    pub assigned_request: Bytes,
}

impl PacketRestorationActivationUploadContext {
    /// Checks context data without authenticating a Source or native grant.
    ///
    /// # Errors
    /// Refuses invalid request data, a non-32-byte digest or context extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.request.validate_data()?;
        if self.assigned_request.as_slice().len() != 32 {
            return Err(invalid());
        }
        crate::connection::serialized_credit(self, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
        Ok(())
    }
}

/// Retains the complete normalized upload proof beside its raw assigned request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationUploadArtifact {
    /// Retains the independently funded exact upload original.
    pub request: PacketRestorationActivationUploadRequest,
    /// Carries the distinct upload-key-domain MAC over its assigned context.
    pub proof: PacketRestorationActivationProof,
}

impl PacketRestorationActivationUploadArtifact {
    /// Validates the closed artifact grammar without granting content reserve.
    ///
    /// # Errors
    /// Refuses malformed upload/proof data or an artifact above sixteen KiB.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.request.validate_data()?;
        if self.proof.schema != "source-owned.packet-restoration-activation-upload-proof/1"
            || self.proof.algorithm != "blake3-256-mac"
            || self.proof.context_digest.as_slice().len() != 32
            || self.proof.mac.as_slice().len() != 32
        {
            return Err(invalid());
        }
        crate::connection::serialized_credit(self, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
        Ok(())
    }
}

/// Checks both immutable upload/activation definitions and their negotiation.
///
/// # Errors
/// Refuses missing, duplicated, changed or unnegotiated full schema definitions.
pub fn authenticate_restoration_activation_upload_selection_data(
    selection: &crate::reference_packet::control::PacketControlSelection,
    authority: &crate::handshake::ConnectionAuthority,
) -> Result<(), ProviderError> {
    super::authenticate_restoration_activation_selection_data(selection, authority)
}

/// Names the independent upload DTO/projection/hash/result fixed views.
pub fn restoration_activation_upload_counter_scratch_data() -> usize {
    storage::counter_scratch_data()
        + contract::restoration_activation_upload_schema_counter_scratch_data()
}

#[cfg(test)]
mod tests;
