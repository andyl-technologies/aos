//! Defines one independently signed observation after restored world publication.
//!
//! Portable rows, proofs and matching scope data issue no Core claim or native
//! permission. The actual Source and native owners authenticate their same
//! once transaction independently, retaining every partial before a fallible use.
//!
//! ```text
//! observe/1 = {request:{schema,scope,world_original,world_terminal,
//!                       maximum_items,native_allocation},proof}
//! MAC context = {request,assigned_request}; maximum_items is exactly 1.
//! ```

use crucible_node_contract::{Bytes, ContentRef, U64, Validate};
use serde::{Deserialize, Serialize};

use super::activation::{
    PacketRestorationActivationAllocationRow, PacketRestorationActivationScope,
};
use crate::ProviderError;

mod contract;
mod crypto;
mod projection;
mod prospective;
mod retained;
mod selection;
mod storage;
mod wire;
pub(crate) use wire::{verify_selected_wire_data, verify_selected_wire_header_data};

#[cfg(test)]
mod tests;

pub use contract::{
    authenticate_restoration_observe_schema_data, restoration_observe_contract_data,
    restoration_observe_schema, restoration_observe_schema_counter_scratch_data,
};
pub use crypto::{
    maximum_restoration_observe_proof_encoded_bytes_data,
    restoration_observe_assigned_request_digest, restoration_observe_context_digest_data,
    restoration_observe_proof_data, verify_restoration_observe_proof_data,
};
pub use prospective::original_installed_restoration_observation_construction_counter_scratch_data;
pub(crate) use prospective::original_native_restoration_observation_required_storage_data;
pub(crate) use prospective::quote_from_cached_model_data as restoration_observe_cached_model_projection_data;
pub use retained::RetainedRestorationObservationData;
pub use selection::authenticate_restoration_observe_selection_data;
pub use storage::{
    OriginalInstalledRestorationObservationConstructionData,
    OriginalInstalledRestorationObservationHistoricalData,
};

/// Names the separately installed schema, feature and request extension.
pub const PACKET_RESTORATION_OBSERVE_FEATURE: &str = "source-owned.packet-restoration-observe/1";

/// Bounds the complete inline artifact independently of the negotiated frame.
pub const MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES: usize = 16_384;

/// Binds one observation to the actual complete restored and published world.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationObservationRequest {
    /// Selects exactly the independent observe/1 grammar.
    pub schema: String,
    /// Binds the unchanged complete Source, target, scope and Commit association.
    pub scope: PacketRestorationActivationScope,
    /// Names the actual fully assigned and published WorldActivate request.
    pub world_original: ContentRef,
    /// Names its actual correlated completed terminal response.
    pub world_terminal: ContentRef,
    /// Requests exactly one baseline observation batch, without increasing quotas.
    pub maximum_items: U64,
    /// Carries the independently preadmitted native observation allocation.
    pub native_allocation: PacketRestorationActivationAllocationRow,
}

impl PacketRestorationObservationRequest {
    /// Checks the closed geometry without authenticating publication or a claim.
    ///
    /// # Errors
    /// Refuses another grammar, changed fixed allowance, invalid full scope or
    /// references, identical World pair references or checked row/frame overflow.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_RESTORATION_OBSERVE_FEATURE || self.maximum_items.get() != 1 {
            return Err(invalid());
        }
        super::activation::validate_scope_data(&self.scope)?;
        for reference in [&self.world_original, &self.world_terminal] {
            reference.validate()?;
            if reference.media_type != "application/json" || reference.length.get() == 0 {
                return Err(invalid());
            }
        }
        if self.world_original == self.world_terminal {
            return Err(invalid());
        }
        self.native_allocation.requested_bytes_data()?;
        crate::connection::serialized_credit(self, MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES)?;
        Ok(())
    }

    /// Compares the actual ordinary Observe body with this signed request.
    ///
    /// # Errors
    /// Refuses a changed whole binding, owner generation, baseline cursor,
    /// observation allowance or any ordinary body extension.
    pub fn authenticate_body_data(
        &self,
        body: &crate::bodies::ObserveRequest,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        body.validate()?;
        if body.binding_hash != self.scope.target.binding_hash
            || body.owner_generation != self.scope.target.owner_generation
            || body.after_observation_sequence.get() != 0
            || body.maximum_items != self.maximum_items
            || !body.extensions.is_empty()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Binds the complete unsigned request to the real SDK-assigned Envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationObservationContext {
    /// Retains every unsigned scope, World pair and native allocation field.
    pub request: PacketRestorationObservationRequest,
    /// Hashes the assigned Envelope with only this artifact's proof removed.
    pub assigned_request: Bytes,
}

impl PacketRestorationObservationContext {
    /// Checks complete bounded MAC context data without issuing an observation.
    ///
    /// # Errors
    /// Refuses invalid request data, a non-32-byte digest or a context beyond
    /// the explicitly bounded inline artifact geometry.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.request.validate_data()?;
        if self.assigned_request.as_slice().len() != 32 {
            return Err(invalid());
        }
        crate::connection::serialized_credit(self, MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES)?;
        Ok(())
    }
}

/// Carries domain-separated MAC data; it cannot mint a current native claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationObservationProof {
    /// Selects exactly the observe-proof/1 grammar.
    pub schema: String,
    /// Selects independently derived keyed BLAKE3.
    pub algorithm: String,
    /// Hashes the complete canonical context, exactly 32 bytes.
    pub context_digest: Bytes,
    /// Authenticates that context under the real private birth key.
    pub mac: Bytes,
}

/// Retains the complete separately negotiated inline request artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationObservationArtifact {
    /// Carries the complete unsigned World, Commit and allocation correspondence.
    pub request: PacketRestorationObservationRequest,
    /// Carries the distinct Source proof data.
    pub proof: PacketRestorationObservationProof,
}

impl PacketRestorationObservationArtifact {
    /// Checks full bounded artifact syntax while leaving MAC verification separate.
    ///
    /// # Errors
    /// Refuses invalid request data, another proof grammar or algorithm,
    /// truncated digests or a full artifact beyond the hard inline cap.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.request.validate_data()?;
        crypto::validate_proof_data(&self.proof)?;
        crate::connection::serialized_credit(self, MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES)?;
        Ok(())
    }
}

/// Names actual fixed typed, hashing, serializer and borrowed result views.
///
/// Independently owned raw/canonical banks and all dynamic owner capacities are
/// separate row terms. This does not estimate compiler or allocator frames.
pub fn restoration_observe_protocol_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<PacketRestorationObservationRequest>()
        + size_of::<PacketRestorationObservationContext>()
        + size_of::<PacketRestorationObservationProof>()
        + size_of::<PacketRestorationObservationArtifact>()
        + size_of::<Result<PacketRestorationObservationRequest, serde_json::Error>>()
        + size_of::<Result<PacketRestorationObservationArtifact, serde_json::Error>>()
        + size_of::<Result<PacketRestorationObservationProof, ProviderError>>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<
            Result<PacketRestorationObservationRequest, crucible_node_contract::ContractError>,
        >()
        + size_of::<
            Result<PacketRestorationObservationArtifact, crucible_node_contract::ContractError>,
        >()
        + size_of::<Result<crate::bodies::ObserveRequest, crucible_node_contract::ContractError>>()
        + size_of::<Result<serde_json::Value, crucible_node_contract::ContractError>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
        + size_of::<crate::bodies::ObserveRequest>()
        + size_of::<&crate::bodies::ObserveRequest>()
        + size_of::<crypto::ProofView<'static>>()
        + size_of::<RetainedRestorationObservationData<'static>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>() * 4
        + size_of::<[&ContentRef; 2]>()
        + size_of::<std::array::IntoIter<&ContentRef, 2>>()
        + size_of::<&PacketRestorationObservationContext>()
        + size_of::<&PacketRestorationObservationRequest>()
        + size_of::<&PacketRestorationActivationScope>()
        + super::activation::restoration_activation_protocol_counter_scratch_data()
        + restoration_observe_schema_counter_scratch_data()
        + retained::counter_scratch_data()
        + selection::counter_scratch_data()
        + crypto::counter_scratch_data()
        + wire::counter_scratch_data()
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("installed restoration observation data")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("installed restoration observation requested storage")
}

// A sibling prospective producer uses the same closed wire/model projection;
// the returned geometry carries no first-Observe credit or live permission.
pub(crate) fn restoration_observe_repeated_projection_data(
    maximum: usize,
) -> Result<
    [crate::retained_metadata::serialization_storage::OriginalSerializationStorageData; 5],
    ProviderError,
> {
    projection::wire_projection_data(maximum)
}

pub(crate) use crypto::restoration_observe_proof_layout_data;
