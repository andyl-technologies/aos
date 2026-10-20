//! Defines separately signed restoration activation, without reusing Commit credit.
//!
//! The selected contract binds a Source-issued phase to its actual assigned CNP
//! request and complete restoration association. DTOs and valid MAC data alone
//! do not create the native phase owner or the Core once claim.
//!
//! ```text
//! activation/1 = {request:{schema,phase,scope,native_allocation},proof}
//! MAC context = {request,assigned_request}; the digest is not a wire field.
//! scope = {source_birth,source_runtime,scope_proof,target,restoration}
//! ```

use crucible_node_format::{Bytes, ContentRef, HashRef, Id, U64, Validate};
use serde::{Deserialize, Serialize};

use crate::{ProviderError, envelope::Method};

/// Carries an ordinary method body without issuing an activation claim.
#[derive(Clone)]
pub enum PacketRestorationActivationCommand {
    /// Contains the actual nonexecuting owner-readiness request.
    Arm(crate::bodies::ActivateRequest),
    /// Contains the actual all-owner world publication request.
    WorldActivate(crate::bodies::WorldActivateRequest),
}

impl PacketRestorationActivationCommand {
    /// Returns the closed phase corresponding to this actual baseline body.
    pub const fn phase_data(&self) -> PacketRestorationActivationPhase {
        match self {
            Self::Arm(_) => PacketRestorationActivationPhase::Arm,
            Self::WorldActivate(_) => PacketRestorationActivationPhase::WorldActivate,
        }
    }

    /// Compares every signed target field used by the baseline method body.
    ///
    /// The WorldActivate manifest remains a full reference in the assigned
    /// request digest. Source separately authenticates its actual owning world,
    /// all preparation owners and coordinator before its once claim is issued.
    ///
    /// # Errors
    /// Refuses another phase, changed baseline body/target, nonempty body
    /// extensions or invalid manifest data. No body creates native permission.
    pub fn authenticate_request_data(
        &self,
        request: &PacketRestorationActivationRequest,
    ) -> Result<(), ProviderError> {
        request.validate_data()?;
        if self.phase_data() != request.phase {
            return Err(invalid());
        }
        let target = &request.scope.target;
        let matches = match self {
            Self::Arm(body) => {
                body.validate()?;
                body.admission_id == target.admission
                    && body.activation_id == target.activation
                    && body.world_generation == target.generation
                    && body.prepared_token == target.prepared_token
                    && body.world_binding_hash == target.world
                    && body.gate_id == target.gate
                    && body.extensions.is_empty()
            }
            Self::WorldActivate(body) => {
                body.validate()?;
                body.transaction_id == target.transaction
                    && body.activation_id == target.activation
                    && body.world_generation == target.generation
                    && body.prepared_token == target.prepared_token
                    && body.world_binding_hash == target.world
                    && body.gate_id == target.gate
                    && body.extensions.is_empty()
            }
        };
        if !matches {
            return Err(invalid());
        }
        Ok(())
    }
}

mod contract;
mod correspondence;
mod crypto;
mod projection;
mod prospective;
mod retained;
mod selection;
mod storage;
/// Defines the separately signed upload-before-activation wire boundary.
pub mod upload;
mod wire;
pub(crate) use wire::{verify_selected_wire_data, verify_selected_wire_header_data};

#[cfg(test)]
pub(crate) mod tests;

pub use contract::{
    authenticate_restoration_activation_schema_data, restoration_activation_contract_data,
    restoration_activation_schema, restoration_activation_schema_counter_scratch_data,
};
pub use correspondence::authenticate_restoration_activation_held_correspondence_data;
pub use prospective::original_installed_restoration_activation_construction_counter_scratch_data;
pub(crate) use prospective::original_native_restoration_activation_required_storage_data;
pub use retained::{
    RetainedRestorationActivationData,
    restoration_activation_historical_native_evidence_transient_bytes_data,
    restoration_activation_record_native_evidence_metadata_data,
    restoration_activation_retained_counter_scratch_data,
    restoration_activation_retained_native_evidence_counter_scratch_data,
    restoration_activation_retained_native_evidence_data,
};
pub use selection::authenticate_restoration_activation_selection_data;
pub use storage::{
    OriginalInstalledRestorationActivationConstructionData,
    OriginalInstalledRestorationActivationHistoricalData,
    PacketRestorationActivationCoordinatorConstructionInputs,
};

pub use crypto::{
    maximum_restoration_activation_proof_encoded_bytes_data,
    restoration_activation_assigned_request_digest, restoration_activation_context_digest_data,
    restoration_activation_proof_data, restoration_activation_scope_digest_data,
    verify_restoration_activation_proof_data,
};

/// Names the explicitly installed activation contract and request extension.
pub const PACKET_RESTORATION_ACTIVATION_FEATURE: &str =
    "source-owned.packet-restoration-activation/1";

/// Bounds the selected artifact independently of larger model and proof owners.
pub const MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES: usize = 16_384;

/// Names fixed typed, hashing, deserialization and borrowed activation views.
///
/// This excludes compiler/recursive frames and physical allocator overhead.
/// Typed/raw/canonical owning banks remain independently charged phase terms.
pub fn restoration_activation_protocol_counter_scratch_data() -> usize {
    use std::mem::size_of;
    restoration_activation_retained_counter_scratch_data()
        + selection::counter_scratch_data()
        + wire::counter_scratch_data()
        + size_of::<PacketRestorationActivationCommand>()
        + size_of::<PacketRestorationActivationRequest>()
        + size_of::<PacketRestorationActivationArtifact>()
        + size_of::<PacketRestorationActivationContext>()
        + size_of::<PacketRestorationActivationProof>()
        + size_of::<crypto::ProofView<'static>>()
        + upload::restoration_activation_upload_counter_scratch_data()
        + size_of::<Result<PacketRestorationActivationArtifact, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationRequest, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationCommand, ProviderError>>()
        + size_of::<Result<PacketRestorationActivationProof, ProviderError>>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<Result<crate::reference_packet::control::PacketNative5UnderlyingRecord, ProviderError>>()
        + size_of::<RetainedRestorationActivationData<'static>>()
        + size_of::<[u8; 32]>() * 4
        + size_of::<blake3::Hasher>() + size_of::<blake3::Hash>()
        + size_of::<&PacketRestorationActivationContext>()
        + size_of::<&PacketRestorationActivationScope>()
        + size_of::<(&crucible_node_format::Position, crucible_node_format::HashRef)>()
        + size_of::<(crucible_node_format::Position, crucible_node_format::HashRef)>()
        + restoration_activation_schema_counter_scratch_data()
        + restoration_activation_retained_native_evidence_counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}

/// Distinguishes signed phase data; constructing it issues no phase claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketRestorationActivationPhase {
    /// Prepares genuine owner readiness while retaining the physical hold.
    Arm,
    /// Publishes the actual complete world before releasing the physical hold.
    WorldActivate,
}

impl PacketRestorationActivationPhase {
    /// Returns the one baseline method permitted by this phase's grammar.
    pub const fn method(self) -> Method {
        match self {
            Self::Arm => Method::Activate,
            Self::WorldActivate => Method::WorldActivate,
        }
    }
}

/// Names a separately admitted native activation allocation as inert DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationAllocationRow {
    /// Covers all new persistent native owners through phase completion/refusal.
    pub retained_requested_bytes: U64,
    /// Covers the full simultaneous native construction and publication phase.
    pub maximum_simultaneous_transient_bytes: U64,
    /// Covers exact fixed counters and borrowed/conversion views.
    pub declared_counter_scratch_bytes: U64,
}

impl PacketRestorationActivationAllocationRow {
    /// Returns the checked whole row without granting its allocation.
    ///
    /// # Errors
    /// Refuses missing phase terms or checked requested-storage overflow.
    pub fn requested_bytes_data(&self) -> Result<u64, ProviderError> {
        if self.retained_requested_bytes.get() == 0
            || self.maximum_simultaneous_transient_bytes.get() == 0
            || self.declared_counter_scratch_bytes.get() == 0
        {
            return Err(invalid());
        }
        self.retained_requested_bytes
            .get()
            .checked_add(self.maximum_simultaneous_transient_bytes.get())
            .and_then(|bytes| bytes.checked_add(self.declared_counter_scratch_bytes.get()))
            .ok_or_else(invalid)
    }
}

/// Binds the actual installed native target and complete readiness transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationTarget {
    /// Names the actual same native process, never a captured historical PID.
    pub native_pid: U64,
    /// Names the original negotiated session.
    pub session: Id,
    /// Names the original negotiated incarnation.
    pub incarnation: Id,
    /// Names the exact native component.
    pub node: Id,
    /// Names its indivisible current owner.
    pub owner: Id,
    /// Names the actual target owner generation.
    pub owner_generation: U64,
    /// Binds the whole current owner binding.
    pub binding_hash: HashRef,
    /// Binds the immutable complete world.
    pub world: HashRef,
    /// Names the actual Core-owned target activation.
    pub activation: Id,
    /// Names that target's exact generation.
    pub generation: U64,
    /// Names the actual original realization token.
    pub prepared_token: Id,
    /// Names the originally installed gate.
    pub gate: Id,
    /// Names the original once-Admit transaction.
    pub admission: Id,
    /// Names the actual complete world publication transaction.
    pub transaction: Id,
}

/// Binds the actual completed restoration rather than a decoded replacement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationOriginals {
    /// Names the exact authenticated captured native owner state.
    pub captured_owner_state: ContentRef,
    /// Names the exact reconstructed model and Control body.
    pub captured_control: ContentRef,
    /// Names the actual unchanged-cut captured journal.
    pub captured_journal: ContentRef,
    /// Names the same installed historical mapping.
    pub mapping: ContentRef,
    /// Names the actual assigned complete Commit request.
    pub commit_request: ContentRef,
    /// Names the actual correlated completed Commit response.
    pub commit_response: ContentRef,
    /// Binds the independently verified Commit context, exactly 32 bytes.
    pub context_digest: Bytes,
}

/// Retains complete common correspondence shared by the two distinct phases.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationScope {
    /// Names the immutable authenticated original invocation Source birth body.
    pub source_birth: ContentRef,
    /// Names the exact signed source Runtime7 record.
    pub source_runtime: ContentRef,
    /// Names the genuinely issued new all-four-owner scope artifact.
    pub scope_proof: ContentRef,
    /// Binds the actual newly owned target.
    pub target: PacketRestorationActivationTarget,
    /// Binds the actual already completed restoration association.
    pub restoration: PacketRestorationActivationOriginals,
}

/// Binds exact restoration scope and its separately admitted native phase row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationRequest {
    /// Selects exactly the activation/1 grammar.
    pub schema: String,
    /// Selects exactly one separately spent native phase.
    pub phase: PacketRestorationActivationPhase,
    /// Retains the complete same-Window, same-Source correspondence.
    pub scope: PacketRestorationActivationScope,
    /// Retains the independently Source-admitted native construction row.
    pub native_allocation: PacketRestorationActivationAllocationRow,
}

impl PacketRestorationActivationRequest {
    /// Checks closed data geometry without authenticating a Source or native owner.
    ///
    /// # Errors
    /// Refuses another grammar, invalid full references or identifiers, missing
    /// target/digest fields, inconsistent Commit references or requested overflow.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_RESTORATION_ACTIVATION_FEATURE {
            return Err(invalid());
        }
        validate_scope_data(&self.scope)?;
        self.native_allocation.requested_bytes_data()?;
        crate::connection::serialized_credit(self, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
        Ok(())
    }
}

/// Binds a separate MAC context to the complete actual assigned wire request.
///
/// The assigned digest is deliberately absent from the wire request, avoiding
/// a recursive hash. Its projection removes only this artifact's nested proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationContext {
    /// Retains the complete unsigned selected wire request.
    pub request: PacketRestorationActivationRequest,
    /// Hashes the actual assigned Envelope with only the nested proof removed.
    pub assigned_request: Bytes,
}

impl PacketRestorationActivationContext {
    /// Checks complete MAC context data without issuing a native phase claim.
    ///
    /// # Errors
    /// Refuses invalid unsigned request data, a truncated assigned digest or
    /// canonical context geometry exceeding the explicit artifact bound.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.request.validate_data()?;
        if self.assigned_request.as_slice().len() != 32 {
            return Err(invalid());
        }
        crate::connection::serialized_credit(self, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
        Ok(())
    }
}

/// Carries MAC data that grants nothing without the actual retained native claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationProof {
    /// Selects the distinct activation/1 proof grammar.
    pub schema: String,
    /// Selects domain-derived keyed BLAKE3.
    pub algorithm: String,
    /// Hashes the complete bounded canonical phase context.
    pub context_digest: Bytes,
    /// Authenticates that complete context under the actual private birth key.
    pub mac: Bytes,
}

/// Carries the complete separately selected request-only artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestorationActivationArtifact {
    /// Retains the whole assigned-request and native-row correspondence.
    pub request: PacketRestorationActivationRequest,
    /// Retains its separate Source-produced proof data.
    pub proof: PacketRestorationActivationProof,
}

impl PacketRestorationActivationArtifact {
    /// Checks the complete bounded artifact while leaving MAC authentication separate.
    ///
    /// # Errors
    /// Refuses invalid request data, another proof grammar/algorithm, truncated
    /// proof fields or a complete artifact exceeding its independent hard cap.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.request.validate_data()?;
        if self.proof.schema != "source-owned.packet-restoration-activation-proof/1"
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

fn invalid() -> ProviderError {
    ProviderError::Correlation("installed restoration activation data")
}

// Both explicit artifact editions validate exactly the same retained common
// identities. This borrowed predicate constructs no synthetic phase DTO.
pub(crate) fn validate_scope_data(
    scope: &PacketRestorationActivationScope,
) -> Result<(), ProviderError> {
    if scope.restoration.context_digest.as_slice().len() != 32
        || scope.restoration.commit_request == scope.restoration.commit_response
        || scope.target.native_pid.get() == 0
        || scope.target.native_pid.get() > i32::MAX as u64
        || scope.target.owner_generation.get() == 0
        || scope.target.generation.get() == 0
    {
        return Err(invalid());
    }
    let target = &scope.target;
    for id in [
        &target.session,
        &target.incarnation,
        &target.node,
        &target.owner,
        &target.activation,
        &target.prepared_token,
        &target.gate,
        &target.admission,
        &target.transaction,
    ] {
        id.validate()?;
    }
    target.binding_hash.validate()?;
    target.world.validate()?;
    let originals = &scope.restoration;
    for reference in [
        &scope.source_birth,
        &scope.source_runtime,
        &scope.scope_proof,
        &originals.captured_owner_state,
        &originals.captured_control,
        &originals.captured_journal,
        &originals.mapping,
        &originals.commit_request,
        &originals.commit_response,
    ] {
        reference.validate()?;
    }
    Ok(())
}

pub(crate) use retained::observe_response as observe_retained_response_metadata_data;

pub use retained::HistoricalRestorationActivationData;

/// Exposes the actual signed upload request without creating an upload permit.
pub use upload::PacketRestorationActivationUploadRequest;
