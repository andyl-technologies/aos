//! Defines import18 DATA while preserving the exact import17 contract.
//!
//! The required captured-Source and semantic-spend discriminators change the
//! closed binding and normalization grammar. They select this separate full
//! definition; they never widen the older parser or create a phase permission.
//! Stage/proof/record17 domains retain their separately versioned definitions.
//!
//! ```text
//! binding18 = {schema,prepare_digest,native_family,native_before,controller17,source_family,
//!   source17,node25,geometry_identity,role_extents,limits,normalization,
//!   normalization_maximum,semantic_spend_family,semantic_spend,
//!   semantic_spend_maximum}
//! ```

use super::PACKET_COMPLETE_RESTORE_ALGORITHM;
use super::transfer::{PacketCompleteRestoreCommitRequest, PacketCompleteRestorePrepareRequest};
use super::{Bytes, ContentRef, Id, ProviderError, SchemaRef, U64, Validate, canonical};
use crate::envelope::Envelope;
use crucible_node_format::ContractError;
use serde::{Deserialize, Serialize};

mod assigned;
mod binding;
mod context;
mod contract;
mod families;
mod initial_funding;
mod input;
mod launch_identity;
mod normalization;
mod phase;
mod prebirth_recipe;
pub(in crate::reference_packet) use prebirth_recipe::normalization_counter_scratch_data as native_import18_normalization_counter_scratch_data;
mod private_prefix;
mod receipt;
mod record_contract;
mod restored_record;
mod selection;
mod stage_contract;
mod startup_wire;
pub use hello::PacketNativeImport18HelloDeclarationData;

#[cfg(test)]
pub(in crate::reference_packet) mod inert_bootstrap_fixtures;

#[cfg(test)]
mod tests;

pub use super::import17::{
    MAXIMUM_NATIVE_IMPORT17_CONTEXT_BYTES, MAXIMUM_NATIVE_IMPORT17_RECEIPT_BYTES,
    PacketNativeImport17CommitReceipt, PacketNativeImport17Context, PacketNativeImport17Limits,
    PacketNativeImport17PeerContext, PacketNativeImport17PrepareReceipt, PacketNativeImport17Proof,
    PacketNativeImportReceiptAssignmentData, verify_native_import17_proof_data,
};
pub use assigned::{
    native_import18_assigned_request_digest, native_import18_assigned_response_digest,
};
pub use contract::{
    authenticate_native_import18_schema_data, native_import18_contract_counter_scratch_data,
    native_import18_contract_data, native_import18_contract_storage_data,
    native_import18_schema_data,
};
pub use families::{
    PacketNativeImport18NativeFamily, PacketNativeImport18SemanticSpendFamily,
    PacketNativeImport18SourceFamily,
};
pub use input::{PacketNativeImport18InputRole, native_import18_input_roster_digest_data};
pub(in crate::reference_packet) use normalization::OriginalImport18NormalizationAttempt;
pub use normalization::{NATIVE_IMPORT18_NORMALIZATION_SCHEMA, PacketNativeImport18Normalization};
pub use phase::PacketNativeImport18Phase;
pub use prebirth_recipe::{
    NATIVE_IMPORT18_PREBIRTH_RECIPE_SCHEMA, PacketNativeImport18PrebirthPhase,
    PacketNativeImport18PrebirthRecipeData, PacketNativeImport18PrebirthRecipeWireData,
    native_import18_mapping_lease_identity_counter_scratch_data,
    native_import18_mapping_lease_identity_data,
    native_import18_mapping_nonce_counter_scratch_data, native_import18_mapping_nonce_data,
    native_import18_mapping_occurrence_counter_scratch_data,
    native_import18_prebirth_recipe_construction_transient_data,
    native_import18_prebirth_recipe_counter_scratch_data,
    native_import18_recipe_identity_construction_data,
    native_import18_recipe_identity_counter_scratch_data,
    native_import18_recipe_inputs_counter_scratch_data, native_import18_reference_identity_data,
};
pub use receipt::{
    PacketNativeImport18ReceiptContextData, native_import18_commit_receipt_data,
    native_import18_prepare_receipt_data, verify_native_import18_commit_receipt_data,
    verify_native_import18_prepare_receipt_data,
};

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import18::definitions::NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA;

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import18::definitions::NATIVE_IMPORT18_EXTENSION;
/// Preserves the independently enforced binding extent from the original family.
pub const MAXIMUM_NATIVE_IMPORT18_BINDING_BYTES: usize = 4096;

/// Retains all additional full-reference and geometry bindings for Native17.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18Binding {
    /// Selects exactly [`NATIVE_IMPORT18_EXTENSION`].
    pub schema: String,
    /// Hashes the complete canonical inert Prepare payload, including allocation.
    pub prepare_digest: Bytes,
    /// Selects the native Snapshot grammar independently of the Source family.
    pub native_family: PacketNativeImport18NativeFamily,
    /// Names the actual complete before body embedded by that Snapshot.
    pub native_before: ContentRef,
    /// Names the actual independently decoded Controller17 root.
    pub controller17: ContentRef,
    /// Selects the actual captured Source body grammar explicitly.
    pub source_family: PacketNativeImport18SourceFamily,
    /// Names the actual complete captured semantic body.
    pub source17: ContentRef,
    /// Names that Source's actual Node25 proof body.
    pub node25: ContentRef,
    /// Binds the defining geometry's complete role/limit correspondence identity.
    pub geometry_identity: Bytes,
    /// Retains exact body lengths in Snapshot, after, Control, anchor, Journal order.
    pub role_extents: [U64; 5],
    /// Retains actual independent reader and typed target limits.
    pub limits: PacketNativeImport17Limits,
    /// Names the actual full normalization bank also bound by Prepare.
    pub normalization: ContentRef,
    /// Retains its original independent maximum without renewal.
    pub normalization_maximum: U64,
    /// Selects this independent seventh body grammar explicitly.
    pub semantic_spend_family: PacketNativeImport18SemanticSpendFamily,
    /// Names the separate actual Source/Node/Runtime semantic-spend body.
    ///
    /// This seventh bank preserves used logical IDs and pending associations;
    /// it is independent of old-session reply caches and the normalization cap.
    pub semantic_spend: ContentRef,
    /// Bounds the actual seventh bank under its independent original row.
    pub semantic_spend_maximum: U64,
}

fn bounded(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, ProviderError> {
    crate::connection::serialized_credit(value, maximum)?;
    let value = serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?;
    let encoded = canonical::canonical_json(&value)?;
    if encoded.len() > maximum {
        return Err(invalid());
    }
    Ok(encoded)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("complete import18 DATA correspondence")
}

fn digest32(value: &Bytes) -> Result<&[u8; 32], ProviderError> {
    value.as_slice().try_into().map_err(|_| invalid())
}

fn same_digest(left: &[u8], right: &[u8]) -> Result<(), ProviderError> {
    if left.len() != 32 || right.len() != 32 || left != right {
        return Err(invalid());
    }
    Ok(())
}

pub use private_prefix::{
    NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES, PacketNativeImport18PrivatePrefixData,
    decode_native_import18_private_prefix_data, encode_native_import18_private_prefix_data,
    native_import18_private_prefix_construction_transient_data,
    native_import18_private_prefix_counter_scratch_data,
};

pub use launch_identity::{
    PacketNativeImport18LaunchIdentityData, derive_native_import18_launch_identity_data,
    native_import18_launch_identity_construction_data,
    native_import18_launch_identity_counter_scratch_data, native_import18_launch_identity_data,
    native_import18_launch_identity_projection_data,
};
pub use record_contract::{
    authenticate_native_import18_restored_record_schema_data,
    native_import18_restored_record_contract_counter_scratch_data,
    native_import18_restored_record_contract_data,
    native_import18_restored_record_contract_storage_data,
    native_import18_restored_record_schema_data,
};
pub use restored_record::{
    PacketNativeImport18CommitHeldRecordData, PacketNativeImport18FirstObservedRecordData,
    PacketNativeImport18RecordPairData, PacketNativeImport18RecordScopeData,
    PacketNativeImport18RestoredRecordData,
};
pub use selection::{
    PacketNativeImport18Selection, authenticate_native_import18_immutable_declaration_data,
    native_import18_declared_features_data, native_import18_selection_construction_storage_data,
    native_import18_selection_counter_scratch_data, native_import18_selection_prewalk_data,
};
pub use stage_contract::{
    NATIVE_IMPORT18_STAGE_SELECTION, authenticate_native_import18_stage_schema_data,
    native_import18_stage_contract_counter_scratch_data, native_import18_stage_contract_data,
    native_import18_stage_contract_storage_data, native_import18_stage_schema_data,
};

pub(in crate::reference_packet) use prebirth_recipe::projection::{
    digest as native_import18_recipe_identity_projection_data,
    native_import18_initial_row_projection_data, native_import18_prebirth_recipe_projection_data,
    native_import18_prebirth_recipe_serialization_data,
    native_import18_recipe_projection_counter_scratch_data,
};

pub use crate::reference_packet::service::ack_emitter::native_boot::{
    native_import18_receiving_bank_backing_construction_data,
    native_import18_receiving_bank_backing_counter_scratch_data,
};

pub use initial_funding::{
    PacketNativeImport18InitialFundingData, PacketNativeImport18InitialFundingInputs,
    derive_native_import18_initial_funding_data,
    native_import18_initial_funding_construction_transient_data,
    native_import18_initial_funding_counter_scratch_data,
    native_import18_initial_funding_producer_construction_data,
    native_import18_initial_funding_producer_counter_scratch_data,
    native_import18_initial_funding_producer_projection_data,
};

// This borrowed DATA preserves all partial initial-result operands.
pub use initial_funding::PacketNativeImport18InitialFundingHistoryData;

pub(in crate::reference_packet) use startup_wire::{
    InitialConstructionData, OriginalImport18DecodedBodies, OriginalImport18DecodedBodyLoans,
    PacketNativeImport18BootstrapTypedBirthView, authenticate_initial_headers_data,
    initial_construction_counter_scratch_data, initial_construction_from_wire_data,
    initial_construction_projection_data, initial_quote_formatter_data,
    private_body_decode_counter_scratch_data, private_body_owner_counter_scratch_data,
    source_authentication_construction_data, source_authentication_counter_scratch_data,
    source_authentication_projection_data, source_authentication_quote_construction_data,
};

pub use startup_wire::{
    NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA, PacketNativeImport18InitialConstructionData,
    PacketNativeImport18PrivateBootProjectionView, PacketNativeImport18PrivateBootWireData,
    PacketNativeImport18SelectedLaunchWireData, PacketNativeImport18SourceBindingView,
    PacketNativeImport18SourceBindingWireData, PacketNativeImport18SourceDeclarationView,
    PacketNativeImport18SourceDeclarationWireData,
    native_import18_initial_construction_counter_scratch_data,
    native_import18_initial_construction_data, native_import18_initial_quote_formatter_data,
    native_import18_private_boot_projection_wire_data, native_import18_private_boot_wire_data,
    native_import18_selected_launch_wire_data, native_import18_source_binding_wire_data,
    native_import18_source_declaration_bank_view_data,
    native_import18_source_declaration_counter_scratch_data,
    native_import18_source_declaration_encoding_construction_data,
    native_import18_source_declaration_encoding_counter_scratch_data,
    native_import18_source_declaration_wire_data,
    native_import18_startup_wire_construction_transient_data,
    native_import18_startup_wire_counter_scratch_data,
};

/// Defines the distinct model-absent bootstrap ACK vocabulary.
pub mod bootstrap_ack;

/// Owns the closed native Hello declaration and prospective identity DATA.
pub mod hello;
