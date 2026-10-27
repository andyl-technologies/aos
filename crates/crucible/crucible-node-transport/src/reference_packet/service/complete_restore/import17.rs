//! Binds explicit Native17 import DATA to one actual assigned fresh transaction.
//!
//! This family retains the existing Prepare/Commit DTOs as inert payloads but
//! uses distinct extension, context, proof and receipt domains. Old transfer12
//! envelope guards remain unchanged. A proof comparison issues no lease, model,
//! socket, physical hold, Source permission or released World.
//!
//! ```text
//! extensions = { phase_request12: payload, native_import17: binding,
//!                phase_proof17: proof }
//! ```
//!
//! A Source producer must first consume its genuine completed cold/factory/
//! parent/Window conjunction and independently admit construction. The native
//! owner must separately validate all historical bodies, retain its once-only
//! input/model custody and complete actual installation and activation. This
//! module does not open either producer or native dispatcher.

use super::transfer::{
    PacketCompleteRestoreCommitContext, PacketCompleteRestoreCommitRequest,
    PacketCompleteRestorePrepareContext, PacketCompleteRestorePrepareRequest,
    PacketCompleteRestoreTransferPhase,
};
use super::*;
use crate::envelope::Envelope;
use crucible_node_format::ContractError;

mod assigned;
mod binding;
mod context;
mod contract;
mod crypto;
mod prebirth_contract;
mod receipt;
/// Defines finite original stage labels and key domains without native authorization.
pub mod stage;
pub use prebirth_contract::{
    NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN, NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC,
    NATIVE_IMPORT17_STARTUP_WRAPPER_VERSION,
};

#[cfg(test)]
mod tests;

pub use assigned::{
    native_import17_assigned_request_digest, native_import17_assigned_response_digest,
};
pub use contract::{
    authenticate_native_import17_schema_data, native_import17_contract_counter_scratch_data,
    native_import17_contract_storage_data, native_import17_schema_data,
};
pub use crypto::{native_import17_proof_data, verify_native_import17_proof_data};
pub use receipt::{
    PacketNativeImport17CommitReceipt, PacketNativeImport17PrepareReceipt,
    PacketNativeImportReceiptAssignmentData, native_import17_commit_receipt_data,
    native_import17_prepare_receipt_data, verify_native_import17_commit_receipt_data,
    verify_native_import17_prepare_receipt_data,
};

/// Names the independently selected full import contract and binding extension.
pub const NATIVE_IMPORT17_EXTENSION: &str = "source-owned.packet-native-import/17";
/// Bounds the closed binding, independently of the actual negotiated frame.
pub const MAXIMUM_NATIVE_IMPORT17_BINDING_BYTES: usize = 4096;
/// Bounds the complete phase context, independently of older context ceilings.
pub const MAXIMUM_NATIVE_IMPORT17_CONTEXT_BYTES: usize = 4096;
/// Bounds a distinct phase proof before it enters an assigned Envelope.
pub const MAXIMUM_NATIVE_IMPORT17_PROOF_BYTES: usize = 512;
/// Bounds the exact same-phase receipt without enlarging an older family.
pub const MAXIMUM_NATIVE_IMPORT17_RECEIPT_BYTES: usize = 1024;

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import17::PacketNativeImport17Phase;

/// Retains exact independent reader limits without creating an allocation grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17Limits {
    /// Bounds Snapshot, after, Control, anchor and Journal in that exact order.
    pub role_maximums: [U64; 5],
    /// Bounds external immutable object count independently of native aliases.
    pub immutable_objects: U64,
    /// Bounds independently verified immutable body bytes.
    pub immutable_bytes: U64,
    /// Bounds the actual archive traversal depth, at most sixty-four.
    pub immutable_depth: U64,
    /// Bounds strict native parser nodes independently of raw byte capacity.
    pub maximum_nodes: U64,
    /// Retains the exact original raw/bank constructor ceiling.
    pub maximum_requested_bytes: U64,
    /// Bounds the independently admitted selected typed target construction.
    pub maximum_target_requested_bytes: U64,
    /// Bounds the complete embedded before graph independently of Snapshot.
    pub maximum_before_bytes: U64,
}

/// Retains all additional full-reference and geometry bindings for Native17.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17Binding {
    /// Selects exactly [`NATIVE_IMPORT17_EXTENSION`].
    pub schema: String,
    /// Hashes the complete canonical inert Prepare payload, including allocation.
    pub prepare_digest: Bytes,
    /// Names the actual complete before body embedded by the Snapshot17.
    pub native_before: ContentRef,
    /// Names the actual independently decoded Controller17 root.
    pub controller17: ContentRef,
    /// Names the actual Source17 body from the completed cold group.
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
}

/// Retains an actual phase's complete independently derived peer context.
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "phase",
    content = "context",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PacketNativeImport17PeerContext {
    /// Retains original birth/kernel/policy/Hello/roster bindings for Prepare.
    Prepare(PacketCompleteRestorePrepareContext),
    /// Retains completed Prepare, full normalization and Commit bindings.
    Commit(PacketCompleteRestoreCommitContext),
}

/// Binds the full import payload and same actual assignment to a peer context.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17Context {
    /// Selects the distinct Native17 phase context grammar.
    pub schema: String,
    /// Selects the existing keyed canonical construction with a new key domain.
    pub algorithm: String,
    /// Retains the actual independently recomputed native peer bindings.
    pub peer: PacketNativeImport17PeerContext,
    /// Hashes every canonical field of the additional import binding.
    pub import_binding_digest: Bytes,
    /// Hashes the full same assigned Envelope after removing only its new proof.
    pub assigned_original_digest: Bytes,
}

/// Carries phase-specific inert proof bytes without creating a native token.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17Proof {
    /// Selects exactly the corresponding distinct phase proof extension.
    pub schema: String,
    /// Names the canonical keyed construction.
    pub algorithm: String,
    /// Hashes the full canonical independently derived Native17 context.
    pub context_digest: Bytes,
    /// Retains the thirty-two-byte phase-specific keyed output.
    pub mac: Bytes,
}

fn bounded(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, ProviderError> {
    crate::connection::serialized_credit(value, maximum)?;
    let value = serde_json::to_value(value).map_err(ContractError::from)?;
    let encoded = canonical::canonical_json(&value)?;
    if encoded.len() > maximum {
        return Err(invalid());
    }
    Ok(encoded)
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

fn invalid() -> ProviderError {
    ProviderError::Correlation("complete Native17 import DATA correspondence")
}
