//! Defines closed held-Commit and first-observed record18 DATA.
//!
//! ```text
//! {kind: commit_held, schema, scope, commit, context_digest,
//!  local_cursor, inventory_hash, physical_gate_held: true}
//! {kind: first_observed, schema, scope, commit, arm, world,
//!  observe, native_record, physical_gate_held: false}
//! ```
//!
//! Each current request is named before its carrying response exists. Only
//! preceding phases have completed pairs. Deserialization and validation create
//! no current native model, same-World release, Source witness or phase credit.

use super::super::activation::PacketRestorationActivationTarget;
use super::*;
use crucible_node_format::{HashRef, Position};

mod retained;
mod validation;

#[cfg(test)]
mod tests;

/// Retains the complete original and terminal references of a preceding SDK phase.
///
/// Actual assignment, correlation, literal completion, proof and receipt
/// authentication remain the live issuer and consumer's independent duties.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18RecordPairData {
    /// Names the actual assigned complete original request, including its proof.
    pub original: ContentRef,
    /// Names the actual correlated complete terminal response and receipt.
    pub terminal: ContentRef,
}

/// Retains common immutable correspondence for both separate record18 kinds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18RecordScopeData {
    /// Binds the complete fresh target without rewriting captured historical IDs.
    pub target: PacketRestorationActivationTarget,
    /// Names the same complete original SourceBinding18 body.
    pub source_birth: ContentRef,
    /// Names the completed model-absent bootstrap ACK request and response.
    pub bootstrap: PacketNativeImport18RecordPairData,
    /// Binds the exact independently reconstructed immutable recipe identity.
    pub recipe_identity: Bytes,
    /// Names the full original import18 binding, including families and limits.
    pub import_binding: ContentRef,
    /// Retains the seven references in [`PacketNativeImport18InputRole::ALL`] order.
    pub inputs: [ContentRef; 7],
    /// Names the completed new18 Prepare pair, without implying model installation.
    pub prepare: PacketNativeImport18RecordPairData,
}

/// Retains nonrecursive evidence after actual Commit installation under a Hold.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18CommitHeldRecordData {
    /// Selects exactly [`NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA`].
    pub schema: String,
    /// Retains the same original bootstrap, target, recipe and seven-bank roster.
    pub scope: PacketNativeImport18RecordScopeData,
    /// Names the current assigned Commit request; its response does not yet exist.
    pub commit: ContentRef,
    /// Binds the exact verified Commit context, with 32 decoded bytes.
    pub context_digest: Bytes,
    /// Retains the captured local model cursor after unchanged-state installation.
    pub local_cursor: Position,
    /// Retains the captured complete logical inventory hash.
    pub inventory_hash: HashRef,
    /// Reports the separate current physical Hold and must be true for this kind.
    pub physical_gate_held: bool,
}

/// Retains evidence from the first real native observation after actual World release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18FirstObservedRecordData {
    /// Selects exactly [`NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA`].
    pub schema: String,
    /// Retains the same original bootstrap, target, recipe and seven-bank roster.
    pub scope: PacketNativeImport18RecordScopeData,
    /// Names the completed Commit pair, including held evidence and its receipt.
    pub commit: PacketNativeImport18RecordPairData,
    /// Names the completed same-target Arm pair made under the physical Hold.
    pub arm: PacketNativeImport18RecordPairData,
    /// Names the completed same-target World pair after actual publication/release.
    pub world: PacketNativeImport18RecordPairData,
    /// Names the current assigned first Observe request, without its carrying response.
    pub observe: ContentRef,
    /// Names the unchanged producer-two or reactive-four native proof body.
    pub native_record: ContentRef,
    /// Reports the separate released physical gate and must be false for this kind.
    pub physical_gate_held: bool,
}

/// Selects exactly one complete separate18 native evidence shape.
///
/// The kind cannot substitute for actual phase provenance. Old record editions,
/// mixed kind fields and extra carrying-response references refuse decoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PacketNativeImport18RestoredRecordData {
    /// Retains installed Commit evidence while the fresh physical Hold remains held.
    CommitHeld(PacketNativeImport18CommitHeldRecordData),
    /// Retains the first actual observation after the completed same-target World.
    FirstObserved(PacketNativeImport18FirstObservedRecordData),
}
