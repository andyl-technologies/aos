//! Defines separately selected, source-signed complete restoration messages.
//!
//! Baseline `Begin/PrepareRestore` arguments and result remain unchanged. Three
//! registered envelope extensions bind the exact assigned request, signed archive,
//! fresh target and prepared historical mapping. These portable values and MAC
//! helpers issue no native token or installation permission.
//!
//! ```text
//! request: source-owned.packet-complete-restore/11
//! proof:   source-owned.packet-complete-restore-proof/11
//! receipt: source-owned.packet-complete-restore-receipt/11
//! ```

use crate::ProviderError;
use crucible_node_format::{
    Bytes, ContentRef, HashRef, Id, Position, SchemaRef, U64, Validate, canonical,
};
use serde::{Deserialize, Serialize};

mod commit_held;
pub use commit_held::{
    PacketNativeRestoredCommitHold, maximum_complete_restore_held_evidence_bytes,
    maximum_complete_restore_held_evidence_counter_scratch_data,
    restored_commit_hold_serialization_counter_scratch_data,
};
mod restored_record;
pub use restored_record::{
    PACKET_NATIVE_RESTORED_RECORD_FEATURE, PacketNativeRestoredRecord,
    native_restored_record_contract, native_restored_record_schema,
};

mod assigned;
mod contract;
mod crypto;
pub mod transfer;

/// Defines distinct signed Native17 import DATA without installing an owner.
pub mod import17;
/// Names successor complete-state identities without installing a reader or producer.
pub mod restored_settled18;

/// Defines the separately signed restoration activation contract and DATA.
pub mod activation;

/// Defines separately signed once observation after complete restored publication.
pub mod restoration_observe;

/// Validates progressed Producer evidence independently of historical held equality.
pub mod producer_progress;

pub use assigned::{
    complete_restore_assigned_request_digest, complete_restore_assigned_response_digest,
};
pub use contract::{
    complete_restore_contract, complete_restore_proof_schema, complete_restore_receipt_schema,
    complete_restore_request_schema,
};
pub use crypto::{
    complete_restore_proof_data, complete_restore_receipt_data, verify_complete_restore_proof_data,
    verify_complete_restore_receipt_data,
};

/// Names the separately negotiated complete restoration feature and request key.
pub const PACKET_COMPLETE_RESTORE_FEATURE: &str = "source-owned.packet-complete-restore/11";
/// Names the assigned request's proof extension.
pub const PACKET_COMPLETE_RESTORE_PROOF_EXTENSION: &str =
    "source-owned.packet-complete-restore-proof/11";
/// Names the actual completed response's receipt extension.
pub const PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION: &str =
    "source-owned.packet-complete-restore-receipt/11";
/// Names the distinct normalized restoration context grammar.
pub const PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA: &str =
    "source-owned.packet-complete-restore-context/11";
/// Names the keyed BLAKE3 construction, independently domain-separated from Admit.
pub const PACKET_COMPLETE_RESTORE_ALGORITHM: &str = "blake3-keyed-canonical/1";
/// Bounds the canonical request extension, independently of the enclosing frame.
pub const MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES: usize = 8192;
/// Bounds the canonical twelve-digest context and its charged scratch.
pub const MAXIMUM_COMPLETE_RESTORE_CONTEXT_BYTES: usize = 2048;
/// Bounds the canonical proof extension before assigning its original frame.
pub const MAXIMUM_COMPLETE_RESTORE_PROOF_BYTES: usize = 256;
/// Bounds the canonical completed receipt extension.
pub const MAXIMUM_COMPLETE_RESTORE_RECEIPT_BYTES: usize = 1024;

/// Selects the explicit complete restoration mechanism without granting authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketNative5CompleteRestoreSelection {
    /// Requires a current source-signed request and one-shot native installation.
    SourceSignedOwned11,
    /// Authenticates exact large-object preparation before the one-shot commit.
    SourceSignedTransfer12,
}

/// Binds one signed archive to one fresh target and prepared mapping.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreRequest {
    /// Names the exact registered request grammar.
    pub schema: String,
    /// Names the signed index3 artifact, loaded through complete admission.
    pub archive_index: ContentRef,
    /// Names the exact baseline capture manifest inside the signed archive.
    pub capture_manifest: ContentRef,
    /// Names this owner's complete archived state body.
    pub owner_state: ContentRef,
    /// Names the independently verified complete local settlement journal.
    pub journal: ContentRef,
    /// Names the original complete runtime object.
    pub source_runtime: ContentRef,
    /// Names the full measured backend implementation identity body.
    pub backend_implementation: ContentRef,
    /// Binds the exact installed backend schema and complete definition.
    pub backend_schema: SchemaRef,
    /// Locates the authenticated archived semantic cut.
    pub archived_cut: Position,
    /// Identifies the archived event ordinal at that cut.
    pub archived_ordinal: U64,
    /// Binds the exact fresh world's admitted binding hash.
    pub target_world: HashRef,
    /// Names the target capture owner.
    pub target_owner: Id,
    /// Binds the exact fresh owner binding.
    pub target_owner_binding: HashRef,
    /// Names the actual Core target activation.
    pub target_activation: Id,
    /// Identifies the fresh world generation.
    pub target_generation: U64,
    /// Identifies the fresh owner generation.
    pub target_owner_generation: U64,
    /// Names the full canonical SDK-prepared mapping normalization.
    pub mapping: ContentRef,
    /// Contains the exact source-owned mapping nonce, 32 decoded bytes.
    pub nonce: Bytes,
}

/// Carries twelve digests of independently retained original normalized inputs.
///
/// The first eight inputs use the canonical ACK admission role normalization,
/// except that `assigned_restore` hashes the actual assigned PrepareRestore
/// envelope with only the proof extension removed. Hello inputs hash the full
/// raw header and body with `source-owned.cnp-original-hello-frame/5`. Other
/// inputs use standard BLAKE3 over complete canonical bytes. Full owners remain
/// retained; digest equality never substitutes for those owners.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreContext {
    /// Names the exact context grammar.
    pub schema: String,
    /// Names the exact MAC construction.
    pub algorithm: String,
    /// Binds the freshly issued source birth body.
    pub source_birth: Bytes,
    /// Binds both actual kernel identities and measured executables.
    pub kernel_binding: Bytes,
    /// Binds the complete installed selected policy and backend tuple.
    pub policy_binding: Bytes,
    /// Binds the actual host registration.
    pub host_registration: Bytes,
    /// Binds the actual native registration.
    pub native_registration: Bytes,
    /// Binds the original literal Hello request.
    pub hello_request: Bytes,
    /// Binds the original literal Hello response.
    pub hello_response: Bytes,
    /// Binds the exact assigned request, sequence and request extension.
    pub assigned_restore: Bytes,
    /// Binds the closed archive projection generated by the shared helper.
    pub archive_binding: Bytes,
    /// Binds the closed target projection generated by the shared helper.
    pub target_binding: Bytes,
    /// Binds the full canonical SDK-prepared mapping bytes.
    pub mapping_binding: Bytes,
    /// Binds the complete canonical request extension.
    pub request_binding: Bytes,
}

/// Contains inert proof data for one exact assigned restore request.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreProof {
    /// Names the registered proof grammar.
    pub schema: String,
    /// Names the exact MAC construction.
    pub algorithm: String,
    /// Hashes the complete twelve-digest canonical context.
    pub context_digest: Bytes,
    /// Contains the 32-byte request MAC.
    pub mac: Bytes,
}

/// Binds a completed native installation to its actual assigned response.
///
/// The response digest covers the actual sequence and complete response envelope
/// with only this receipt extension removed. Its original response slot must be
/// retained before any installation effects; no predicted counter is accepted.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCompleteRestoreReceipt {
    /// Names the registered completed receipt grammar.
    pub schema: String,
    /// Names the exact MAC construction.
    pub algorithm: String,
    /// Hashes the full canonical request extension.
    pub request_digest: Bytes,
    /// Hashes the complete canonical restoration context.
    pub context_digest: Bytes,
    /// Names the exact mapping consumed by the native installer.
    pub installed_mapping: ContentRef,
    /// Records the actual assigned native response sequence.
    pub native_sequence: U64,
    /// Hashes the full assigned response with only this receipt removed.
    pub assigned_response: Bytes,
    /// Contains the separately domain-separated 32-byte receipt MAC.
    pub mac: Bytes,
}

/// Contains inert archive, target, mapping and request digest projections.
pub struct PacketCompleteRestoreBindings {
    /// Hashes the complete archive projection.
    pub archive_binding: Bytes,
    /// Hashes the complete target projection.
    pub target_binding: Bytes,
    /// Hashes the canonical prepared mapping bytes after reference verification.
    pub mapping_binding: Bytes,
    /// Hashes the complete canonical request extension.
    pub request_binding: Bytes,
}

impl PacketCompleteRestoreRequest {
    /// Checks the closed request and finite canonical extent.
    ///
    /// # Errors
    /// Refuses a foreign schema, invalid nested values, wrong nonce length or
    /// an extension larger than the fixed selected request bound.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_COMPLETE_RESTORE_FEATURE || self.nonce.as_slice().len() != 32 {
            return Err(ProviderError::Correlation(
                "complete restore request syntax",
            ));
        }
        for reference in [
            &self.archive_index,
            &self.capture_manifest,
            &self.owner_state,
            &self.journal,
            &self.source_runtime,
            &self.backend_implementation,
            &self.mapping,
        ] {
            reference.validate()?;
        }
        self.backend_schema.validate()?;
        self.archived_cut.validate()?;
        self.target_world.validate()?;
        self.target_owner_binding.validate()?;
        self.target_owner.validate()?;
        self.target_activation.validate()?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES)?;
        Ok(())
    }

    /// Derives the four exact data projections after checking mapping bytes.
    ///
    /// The caller retains the actual SDK mapping and full source/target bodies.
    /// This helper verifies referenced bytes and syntax, not Core authority.
    ///
    /// # Errors
    /// Refuses invalid request data, another mapping body or serialization errors.
    pub fn context_bindings(
        &self,
        canonical_mapping: &[u8],
    ) -> Result<PacketCompleteRestoreBindings, ProviderError> {
        self.validate_data()?;
        self.mapping.verify(canonical_mapping)?;
        let archive = serde_json::json!({
            "schema":"source-owned.packet-complete-restore-archive-binding/11",
            "archive_index":self.archive_index,"capture_manifest":self.capture_manifest,"owner_state":self.owner_state,
            "journal":self.journal,"source_runtime":self.source_runtime,
            "backend_implementation":self.backend_implementation,"backend_schema":self.backend_schema,
            "archived_cut":self.archived_cut,"archived_ordinal":self.archived_ordinal
        });
        let target = serde_json::json!({
            "schema":"source-owned.packet-complete-restore-target-binding/11",
            "world":self.target_world,"owner":self.target_owner,
            "owner_binding":self.target_owner_binding,"activation":self.target_activation,
            "generation":self.target_generation,"owner_generation":self.target_owner_generation,
            "nonce":self.nonce
        });
        Ok(PacketCompleteRestoreBindings {
            archive_binding: digest(&canonical::canonical_json(&archive)?),
            target_binding: digest(&canonical::canonical_json(&target)?),
            mapping_binding: digest(canonical_mapping),
            request_binding: digest(&bounded_canonical(
                self,
                MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES,
            )?),
        })
    }
}

impl PacketCompleteRestoreContext {
    /// Checks the fixed context grammar and digest lengths.
    ///
    /// # Errors
    /// Refuses a foreign schema, algorithm or non-32-byte input digest.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
            || [
                &self.source_birth,
                &self.kernel_binding,
                &self.policy_binding,
                &self.host_registration,
                &self.native_registration,
                &self.hello_request,
                &self.hello_response,
                &self.assigned_restore,
                &self.archive_binding,
                &self.target_binding,
                &self.mapping_binding,
                &self.request_binding,
            ]
            .iter()
            .any(|value| value.as_slice().len() != 32)
        {
            return Err(ProviderError::Correlation(
                "complete restore context syntax",
            ));
        }
        Ok(())
    }

    /// Checks all request-derived projections against the actual mapping bytes.
    ///
    /// # Errors
    /// Refuses changed archive, target, mapping or request digest correspondence.
    pub fn authenticate_request_bindings_data(
        &self,
        request: &PacketCompleteRestoreRequest,
        canonical_mapping: &[u8],
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        let bindings = request.context_bindings(canonical_mapping)?;
        for (actual, expected) in [
            (&self.archive_binding, &bindings.archive_binding),
            (&self.target_binding, &bindings.target_binding),
            (&self.mapping_binding, &bindings.mapping_binding),
            (&self.request_binding, &bindings.request_binding),
        ] {
            let expected: [u8; 32] = expected.as_slice().try_into().map_err(|_| {
                ProviderError::Correlation("complete restore binding digest length")
            })?;
            if blake3::Hash::from_bytes(expected) != *actual.as_slice() {
                return Err(ProviderError::Correlation(
                    "complete restore request projections",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, ProviderError> {
        self.validate_data()?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_CONTEXT_BYTES)
    }
}

impl PacketCompleteRestoreProof {
    /// Checks proof data without issuing an installation token.
    ///
    /// # Errors
    /// Refuses a foreign schema, algorithm, digest length or excessive extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_COMPLETE_RESTORE_PROOF_EXTENSION
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
            || self.context_digest.as_slice().len() != 32
            || self.mac.as_slice().len() != 32
        {
            return Err(ProviderError::Correlation("complete restore proof syntax"));
        }
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_PROOF_BYTES)?;
        Ok(())
    }
}

impl PacketCompleteRestoreReceipt {
    /// Checks completed receipt data without asserting installation success.
    ///
    /// # Errors
    /// Refuses a foreign grammar, invalid reference, wrong digest lengths or extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
            || [
                &self.request_digest,
                &self.context_digest,
                &self.assigned_response,
                &self.mac,
            ]
            .iter()
            .any(|value| value.as_slice().len() != 32)
        {
            return Err(ProviderError::Correlation(
                "complete restore receipt syntax",
            ));
        }
        self.installed_mapping.validate()?;
        bounded_canonical(self, MAXIMUM_COMPLETE_RESTORE_RECEIPT_BYTES)?;
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> Bytes {
    Bytes::new(blake3::hash(bytes).as_bytes().to_vec())
}

fn bounded_canonical(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, ProviderError> {
    let value = serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?;
    let encoded = canonical::canonical_json(&value)?;
    if encoded.len() > maximum {
        return Err(ProviderError::ResourceExhausted(
            "complete restore canonical extent",
        ));
    }
    Ok(encoded)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These closed data controls intentionally panic on failed fixture invariants.
#[allow(clippy::unwrap_used)]
mod tests;

#[path = "complete_restore/selected.rs"]
mod selected;
pub use selected::{
    complete_restore_selected_contracts, complete_restore_selected_envelope_extensions,
    complete_restore_selected_features, complete_restore_selected_schemas,
};

#[path = "complete_restore/input_emitter.rs"]
pub mod input_emitter;
pub use input_emitter::{
    PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, PacketNative5RestoreInputEmitterSelection,
    canonical_restore_inputs_contract, canonical_restore_inputs_schema,
};

pub(crate) use contract::complete_restore_contract_storage_data;
pub(crate) use restored_record::native_restored_record_contract_storage_data;

/// Defines the closed immutable settled17 declaration and output policy DATA.
pub mod settled_recapture;

pub(crate) use input_emitter::canonical_restore_inputs_contract_storage_data;

/// Defines the explicit successor import DATA without widening import17.
pub mod import18;
