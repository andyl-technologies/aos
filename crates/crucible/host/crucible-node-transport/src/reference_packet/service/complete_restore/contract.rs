//! Registers the distinct complete restoration wire and cryptographic contract.

use super::*;

/// Encodes the complete immutable selected restore contract.
///
/// # Errors
/// Reports canonical specification encoding failure.
pub fn complete_restore_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(CompleteRestoreContractValue)
            .map_err(crucible_node_format::ContractError::from)?,
    )?)
}

fn schema(id: &str) -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(id)?,
        version: 11,
        definition: canonical::content_ref(&complete_restore_contract()?, "application/json")?,
        extensions: Default::default(),
    })
}

/// Names the exact registered restore request and complete definition.
///
/// # Errors
/// Reports invalid identifier or canonical contract encoding failure.
pub fn complete_restore_request_schema() -> Result<SchemaRef, ProviderError> {
    schema(PACKET_COMPLETE_RESTORE_FEATURE)
}

/// Names the exact registered request proof and complete definition.
///
/// # Errors
/// Reports invalid identifier or canonical contract encoding failure.
pub fn complete_restore_proof_schema() -> Result<SchemaRef, ProviderError> {
    schema(PACKET_COMPLETE_RESTORE_PROOF_EXTENSION)
}

/// Names the exact registered response receipt and complete definition.
///
/// # Errors
/// Reports invalid identifier or canonical contract encoding failure.
pub fn complete_restore_receipt_schema() -> Result<SchemaRef, ProviderError> {
    schema(PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION)
}

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.
struct CompleteRestoreContractValue;

impl serde::Serialize for CompleteRestoreContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-complete-restore-contract/11"),
            ),
            ("feature", V::Text(PACKET_COMPLETE_RESTORE_FEATURE)),
            (
                "selection",
                V::Text(
                    "closed optional SourceSignedOwned11; absent selection preserves existing bytes and routes; selected Owned11 alone is not this installation selection",
                ),
            ),
            (
                "request_extension",
                V::Text(PACKET_COMPLETE_RESTORE_FEATURE),
            ),
            (
                "proof_extension",
                V::Text(PACKET_COMPLETE_RESTORE_PROOF_EXTENSION),
            ),
            (
                "receipt_extension",
                V::Text(PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION),
            ),
            (
                "method",
                V::Text(
                    "Begin/PrepareRestore; baseline arguments and PrepareRestoreResult unchanged; baseline transaction, manifest, world, owner and destination roster must equal source authenticated context and prepared mapping",
                ),
            ),
            (
                "request_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("archive_index"),
                    V::Text("capture_manifest"),
                    V::Text("owner_state"),
                    V::Text("journal"),
                    V::Text("source_runtime"),
                    V::Text("backend_implementation"),
                    V::Text("backend_schema"),
                    V::Text("archived_cut"),
                    V::Text("archived_ordinal"),
                    V::Text("target_world"),
                    V::Text("target_owner"),
                    V::Text("target_owner_binding"),
                    V::Text("target_activation"),
                    V::Text("target_generation"),
                    V::Text("target_owner_generation"),
                    V::Text("mapping"),
                    V::Text("nonce"),
                ]),
            ),
            (
                "request_bound",
                V::Number(MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES as u64),
            ),
            (
                "context_schema",
                V::Text(PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA),
            ),
            (
                "context_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("algorithm"),
                    V::Text("source_birth"),
                    V::Text("kernel_binding"),
                    V::Text("policy_binding"),
                    V::Text("host_registration"),
                    V::Text("native_registration"),
                    V::Text("hello_request"),
                    V::Text("hello_response"),
                    V::Text("assigned_restore"),
                    V::Text("archive_binding"),
                    V::Text("target_binding"),
                    V::Text("mapping_binding"),
                    V::Text("request_binding"),
                ]),
            ),
            (
                "context_bound",
                V::Number(MAXIMUM_COMPLETE_RESTORE_CONTEXT_BYTES as u64),
            ),
            (
                "digest",
                V::Text(
                    "each digest is 32 decoded bytes; source_birth/kernel_binding/policy_binding/registrations use BLAKE3 of retained complete canonical role-normalized bodies as canonical ACK admission; Hello uses derive_key(source-owned.cnp-original-hello-frame/5,full original header+body); assigned_restore is BLAKE3 of full canonical SDK assigned request including sequence and request extension, removing ONLY proof extension",
                ),
            ),
            (
                "archive_binding",
                V::Text(
                    "BLAKE3 canonical closed archive projection from context_bindings: schema source-owned.packet-complete-restore-archive-binding/11 and exact archive_index,capture_manifest,owner_state,journal,source_runtime,backend_implementation,backend_schema,archived_cut,archived_ordinal",
                ),
            ),
            (
                "target_binding",
                V::Text(
                    "BLAKE3 canonical closed target projection from context_bindings: schema source-owned.packet-complete-restore-target-binding/11 and exact world,owner,owner_binding,activation,generation,owner_generation,nonce",
                ),
            ),
            (
                "mapping_binding",
                V::Text(
                    "BLAKE3 of actual SDK PreparedArchivedProtocolMapping full canonical normalization_view after full request.mapping ContentRef verification; full refs, complete classes, fresh actual authority and nonce are independently checked",
                ),
            ),
            (
                "request_binding",
                V::Text("BLAKE3 of entire canonical PacketCompleteRestoreRequest extension"),
            ),
            ("algorithm", V::Text(PACKET_COMPLETE_RESTORE_ALGORITHM)),
            (
                "request_mac",
                V::Text(
                    "K=blake3.derive_key(source-owned.packet-complete-restore-key/11,fresh32Bbirthkey); mac=blake3.keyed_hash(K,complete canonical context); context_digest=blake3.hash(context)",
                ),
            ),
            (
                "proof_bound",
                V::Number(MAXIMUM_COMPLETE_RESTORE_PROOF_BYTES as u64),
            ),
            (
                "receipt_mac",
                V::Text(
                    "separate K=blake3.derive_key(source-owned.packet-complete-restore-receipt-key/11,fresh32Bbirthkey); keyed_hash over closed ReceiptMacInput schema source-owned.packet-complete-restore-receipt-input/11,algorithm,request_digest,context_digest,installed_mapping,native_sequence,assigned_response; assigned_response hashes actual full canonical assigned response removing ONLY receipt extension",
                ),
            ),
            (
                "receipt_bound",
                V::Number(MAXIMUM_COMPLETE_RESTORE_RECEIPT_BYTES as u64),
            ),
            (
                "source_issuer",
                V::Text(
                    "actual complete selected archive loader receipt, full signed Core source/native ticket and owner-linked closure, exact semantic and literal Capture/three ACKed bodies/terminal/native after/fourth Poll and host complete state, source-installed backend full identity, actual fresh Core target context and target controller mapping must all authenticate before source signs; parsed data or an old live Source is insufficient",
                ),
            ),
            (
                "native_issuer",
                V::Text(
                    "same genuine fresh boot key, current kernel/Hello/registration/policy and exact assigned incoming request; retain original request and prepared mapping before validation; spend original one-shot slot before first installation effect; private token has no public DTO constructor",
                ),
            ),
            (
                "success",
                V::Text(
                    "receipt only after mechanical installation and correspondence checks; retain assigned actual response before effects; host verifies exact correlated original response plus real source/Core target checks; no success from portable receipt alone",
                ),
            ),
            (
                "failure",
                V::Text(
                    "partial IO, proof/signing/install/refusal/unwind retains same original key, request, frame banks, mapping, offsets and cut; no reassignment, retry, spent-flag reset or deadline renewal",
                ),
            ),
            (
                "freshness",
                V::Text(
                    "historical key/proofs/registrations remain inert archived data, never overwrite or activate fresh current guards; new world/key/activation/generation/mapping/nonce bind independently; a second restoration needs a separately admitted archive source, tickets and fresh boot",
                ),
            ),
            (
                "ownership",
                V::Text(
                    "all full bodies, actual capacities, aliases, keys, proof/context scratch and partial installation owners are precharged; hashes confer no allocation identity or dedup credit; no physical tree/controlblock/stack accounting claim from serialized extent",
                ),
            ),
            (
                "boundary",
                V::Text(
                    "no Rust layout, pointer, callback or trait object crosses the process boundary; only explicitly versioned portable protocol values",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

pub(crate) fn complete_restore_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &CompleteRestoreContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}
