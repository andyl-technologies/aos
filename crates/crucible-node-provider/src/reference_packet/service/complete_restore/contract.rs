//! Registers the distinct complete restoration wire and cryptographic contract.

use super::*;

/// Encodes the complete immutable selected restore contract.
///
/// # Errors
/// Reports canonical specification encoding failure.
pub fn complete_restore_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-complete-restore-contract/11",
        "feature":PACKET_COMPLETE_RESTORE_FEATURE,
        "selection":"closed optional SourceSignedOwned11; absent selection preserves existing bytes and routes; selected Owned11 alone is not this installation selection",
        "request_extension":PACKET_COMPLETE_RESTORE_FEATURE,
        "proof_extension":PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
        "receipt_extension":PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
        "method":"Begin/PrepareRestore; baseline arguments and PrepareRestoreResult unchanged; baseline transaction, manifest, world, owner and destination roster must equal source authenticated context and prepared mapping",
        "request_fields":["schema","archive_index","capture_manifest","owner_state","journal","source_runtime","backend_implementation","backend_schema","archived_cut","archived_ordinal","target_world","target_owner","target_owner_binding","target_activation","target_generation","target_owner_generation","mapping","nonce"],
        "request_bound":MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES,
        "context_schema":PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA,
        "context_fields":["schema","algorithm","source_birth","kernel_binding","policy_binding","host_registration","native_registration","hello_request","hello_response","assigned_restore","archive_binding","target_binding","mapping_binding","request_binding"],
        "context_bound":MAXIMUM_COMPLETE_RESTORE_CONTEXT_BYTES,
        "digest":"each digest is 32 decoded bytes; source_birth/kernel_binding/policy_binding/registrations use BLAKE3 of retained complete canonical role-normalized bodies as canonical ACK admission; Hello uses derive_key(source-owned.cnp-original-hello-frame/5,full original header+body); assigned_restore is BLAKE3 of full canonical SDK assigned request including sequence and request extension, removing ONLY proof extension",
        "archive_binding":"BLAKE3 canonical closed archive projection from context_bindings: schema source-owned.packet-complete-restore-archive-binding/11 and exact archive_index,capture_manifest,owner_state,journal,source_runtime,backend_implementation,backend_schema,archived_cut,archived_ordinal",
        "target_binding":"BLAKE3 canonical closed target projection from context_bindings: schema source-owned.packet-complete-restore-target-binding/11 and exact world,owner,owner_binding,activation,generation,owner_generation,nonce",
        "mapping_binding":"BLAKE3 of actual SDK PreparedArchivedProtocolMapping full canonical normalization_view after full request.mapping ContentRef verification; full refs, complete classes, fresh actual authority and nonce are independently checked",
        "request_binding":"BLAKE3 of entire canonical PacketCompleteRestoreRequest extension",
        "algorithm":PACKET_COMPLETE_RESTORE_ALGORITHM,
        "request_mac":"K=blake3.derive_key(source-owned.packet-complete-restore-key/11,fresh32Bbirthkey); mac=blake3.keyed_hash(K,complete canonical context); context_digest=blake3.hash(context)",
        "proof_bound":MAXIMUM_COMPLETE_RESTORE_PROOF_BYTES,
        "receipt_mac":"separate K=blake3.derive_key(source-owned.packet-complete-restore-receipt-key/11,fresh32Bbirthkey); keyed_hash over closed ReceiptMacInput schema source-owned.packet-complete-restore-receipt-input/11,algorithm,request_digest,context_digest,installed_mapping,native_sequence,assigned_response; assigned_response hashes actual full canonical assigned response removing ONLY receipt extension",
        "receipt_bound":MAXIMUM_COMPLETE_RESTORE_RECEIPT_BYTES,
        "source_issuer":"actual complete selected archive loader receipt, full signed Core source/native ticket and owner-linked closure, exact semantic and literal Capture/three ACKed bodies/terminal/native after/fourth Poll and host complete state, source-installed backend full identity, actual fresh Core target context and target controller mapping must all authenticate before source signs; parsed data or an old live Source is insufficient",
        "native_issuer":"same genuine fresh boot key, current kernel/Hello/registration/policy and exact assigned incoming request; retain original request and prepared mapping before validation; spend original one-shot slot before first installation effect; private token has no public DTO constructor",
        "success":"receipt only after mechanical installation and correspondence checks; retain assigned actual response before effects; host verifies exact correlated original response plus real source/Core target checks; no success from portable receipt alone",
        "failure":"partial IO, proof/signing/install/refusal/unwind retains same original key, request, frame banks, mapping, offsets and cut; no reassignment, retry, spent-flag reset or deadline renewal",
        "freshness":"historical key/proofs/registrations remain inert archived data, never overwrite or activate fresh current guards; new world/key/activation/generation/mapping/nonce bind independently; a second restoration needs a separately admitted archive source, tickets and fresh boot",
        "ownership":"all full bodies, actual capacities, aliases, keys, proof/context scratch and partial installation owners are precharged; hashes confer no allocation identity or dedup credit; no physical tree/controlblock/stack accounting claim from serialized extent",
        "boundary":"no Rust layout, pointer, callback or trait object crosses the process boundary; only explicitly versioned portable protocol values"
    }))?)
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
