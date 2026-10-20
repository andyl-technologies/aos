//! Defines the distinct process-protocol contract independently of any live route.

use super::*;

const CONTRACT: &[u8] = br#"{
  "schema":"source-owned.packet-native-import-contract/17",
  "selection":"same complete SchemaRef in immutable provider and binding rosters plus negotiated feature and exact three-key phase extension set",
  "binding":["schema","prepare_digest","native_before","controller17","source17","node25","geometry_identity","role_extents","limits","normalization","normalization_maximum"],
  "limits":["role_maximums","immutable_objects","immutable_bytes","immutable_depth","maximum_nodes","maximum_requested_bytes","maximum_target_requested_bytes","maximum_before_bytes"],
  "role_order":["snapshot17","after17","control17","anchor5","journal17"],
  "input_bank_order":["after17","control17","anchor5","snapshot17","journal17","normalization"],
  "phase_payload":"unchanged Prepare12 or Commit12 DTO is inert nested vocabulary only",
  "phase_context":["schema","algorithm","peer","import_binding_digest","assigned_original_digest"],
  "assignment":"same SDK Envelope, complete header and body, exact request12/import17/proof17 extension keys; remove only the corresponding new17 proof for assigned digest",
  "proof":["schema","algorithm","context_digest","mac"],
  "proof_domains":["source-owned.packet-native-import-prepare-key/17","source-owned.packet-native-import-commit-key/17"],
  "prepare_receipt":["schema","algorithm","import_binding_digest","context_digest","prepare_digest","input_roster","transfer_token","generation","native_sequence","assigned_response","mac"],
  "commit_receipt":["schema","algorithm","import_binding_digest","context_digest","commit_digest","installed_mapping","transfer_token","native_sequence","assigned_response","mac"],
  "lease_domain":"source-owned.packet-native-import-transfer-token-key/17",
  "receipt_domains":["source-owned.packet-native-import-prepare-receipt-key/17","source-owned.packet-native-import-commit-receipt-key/17"],
  "source_conjunction":"genuine completed cold65 plus signed parents plus actual fresh Source factory and actual Window, target World/owner/generation and SDK once-assignment before signing",
  "native_conjunction":"actual fresh birth/current registration and once-only admitted input custody, strict five-role/native-before/SDK-journal/normalization validation, complete logical Control/model and spent ledgers, same fresh socket/hold, actual Commit and Arm/World/firstObserve publication",
  "authority":"DATA, matching schemas, proof helpers, MAC equality and decoder completion issue no Source permission, native lease, model installation or released World",
  "compatibility":"old transfer12 guards, contexts, proofs and tokens unchanged; no Initial15 or old release cast; absent or unknown import17 selection refuses",
  "public_route":"requires complete actual producer, native adopter and Window conjunction; no route follows from this definition"
}"#;

/// Constructs the exact immutable Native17 import SchemaRef as DATA.
///
/// Both actual producer and native policy still require their independently
/// installed complete rosters and live conjunctions. Constructing this value
/// neither installs a mechanism nor opens a public restoration dispatcher.
/// The caller independently admits the compiled contract factory work first.
///
/// # Errors
/// Refuses fixed contract parsing/canonical encoding or identity construction.
pub fn native_import17_schema_data() -> Result<SchemaRef, ProviderError> {
    let value = canonical::parse_json(CONTRACT, CONTRACT.len())?;
    let bytes = canonical::canonical_json(&value)?;
    Ok(SchemaRef {
        id: Id::new(NATIVE_IMPORT17_EXTENSION)?,
        version: 17,
        definition: canonical::content_ref(&bytes, "application/json")?,
        extensions: Default::default(),
    })
}

/// Compares every field of the actual complete selected import schema.
///
/// This separately funded factory comparison supplies no live policy, Source
/// permission or native token; an ID-only match is deliberately insufficient.
///
/// # Errors
/// Refuses malformed or substituted ID/version/definition/extensions or factory failure.
pub fn authenticate_native_import17_schema_data(schema: &SchemaRef) -> Result<(), ProviderError> {
    schema.validate()?;
    if schema != &native_import17_schema_data()? {
        return Err(invalid());
    }
    Ok(())
}

/// Quotes the actual compiled contract factory before creating a SchemaRef.
///
/// The lexical bound describes this fixed literal's real parser/Value/canonical
/// phases. It is independent of launch or archive byte ceilings. Returned
/// SchemaRef strings remain charged alongside the encoded definition window.
///
/// # Errors
/// Refuses checked overflow or a temporary-plus-counter row above `maximum`.
pub fn native_import17_contract_storage_data(
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
    let value = original_json_value_storage_extent_data(CONTRACT.len())?;
    let temporary = value
        .canonical_pass_requested_bytes()?
        .checked_add(NATIVE_IMPORT17_EXTENSION.len())
        .and_then(|bytes| bytes.checked_add("blake3-256".len()))
        .and_then(|bytes| bytes.checked_add("cnp.blob.v1".len()))
        .and_then(|bytes| bytes.checked_add(2 * blake3::OUT_LEN))
        .and_then(|bytes| bytes.checked_add("application/json".len()))
        .ok_or_else(invalid)?;
    let scratch = native_import17_contract_counter_scratch_data();
    if temporary
        .checked_add(scratch)
        .is_none_or(|sum| sum > maximum)
    {
        return Err(invalid());
    }
    Ok((temporary, scratch))
}

/// Names fixed actual schema factory and prospective-counter values.
pub fn native_import17_contract_counter_scratch_data() -> usize {
    use std::mem::size_of;
    crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + size_of::<serde_json::Value>()
        + size_of::<Vec<u8>>()
        + size_of::<SchemaRef>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<String>()
}
