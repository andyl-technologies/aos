//! Defines the distinct process-protocol contract independently of any live route.

use super::*;

const CONTRACT: &[u8] = br#"{
  "schema":"source-owned.packet-native-import-contract/18",
  "selection":"same complete SchemaRef in immutable provider and binding rosters plus negotiated feature and exact three-key phase extension set",
  "binding":["schema","prepare_digest","native_family","native_before","controller17","source_family","source17","node25","geometry_identity","role_extents","limits","normalization","normalization_maximum","semantic_spend_family","semantic_spend","semantic_spend_maximum"],
  "limits":["role_maximums","immutable_objects","immutable_bytes","immutable_depth","maximum_nodes","maximum_requested_bytes","maximum_target_requested_bytes","maximum_before_bytes"],
  "captured_source_families":{"captured17":"source-private.semantic-state-restored-settled/17","captured18":"source-private.semantic-state-restored-settled/18 with genuine InitialInvocation15 first lineage","imported18":"source-private.semantic-state-restored-settled/18 with genuine completed NativeImport18 first lineage"},
  "native_families":{"snapshot17":"source-owned.packet-native-continuation/17","snapshot18":"source-owned.packet-native-continuation/18"},
  "independent_families":"native Snapshot family is required independently of Source lineage and seventh-bank family; Source18 never implies Snapshot18; labels do not create completed owners",
  "prebirth_recipe_identity":{"algorithm":"BLAKE3 derive-key","domain":"source-owned.packet-native-import-prebirth-recipe-identity/18","body":"canonical JSON of every RecipeFields24 field except identity; closed field names and serde representations unchanged","meaning":"self-consistency only; complete independent native recipe reconstruction from actual seven-bank inputs precedes model or Hold effects"},
  "normalization_fields":["schema","archive_index","capture_manifest","source_runtime","native_family","native_snapshot","native_after","native_control","native_anchor","native_journal","native_before","controller17","source_family","source17","node25","backend_implementation","backend_profile","backend_schema","archived_cut","archived_ordinal","host_registration","target_world","target_owner","target_owner_binding","target_activation","target_generation","target_owner_generation","transaction_id","commit_request_id","lease_generation","nonce","limits","semantic_spend_family","semantic_spend","semantic_spend_maximum"],
  "normalization_correspondence":"strict closed normalization18 DATA, independently bounded to at most 65536 bytes and the original recipe projection; exact selected families, original nonce/generation, all twelve reader/constructor limits, five archived fullrefs, semantic fullref/maximum and original Host registration; actual signed Prepare additionally authenticates every archived/fresh target binding before installation",
  "initial_partition":"each independently derived initial retained/transient/counter demand fits its original Prepare partition; whole escrow or later phase maxima cannot substitute",
  "prepare_completion":"independently funded prepared-to-receive expected seven empty bank headers and original escrow; completed bytes and full recipe recomputation are required before model adoption, Hold, Arm or World",
  "role_order":["snapshot","after","control","anchor5","journal"],
  "input_bank_order":["after","control","anchor5","snapshot","journal","normalization18","explicit_semantic_spend_family"],
  "semantic_spend_families":{"legacy17":"source-private.semantic-spend/17","complete18":"source-private.semantic-spend/18"},
  "recipe_full_reference_identity":{"domain":"source-owned.packet-native-import-fullref-identity/18","framing":"BLAKE3 derive-key over algorithm, domain, digest and media_type, each UTF-8 string prefixed with its u64 big-endian byte length, followed by content length as u64 big endian","archive_order":["snapshot","after","control","anchor5","journal"],"semantic_reference":"separate seventh-bank full reference; normalization is bound by actual signed Prepare"},
  "input_roster":"canonical seven rows of [role,fullref,maximum] in exact receive order, hashed under source-owned.packet-native-import-input-roster/18; old six-bank roster digest is not substituted",
  "semantic_spend":"separate seventh body; exact Source/Node/Runtime logical used IDs and pending Stage/Commit/ACK relations, never old-session retry authority; native actual semantic consumers required",
  "phase_payload":"unchanged Prepare12 or Commit12 DTO is inert nested vocabulary only",
  "phase_context":["schema","algorithm","peer","import_binding_digest","assigned_original_digest"],
  "assignment":"same SDK Envelope, complete header and body, exact request12/import18/proof18 extension keys; remove only the corresponding new17 proof for assigned digest",
  "wire_proof_keys":["source-owned.packet-native-import-prepare-proof/18","source-owned.packet-native-import-commit-proof/18"],
  "wire_receipt_keys":["source-owned.packet-native-import-prepare-receipt/18","source-owned.packet-native-import-commit-receipt/18"],
  "inner_data":"phase context/proof/receipt17 schemas and cryptographic domains are unchanged DATA; new18 adapters bind the complete binding18 digest and exact18 assignment, never old17 guard fallback",
  "proof":[ "schema","algorithm","context_digest","mac"],
  "proof_domains":["source-owned.packet-native-import-prepare-key/17","source-owned.packet-native-import-commit-key/17"],
  "prepare_receipt":["schema","algorithm","import_binding_digest","context_digest","prepare_digest","input_roster","transfer_token","generation","native_sequence","assigned_response","mac"],
  "commit_receipt":["schema","algorithm","import_binding_digest","context_digest","commit_digest","installed_mapping","transfer_token","native_sequence","assigned_response","mac"],
  "lease_domain":"source-owned.packet-native-import-transfer-token-key/17",
  "receipt_domains":["source-owned.packet-native-import-prepare-receipt-key/17","source-owned.packet-native-import-commit-receipt-key/17"],
  "source_conjunction":"genuine completed cold65 plus signed parents plus actual fresh Source factory and actual Window, target World/owner/generation and SDK once-assignment before signing",
  "native_conjunction":"actual fresh birth/current registration and once-only admitted input custody, strict five-role/native-before/SDK-journal/normalization/seventh-semantic-spend validation, complete logical Control/model and spent ledgers, same fresh socket/hold, actual Commit and Arm/World/firstObserve publication",
  "bootstrap_ack":{
    "request_method":"native_import18_bootstrap",
    "required_feature":"source-owned.packet-native-import-bootstrap/18",
    "request_schema":"source-owned.packet-native-import-bootstrap-request/18",
    "request":["schema","recipe_identity","initial_funding"],
    "result_schema":"source-owned.packet-native-import-bootstrap-result/18",
    "result":["schema","state","recipe_identity","initial_funding"],
    "result_state":"bootstrap_only",
    "method_scope":"profile-specific explicitly negotiated method; ordinary Admit remains Realized-only with its unchanged required result; generic baseline dispatch refuses this method without actual new18 bootstrap owner",
    "proof_extension":"source-owned.packet-native-import-bootstrap-ack-proof/18",
    "receipt_extension":"source-owned.packet-native-import-bootstrap-ack-receipt/18",
    "context_schema":"source-owned.packet-native-import-bootstrap-ack-context/18",
    "context":["schema","algorithm","source_birth","kernel_binding","policy_binding","host_registration","native_registration","hello_request","hello_response","assigned_request","recipe_identity","initial_funding"],
    "proof":["schema","algorithm","context_digest","mac"],
    "receipt":["schema","algorithm","state","context_digest","assigned_response","mac"],
    "receipt_state":"bootstrap_only",
    "proof_domain":"source-owned.packet-native-import-bootstrap-ack-key/18",
    "receipt_domain":"source-owned.packet-native-import-bootstrap-ack-receipt-key/18",
    "source_birth":"complete actual SourceBinding18 plus original birth/private-launch/Host association, including same immutable recipe and complete definitions",
    "assignment":"complete same assigned native_import18_bootstrap request, removing only proof18; response digest removes only receipt18",
    "meaning":"same original bootstrap channel/Hello/Source occurrence only; no ordinary Realize/Admit/Ready flag, modeled receipt, model installation or fresh-query13 frontier",
    "custody":"native initial-only owner and Source once owner retain all partial original/context/proof/response/receipt fields before fallible work; native recomputes all physical operands under independent initial funding"
  },
  "authority":"DATA, matching schemas, proof helpers, MAC equality and decoder completion issue no Source permission, native lease, model installation or released World",
  "compatibility":"old import17 and transfer12 guards, contexts, proofs and tokens unchanged; no Initial15 or old release cast; absent or unknown import18 selection refuses",
  "public_route":"requires complete actual producer, native adopter and Window conjunction; no route follows from this definition"
}"#;

/// Returns the canonical compiled import18 contract body as DATA.
///
/// The existing contract factory quote bounds this parser and writer. Reading
/// this body selects no Source mechanism or native phase.
///
/// # Errors
/// Refuses compiled literal parsing or canonical encoding failure.
pub fn native_import18_contract_data() -> Result<Vec<u8>, ProviderError> {
    let value = canonical::parse_json(CONTRACT, CONTRACT.len())?;
    Ok(canonical::canonical_json(&value)?)
}

/// Constructs the exact immutable Native17 import SchemaRef as DATA.
///
/// Both actual producer and native policy still require their independently
/// installed complete rosters and live conjunctions. Constructing this value
/// neither installs a mechanism nor opens a public restoration dispatcher.
/// The caller independently admits the compiled contract factory work first.
///
/// # Errors
/// Refuses fixed contract parsing/canonical encoding or identity construction.
pub fn native_import18_schema_data() -> Result<SchemaRef, ProviderError> {
    let value = canonical::parse_json(CONTRACT, CONTRACT.len())?;
    let bytes = canonical::canonical_json(&value)?;
    Ok(SchemaRef {
        id: Id::new(NATIVE_IMPORT18_EXTENSION)?,
        version: 18,
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
pub fn authenticate_native_import18_schema_data(schema: &SchemaRef) -> Result<(), ProviderError> {
    schema.validate()?;
    if schema != &native_import18_schema_data()? {
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
pub fn native_import18_contract_storage_data(
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
    let value = original_json_value_storage_extent_data(CONTRACT.len())?;
    let temporary = value
        .canonical_pass_requested_bytes()?
        .checked_add(NATIVE_IMPORT18_EXTENSION.len())
        .and_then(|bytes| bytes.checked_add("blake3-256".len()))
        .and_then(|bytes| bytes.checked_add("cnp.blob.v1".len()))
        .and_then(|bytes| bytes.checked_add(2 * blake3::OUT_LEN))
        .and_then(|bytes| bytes.checked_add("application/json".len()))
        .ok_or_else(invalid)?;
    let scratch = native_import18_contract_counter_scratch_data();
    if temporary
        .checked_add(scratch)
        .is_none_or(|sum| sum > maximum)
    {
        return Err(invalid());
    }
    Ok((temporary, scratch))
}

/// Names actual strict parser, JCS and prospective factory controls.
pub fn native_import18_contract_counter_scratch_data() -> usize {
    use std::mem::size_of;
    canonical::json_parse_counter_scratch_bytes_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
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
