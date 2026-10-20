//! Defines the immutable stage18 selection over unchanged inner17 DATA contract and its real factory geometry.

use super::*;
pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import18::stage_contract::NATIVE_IMPORT18_STAGE_SELECTION;

const CONTRACT: &[u8] = br#"{
  "schema":"source-owned.packet-native-import-stage-contract/18",
  "selection":"actual full import18 and stage18 SchemaRefs in immutable provider and every binding roster, negotiated stage18 feature and exact per-phase keys",
  "inner_data":"unchanged StageBinding/Context/Proof/Receipt17 grammars, stage17 Envelope keys and cryptographic domains; complete import18 binding digest and genuine new18 transaction/physical Hold are required",
  "wire_binding_key":"source-owned.packet-native-import-stage/17",
  "phases":["arm","world","first_observe"],
  "methods":["activate","world_activate","observe"],
  "binding":["schema","phase","import_binding_digest","source_birth","source_runtime","scope_proof","target","prepare","commit","hold","arm","world","native_allocation"],
  "target":["native_pid","session","incarnation","node","owner","owner_generation","binding_hash","world","activation","generation","prepared_token","gate","admission","transaction"],
  "completed_prepare":["pair","receipt"],
  "completed_commit":["pair","receipt"],
  "pair":["original","terminal"],
  "receipt_vocabulary":"complete typed new17 Prepare and Commit receipts from the actual retained same-lease native/SDK attempts, never transfer12 receipts",
  "nullable":"arm and world are mandatory wire fields; Arm null/null, World completed-Arm/null, firstObserve completed-Arm/completed-World",
  "context":["schema","algorithm","phase","birth_context_digest","stage_binding_digest","assigned_original_digest"],
  "birth":"digest of complete actual admitted ACK context, including Source/kernel/policy, both complete registrations, literal Hello request/response and assigned Admit",
  "assignment":"same actual assigned Envelope, complete header and baseline body; exact stage17 and per-stage-proof17 keys; omit only that proof from assigned request digest",
  "proof":["schema","algorithm","context_digest","mac"],
  "proof_domains":["source-owned.packet-native-import-arm-key/17","source-owned.packet-native-import-world-key/17","source-owned.packet-native-import-first-observe-key/17"],
  "receipt":["schema","algorithm","phase","context_digest","assigned_response","physical_gate_held","mac"],
  "receipt_domains":["source-owned.packet-native-import-arm-receipt-key/17","source-owned.packet-native-import-world-receipt-key/17","source-owned.packet-native-import-first-observe-receipt-key/17"],
  "physical_gate_results":[true,false,false],
  "first_observe":"exactly one baseline observation after sequence zero, after actual same-World publication/release; no scheduler/model advance synthesized",
  "native_conjunction":"genuine inherited native17 once budget, same Boot/actor/registration/current literal, actual seven-bank completed import, semantic/model custody, same fresh socket/physical Hold, exact prior completed pairs and baseline target/control checks before any native effect",
  "source_conjunction":"same actual Source/cold/Window once owner, real target ActivationRecord and all-owner Scope; World proof only after real global World publisher; literal SDK assignment retained before signing",
  "authority":"DTOs, bools, valid MACs, fullrefs and matching schemas do not create native phases, Source grants, World publication or released17 witness",
  "compatibility":"no old activation1/observation1 proofs, transfer12 tokens, native-record13 relabel or Initial15 released witness accepted; selected route remains closed until complete paired issuer/adopter"
}"#;

/// Constructs the complete separate18 stage schema without installing a verifier.
///
/// # Errors
/// Refuses fixed literal parsing/canonicalization or reference construction.
pub fn native_import18_stage_schema_data() -> Result<SchemaRef, ProviderError> {
    let value = canonical::parse_json(CONTRACT, CONTRACT.len())?;
    let body = canonical::canonical_json(&value)?;
    Ok(SchemaRef {
        id: Id::new(NATIVE_IMPORT18_STAGE_SELECTION)?,
        version: 18,
        definition: canonical::content_ref(&body, "application/json")?,
        extensions: Default::default(),
    })
}

/// Compares every field of the exact stage schema after independent factory admission.
///
/// # Errors
/// Refuses a changed ID, definition, version, extensions or fixed factory failure.
pub fn authenticate_native_import18_stage_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    schema.validate()?;
    if schema != &native_import18_stage_schema_data()? {
        return Err(invalid());
    }
    Ok(())
}

/// Quotes only this actual compiled schema factory's transient and fixed controls.
///
/// This row does not cover stage DTO parsing, original/Scope/model owners,
/// cryptographic constructors, native effects or any live allocation admission.
///
/// # Errors
/// Refuses checked overflow or an independently supplied restriction below demand.
pub fn native_import18_stage_contract_storage_data(
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    use crate::retained_metadata::serialization_storage::{
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    };
    use std::mem::size_of;
    let literal = original_json_value_storage_extent_data(CONTRACT.len())?;
    let temporary = literal
        .canonical_pass_requested_bytes()?
        .checked_add(NATIVE_IMPORT18_STAGE_SELECTION.len())
        .and_then(|bytes| {
            bytes.checked_add(
                "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len(),
            )
        })
        .ok_or_else(invalid)?;
    let scratch = native_import18_stage_contract_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + size_of::<serde_json::Value>()
        + size_of::<Vec<u8>>()
        + size_of::<SchemaRef>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<String>();
    if temporary
        .checked_add(scratch)
        .is_none_or(|total| total > maximum)
    {
        return Err(invalid());
    }
    Ok((temporary, scratch))
}

/// Names actual strict parser and JCS fixed controls of this compiled factory.
///
/// Container/key/output backing remains in the separately derived dynamic row.
pub fn native_import18_stage_contract_counter_scratch_data() -> usize {
    canonical::json_parse_counter_scratch_bytes_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
}
