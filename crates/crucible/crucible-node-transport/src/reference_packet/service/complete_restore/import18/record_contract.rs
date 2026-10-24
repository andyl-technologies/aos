//! Defines the complete separate18 restored-native evidence contract as DATA.
//!
//! Commit-held and first-observed records have distinct closed field rosters.
//! A response's own evidence cannot reference that response: completed pairs
//! refer only to preceding phases. Neither this factory nor a matching full
//! schema constructs a model, native transaction, physical gate or live witness.

use super::*;
use std::mem::size_of;

const CONTRACT: &[u8] = br#"{
  "schema":"source-owned.packet-restored-native-contract/18",
  "selection":"exact full record18 SchemaRef in the immutable provider and every binding roster, plus negotiated record18 feature; import18 and stage18 definitions remain independently mandatory",
  "record_schema":"source-owned.packet-restored-native/18",
  "discriminator":"kind; exactly commit_held or first_observed; unknown fields and other record editions refuse",
  "commit_held_fields":["schema","kind","scope","commit","context_digest","local_cursor","inventory_hash","physical_gate_held"],
  "first_observed_fields":["schema","kind","scope","commit","arm","world","observe","native_record","physical_gate_held"],
  "scope":["target","source_birth","bootstrap","recipe_identity","import_binding","inputs","prepare"],
  "target":["native_pid","session","incarnation","node","owner","owner_generation","binding_hash","world","activation","generation","prepared_token","gate","admission","transaction"],
  "target_meaning":"complete actual fresh Core target and same native process/SDK installation; historical PID, session, incarnation, owner and World remain unchanged inside captured evidence",
  "source_birth":"full application/json reference of the same complete original SourceBinding18; actual private Birth, launch, Source and Host ancestry remain independent acceptance conjuncts",
  "bootstrap":"complete actual bootstrap-only request and correlated response full references, with proof18 and receipt18 retained; no ordinary Admit or model-installed meaning",
  "recipe_identity":"exact same independently reconstructed 32-byte immutable recipe identity, never a numeric or wire-to-Recipe conversion",
  "import_binding":"full application/json reference of complete binding18, including explicit native/Source/semantic families, all five role extents and fullrefs, normalization and semantic maxima, and all independent decoder limits",
  "inputs":"seven full ContentRefs in after, Control, anchor5, Snapshot, Journal, normalization18, semantic-spend order, retaining each defining media type; exact same authenticated Prepare roster, no transfer12 six-bank substitution",
  "completed_pair":["original","terminal"],
  "pair_meaning":"full application/json references of the actual complete assigned SDK original and correlated terminal including phase proof/receipt; same registration, once owner, transfer token and retained literal completion remain independently authenticated",
  "prepare":"completed new18 Prepare pair; prepared-to-receive is not model validation or installation",
  "commit_held_commit":"full reference of the current actual assigned Commit request, including proof18; its response is absent because this record precedes that response",
  "commit_held_context":"exact 32-byte verified Commit context digest; complete independently validated seven-bank import and actual same-socket model installation precede publication",
  "commit_held_inventory":"actual installed Control/model local Position and full inventory HashRef equal the captured logical state; current fresh physical Hold is independent and physical_gate_held must be true",
  "first_observed_commit":"completed same-token Commit pair, including the separately authenticated commit-held proof and receipt",
  "arm":"completed same-target Arm pair with the genuine current physical Hold still held",
  "world":"completed same-target World pair after actual global World publisher and physical release; no publication inferred from matching DTOs or a MAC",
  "observe":"full reference of the current actual assigned first Observe request, including stage proof17 under explicit stage18 selection; sequence must be after sequence zero and after the completed World",
  "native_record":"full reference of the actual separate unchanged producer-two or reactive-four proof from that first real native observation; no synthetic model advancement or relabeled receipt5",
  "first_observed_gate":"physical_gate_held must be false; old imported logical gate fields remain literal historical evidence",
  "nonrecursive":"neither record includes the full reference or digest of its own carrying response; the Source separately retains and authenticates that completed response and its stage receipt before accepting evidence",
  "validation":"closed selected kind, complete target and reference validation, exact digest widths, exact seven-bank roster and phase correspondence, independently bounded raw/typed/canonical construction; partial records stay owned and cannot become live witnesses",
  "native_conjunction":"same actual admitted original bootstrap, complete model-absent immutable policy, independently derived Initial/Recipe/phase rows, actual native model and semantic-spend consumers, original SDK/literal owners and physical gate",
  "source_conjunction":"actual same Source/cold/factory/Window once owner, signed full ancestry, complete archive/SDK journal and same current Core target; first-observed evidence is accepted only after the actual completed same-World first Observe",
  "authority":"record DATA, bools, digests, complete schema references and valid phase MACs create no native owner, model, physical Hold, World publication, Ready or restoration permission",
  "compatibility":"old restored-native12, native receipt5 and record13/17 witnesses remain unchanged and cannot be relabeled as this edition; no writer or live route follows from this compiled definition"
}"#;

/// Returns the complete canonical restored-native18 contract body as DATA.
///
/// # Errors
/// Refuses invalid compiled JSON or canonical encoding failure.
pub fn native_import18_restored_record_contract_data() -> Result<Vec<u8>, ProviderError> {
    let value = canonical::parse_json(CONTRACT, CONTRACT.len())?;
    Ok(canonical::canonical_json(&value)?)
}

/// Constructs the independently versioned complete record18 schema reference.
///
/// The caller admits the defining factory row first. This supplies immutable
/// contract DATA only and installs no record producer or verifier authority.
///
/// # Errors
/// Refuses compiled literal parsing, canonicalization or reference construction.
pub fn native_import18_restored_record_schema_data() -> Result<SchemaRef, ProviderError> {
    let body = native_import18_restored_record_contract_data()?;
    Ok(SchemaRef {
        id: Id::new(NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA)?,
        version: 18,
        definition: canonical::content_ref(&body, "application/json")?,
        extensions: Default::default(),
    })
}

/// Authenticates every field of the exact selected record18 schema reference.
///
/// Matching this DATA creates no live native record or restoration permission.
///
/// # Errors
/// Refuses invalid or changed ID, version, definition, extensions or factory work.
pub fn authenticate_native_import18_restored_record_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    schema.validate()?;
    if schema != &native_import18_restored_record_schema_data()? {
        return Err(invalid());
    }
    Ok(())
}

/// Quotes complete factory backing and fixed controls before allocating a schema.
///
/// The quote uses the defining literal's strict parser and canonical-writer
/// layouts. Original selected-schema owners and enclosing guards stay separate.
///
/// # Errors
/// Refuses checked overflow or a restriction below temporary plus fixed demand.
pub fn native_import18_restored_record_contract_storage_data(
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    use crate::retained_metadata::serialization_storage::{
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    };

    let literal = original_json_value_storage_extent_data(CONTRACT.len())?;
    let temporary = literal
        .canonical_pass_requested_bytes()?
        .checked_add(NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA.len())
        .and_then(|n| {
            n.checked_add("blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len())
        })
        .ok_or_else(invalid)?;
    let scratch = native_import18_restored_record_contract_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + size_of::<serde_json::Value>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<&SchemaRef>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<SchemaRef>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<String>();
    if temporary
        .checked_add(scratch)
        .is_none_or(|peak| peak > maximum)
    {
        return Err(invalid());
    }
    Ok((temporary, scratch))
}

/// Names the actual strict parser and canonical writer fixed controls.
pub fn native_import18_restored_record_contract_counter_scratch_data() -> usize {
    canonical::json_parse_counter_scratch_bytes_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
}

#[cfg(test)]
mod tests;
