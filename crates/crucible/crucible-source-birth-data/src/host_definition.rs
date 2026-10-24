//! Preserves the actual Host2 factory DATA independently of expected-contract serializers.

use crucible_node_format::{Id, SchemaRef, canonical};
use serde_json::json;

const PROFILE: &str = "source-owned.host-scheduling-original-lineage/2";

/// Encodes the concrete original common-state capture and fresh-installation contract.
///
/// # Errors
/// Reports canonical encoding failure of the fixed installed definition.
pub fn host_scheduling_complete_owner_definition()
-> Result<Vec<u8>, crucible_node_format::ContractError> {
    canonical::canonical_json(&json!({
        "schema":"source-owned.host-scheduling-complete-owner/2",
        "state":"same original Runtime7/Scheduling1 allocation plus all retained original payload and lineage bodies",
        "capture":"core-issued unchanged-cut administrative ticket; original producer before any native request; once-owned snapshot transfer; explicit host settlement journal",
        "restore":"signed complete index3 and genuine fresh Runtime7 context; original host snapshot plus core administrative lifetime ledger before Arm; one original scheduler installation; no replay",
        "profile":PROFILE,
        "native_scope":"host coordinator and declared connection resources only; native peers require independently installed native-five capture and genuine fresh adoption"
    }))
}

/// Binds the complete source-two state codec independently of native peer schemas.
///
/// # Errors
/// Reports invalid fixed identity or canonical definition encoding failure.
pub fn host_scheduling_complete_continuation_schema()
-> Result<SchemaRef, crucible_node_format::ContractError> {
    let bytes = canonical::canonical_json(&json!({
        "schema":"source-owned.host-scheduling-continuation/2",
        "fields":["schema_version","source","runtime","scheduling","objects"],
        "runtime":"closed original-lineage Runtime7; complete native ancestry and typed original bodies",
        "administration":"separate runtime-original-capture-journal/1 in index3; unchanged Runtime7 and Coordinator7"
    }))?;
    Ok(SchemaRef {
        id: Id::new("source-owned.host-scheduling-continuation/2")?,
        version: 2,
        definition: canonical::content_ref(&bytes, "application/json")?,
        extensions: Default::default(),
    })
}
