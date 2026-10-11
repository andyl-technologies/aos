//! Complete immutable semantic contracts for the opt-in immediate packet source.
//!
//! These specification bytes are data, not qualification evidence. Source
//! installation must bind them to the measured actual program and independently
//! accepted class report. The earlier component dialect retains its old refs.

use crucible_node_contract::canonical;

use crate::ProviderError;

/// Encodes the complete native, configuration and opaque-octet contract edition 2.
///
/// Schema identifiers select sections of this one complete immutable document.
/// Native record definitions refer to the unchanged public CNP/1 Envelope and
/// canonical scalar contracts, never process-private pointer or Rust layouts.
///
/// # Errors
/// Reports failure to encode the fixed source-owned specification canonically.
pub fn immediate_packet_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-semantic-contract/2",
        "source_role":"external_device",
        "operating_mode":"exact",
        "native_record":{
            "identifier":"source-owned.packet-receipt/2", "schema_literal":"source-owned.packet-native/2",
            "closed_fields":["schema","native_pid","original","inventory","grant"],
            "native_pid":"Actual original process ID; matched independently to Unix peer credentials and measured executable.",
            "original":"Complete unchanged CNP/1 request Envelope; full original authenticated response must reference this exact body.",
            "inventory":{
                "closed_fields":["reached","gate_closed","pending","retained_outputs","private_mutations","packet_effects"],
                "reached":"Actual canonical CNP Position, independent of the requested grant ceiling.",
                "gate_closed":"Actual original native nonexecuting gate, not an inferred stopped cursor.",
                "pending":"Complete unchanged suffix of configured original callback rows in native evaluation order.",
                "retained_outputs":"Complete actual unacknowledged publication rows, in native FIFO order.",
                "counters":"Canonical U64 counts of actual completed private and packet callbacks, never predicted effects."
            },
            "grant":{
                "nullable":true,
                "closed_fields":["operation","start","limit","inventory","newborn","complete"],
                "operation":"Original unchanged common and CNP operation ID; never reused in the original session.",
                "interval":"Canonical Positions start <= actual reached <= exclusive limit.",
                "newborn":"Complete ordered publications born under this original grant.",
                "complete":"True only after the entire original authorized native prefix completed. Incomplete or unknown originals cannot authorize retry."
            },
            "publication":{
                "closed_fields":["event","operation","sequence","evaluation","publication","payload"],
                "event":"Original unique configured event ID.",
                "operation":"The original Begin that caused the actual publication birth.",
                "sequence":"Positive node-wide native packet FIFO sequence; contiguous birth order independent of host collection.",
                "evaluation":"Original configured Reaction Position.",
                "publication":"Original configured later Publication Position; never host completion time.",
                "payload":"Full canonical Bytes matching the configured packet payload."
            }
        },
        "configuration":{
            "identifier":"source-owned.packet-program/1",
            "schema_literal":"source-owned.packet-program.v1",
            "closed_fields":["schema","events"],
            "event_closed_fields":["id","evaluation","completion","payload"],
            "events":2, "private_callbacks":1,"packet_callbacks":1,"maximum_packet_bytes":32,
            "event_rules":"Unique IDs; increasing Reaction evaluation; private completion equals evaluation; packet completion is a strictly later Publication; no ingress or external rescheduling.",
            "payload":"Explicit null for the private callback; full canonical Bytes, including an empty packet, for the output callback."
        },
        "payload":{
            "identifier":"source-owned.packet-octets/1", "encoding":"opaque octets",
            "maximum_bytes":32,"empty_valid":true,
            "semantics":"Exactly the configured original packet bytes; no implicit Block, filesystem, clock, CPU or typed-extension decoding."
        },
        "original_control":{
            "execution":"Immediate complete original Begin; callback traces, result inventory, publication copies and all original slots prebuilt before any socket effect.",
            "exclusive_cut":"Only callbacks whose complete completion Position is strictly less than the grant ceiling execute. A straddling callback remains intact; the common selected source refuses such grants before native activation.",
            "poll":"Read-only query of the same retained terminal; never executes or retries a callback.",
            "cancel":"Read-only advisory refusal; completed originals and retained output bodies remain unchanged.",
            "retirement":"Only the exact original consumption body and complete output population discharge the current reservation; immutable original bodies and IDs remain retained.",
            "uncertainty":"An incomplete original is fenced with its complete native resources; transport loss, timeout and query cannot authorize replacement execution."
        },
        "absent_facets":["input","compute","clock","physical_pause","capture","durable_restart","fork","replay","fault_injection","debug_mutation"],
        "limits":{
            "source_events":2,"native_original_grants":64,"native_original_requests":256,
            "one_unacknowledged_owner_grant":1,"one_pending_packet":1,
            "frame_bytes":65536,"common_authorization_bytes":8192,
            "native_objects":256,"native_object_bytes":4194304
        },
        "qualification":"Mandatory independent base-provider, exact-timing and role-profile acceptance for the exact measured unit. This document and successful decoding confer no authority."
    }))?)
}

/// Encodes the independent closed input-storage schema for the owning endpoint.
///
/// This grammar grants no native effect or class acceptance. Full correlation
/// is checked again by the original native control operation before consuming
/// an installed coordinator, activation, grant or output-consumption body.
///
/// # Errors
/// Reports canonical encoding failure for the complete fixed specification.
pub fn installed_ingress_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-ingress-contract/1",
        "identifier":"source-owned.packet-ingress/1",
        "encoding":"canonical application/json; closed selected union",
        "ceiling":65536,
        "alternatives":[
            {"kind":"installed_initial_coordinator", "validation":"Complete bytes exactly equal the separately installed original coordinator; canonical object with no schema substitution."},
            {"kind":"activation", "validation":"Complete CNP/1 ActivationManifest closed schema and Validate; original control rechecks every owner, prepared token, ready receipt, coordinator and whole-world binding."},
            {"kind":"common_grant", "validation":"Complete source-owned.packet-common-grant.v1 closed schema; original Begin rechecks authentic private source owner, activated world, original operation and exclusive full interval before any callback."},
            {"kind":"consumption", "schema":"source-owned.packet-consumption.v1", "closed_fields":["schema","operation","outputs"], "maximum_outputs":1,
             "validation":"Original control requires exact retained original grant and complete native output population before retirement; transfer ACK alone is insufficient."}
        ],
        "unsupported":"Other schemas, noncanonical bytes, capture, restart, arbitrary paths, external input and restored authority refuse.",
        "authority":"Only independently installed source code selects this schema. Parsing, digest equality and passing transfer checks do not issue acceptance or common execution authority."
    }))?)
}

/// Encodes separately selected complete common-coordinator ingress edition 2.
///
/// Static source/world/owner scope is enrolled before launch; actual preparation
/// rows are accepted only after the native Arm and checked before gate opening.
/// The older exact preinstalled coordinator contract remains byte-identical.
///
/// # Errors
/// Reports canonical encoding failure for the immutable source specification.
pub fn common_ingress_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-ingress-contract/2",
        "identifier":"source-owned.packet-ingress/2",
        "encoding":"canonical application/json; separately selected closed union",
        "ceiling":65536,
        "static_installation":"source-owned.packet-common-coordinator-installation/1 contains every original coordinator field, preparations exactly empty; no predicted Ready.",
        "coordinator":"Complete crucible/coordinator-initial/1 matches the static template byte-for-field; exactly one preparation is joined to the native original Arm, actual Ready root, prepared token, binding, incarnation, generation and whole world before WorldActivate.",
        "other_bodies":"Unchanged closed CNP/1 ActivationManifest, source-owned.packet-common-grant.v1 and source-owned.packet-consumption.v1; native original control rechecks complete associations.",
        "unsupported":"Other bodies, changed worlds/owners, unknown fields, duplicate/missing/predicted preparations, noncanonical bytes and restored authority refuse.",
        "authority":"No acceptance, Ready, ordinary admission, capture or activation authority follows from this grammar or decoding."
    }))?)
}
