//! Complete immutable semantic contracts for the opt-in immediate packet source.
//!
//! These specification bytes are data, not qualification evidence. Source
//! installation must bind them to the measured actual program and independently
//! accepted class report. The earlier component dialect retains its old refs.

use crucible_node_format::canonical;

use crate::ProviderError;

/// Encodes the distinct complete connected consuming-storage grammar edition 4.
///
/// The exact original source, byte journal and opaque runtime cut remain
/// mandatory. A successful digest, codec or transport ACK grants no consumption.
///
/// # Errors
/// Reports failure to encode the fixed complete specification canonically.
pub fn connected_ingress_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-ingress-contract/4",
        "identifier":"source-owned.packet-ingress/4",
        "initial_coordinator":"source-owned.packet-connected-coordinator-installation/4; complete original three-native-peer plus genuine host-scheduler-owner static roster, declared ports, policies and host-captured connection domains; no predicted Ready",
        "activated_coordinator":"crucible/coordinator-initial/1 with complete actual four-owner original preparations, matched to local retained native Arm and the genuine attached host scheduler Arm; original host publisher authenticates all sources",
        "activation":"Unchanged closed CNP/1 ActivationManifest; every actual preparation and whole-world binding is rechecked before native gate opening",
        "grants":"source-owned.packet-common-grant.v4 for connected inputs; source-owned.packet-common-grant.v2 only for the unchanged output-only producer",
        "input_feature":"source-owned.packet-input/4; one request-only closed Stage or Commit context carrying unchanged full Position cutoff and exact original byte/delivery associations",
        "delivery_inventory":"Canonical application/vnd.crucible.input-inventory+json, at most four original ordered deliveries per batch; every causal, source, endpoint, connection and fixed-delay association checked against actual native original context",
        "payload":"Original application/octet-stream bytes; maximum1024 source component bytes and independently declared lane ceiling, including an actual empty packet",
        "consumption":"Staging is nonexecuting byte custody; only the original later native consumed journal precedes a grant. Actual empty prefixes use this same Stage/ACK/Commit path and genuine producer closure; no EOF inferred from empty queues",
        "retirement":"source-owned.packet-consumption.v4 for reactive nodes and unchanged .v1 for the producer; complete original output population, with native future phases retained across original empty-output retirement",
        "limits":{"frame_bytes":65536,"common_grant_bytes":8192,"input_events":4,"microsteps":16,"participants":3},
        "unsupported":"Other media, feature/context editions, unknown/duplicate fields, arbitrary input routes, source replacement, mutation, capture, restart, CPU/Clock promotion or syntactic qualification",
        "authority":"Only independently installed source code selects this grammar. Complete native process/currentness, original journal and opaque runtime authority remain mandatory; all unresolved normative qualification remains unresolved"
    }))?)
}

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

/// Encodes distinct three-owner static roster and post-Arm ingress edition 3.
///
/// Each native peer verifies its own original staged preparation. Full foreign
/// owner authentication belongs to the independently installed host publisher;
/// a portable preparation row or matching hash cannot establish native Ready.
///
/// # Errors
/// Reports canonical encoding failure of the complete fixed specification.
pub fn world_ingress_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-ingress-contract/3",
        "identifier":"source-owned.packet-ingress/3",
        "encoding":"canonical application/json; separately selected closed union",
        "ceiling":65536,
        "static_installation":"source-owned.packet-common-coordinator-installation/2",
        "participants":3,
        "coordinator":"Complete immutable three-node/world/source roster is installed before Child; exactly three actual post-Arm preparation rows fill the body. Local Ready must equal the original retained native Arm. Host independently authenticates all three original owners before publication.",
        "activation":"Complete CNP/1 ActivationManifest owners exactly equal all three complete prepared rows, local transaction/gate and original common world.",
        "common_grant":"Distinct source-owned.packet-common-grant.v2 binds the complete installed three-owner activation and local original route under the unchanged8192-byte ceiling; only original admitted operation authority can grant native callbacks.",
        "consumption":"Unchanged source-owned.packet-consumption.v1; exact original output population, no transport ACK substitution.",
        "unsupported":"No capture, restart, external input, CPU/Clock promotion or partial/synthetic Ready.",
        "authority":"This codec grants no class, admission, native Ready or execution authority. Independent installed source and actual host all-owner conjunction are mandatory."
    }))?)
}

/// Encodes the distinct phased connected source specification edition four.
///
/// The output-only edition-two and edition-three specifications are unchanged.
/// This document selects actual staged-byte custody, separate later consumption
/// and independently observable reaction/publication steps. Decoding the
/// specification supplies no native or behavioral qualification authority.
///
/// # Errors
/// Reports canonical encoding failure for the complete fixed specification.
pub fn connected_packet_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-semantic-contract/4",
        "source_role":"external_device",
        "operating_mode":"exact",
        "ordering_profile":"superdense-v1",
        "input_feature":"source-owned.packet-input/4",
        "configuration":{
            "schema":"source-owned.packet-connected-program/4",
            "closed_fields":["schema","connections","output"],
            "connection_fields":["id","policy","producer","consumer","delay_ps"],
            "connections":"One to four complete preinstalled input routes; exact canonical endpoints, policy reference and literal picosecond delay. Frames cannot introduce a route.",
            "output":"One source-owned local output endpoint or explicit null for a consuming sink. No CPU, clock, Block or architecture semantics follow from this label."
        },
        "input_context":{
            "encoding":"One negotiated request-envelope extension; unchanged baseline CNP/1 Input body and empty method-body extensions.",
            "actions":["stage","commit"],
            "stage_fields":["action","cut"],
            "commit_fields":["action","cut","input_request_id","staging_receipt"],
            "cut_fields":["schema_version","session_id","incarnation_id","node_id","execution_owner_id","owner_generation","activation_id","world_generation","world_binding_hash","stage_operation_id","batch_id","batch_sequence","input_epoch","batch_hash","delivery_inventory","cutoff"],
            "cutoff":"Exclusive complete Position. Every Delivery is strictly below the cut; phase and microstep are preserved. No BoundaryControl-zero conversion is permitted.",
            "stage":"Actual original payload and complete canonical delivery bytes are retained in the source journal before the unchanged baseline Input custody reply. No reaction, publication or modeled cursor moves.",
            "commit":"The same original staged request, full cut, byte journal and source-issued staging receipt are retained under one distinct original consumed request before eligibility for any grant. ACK alone is insufficient.",
            "lineage":"Complete canonical CommittedDeliveryV1 fields are retained. Parent labels are packet-parent-TIME-MICROSTEP-PHASE, sorted/deduplicated as IdSet; native reaction keeps the actual recipient Delivery Position as immediate parent.",
            "receipt":"Standard provider-issued InputCustody ControlReceipt and InputCustodyRecord bind one exact batch hash and complete native record. Actual source-owned record bytes and original response are mandatory."
        },
        "native_staging":{
            "schema":"source-owned.packet-staged-bytes/4",
            "closed_fields":["schema","native_pid","original","cut","batch","deliveries","payloads","inventory"],
            "payloads":"Actual complete retained Bytes in the same original input-event order. Digest references or predicted checksums cannot replace source-owned bytes."
        },
        "native_commit":{
            "schema":"source-owned.packet-consumed-input/4",
            "closed_fields":["schema","native_pid","original","staged_record","staging_receipt","cut","reactions","reached"],
            "reached":"Actual modeled cursor, unchanged at commitment."
        },
        "native_inventory":{
            "closed_fields":["reached","gate_closed","reactions","delivered_inputs","publications","retained_outputs","reactions_completed","packet_effects","stages","commits"],
            "delivered_inputs":"Complete actual native Delivery steps in original canonical recipient order. Each retains its original input, native consumed-byte association and actual delivery operation; a Reaction ceiling may complete Delivery without running the Reaction.",
            "reactions":"Complete pending source-consumed callbacks in native order; every original byte, input ID, staging/commit association, Delivery parent and Reaction coordinate is retained.",
            "publications":"Complete actual evaluated outputs held for next-microstep publication; reaction operation and original lineage remain unchanged.",
            "stages_and_commits":"Complete source-native proof references retained in actual receiving stream order, including already evaluated inputs."
        },
        "execution":{
            "delivery":"A distinct original native Delivery step occurs strictly below the grant ceiling, retains exactly-once consumed identity and emits an independently observed typed datagram. Staging and input commitment do not complete this step.",
            "reaction":"Occurs at the original Delivery time and microstep in Reaction phase, strictly below the granted cut. A sink performs only this native mutation. A relay retains a publication at the next microstep, Publication phase.",
            "publication":"Only a later included Publication step emits the actual immutable packet and allocates the positive native FIFO sequence. A cut at equality emits nothing; a reaction may stop with its future publication still retained.",
            "originals":"Complete original grant and response credit precedes native effects. An uncertain datagram or callback remains the same incomplete fenced original; Poll, timeout and retry cannot cause replacement execution.",
            "input_closure":"An explicit source-consumed cut bounds native execution. Empty queues, missing staging and transport EOF never imply future producer closure.",
            "retirement":"Exact complete output membership is acknowledged once; immutable grant/input/proof identities remain retained after ACK."
        },
        "limits":{
            "connections":4,"original_input_batches":16,"total_input_events":32,
            "events_per_batch":4,"maximum_payload_bytes":1024,"maximum_microsteps":16,
            "original_native_grants":64,"maximum_native_record_bytes":65536
        },
        "absent_facets":["compute","clock","physical_pause","capture","durable_restart","fork","replay","fault_injection","debug_mutation"],
        "qualification":"Mandatory independently installed source/runtime/behavioral acceptance for the exact measured implementation, configuration, ports and full class selection. Component tests, portable records and specification bytes confer no Ready or accepted Node authority."
    }))?)
}
