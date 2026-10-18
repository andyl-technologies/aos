//! Defines immutable complete packet preservation contracts separately from execution.
//!
//! The specifications bind the concrete Native5 and independent Host2 codecs.
//! Encoding, decoding or hashing these bytes issues no capture ticket, native
//! association, readiness, restoration permission or qualification evidence.
//!
//! ```text
//! {"schema":"source-owned.packet-semantic-contract/5", "closure":{...}}
//! ```

use crucible_node_contract::{ContentRef, Id, SchemaRef, canonical};

use crate::ProviderError;

/// Names the separately negotiated complete preservation feature.
pub const PACKET_COMPLETE_LINEAGE_FEATURE: &str = "packet-complete-original-lineage/5";

/// Names the separately installed complete native preservation profile.
pub const PACKET_COMPLETE_LINEAGE_PROFILE: &str = "source-owned.packet-complete-original-lineage/5";

/// Names the complete native implementation without selecting its authority.
pub const PACKET_NATIVE5_IMPLEMENTATION: &str = "source-owned.packet-native/5";

/// Names the distinct complete static four-owner coordinator schema.
pub const PACKET_NATIVE5_COORDINATOR_SCHEMA: &str =
    "source-owned.packet-complete-coordinator-installation/5";

/// Encodes the complete native, protocol, host association and restoration specification.
///
/// Earlier producer and reactive record bodies remain immutable. New source-five
/// receipts bind those originals to the actual fresh owner; they never rewrite
/// historical PIDs, envelopes, activation, cuts, event IDs or acknowledgements.
///
/// # Errors
/// Reports failure to encode the fixed specification canonically.
pub fn complete_packet_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(CompletePacketContractValue)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?)
}

/// Encodes the distinct complete coordinator and restore-channel ingress contract.
///
/// # Errors
/// Reports canonical encoding failure of the fixed specification.
pub fn complete_ingress_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(CompleteIngressContractValue)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?)
}

/// Binds the distinct live source-five receipt grammar to its complete specification.
///
/// # Errors
/// Reports invalid fixed identity or canonical specification encoding failure.
pub fn complete_packet_receipt_schema() -> Result<SchemaRef, ProviderError> {
    packet_schema("source-owned.packet-receipt/5", complete_packet_contract()?)
}

/// Binds the complete native capture codec separately from live wrapper receipts.
///
/// # Errors
/// Reports invalid fixed identity or canonical specification encoding failure.
pub fn complete_packet_continuation_schema() -> Result<SchemaRef, ProviderError> {
    packet_schema(
        "source-owned.packet-native-continuation/5",
        complete_packet_contract()?,
    )
}

/// Binds complete coordinator and fresh target ingress to its distinct grammar.
///
/// # Errors
/// Reports invalid fixed identity or canonical specification encoding failure.
pub fn complete_packet_ingress_schema() -> Result<SchemaRef, ProviderError> {
    packet_schema(
        "source-owned.packet-ingress/5",
        complete_ingress_contract()?,
    )
}

fn packet_schema(identifier: &str, bytes: Vec<u8>) -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(identifier)?,
        version: 5,
        definition: canonical::content_ref(&bytes, "application/json")?,
        extensions: Default::default(),
    })
}

pub(super) fn complete_host_definition() -> Result<ContentRef, ProviderError> {
    // Exact immutable Host2 complete factory definition (qualified source32).
    // This inert reference does not replace that factory's original source guard.
    let bytes = canonical::canonical_json(
        &serde_json::to_value(CompleteHostDefinitionValue)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?;
    Ok(canonical::content_ref(&bytes, "application/json")?)
}

pub(super) fn complete_host_continuation_schema() -> Result<SchemaRef, ProviderError> {
    let bytes = canonical::canonical_json(
        &serde_json::to_value(CompleteHostContinuationValue)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?;
    Ok(SchemaRef {
        id: Id::new("source-owned.host-scheduling-continuation/2")?,
        version: 2,
        definition: canonical::content_ref(&bytes, "application/json")?,
        extensions: Default::default(),
    })
}

mod confirmation;
pub use confirmation::{
    PacketNative5ConfirmationDeclaration, complete_packet_confirmation_declaration,
};
mod ack_emitter;
pub use ack_emitter::{
    PacketNative5AckEmitterDeclaration, complete_packet_ack_emitter_declaration,
};

mod complete_restore;
mod fresh_restore;
pub use complete_restore::{
    PacketNative5CompleteRestoreDeclaration, complete_packet_capture_allocation_declaration,
    complete_packet_restore_declaration, complete_packet_restore_input_emitter_declaration,
};
pub use fresh_restore::complete_packet_fresh_restore_allocation_declaration;

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.
struct CompleteIngressContractValue;

impl serde::Serialize for CompleteIngressContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            ("schema", V::Text("source-owned.packet-ingress-contract/5")),
            ("identifier", V::Text("source-owned.packet-ingress/5")),
            ("coordinator", V::Text(PACKET_NATIVE5_COORDINATOR_SCHEMA)),
            (
                "roster",
                V::Text(
                    "Complete original native3 plus independently selected concrete Host2; empty preparation template followed by all four actual original preparations, each joined to retained native/host Arm before WorldActivate",
                ),
            ),
            (
                "ordinary_input",
                V::Text(
                    "Unchanged source-owned.packet-input/4 request-only extension and complete Stage/Commit4 source journals under fresh actual owner bindings",
                ),
            ),
            (
                "ordinary_bodies",
                V::Text(
                    "Unchanged baseline ActivationManifest; distinct complete CommonGrant5 restoration association and exact original output retirement population; producer.v1/reactive.v4 historical consumption bodies remain unchanged under the independently authenticated source-five owner association",
                ),
            ),
            (
                "restore_ingress",
                V::Text(
                    "Separate pre-Ready actual original target channel installs complete snapshot5 and locally source-authenticated settlement journal5, actual native protocol/counter history and complete original fresh target/InputACK association; no labels issuing association",
                ),
            ),
            (
                "limits",
                V::Object(&[
                    ("coordinator_bytes", V::Number(131072_u64)),
                    ("frame_bytes", V::Number(65536_u64)),
                    ("grant_retirement_bytes", V::Number(8192_u64)),
                    ("blob_chunk_bytes", V::Number(4096_u64)),
                ]),
            ),
            (
                "authority",
                V::Text(
                    "This fixed grammar provides no source currentness, capture, Ready, class acceptance or restored-native permission; installed whole-source/current/fresh-issuer validators remain mandatory",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

pub(crate) fn complete_ingress_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &CompleteIngressContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

// The same immutable rosters drive ordinary encoding and prospective counting.
struct CompletePacketContractValue;

impl serde::Serialize for CompletePacketContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            ("schema", V::Text("source-owned.packet-semantic-contract/5")),
            ("implementation", V::Text(PACKET_NATIVE5_IMPLEMENTATION)),
            (
                "preservation_contract",
                V::Text(PACKET_COMPLETE_LINEAGE_PROFILE),
            ),
            (
                "receipt",
                V::Text(
                    "source-owned.packet-receipt/5; complete original source association, immutable underlying producer-native/2 or reactive-native/4 journal and authenticated fresh restoration association",
                ),
            ),
            (
                "selected_facets",
                V::Array(&[
                    V::Text("source-owned.packet-exact/5"),
                    V::Text(PACKET_COMPLETE_LINEAGE_PROFILE),
                ]),
            ),
            (
                "required_features",
                V::Array(&[
                    V::Text(PACKET_COMPLETE_LINEAGE_FEATURE),
                    V::Text(super::input::PACKET_INPUT_FEATURE),
                ]),
            ),
            (
                "configuration",
                V::Text(
                    "Original packet-program/1 producer definition or packet-connected-program/4 reactive definition and all exact source-installed routes; no input/5 grammar",
                ),
            ),
            (
                "ordinary_input",
                V::Text(
                    "Unchanged packet-input/4 Stage/Commit4 under actual fresh bindings; ACK is nonexecuting byte custody and cannot replace consumed Commit",
                ),
            ),
            (
                "execution",
                V::Text(
                    "Original full Position exclusive cut, distinct Delivery then Reaction then next-microstep Publication; physical ExactRun and same-instant BoundarySettle remain separate representable baseline requests",
                ),
            ),
            (
                "closure",
                V::Object(&[
                    (
                        "model",
                        V::Text(
                            "ALL producer events/index/cursor/gate/outputs/grants/private-mutations/packet-effects/retired/failed or ALL reactive definition/live-owner/cursor/gate/reactions/delivered/publications/outputs/stages/commits/full original replies/grants/retired/counters/failed; exact reserved capacities and actual original event/input IDs",
                        ),
                    ),
                    (
                        "control",
                        V::Text(
                            "ALL installed selection, originals/full cached replies/evidence, begins/begin-requests, content/byte credit, realized/admitted/staged/active/fenced/effect-attempted/immediate/current-operation/terminals and every coordinator variant; pending original Capture reservation included",
                        ),
                    ),
                    (
                        "endpoint",
                        V::Text(
                            "ALL original request/reply records, pins, blob receiver, sequence/lifetime credit, parsed-frame boundary and actual managed sockets; unresolved partial bytes refuse",
                        ),
                    ),
                    (
                        "protocol",
                        V::Text(
                            "SAME original Connection/ProtocolSession/CorrelationGuard complete next counters, used IDs, requests/responses, prepared exchanges, negotiated codec and transport state; actual effect and provider-prefix acknowledgements drained",
                        ),
                    ),
                    (
                        "client",
                        V::Text(
                            "SAME original host controller/ClientCustody request-origin namespaces, complete request/response and provider-origin Blob/ACK journals, content, lifetime budgets and semantic active opaque activation; no alternate controller or restored live labels",
                        ),
                    ),
                    (
                        "host",
                        V::Text(
                            "Independent concrete Host2 codec retains SAME Runtime7/Scheduling1 and complete typed payload/lineage closure; full four-owner world and connection histories remain jointly required",
                        ),
                    ),
                ]),
            ),
            (
                "capture",
                V::Object(&[
                    (
                        "operation",
                        V::Text(
                            "Baseline Begin/Capture with core-issued administrative ticket operation ID and capture owner, unchanged full capture_id/participant_ids/cut_id/Position/ordinal/superdense-v1 and named preservation contract; no modeled grant synthesis",
                        ),
                    ),
                    (
                        "pending_snapshot",
                        V::Text(
                            "Complete native-continuation/5 bytes retain current original Capture request/reservation before response settlement, independent global administrative cut and actual local model cursor; no cursor normalization",
                        ),
                    ),
                    (
                        "unchanged_cut",
                        V::Text(
                            "Independent source-owned unchanged-cut anchor; CaptureResult references snapshot and anchor, never its own settlement journal",
                        ),
                    ),
                    (
                        "settlement",
                        V::Text(
                            "Host Source5 locally seals native-capture-journal/5 from SAME authenticated complete original Capture pair and ALL actual provider BlobBegin/Chunk/Finish/ACK prefix and actual counter/credit transitions; this journal is never exported over the captured channel",
                        ),
                    ),
                    (
                        "dependencies",
                        V::Text(
                            "Snapshot names only actual pre-settlement dependencies; settlement journal names snapshot/anchor/raw original bodies; owner inventory names both. No snapshot-to-settlement edge or self-hash suffix",
                        ),
                    ),
                ]),
            ),
            (
                "restore",
                V::Object(&[
                    (
                        "whole_source",
                        V::Text(
                            "Private signed archive index3 plus actual installed complete factory verifies full measured code, world, runtime/scheduling/admin journal1, all per-owner leaves and exact dependency closure before target effects",
                        ),
                    ),
                    (
                        "native_target",
                        V::Text(
                            "Genuine fresh original child/datagram/control owners plus selected fresh Hello codec installed before authenticated original counter/history adoption; exact pending-to-settled prefix transition applied before Ready with effect gate held",
                        ),
                    ),
                    (
                        "history",
                        V::Text(
                            "Historical source PID, sessions, envelopes, Stage/Commit cuts/ACKs, event IDs, original grants/retirements/used IDs/capacities/budgets unchanged; fresh live PID/controller/activation associations are separately authenticated",
                        ),
                    ),
                    (
                        "restored_inputs",
                        V::Text(
                            "Distinct CommonGrant5 association joins original consumed cut to opaque fresh core target/InputACK context; old CommonGrant4 equality remains strict and no Stage/Begin replay occurs",
                        ),
                    ),
                    (
                        "host_target",
                        V::Text(
                            "One-shot archive-origin Host2 ticket, SAME genuine fresh scheduler slot and original restoration context, historical administrative ledger installed before native callbacks/Arm",
                        ),
                    ),
                    (
                        "admission",
                        V::Text(
                            "Actual source-owned validate/admit/install restoration callbacks and complete native suffix/current checks conjunct core Event/body/ancestry checks; portable decoded content or live-source validation cannot stand for restoration",
                        ),
                    ),
                ]),
            ),
            (
                "limits",
                V::Object(&[
                    ("native_snapshot_bytes", V::Number(8388608)),
                    ("unchanged_cut_anchor_bytes", V::Number(8192)),
                    ("provider_prefix_frames", V::Number(4096)),
                    ("provider_request_window", V::Number(32)),
                    ("ordinary_frame_bytes", V::Number(65536)),
                    ("raw_grant_retirement_bytes", V::Number(8192)),
                    ("coordinator_bytes", V::Number(131072)),
                ]),
            ),
            (
                "selected_geometry",
                V::Text(
                    "Limits are hard ceilings, not mandatory selected allocations. Actual finite ordinary frame/snapshot/bank/window limits may be smaller; Hello retains its separate limit. Source-checked aggregate native3 plus Host2 peak and retention demand must fit the independently installed 512MiB whole-world budget before effects. No smaller selection is qualified by this document.",
                ),
            ),
            (
                "preflight",
                V::Text(
                    "Full per-owner raw/encoded/canonical transient and retained-copy geometry plus ALL source/client/prefix leaves reserved for all four owners before Child and first Capture; minimum snapshot/journal slots are insufficient",
                ),
            ),
            (
                "guarantees",
                V::Text(
                    "Only separately installed complete factory: unqualified repeatability, complete-model/exact continuation/durable restart; no isolated fork, conditional replay, CPU/Clock or qualification from syntax",
                ),
            ),
            (
                "authority",
                V::Text(
                    "Actual original opaque capture ticket, independent retained active activation, source guards and complete installed native/host/factory issuers are mandatory; old Source2/3/4 CaptureNone/Unsupported routes unchanged",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

struct CompleteHostDefinitionValue;

impl serde::Serialize for CompleteHostDefinitionValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.host-scheduling-complete-owner/2"),
            ),
            (
                "state",
                V::Text(
                    "same original Runtime7/Scheduling1 allocation plus all retained original payload and lineage bodies",
                ),
            ),
            (
                "capture",
                V::Text(
                    "core-issued unchanged-cut administrative ticket; original producer before any native request; once-owned snapshot transfer; explicit host settlement journal",
                ),
            ),
            (
                "restore",
                V::Text(
                    "signed complete index3 and genuine fresh Runtime7 context; original host snapshot plus core administrative lifetime ledger before Arm; one original scheduler installation; no replay",
                ),
            ),
            (
                "profile",
                V::Text("source-owned.host-scheduling-original-lineage/2"),
            ),
            (
                "native_scope",
                V::Text(
                    "host coordinator and declared connection resources only; native peers require independently installed native-five capture and genuine fresh adoption",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

struct CompleteHostContinuationValue;

impl serde::Serialize for CompleteHostContinuationValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.host-scheduling-continuation/2"),
            ),
            (
                "fields",
                V::Array(&[
                    V::Text("schema_version"),
                    V::Text("source"),
                    V::Text("runtime"),
                    V::Text("scheduling"),
                    V::Text("objects"),
                ]),
            ),
            (
                "runtime",
                V::Text(
                    "closed original-lineage Runtime7; complete native ancestry and typed original bodies",
                ),
            ),
            (
                "administration",
                V::Text(
                    "separate runtime-original-capture-journal/1 in index3; unchanged Runtime7 and Coordinator7",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

/// Counts all static contract generators called by one complete coordinator validator.
///
/// Each native validation retains receipt/continuation/ingress references while
/// another definition is encoded. Summing the complete phases for all3 peers
/// and the independent Host validators is conservative; no schema DOM is made.
pub(crate) fn complete_coordinator_contract_storage_data(
    maximum: usize,
) -> Result<usize, ProviderError> {
    use crate::retained_metadata::{
        RetainedProtocolMetadataFacts, serialization_storage::actual_serialization_storage_data,
    };
    let packet = actual_serialization_storage_data(
        &CompletePacketContractValue,
        RetainedProtocolMetadataFacts::default(),
        maximum,
    )?
    .requested_total()?;
    let ingress = complete_ingress_contract_storage_data(maximum)?.requested_total()?;
    let host_definition = actual_serialization_storage_data(
        &CompleteHostDefinitionValue,
        RetainedProtocolMetadataFacts::default(),
        maximum,
    )?
    .requested_total()?;
    let host_continuation = actual_serialization_storage_data(
        &CompleteHostContinuationValue,
        RetainedProtocolMetadataFacts::default(),
        maximum,
    )?
    .requested_total()?;
    // Three native validators each call receipt + continuation + ingress;
    // Host validation and host_configuration independently build the definition.
    [
        packet,
        packet,
        ingress,
        packet,
        packet,
        ingress,
        packet,
        packet,
        ingress,
        host_definition,
        host_definition,
        host_continuation,
        // Nine native SchemaRefs and five Host definition/configuration/schema
        // refs remain independent. SchemaRef includes ContentRef inline; Id
        // grammar supplies its finite128-byte dynamic child bound.
        14 * (std::mem::size_of::<SchemaRef>()
            + 128
            + "blake3-256".len()
            + "cnp.blob.v1".len()
            + 64
            + "application/json".len()),
    ]
    .into_iter()
    .try_fold(0usize, |sum, bytes| {
        sum.checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "complete coordinator contract storage",
            ))
    })
}

#[cfg(test)]
#[path = "continuation_contracts/precision_tests.rs"]
mod precision_tests;

#[path = "continuation_contracts/initial15.rs"]
mod initial15;
pub use initial15::complete_packet_contract_history_data;
