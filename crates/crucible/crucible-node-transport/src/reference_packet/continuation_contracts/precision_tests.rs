//! Checks shared contract rosters against the exact old ordinary JSON bodies.
use super::*;
use crucible_node_format::canonical;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn complete_packet_contract_preserves_original_literal_bytes() -> TestResult {
    let bytes = canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-semantic-contract/5",
        "implementation":PACKET_NATIVE5_IMPLEMENTATION,
        "preservation_contract":PACKET_COMPLETE_LINEAGE_PROFILE,
        "receipt":"source-owned.packet-receipt/5; complete original source association, immutable underlying producer-native/2 or reactive-native/4 journal and authenticated fresh restoration association",
        "selected_facets":["source-owned.packet-exact/5",PACKET_COMPLETE_LINEAGE_PROFILE],
        "required_features":[PACKET_COMPLETE_LINEAGE_FEATURE,crate::reference_packet::input::PACKET_INPUT_FEATURE],
        "configuration":"Original packet-program/1 producer definition or packet-connected-program/4 reactive definition and all exact source-installed routes; no input/5 grammar",
        "ordinary_input":"Unchanged packet-input/4 Stage/Commit4 under actual fresh bindings; ACK is nonexecuting byte custody and cannot replace consumed Commit",
        "execution":"Original full Position exclusive cut, distinct Delivery then Reaction then next-microstep Publication; physical ExactRun and same-instant BoundarySettle remain separate representable baseline requests",
        "closure":{
            "model":"ALL producer events/index/cursor/gate/outputs/grants/private-mutations/packet-effects/retired/failed or ALL reactive definition/live-owner/cursor/gate/reactions/delivered/publications/outputs/stages/commits/full original replies/grants/retired/counters/failed; exact reserved capacities and actual original event/input IDs",
            "control":"ALL installed selection, originals/full cached replies/evidence, begins/begin-requests, content/byte credit, realized/admitted/staged/active/fenced/effect-attempted/immediate/current-operation/terminals and every coordinator variant; pending original Capture reservation included",
            "endpoint":"ALL original request/reply records, pins, blob receiver, sequence/lifetime credit, parsed-frame boundary and actual managed sockets; unresolved partial bytes refuse",
            "protocol":"SAME original Connection/ProtocolSession/CorrelationGuard complete next counters, used IDs, requests/responses, prepared exchanges, negotiated codec and transport state; actual effect and provider-prefix acknowledgements drained",
            "client":"SAME original host controller/ClientCustody request-origin namespaces, complete request/response and provider-origin Blob/ACK journals, content, lifetime budgets and semantic active opaque activation; no alternate controller or restored live labels",
            "host":"Independent concrete Host2 codec retains SAME Runtime7/Scheduling1 and complete typed payload/lineage closure; full four-owner world and connection histories remain jointly required"
        },
        "capture":{
            "operation":"Baseline Begin/Capture with core-issued administrative ticket operation ID and capture owner, unchanged full capture_id/participant_ids/cut_id/Position/ordinal/superdense-v1 and named preservation contract; no modeled grant synthesis",
            "pending_snapshot":"Complete native-continuation/5 bytes retain current original Capture request/reservation before response settlement, independent global administrative cut and actual local model cursor; no cursor normalization",
            "unchanged_cut":"Independent source-owned unchanged-cut anchor; CaptureResult references snapshot and anchor, never its own settlement journal",
            "settlement":"Host Source5 locally seals native-capture-journal/5 from SAME authenticated complete original Capture pair and ALL actual provider BlobBegin/Chunk/Finish/ACK prefix and actual counter/credit transitions; this journal is never exported over the captured channel",
            "dependencies":"Snapshot names only actual pre-settlement dependencies; settlement journal names snapshot/anchor/raw original bodies; owner inventory names both. No snapshot-to-settlement edge or self-hash suffix"
        },
        "restore":{
            "whole_source":"Private signed archive index3 plus actual installed complete factory verifies full measured code, world, runtime/scheduling/admin journal1, all per-owner leaves and exact dependency closure before target effects",
            "native_target":"Genuine fresh original child/datagram/control owners plus selected fresh Hello codec installed before authenticated original counter/history adoption; exact pending-to-settled prefix transition applied before Ready with effect gate held",
            "history":"Historical source PID, sessions, envelopes, Stage/Commit cuts/ACKs, event IDs, original grants/retirements/used IDs/capacities/budgets unchanged; fresh live PID/controller/activation associations are separately authenticated",
            "restored_inputs":"Distinct CommonGrant5 association joins original consumed cut to opaque fresh core target/InputACK context; old CommonGrant4 equality remains strict and no Stage/Begin replay occurs",
            "host_target":"One-shot archive-origin Host2 ticket, SAME genuine fresh scheduler slot and original restoration context, historical administrative ledger installed before native callbacks/Arm",
            "admission":"Actual source-owned validate/admit/install restoration callbacks and complete native suffix/current checks conjunct core Event/body/ancestry checks; portable decoded content or live-source validation cannot stand for restoration"
        },
        "limits":{"native_snapshot_bytes":8388608,"unchanged_cut_anchor_bytes":8192,"provider_prefix_frames":4096,"provider_request_window":32,"ordinary_frame_bytes":65536,"raw_grant_retirement_bytes":8192,"coordinator_bytes":131072},
        "selected_geometry":"Limits are hard ceilings, not mandatory selected allocations. Actual finite ordinary frame/snapshot/bank/window limits may be smaller; Hello retains its separate limit. Source-checked aggregate native3 plus Host2 peak and retention demand must fit the independently installed 512MiB whole-world budget before effects. No smaller selection is qualified by this document.",
        "preflight":"Full per-owner raw/encoded/canonical transient and retained-copy geometry plus ALL source/client/prefix leaves reserved for all four owners before Child and first Capture; minimum snapshot/journal slots are insufficient",
        "guarantees":"Only separately installed complete factory: unqualified repeatability, complete-model/exact continuation/durable restart; no isolated fork, conditional replay, CPU/Clock or qualification from syntax",
        "authority":"Actual original opaque capture ticket, independent retained active activation, source guards and complete installed native/host/factory issuers are mandatory; old Source2/3/4 CaptureNone/Unsupported routes unchanged"
    }))?;
    assert_eq!(complete_packet_contract()?, bytes);
    Ok(())
}

#[test]
fn complete_host_definition_preserves_original_literal_bytes() -> TestResult {
    let bytes = canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.host-scheduling-complete-owner/2",
        "state":"same original Runtime7/Scheduling1 allocation plus all retained original payload and lineage bodies",
        "capture":"core-issued unchanged-cut administrative ticket; original producer before any native request; once-owned snapshot transfer; explicit host settlement journal",
        "restore":"signed complete index3 and genuine fresh Runtime7 context; original host snapshot plus core administrative lifetime ledger before Arm; one original scheduler installation; no replay",
        "profile":"source-owned.host-scheduling-original-lineage/2",
        "native_scope":"host coordinator and declared connection resources only; native peers require independently installed native-five capture and genuine fresh adoption"
    }))?;
    assert_eq!(
        complete_host_definition()?,
        canonical::content_ref(&bytes, "application/json")?
    );
    Ok(())
}

#[test]
fn complete_host_continuation_schema_preserves_original_literal_bytes() -> TestResult {
    let bytes = canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.host-scheduling-continuation/2",
        "fields":["schema_version","source","runtime","scheduling","objects"],
        "runtime":"closed original-lineage Runtime7; complete native ancestry and typed original bodies",
        "administration":"separate runtime-original-capture-journal/1 in index3; unchanged Runtime7 and Coordinator7"
    }))?;
    assert_eq!(
        complete_host_continuation_schema()?.definition,
        canonical::content_ref(&bytes, "application/json")?
    );
    Ok(())
}

#[test]
fn complete_contract_phase_quote_preserves_exact_and_one_short_boundary() -> TestResult {
    let bytes = complete_coordinator_contract_storage_data(usize::MAX)?;
    assert!(bytes > 0);
    assert_eq!(complete_coordinator_contract_storage_data(bytes)?, bytes);
    assert!(complete_coordinator_contract_storage_data(bytes - 1).is_err());
    Ok(())
}
