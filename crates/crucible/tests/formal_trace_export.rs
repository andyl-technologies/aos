//! Checks T-ASRT-9 external-only formal trace export.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    AssertionId, ConditionEvaluationError, ContentHash, EventAttributeValue,
    EventDiagnosticPayload, EventId, EventLevel, ExternalFormalTraceExporter, FaultId,
    GuestAssertionDetail, GuestAssertionKind, GuestAssertionMarker, Icount, NodeId,
    ObservableEvent, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry,
    SchedulerEventLogPayload, VirtualTime,
};

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn retained_log() -> Vec<SchedulerEventLogEntry> {
    let delivered = ObservableEvent::network_delivered(time(7), None, b"ack".to_vec());
    vec![
        crucible::test_support::condition_observation_entry_for_test(0, &delivered),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            time(7),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ]
}

#[test]
fn formal_trace_export_is_deterministic_trace_bytes_only() {
    let event_log = retained_log();

    let first = ExternalFormalTraceExporter::export_event_log(&event_log)
        .expect("retained event log should export");
    let second = ExternalFormalTraceExporter::export_event_log(&event_log)
        .expect("retained event log should export deterministically");

    assert_eq!(first, second);
    assert_eq!(first.format(), "crucible.external-formal-trace.v1");
    assert_eq!(first.entry_count(), 2);
    assert_eq!(first.content_hash(), ContentHash::from_bytes(first.bytes()));
    let text = std::str::from_utf8(first.bytes()).expect("trace export should be utf-8");
    assert!(text.contains("format=crucible.external-formal-trace.v1"));
    assert!(text.contains("scheduler_event_log_previous_prefix="));
    assert!(text.contains("entry_begin"));
    assert!(text.contains("entry.sequence=0"));
    assert!(text.contains("entry.sequence=1"));
    assert!(text.contains("entry.payload_begin"));
    assert!(text.contains("payload=observable"));
    assert!(text.contains("observable=network-delivered"));
    assert!(text.contains("payload=evaluation-boundary"));
    assert!(text.contains("boundary.kind=quantum"));
    assert!(!text.contains("entry.payload=Observable"));
    assert!(!text.contains("NetworkDelivered"));
    assert!(!text.contains("Quantum"));
}

#[test]
fn formal_trace_export_rejects_invalid_recorded_log() {
    let mut event_log = retained_log();
    event_log[0] = crucible::test_support::condition_entry_with_content_hash_for_test(
        event_log[0].clone(),
        ContentHash::from_bytes(b"corrupt trace entry"),
    );

    let error = ExternalFormalTraceExporter::export_event_log(&event_log)
        .expect_err("corrupt retained log should not export");

    assert!(matches!(
        error,
        ConditionEvaluationError::InvalidEventLogEntryHash { sequence: 0 }
    ));
}

#[test]
fn formal_trace_export_hex_encodes_free_form_strings() {
    let marker = GuestAssertionMarker::new(
        AssertionId::from_name("assert\nid"),
        "message\nspoof=entry",
        GuestAssertionKind::Reachable,
        true,
        true,
        vec![GuestAssertionDetail::new(
            "key\nwith=line",
            "value\nentry_end",
        )],
        "guest.rs\n42",
    );
    let event = ObservableEvent::guest_assertion_marker(
        Icount { retired: 13 },
        NodeId {
            name: String::from("node\nzero"),
        },
        marker,
    );
    let log = vec![crucible::test_support::condition_observation_entry_for_test(0, &event)];

    let export = ExternalFormalTraceExporter::export_event_log(&log)
        .expect("retained marker log should export");
    let text = std::str::from_utf8(export.bytes()).expect("trace export should be utf-8");

    assert!(text.contains("observable=guest-assertion-marker"));
    assert!(text.contains("observable.marker.message.bytes="));
    assert!(text.contains("6d6573736167650a73706f6f663d656e747279"));
    assert!(!text.contains("message\nspoof=entry"));
    assert!(!text.contains("key\nwith=line"));
    assert!(!text.contains("value\nentry_end"));
    assert!(!text.contains("guest.rs\n42"));
    assert!(!text.contains("node\nzero"));
}

#[test]
fn formal_trace_export_includes_typed_diagnostic_details() {
    let mut details = BTreeMap::new();
    details.insert(String::from("flag"), EventAttributeValue::Bool(true));
    details.insert(String::from("count"), EventAttributeValue::U64(37));
    details.insert(
        String::from("detail\nkey"),
        EventAttributeValue::String(String::from("value\nentry_end")),
    );
    details.insert(
        String::from("bytes"),
        EventAttributeValue::Bytes(vec![0, 10, 255]),
    );
    details.insert(
        String::from("node"),
        EventAttributeValue::Node(NodeId {
            name: String::from("node\nzero"),
        }),
    );
    details.insert(
        String::from("event"),
        EventAttributeValue::Event(EventId::from_name("event\nid")),
    );
    details.insert(
        String::from("fault"),
        EventAttributeValue::Fault(FaultId {
            name: String::from("fault\nid"),
        }),
    );
    details.insert(
        String::from("time"),
        EventAttributeValue::VirtualTime(time(9)),
    );
    details.insert(
        String::from("icount"),
        EventAttributeValue::Icount(Icount { retired: 12 }),
    );
    details.insert(
        String::from("severity"),
        EventAttributeValue::Level(EventLevel::Error),
    );
    let log = vec![crucible::test_support::condition_payload_entry_for_test(
        0,
        time(3),
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            "diag\nname",
            EventLevel::Warn,
            details,
        )),
    )];

    let export =
        ExternalFormalTraceExporter::export_event_log(&log).expect("diagnostic log should export");
    let text = std::str::from_utf8(export.bytes()).expect("trace export should be utf-8");

    assert!(text.contains("payload=diagnostic"));
    assert!(text.contains("diagnostic.name.bytes=646961670a6e616d65"));
    assert!(text.contains("diagnostic.level=warn"));
    assert!(text.contains("diagnostic.details=10"));
    for required in [
        ".value.type=bool",
        ".value.bool=true",
        ".value.type=u64",
        ".value.u64=37",
        ".value.type=string",
        ".value.string.bytes=76616c75650a656e7472795f656e64",
        ".value.type=bytes",
        ".value.bytes=000aff",
        ".value.type=node",
        ".value.node.bytes=6e6f64650a7a65726f",
        ".value.type=event",
        ".value.event.bytes=6576656e740a6964",
        ".value.type=fault",
        ".value.fault.bytes=6661756c740a6964",
        ".value.type=virtual-time",
        ".value.ticks=9",
        ".value.type=icount",
        ".value.retired=12",
        ".value.type=level",
        ".value.level=error",
    ] {
        assert!(
            text.contains(required),
            "diagnostic formal trace missing `{required}`"
        );
    }
    assert!(!text.contains("diag\nname"));
    assert!(!text.contains("detail\nkey"));
    assert!(!text.contains("value\nentry_end"));
    assert!(!text.contains("node\nzero"));
    assert!(!text.contains("event\nid"));
    assert!(!text.contains("fault\nid"));
}

#[test]
fn formal_trace_export_does_not_add_runtime_formal_evaluator() {
    let trigger = concat!(
        include_str!("../src/trigger/assertions.rs"),
        include_str!("../src/trigger/evidence.rs"),
    );
    let exporter_block = trigger
        .split("pub struct ExternalFormalTraceExporter")
        .nth(1)
        .expect("external formal trace exporter should exist")
        .split("pub struct OfflineAssertionChecker")
        .next()
        .expect("offline assertion checker should follow trace exporter");

    for required in [
        "pub fn export_event_log",
        "SchedulerEventLogEntry",
        "ContentHash::from_bytes",
        "external_formal_trace_bytes(entries)",
        "validate_recorded_event_log_entries",
    ] {
        assert!(
            exporter_block.contains(required),
            "formal trace export must include {required}"
        );
    }
    let external_trace_block = trigger
        .split("fn external_formal_trace_bytes")
        .nth(1)
        .expect("external trace byte helper should exist")
        .split("fn condition_prefix_from_recorded_log")
        .next()
        .expect("external trace helpers should precede recorded log helper");
    for required in [
        "fn external_formal_trace_entry_material",
        "fn external_scheduler_event_log_payload_material",
        "fn external_observable_event_payload_material",
        "fn external_scheduler_evaluation_boundary_kind_label",
    ] {
        assert!(
            external_trace_block.contains(required),
            "formal trace export helpers must include {required}"
        );
    }
    for forbidden in [":?", "scheduler_event_log_segment_bytes"] {
        assert!(
            !external_trace_block.contains(forbidden),
            "formal trace export must not inherit Debug or scheduler segment material: {forbidden}"
        );
    }
    for (path, source) in [
        ("crates/crucible/Cargo.toml", include_str!("../Cargo.toml")),
        ("src/backend.rs", include_str!("../src/backend.rs")),
        (
            "src/device_subnode.rs",
            include_str!("../src/device_subnode.rs"),
        ),
        ("src/device.rs", include_str!("../src/device.rs")),
        ("src/decision.rs", include_str!("../src/decision.rs")),
        ("src/lib.rs", include_str!("../src/lib.rs")),
        (
            "src/model/canonical.rs",
            include_str!("../src/model/canonical.rs"),
        ),
        ("src/model.rs", include_str!("../src/model.rs")),
        (
            "src/model/binary_plan.rs",
            include_str!("../src/model/binary_plan.rs"),
        ),
        (
            "src/model/binary_state.rs",
            include_str!("../src/model/binary_state.rs"),
        ),
        (
            "src/model/configuration.rs",
            include_str!("../src/model/configuration.rs"),
        ),
        ("src/model/debug.rs", include_str!("../src/model/debug.rs")),
        (
            "src/model/engine.rs",
            include_str!("../src/model/engine.rs"),
        ),
        (
            "src/model/exploration.rs",
            include_str!("../src/model/exploration.rs"),
        ),
        (
            "src/model/failure.rs",
            include_str!("../src/model/failure.rs"),
        ),
        (
            "src/model/failure/material.rs",
            include_str!("../src/model/failure/material.rs"),
        ),
        (
            "src/model/failure/model.rs",
            include_str!("../src/model/failure/model.rs"),
        ),
        (
            "src/model/family.rs",
            include_str!("../src/model/family.rs"),
        ),
        (
            "src/model/material.rs",
            include_str!("../src/model/material.rs"),
        ),
        (
            "src/model/materialized.rs",
            include_str!("../src/model/materialized.rs"),
        ),
        (
            "src/model/plan_properties.rs",
            include_str!("../src/model/plan_properties.rs"),
        ),
        (
            "src/model/reproduction.rs",
            include_str!("../src/model/reproduction.rs"),
        ),
        (
            "src/model/runtime.rs",
            include_str!("../src/model/runtime.rs"),
        ),
        (
            "src/model/scenario.rs",
            include_str!("../src/model/scenario.rs"),
        ),
        (
            "src/model/store_artifacts.rs",
            include_str!("../src/model/store_artifacts.rs"),
        ),
        (
            "src/model/temporal_graph.rs",
            include_str!("../src/model/temporal_graph.rs"),
        ),
        (
            "src/model/temporal_graph/core.rs",
            include_str!("../src/model/temporal_graph/core.rs"),
        ),
        (
            "src/model/temporal_graph/debug_helpers.rs",
            include_str!("../src/model/temporal_graph/debug_helpers.rs"),
        ),
        (
            "src/model/temporal_graph/search_storage.rs",
            include_str!("../src/model/temporal_graph/search_storage.rs"),
        ),
        ("src/model/time.rs", include_str!("../src/model/time.rs")),
        ("src/model/toml.rs", include_str!("../src/model/toml.rs")),
        (
            "src/model/topology_faults.rs",
            include_str!("../src/model/topology_faults.rs"),
        ),
        (
            "src/model/validation.rs",
            include_str!("../src/model/validation.rs"),
        ),
        (
            "src/model/workload.rs",
            include_str!("../src/model/workload.rs"),
        ),
        ("src/node_fault.rs", include_str!("../src/node_fault.rs")),
        ("src/scheduler.rs", include_str!("../src/scheduler.rs")),
        (
            "src/scheduler/control_state.rs",
            include_str!("../src/scheduler/control_state.rs"),
        ),
        (
            "src/scheduler/event_codec.rs",
            include_str!("../src/scheduler/event_codec.rs"),
        ),
        (
            "src/scheduler/event_log.rs",
            include_str!("../src/scheduler/event_log.rs"),
        ),
        (
            "src/scheduler/liveness.rs",
            include_str!("../src/scheduler/liveness.rs"),
        ),
        (
            "src/scheduler/runtime_state.rs",
            include_str!("../src/scheduler/runtime_state.rs"),
        ),
        (
            "src/scheduler/scenario.rs",
            include_str!("../src/scheduler/scenario.rs"),
        ),
        (
            "src/scheduler/single_scheduler_drive.rs",
            include_str!("../src/scheduler/single_scheduler_drive.rs"),
        ),
        (
            "src/scheduler/single_scheduler_state.rs",
            include_str!("../src/scheduler/single_scheduler_state.rs"),
        ),
        (
            "src/scheduler/topology.rs",
            include_str!("../src/scheduler/topology.rs"),
        ),
        ("src/sim_backend.rs", include_str!("../src/sim_backend.rs")),
        ("src/trigger.rs", include_str!("../src/trigger.rs")),
        (
            "src/trigger/assertions.rs",
            include_str!("../src/trigger/assertions.rs"),
        ),
        (
            "src/trigger/conditions.rs",
            include_str!("../src/trigger/conditions.rs"),
        ),
        (
            "src/trigger/evaluation.rs",
            include_str!("../src/trigger/evaluation.rs"),
        ),
        (
            "src/trigger/event_graph.rs",
            include_str!("../src/trigger/event_graph.rs"),
        ),
        (
            "src/trigger/evidence.rs",
            include_str!("../src/trigger/evidence.rs"),
        ),
        (
            "src/trigger/observability.rs",
            include_str!("../src/trigger/observability.rs"),
        ),
    ] {
        for forbidden in [
            "struct Solver",
            "enum Solver",
            "trait Solver",
            "struct ModelChecker",
            "enum ModelChecker",
            "trait ModelChecker",
            "struct SpecEvaluator",
            "enum SpecEvaluator",
            "trait SpecEvaluator",
            "check_conformance",
            "evaluate_spec",
            "model_check",
            "smt",
            "z3",
            "tla",
            "alloy",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} must not add an in-runtime formal evaluator: {forbidden}"
            );
        }
    }

    for forbidden in [
        "ModelChecker",
        "SpecEvaluator",
        "check_conformance",
        "evaluate_spec",
        "model_check",
        "smt",
        "z3",
        "tla",
        "alloy",
    ] {
        assert!(
            !exporter_block.contains(forbidden),
            "formal trace export must not add an in-runtime evaluator: {forbidden}"
        );
    }
}
