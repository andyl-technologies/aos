//! Actual public reference-provider protocol and source-built conformance CLI.
//!
//! These checks establish observed protocol behavior of real local processes.
//! They do not qualify exact state capture, deterministic execution, CPU-model
//! fidelity, or physical pause. The reference profile advertises those limits.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- actual-process fixture setup and independent protocol oracles deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- These conformance reference tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crucible_node_contract::{Repeatability, canonical};
use crucible_node_provider::conformance::{ConformanceReport, UnixProbeConnector, run};

#[path = "conformance_reference/fixture.rs"]
mod fixture;
#[path = "conformance_reference/lifecycle.rs"]
mod lifecycle;
#[path = "conformance_reference/scenario.rs"]
mod scenario;

fn provider() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_crucible-reference-provider"))
}

fn device() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_crucible-reference-device"))
}

#[test]
fn actual_public_provider_preserves_original_requests_across_same_incarnation_reconnect() {
    let service = fixture::NativeService::launch(provider(), device(), 64);
    let plan = scenario::basic_protocol(&service);
    let mut connector = UnixProbeConnector::new(
        service.socket(),
        rustix::process::geteuid().as_raw(),
        provider(),
        Duration::from_secs(3),
    )
    .unwrap();

    let report = run(&plan, &mut connector, service.private_bindings.clone()).unwrap();

    assert!(report.passed(), "{:?}", report.results);
    assert!(report.protocol_only);
    assert_eq!(report.endpoints.len(), 2);
    assert!(
        report
            .endpoints
            .iter()
            .all(|endpoint| endpoint.peer_pid.get() == u64::from(service.process.id()))
    );
    assert_eq!(
        service.profile.guarantees.repeatability,
        Repeatability::Nondeterministic
    );
    assert_eq!(report.results[0].request_identity, None);
    assert_eq!(report.results[0].response_identity, None);
}

#[test]
fn source_built_cli_emits_compact_measured_protocol_report_for_actual_provider() {
    let service = fixture::NativeService::launch(provider(), device(), 64);
    let plan = scenario::basic_protocol(&service);
    let plan_path = service.private_file("plan.json", &serde_json::to_value(&plan).unwrap());
    let binding_path = service.private_file(
        "private-bindings.json",
        &serde_json::to_value(&service.private_bindings).unwrap(),
    );
    let report_path = service.directory.join("report.json");

    let result = Command::new(env!("CARGO_BIN_EXE_crucible-node-conformance"))
        .arg(service.socket())
        .arg(provider())
        .arg(plan_path)
        .arg(&report_path)
        .arg(binding_path)
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "conformance CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(&report_path).unwrap();
    let report: ConformanceReport =
        serde_json::from_value(canonical::parse_json(&bytes, 1_048_576).unwrap()).unwrap();
    assert!(report.passed());
    assert!(report.protocol_only);
    assert!(report.harness_executable.is_some());
    assert!(
        report
            .endpoints
            .iter()
            .all(|endpoint| endpoint.peer_pid.get() == u64::from(service.process.id()))
    );
    assert!(
        bytes.len() < 16 * 1024,
        "report retained unexpectedly large control evidence"
    );
    let text = String::from_utf8(bytes).unwrap();
    for value in service.private_bindings.values() {
        assert!(
            !text.contains(value.as_str().unwrap()),
            "private credential entered protocol report"
        );
    }
}

#[test]
fn actual_native_window_preserves_input_and_output_custody_until_explicit_consumption() {
    let service = fixture::NativeService::launch(provider(), device(), 1);
    let plan = lifecycle::native_window(&service);
    let mut connector = UnixProbeConnector::new(
        service.socket(),
        rustix::process::geteuid().as_raw(),
        provider(),
        Duration::from_secs(3),
    )
    .unwrap();

    let report = run(&plan, &mut connector, service.private_bindings.clone()).unwrap();

    assert!(report.passed(), "{:?}", report.results);
    assert!(report.protocol_only);
    assert!(
        report
            .endpoints
            .iter()
            .all(|endpoint| endpoint.peer_pid.get() == u64::from(service.process.id()))
    );
}

#[test]
fn public_linked_launch_preserves_actual_native_checksum_and_original_custody() {
    let service = fixture::NativeService::launch_public_linked(provider(), device(), 1, false);
    let plan = lifecycle::native_window(&service);
    let mut connector = UnixProbeConnector::new(
        service.socket(),
        rustix::process::geteuid().as_raw(),
        provider(),
        Duration::from_secs(3),
    )
    .unwrap();

    let report = run(&plan, &mut connector, service.private_bindings.clone()).unwrap();

    assert!(report.passed(), "{:?}", report.results);
    assert!(report.protocol_only);
    assert_eq!(
        service.profile.descriptor.ports[0].lanes[0].payload_schema,
        service.profile.descriptor.ports[0].lanes[1].payload_schema
    );
    assert!(
        report
            .endpoints
            .iter()
            .all(|endpoint| endpoint.peer_pid.get() == u64::from(service.process.id()))
    );
}

#[test]
fn public_closed_source_uses_distinct_measured_profile_through_versioned_launch() {
    let service = fixture::NativeService::launch_public_linked(provider(), device(), 1, true);
    let plan = lifecycle::native_window(&service);
    let mut connector = UnixProbeConnector::new(
        service.socket(),
        rustix::process::geteuid().as_raw(),
        provider(),
        Duration::from_secs(3),
    )
    .unwrap();

    let report = run(&plan, &mut connector, service.private_bindings.clone()).unwrap();

    assert!(report.passed(), "{:?}", report.results);
    assert_eq!(service.profile.descriptor.ports[0].lanes.len(), 1);
    assert_eq!(
        service.profile.descriptor.ports[0].lanes[0].direction,
        crucible_node_contract::Direction::Output
    );
}

#[test]
fn actual_provider_enforces_receiving_limits_features_and_malformed_stream_fencing() {
    for scenario in [
        scenario::negotiated_limits,
        scenario::unsupported_required_feature,
        scenario::malformed_stream,
    ] {
        let service = fixture::NativeService::launch(provider(), device(), 64);
        let plan = scenario(&service);
        let mut connector = UnixProbeConnector::new(
            service.socket(),
            rustix::process::geteuid().as_raw(),
            provider(),
            Duration::from_secs(3),
        )
        .unwrap();

        let report = run(&plan, &mut connector, service.private_bindings.clone()).unwrap();

        assert!(report.passed(), "{:?}", report.results);
        assert!(report.protocol_only);
    }
}
