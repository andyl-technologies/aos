//! Real selected lineage source endpoint and original native consumption custody.
//!
//! These component tests independently measure both binaries and authenticate
//! their original private CNP admission. They do not enroll a production source
//! class, qualify higher-hop runtime associations, or prove preservation.

#![cfg(target_os = "linux")]
// crucible-lint: allow panic-shortcut -- Original endpoint or receipt divergence invalidates the actual fixture.
#![allow(clippy::unwrap_used)]

use crucible_node_provider::conformance::{UnixProbeConnector, run};
use std::{path::Path, time::Duration};

#[path = "lineage_source/fixture.rs"]
mod fixture;
#[path = "lineage_source/lifecycle.rs"]
mod lifecycle;
#[path = "lineage_source/scenario.rs"]
mod scenario;

#[test]
fn selected_lineage_source_closes_original_public_and_native_window_before_ack() {
    let provider = Path::new(env!("CARGO_BIN_EXE_crucible-reference-lineage-provider"));
    let device = Path::new(env!("CARGO_BIN_EXE_crucible-reference-lineage-device"));
    for closed_ingress in [true, false] {
        let service = fixture::NativeService::launch(provider, device, closed_ingress);
        let plan = lifecycle::native_window(&service);
        let mut connector = UnixProbeConnector::new(
            service.socket(),
            rustix::process::geteuid().as_raw(),
            provider,
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
        assert_eq!(
            service.profile.guarantees.capture_scope,
            crucible_node_contract::CaptureScope::None
        );
        assert_eq!(
            service.profile.guarantees.repeatability,
            crucible_node_contract::Repeatability::Nondeterministic
        );
        assert!(service.profile.public_profile().is_err());
    }
}

#[path = "lineage_source/client.rs"]
mod client;
#[path = "lineage_source/gate.rs"]
mod gate;
#[path = "lineage_source/sdk_plan.rs"]
mod sdk_plan;

#[path = "lineage_source/predecessor.rs"]
mod predecessor;

#[test]
fn selected_source_sdk_retains_original_ready_input_close_and_public_ack_closure() {
    let provider = Path::new(env!("CARGO_BIN_EXE_crucible-reference-lineage-provider"));
    let device = Path::new(env!("CARGO_BIN_EXE_crucible-reference-lineage-device"));
    let service = fixture::NativeService::launch(provider, device, false);
    let (_handshake, mut controller) = client::connect(&service);
    let observation = controller
        .observe(crucible_node_provider::client::ObservationLimits {
            maximum_requests: 1024,
            maximum_objects: 1024,
            maximum_bytes: 16 * 1024 * 1024,
        })
        .unwrap();
    let bindings = sdk_plan::execute(
        &mut controller,
        &lifecycle::native_window(&service),
        service.private_bindings.clone(),
    );
    let realization_id = fixture::id("realize");
    let input_id = fixture::id("input");
    let begin_id = fixture::id("begin-window");
    let view = controller
        .original_lineage_window(crucible_node_provider::client::LineageWindowRequests {
            realization: &realization_id,
            input: &input_id,
            begin: &begin_id,
        })
        .unwrap();
    assert_eq!(view.native_receipt().output.checksum.get(), 259);
    assert_native_inventory(&view);
    assert_eq!(view.input_batch().events[0].id.as_str(), "fixture-input/1");
    assert_eq!(view.observation().events[0].id.as_str(), "checksum-1");
    assert!(view.observation().events[0].causal_parent_ids.is_empty());
    assert!(view.preceding_public_acknowledgement().is_none());
    let public_close = fixture::id("close");
    let public_ack = fixture::id("consume");
    let acknowledged = view
        .acknowledged_publication(&public_close, &public_ack)
        .unwrap();
    assert_eq!(
        acknowledged.committed_observation().events,
        view.observation().events
    );
    assert_eq!(
        acknowledged.custody_reference(),
        &serde_json::from_value::<crucible_node_contract::ContentRef>(
            bindings["consumption-ref"].clone()
        )
        .unwrap()
    );
    assert!(
        view.acknowledged_publication(&public_close, &begin_id)
            .is_err()
    );
    assert!(!Path::new(&format!("/proc/{}", view.native_pid().get())).exists());
    assert!(!view.native_initialization().unwrap().1.is_empty());
    assert!(!view.native_close().unwrap().1.is_empty());
    let unknown = fixture::id("unknown-source-window");
    assert!(
        controller
            .original_lineage_window(crucible_node_provider::client::LineageWindowRequests {
                realization: &realization_id,
                input: &input_id,
                begin: &unknown,
            })
            .is_err()
    );
    let measurement_ref: crucible_node_contract::ContentRef =
        serde_json::from_value(bindings["measurement-ref"].clone()).unwrap();
    let measurement = crucible_node_contract::canonical::parse_json(
        controller.content(&measurement_ref).unwrap(),
        65536,
    )
    .unwrap();
    assert_eq!(
        measurement["schema"],
        "crucible.reference.lineage-measurement.v1"
    );
    assert!(measurement["previous_publication"].is_null());
    let relation_ref: crucible_node_contract::ContentRef =
        serde_json::from_value(measurement["consumption_relation"].clone()).unwrap();
    let relation = crucible_node_contract::canonical::parse_json(
        controller.content(&relation_ref).unwrap(),
        65536,
    )
    .unwrap();
    assert_eq!(
        relation["schema"],
        "crucible.reference.consumption-relation.v1"
    );
    assert_eq!(
        relation["owner"],
        serde_json::json!(service.bootstrap.owner_id)
    );
    assert_eq!(relation["complete_consumed_prefix"], "1");
    assert_eq!(relation["entries"][0]["byte_start"], "0");
    assert_eq!(relation["entries"][0]["byte_end"], "2");
    assert_eq!(relation["entries"][0]["checksum_after"], "259");
    assert_eq!(relation["entries"][0]["event_id"], "fixture-input/1");
    for field in [
        "input_batch",
        "native_stage",
        "native_receipt",
        "initialize_request",
        "initialize_response_wire",
        "close_request",
        "close_response_wire",
    ] {
        let reference: crucible_node_contract::ContentRef =
            serde_json::from_value(relation[field].clone()).unwrap();
        reference
            .verify(controller.content(&reference).unwrap())
            .unwrap();
    }
    let keys = observation.request_keys().unwrap();
    let references = observation.content_references().unwrap();
    let recorded = observation
        .snapshot(
            &keys,
            &references,
            crucible_node_provider::client::ObservationLimits {
                maximum_requests: 1024,
                maximum_objects: 1024,
                maximum_bytes: 16 * 1024 * 1024,
            },
        )
        .unwrap();
    assert!(recorded.recording_complete);
    assert!(!recorded.observed_unknown);
    assert!(
        recorded
            .evidence
            .requests
            .iter()
            .any(|request| request.key.request_id.as_str() == "consume")
    );
    assert_eq!(
        recorded.evidence.scope.provider_pid.get(),
        u64::from(service.process.id())
    );
    controller.fence();
}

fn assert_native_inventory(view: &crucible_node_provider::client::OriginalLineageWindow<'_>) {
    let original = view.native_receipt().clone();
    assert!(view.native_evidence(0, 600 * 1024).is_err());
    assert!(view.native_evidence(72, 1).is_err());
    assert_eq!(view.native_receipt(), &original);

    let evidence = view.native_evidence(72, 600 * 1024).unwrap();
    assert_eq!(evidence.root(), view.consumption_relation_reference());
    assert_eq!(
        evidence.objects().len(),
        view.input_batch().events.len() + 8
    );
    let measurement = view.measurement_evidence(80, 1024 * 1024).unwrap();
    assert_eq!(measurement.root(), view.measurement_reference());
    assert_eq!(measurement.objects().len(), evidence.objects().len() + 4);
    assert!(view.measurement_evidence(0, 1024 * 1024).is_err());
    assert!(view.measurement_evidence(80, 1).is_err());
    let root = measurement
        .objects()
        .iter()
        .find(|object| object.reference() == measurement.root())
        .unwrap();
    assert!(
        root.dependencies()
            .contains(view.consumption_relation_reference())
    );
    for object in measurement.objects() {
        object.reference().verify(object.bytes()).unwrap();
        for dependency in object.dependencies() {
            assert!(
                measurement.external_dependencies().contains(dependency)
                    || measurement
                        .objects()
                        .iter()
                        .any(|body| body.reference() == dependency)
            );
        }
    }
    assert_eq!(view.native_receipt(), &original);
    let source_proof = &view.input_batch().events[0].provenance_ref;
    assert!(evidence.external_dependencies().contains(source_proof));
    assert!(
        evidence
            .external_dependencies()
            .contains(&view.input_batch().events[0].payload)
    );
    assert!(
        !evidence
            .objects()
            .iter()
            .any(|object| object.reference() == source_proof)
    );
    for object in evidence.objects() {
        object.reference().verify(object.bytes()).unwrap();
        for dependency in object.dependencies() {
            assert!(
                evidence.external_dependencies().contains(dependency)
                    || evidence
                        .objects()
                        .iter()
                        .any(|object| object.reference() == dependency)
            );
        }
    }
    // The borrowed row inventory neither acknowledges nor recreates a source;
    // historical evidence remains readable after the authentic source shutdown.
    assert_eq!(view.native_receipt(), &original);
}
