//! Genuine installed ordinary planner, retained producer receipts and cold alarms.

use super::*;
use crucible::node_adapters::{
    RateAlarmClockDefinition, RateAlarmClockEvent, RateAlarmClockRequest,
};
use std::os::unix::fs::PermissionsExt;

fn request(request: RateAlarmClockRequest) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(request).unwrap()).unwrap()
}

fn original_clock_state(record: &HostArchiveRecord) -> Vec<u8> {
    let owner = record
        .manifest()
        .owners
        .iter()
        .find(|owner| owner.capture_owner_id == id("clock-owner"))
        .unwrap();
    let body = record
        .content_bytes(owner.state_ref.as_ref().unwrap(), 64 * 1024 * 1024)
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(envelope["schema_version"], 8);
    serde_json::from_value(envelope["native"].clone()).unwrap()
}

fn planner_cold_case(drift_ppb: i64) {
    let definition = RateAlarmClockDefinition {
        numerator: 3.into(),
        denominator: 2.into(),
        epoch_ps: 0.into(),
        epoch_counter: 7.into(),
        drift_ppb,
    };
    let target = definition.reading(1000.into()).unwrap();
    // Native proof data outlives this fixture; the signer stays private.
    let directory = tempfile::Builder::new()
        .prefix("rate-alarm-planner-proof-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
        .keep();
    eprintln!(
        "original rate-alarm proof retained: {}",
        directory.display()
    );
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let catalog = || {
        InstalledNodeCatalog::new(
            executable.clone(),
            measure_executable(&executable).unwrap(),
            directory.as_path().to_owned(),
            Duration::from_secs(5),
            4,
        )
        .unwrap()
    };
    let mut original = catalog();
    let script = ScriptedSource::new(
        ScriptedRequestKind::RateAlarmClock,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: request(RateAlarmClockRequest::Read {
                    correlation: id("initial-read"),
                }),
            },
            ScriptedRequest {
                time_ps: 10,
                payload: request(RateAlarmClockRequest::Arm {
                    correlation: id("alarm-a"),
                    target,
                }),
            },
            ScriptedRequest {
                time_ps: 10,
                payload: request(RateAlarmClockRequest::Arm {
                    correlation: id("alarm-b"),
                    target: definition.reading(1100.into()).unwrap(),
                }),
            },
            ScriptedRequest {
                time_ps: 10,
                payload: request(RateAlarmClockRequest::Cancel {
                    correlation: id("cancel-b"),
                    alarm: id("alarm-b"),
                }),
            },
            ScriptedRequest {
                time_ps: 1200,
                payload: request(RateAlarmClockRequest::Read {
                    correlation: id("future-read"),
                }),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let script_ref = canonical::content_ref(&script, "application/octet-stream").unwrap();
    let path = directory.as_path().join("original-clock-script");
    std::fs::write(&path, script).unwrap();
    original
        .install_artifacts(vec![InstalledIoArtifact::path(
            path.clone(),
            script_ref.clone(),
        )])
        .unwrap();
    let selections = vec![
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("clock-owner"),
            kind: InstalledNodeKind::HostRateAlarmClockProducer {
                definition: definition.clone(),
            },
        },
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: script_ref.clone(),
                    consumer: id("disk"),
                },
            },
        },
    ];
    let scenario = original.scenario(&selections).unwrap();
    let factory = original.host_state_factory(&selections, &scenario).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "alarm-clock",
        directory.as_path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.as_path().join("refs")));
    let prepared = original
        .prepare_world(
            &selections,
            scenario.clone(),
            ExecutionId::from_bytes([114; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "clock-source"))
        .unwrap();
    let initial_publications = planner_to(&mut runtime, &graph, &activation, "original", 11);
    let initial_events: Vec<RateAlarmClockEvent> = initial_publications
        .iter()
        .map(|publication| serde_json::from_slice(&publication.payload_bytes).unwrap())
        .collect();
    assert_eq!(initial_events.len(), 4);
    assert_eq!(initial_events[0].kind, "reading");
    assert_eq!(
        initial_events[0].counter,
        definition.reading(10.into()).unwrap()
    );
    assert_eq!(initial_events[2].kind, "armed");
    assert_eq!(initial_events[3].kind, "canceled");
    assert_eq!(initial_events[1].kind, "armed");
    assert_eq!(
        initial_events[1].reaction,
        Position::new(10.into(), 1.into(), Phase::Reaction)
    );
    assert!(pending(&mut runtime, &graph, &activation).is_empty());

    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive_path = directory.as_path().join("archive");
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &activation,
            Position::new(11.into(), 0.into(), Phase::BoundaryControl),
            30.into(),
            id("capture/rational-clock"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    std::fs::write(
        directory.join("original-manifest.json"),
        canonical::canonical_json(&serde_json::to_value(record.manifest()).unwrap()).unwrap(),
    )
    .unwrap();
    std::fs::write(
        directory.join("original-artifact.json"),
        canonical::canonical_json(&serde_json::to_value(record.artifact()).unwrap()).unwrap(),
    )
    .unwrap();

    let original_clock = original_clock_state(&record);
    // These data controls use the actual captured native bytes and original
    // runtime; refusal conveys no replacement archive or restoration authority.
    let original_runtime = runtime
        .runtime_snapshot(
            Position::new(11.into(), 0.into(), Phase::BoundaryControl),
            30.into(),
            16 * 1024 * 1024,
        )
        .unwrap();
    let owner = record
        .manifest()
        .owners
        .iter()
        .find(|owner| owner.capture_owner_id == id("clock-owner"))
        .unwrap();
    let body = record
        .content_bytes(owner.state_ref.as_ref().unwrap(), 64 * 1024 * 1024)
        .unwrap();
    let check = |bytes: &[u8]| {
        crucible::node_adapters::validate_host_continuation(
            bytes,
            &original_runtime,
            graph.descriptor(&id("disk")).unwrap(),
            graph.binding(&id("disk")).unwrap(),
            crucible::node_adapters::HostModelResources::default(),
        )
    };
    check(&body).unwrap();
    let mut altered: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let output_operation = altered["operations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|operation| {
            operation["outcome"]["scheduling"]["publications"]
                .as_array()
                .is_some_and(|publications| !publications.is_empty())
        })
        .unwrap();
    output_operation["outcome"]["scheduling"]["publications"][0]["causal_parents"][0]["microstep"] =
        serde_json::json!("0");
    assert!(check(&canonical::canonical_json(&altered).unwrap()).is_err());
    let mut altered: serde_json::Value = serde_json::from_slice(&body).unwrap();
    altered["pending_causes"][0]["parents"][0]["microstep"] = serde_json::json!("0");
    assert!(check(&canonical::canonical_json(&altered).unwrap()).is_err());
    let mut altered: serde_json::Value = serde_json::from_slice(&body).unwrap();
    altered["schema_version"] = serde_json::json!(1);
    assert!(check(&canonical::canonical_json(&altered).unwrap()).is_err());
    // This selected roster is required, bounded, and independent of the old
    // runtime schema. These data refusals never create native authority.
    let original_envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        !original_envelope["producer_observations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for missing in [true, false] {
        let mut altered = original_envelope.clone();
        if missing {
            altered
                .as_object_mut()
                .unwrap()
                .remove("producer_observations");
        } else {
            altered["producer_observations"] = serde_json::Value::Null;
        }
        assert!(check(&canonical::canonical_json(&altered).unwrap()).is_err());
    }
    let mut altered = original_envelope.clone();
    let duplicate = altered["producer_observations"][0].clone();
    altered["producer_observations"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(check(&canonical::canonical_json(&altered).unwrap()).is_err());
    let mut altered = original_envelope.clone();
    let mut original_root: Vec<u8> =
        serde_json::from_value(altered["producer_observations"][0]["objects"][0]["bytes"].clone())
            .unwrap();
    let mut root: serde_json::Value = serde_json::from_slice(&original_root).unwrap();
    root["owners"][0]["owner"] = serde_json::json!("source-owner");
    original_root = canonical::canonical_json(&root).unwrap();
    altered["producer_observations"][0]["objects"][0]["reference"] = serde_json::to_value(
        canonical::content_ref(&original_root, "application/octet-stream").unwrap(),
    )
    .unwrap();
    altered["producer_observations"][0]["objects"][0]["bytes"] =
        serde_json::to_value(original_root).unwrap();
    assert!(check(&canonical::canonical_json(&altered).unwrap()).is_err());
    let mut altered = original_envelope.clone();
    altered["producer_observations"][0]["objects"][1]["bytes"][0] = serde_json::json!(0);
    assert!(check(&canonical::canonical_json(&altered).unwrap()).is_err());
    let mut altered = original_envelope.clone();
    altered["producer_observations"] = serde_json::Value::Array(vec![
            original_envelope["producer_observations"][0].clone();
            65
        ]);
    assert!(check(&canonical::canonical_json(&altered).unwrap()).is_err());
    let mut lineage_runtime = original_runtime.clone();
    lineage_runtime.schema_version = 7;
    assert!(
        crucible::node_adapters::validate_host_continuation(
            &body,
            &lineage_runtime,
            graph.descriptor(&id("disk")).unwrap(),
            graph.binding(&id("disk")).unwrap(),
            crucible::node_adapters::HostModelResources::default()
        )
        .is_err()
    );
    check(&body).unwrap();

    let artifact = record.artifact().clone();
    drop(record);
    drop(runtime);
    reclaim(&original);
    drop(activation);
    drop(graph);
    drop(factory);
    drop(original);
    drop(archive);
    std::fs::remove_file(&path).unwrap();

    let mut fresh = catalog();
    fresh
        .install_artifacts(vec![InstalledIoArtifact::archive_only(script_ref)])
        .unwrap();
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let (left_graph, mut left) = restore(
        &mut fresh,
        &selections,
        &scenario,
        record.clone(),
        115,
        (&blobs, &refs),
        limits,
    );
    let (right_graph, mut right) = restore(
        &mut fresh,
        &selections,
        &scenario,
        record.clone(),
        116,
        (&blobs, &refs),
        limits,
    );
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    let mut branch_outputs = Vec::new();
    for (branch, graph, activation, name) in [
        (&mut left, &left_graph, &left_activation, "left"),
        (&mut right, &right_graph, &right_activation, "right"),
    ] {
        let fresh_factory = fresh
            .host_state_factory_from_archive(&selections, &scenario, &record)
            .unwrap();
        let repeated = archive
            .capture_world(
                graph,
                branch.runtime_mut(),
                activation,
                Position::new(11.into(), 0.into(), Phase::BoundaryControl),
                1.into(),
                id(&format!("recapture/{name}")),
                requirements(),
                fresh_factory.as_ref(),
                fresh_factory.as_ref(),
            )
            .unwrap();
        assert_eq!(original_clock_state(&repeated), original_clock);
        std::fs::write(
            directory.join(format!("{name}-recaptured-manifest.json")),
            canonical::canonical_json(&serde_json::to_value(repeated.manifest()).unwrap()).unwrap(),
        )
        .unwrap();
        drop(repeated);
        drop(fresh_factory);

        let before = planner_to(
            branch.runtime_mut(),
            graph,
            activation,
            &format!("{name}/exclusive"),
            1000,
        );
        assert!(before.is_empty());
        let alarm = planner_to(
            branch.runtime_mut(),
            graph,
            activation,
            &format!("{name}/alarm"),
            1001,
        );
        let alarm_events: Vec<RateAlarmClockEvent> = alarm
            .iter()
            .map(|publication| serde_json::from_slice(&publication.payload_bytes).unwrap())
            .collect();
        assert_eq!(alarm_events.len(), 1);
        assert_eq!(alarm_events[0].kind, "alarm");
        assert_eq!(alarm_events[0].counter, target);
        assert_eq!(
            alarm_events[0].reaction,
            Position::new(1000.into(), 0.into(), Phase::Reaction)
        );
        assert!(
            planner_to(
                branch.runtime_mut(),
                graph,
                activation,
                &format!("{name}/no-repeat"),
                1100
            )
            .is_empty()
        );
        let future = planner_to(
            branch.runtime_mut(),
            graph,
            activation,
            &format!("{name}/future-read"),
            1201,
        );
        let reads: Vec<RateAlarmClockEvent> = future
            .iter()
            .map(|publication| serde_json::from_slice(&publication.payload_bytes).unwrap())
            .collect();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].counter, definition.reading(1200.into()).unwrap());
        branch_outputs.push((alarm_events, reads));
    }
    assert_eq!(branch_outputs[0], branch_outputs[1]);
    std::fs::write(
        directory.join("actual-future-events.json"),
        canonical::canonical_json(&serde_json::to_value(&branch_outputs).unwrap()).unwrap(),
    )
    .unwrap();
    drop(left);
    drop(right);
    reclaim(&fresh);
    assert!(!path.exists());
    std::fs::write(
        directory.join("native-worlds-reclaimed"),
        b"original and both fresh worlds reclaimed; original script absent\n",
    )
    .unwrap();
}

#[test]
#[ignore = "requires source-built installed catalog identity and signed two-fresh host clock continuation"]
fn installed_rate_alarm_planner_original_proofs_and_alarm_survive_source_gone_twins() {
    planner_cold_case(0);
}

#[test]
#[ignore = "requires source-built installed catalog identity and signed two-fresh drift clock continuation"]
fn installed_rate_alarm_planner_negative_drift_original_proofs_survive_cold() {
    planner_cold_case(-500_000_000);
}

fn planner_to(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    name: &str,
    horizon: u64,
) -> Vec<crucible::node_scheduling::NativePublication> {
    use crate::node_execution::{ExactOperationNames, ExactOperationRequest, plan_exact_operation};
    let mut publications = Vec::new();
    for round in 0..32 {
        for node in graph.node_ids() {
            let observation = runtime.observe_scheduling(activation, node).unwrap();
            let bodies = runtime
                .scheduling_evidence(
                    &observation,
                    crucible::node_contract::InputProvenanceLimits::default(),
                )
                .unwrap();
            assert_eq!(bodies.len(), 3);
            runtime
                .scheduler(graph, activation)
                .unwrap()
                .accept_boundary_observation(observation)
                .unwrap();
        }
        let mut progress = false;
        for node in graph.node_ids() {
            if runtime
                .scheduler(graph, activation)
                .unwrap()
                .position(node)
                .unwrap()
                .time_ps
                .get()
                >= horizon
            {
                continue;
            }
            let operation = format!("{name}/{round}/{node}");
            let grant =
                plan_exact_operation::<crate::node_observed_executor::NodeObservedError, _>(
                    runtime,
                    ExactOperationRequest {
                        graph,
                        activation,
                        node,
                        horizon: horizon.into(),
                        names: ExactOperationNames {
                            operation: id(&operation),
                            stage: id(&format!("{operation}/stage")),
                            batch: id(&format!("{operation}/batch")),
                        },
                    },
                    |_| Ok(()),
                )
                .unwrap();
            if let Some(grant) = grant {
                let outcome = run(runtime, grant);
                if node == &id("disk") {
                    publications.extend(outcome.scheduling.unwrap().publications);
                }
                progress = true;
            }
        }
        if graph.node_ids().all(|node| {
            runtime
                .scheduler(graph, activation)
                .unwrap()
                .position(node)
                .unwrap()
                .time_ps
                .get()
                >= horizon
        }) {
            return publications;
        }
        assert!(
            progress,
            "actual planner is causally blocked before requested horizon"
        );
    }
    panic!("actual planner exceeded its finite fixture round credit");
}
