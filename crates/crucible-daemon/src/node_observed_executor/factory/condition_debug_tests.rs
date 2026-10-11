//! Genuine installed first-condition stop with unchanged future native work.

use super::*;
use crate::node_observed_executor::condition_execution::ConditionExecution;
use crate::node_observed_executor::factory::InstalledConditionDebugProfile;
use crucible::node_adapters::{
    ConditionDebugDefinition, HostSemanticDefinition, HostSemanticInput, HostSemanticInputKind,
};
use crucible::node_contract::{ConditionResultPublisher, PublicationStatus};
use crucible::{AssertionDef, AssertionId, IoEventKind, NodeId, Predicate, Properties, Property};
use crucible_node_contract::{Bytes, Endpoint};

fn condition_program() -> Vec<u8> {
    let disk = NodeId {
        name: "disk".to_owned(),
    };
    let namespace = crucible::model::PropertyNamespace::new(
        std::collections::BTreeMap::from([(
            disk.clone(),
            std::collections::BTreeSet::from([crucible::model::PropertyObservation::Io(
                IoEventKind::Any,
            )]),
        )]),
        false,
        false,
        std::collections::BTreeSet::new(),
    )
    .unwrap();
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![AssertionDef {
            id: AssertionId::from_name("first-native-reply"),
            message: "first actual Block completion".to_owned(),
            property: Property::Sometimes {
                predicate: Predicate::IoPattern {
                    node: disk,
                    kind: IoEventKind::Any,
                },
            },
        }],
    )
    .unwrap();
    let definition = ConditionDebugDefinition {
        version: 1,
        condition: id("first-native-reply"),
        evaluation: HostSemanticDefinition {
            version: 1,
            properties: Bytes::new(properties.to_compact_binary()),
            inputs: vec![HostSemanticInput {
                source: Endpoint {
                    node_id: id("disk"),
                    port_id: id("data"),
                    lane_id: id("output"),
                },
                kind: HostSemanticInputKind::BlockCompletion,
            }],
        },
    };
    canonical::canonical_json(&serde_json::to_value(definition).unwrap()).unwrap()
}

#[test]
#[ignore = "requires actual source-built installed catalog companion measurement"]
fn first_native_completion_stops_before_future_request_and_requires_current_durable_report_before_resume()
 {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    let base = vec![0xab; 4096];
    let write = vec![0x5c; 512];
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(7, 0, write.clone()).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 1_000_000,
                payload: BlockRequest::read(9, 0, 512).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let program = condition_program();
    let mut artifacts = Vec::new();
    let mut references = Vec::new();
    for (name, bytes) in [("base", base), ("script", script), ("condition", program)] {
        let media_type = if name == "condition" {
            "application/json"
        } else {
            "application/octet-stream"
        };
        let reference = canonical::content_ref(&bytes, media_type).unwrap();
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        artifacts.push(InstalledIoArtifact::path(path, reference.clone()));
        references.push(reference);
    }
    catalog.install_artifacts(artifacts).unwrap();
    let mut selections = vec![
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: references[1].clone(),
                    consumer: id("disk"),
                },
            },
        },
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("disk-owner"),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Block {
                    base_image: references[0].clone(),
                    source_node: 7,
                    read_ns: 1.into(),
                    write_ns: 1.into(),
                    flush_ns: 1.into(),
                    get_length_ns: 1.into(),
                    per_byte_ns: 1.into(),
                },
            },
        },
        InstalledNodeSelection {
            node: id("observer"),
            owner: id("observer-owner"),
            kind: InstalledNodeKind::HostConditionDebug {
                profile: InstalledConditionDebugProfile {
                    program: references[2].clone(),
                },
            },
        },
    ];
    selections.sort_by(|left, right| left.node.cmp(&right.node));
    let scenario = catalog.scenario(&selections).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "condition-live",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let prepared = catalog
        .prepare_world(
            &selections,
            scenario,
            ExecutionId::from_bytes([109; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "condition-source"))
        .unwrap();
    let mut driver = ConditionExecution::new(8192).unwrap();
    let barrier = driver
        .stop_at_first_hit(
            &mut runtime,
            &graph,
            &activation,
            &id("observer"),
            2_000_000.into(),
        )
        .unwrap();
    audit_original_model_growth(
        barrier
            .record()
            .native
            .iter()
            .find(|inventory| inventory.node == id("observer"))
            .unwrap(),
    );
    check_model_reopening(
        barrier
            .record()
            .native
            .iter()
            .find(|inventory| inventory.node == id("observer"))
            .unwrap(),
        &barrier.record().hit,
        true,
    );
    let cut = barrier.record().cut;
    assert_eq!(cut.time_ps.get(), 513_010);
    assert_eq!(
        barrier.record().hit.evaluation,
        Position::new(513_010.into(), 2.into(), Phase::Reaction)
    );
    assert_eq!(
        cut,
        Position::new(513_010.into(), 3.into(), Phase::BoundaryControl)
    );
    assert!(cut < Position::new(1_000_000.into(), 0.into(), Phase::Reaction));
    // Future source work survives a live stopped debugger; it is not EOF.
    assert!(runtime.scheduler(&graph, &activation).is_err());
    let BeginResult::Accepted(stop) = runtime.begin_condition_stop(barrier).unwrap() else {
        panic!("original stop was refused")
    };
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(_)) = runtime.poll(&stop, &mut context) else {
        panic!("original stop did not complete")
    };
    let result_name = RefName::new("node-world-coordinators/condition/original").unwrap();
    let mut insufficient = crate::node_observed_executor::StoredConditionResultPublisher::new(
        blobs.clone(),
        refs.clone(),
        result_name.clone(),
        1,
    )
    .unwrap();
    assert_eq!(
        runtime
            .publish_condition_result(&stop, &mut insufficient, 32 << 20)
            .unwrap()
            .0,
        PublicationStatus::NotCommitted
    );
    assert!(
        runtime
            .begin_condition_resume(&activation, id("premature-resume"))
            .is_err()
    );
    let saved = runtime.condition_stop_checkpoint().unwrap().clone();
    let original_barrier = crucible::node_scheduling::InputPayload {
        reference: saved.reference.clone(),
        bytes: canonical::canonical_json(&serde_json::to_value(&saved.record).unwrap()).unwrap(),
    };
    let report = saved.report.unwrap();
    let mut publisher = crate::node_observed_executor::StoredConditionResultPublisher::new(
        blobs.clone(),
        refs.clone(),
        result_name.clone(),
        32 << 20,
    )
    .unwrap();
    assert_eq!(
        publisher.publish_complete(
            &original_barrier,
            &report,
            &saved.record.dependency_objects().collect::<Vec<_>>()
        ),
        PublicationStatus::Committed
    );
    let original_report = runtime
        .publish_condition_result(&stop, &mut publisher, 32 << 20)
        .unwrap()
        .1
        .unwrap();
    // Selected runtime six retains every original reference association but
    // owns each readable source body only once in its opaque complete DAG.
    let stopped_snapshot = runtime
        .condition_runtime_snapshot(saved.record.cut, 7.into(), 32 << 20)
        .unwrap();
    assert!(
        runtime
            .runtime_snapshot(saved.record.cut, 7.into(), 32 << 20)
            .is_err()
    );
    let stopped_bytes =
        canonical::canonical_json(&serde_json::to_value(&stopped_snapshot).unwrap()).unwrap();
    let stopped_restored: crucible::node_contract::RuntimeSnapshot =
        serde_json::from_slice(&stopped_bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&stopped_restored).unwrap(),
        serde_json::to_value(&stopped_snapshot).unwrap()
    );
    let stopped_wire: serde_json::Value = serde_json::from_slice(&stopped_bytes).unwrap();
    assert_eq!(stopped_wire["schema_version"], 6);
    assert!(stopped_wire["original_bodies"].is_string());
    let mut omitted = stopped_wire.clone();
    omitted.as_object_mut().unwrap().remove("original_bodies");
    assert!(serde_json::from_value::<crucible::node_contract::RuntimeSnapshot>(omitted).is_err());
    let mut legacy = stopped_wire.clone();
    legacy["schema_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<crucible::node_contract::RuntimeSnapshot>(legacy).is_err());
    let original_dag: Bytes =
        serde_json::from_value(stopped_wire["original_bodies"].clone()).unwrap();
    let mut dag: serde_json::Value = serde_json::from_slice(original_dag.as_slice()).unwrap();
    dag["objects"][0]["bytes"] =
        serde_json::to_value(Bytes::new(b"changed original body".to_vec())).unwrap();
    let mut corrupt = stopped_wire.clone();
    corrupt["original_bodies"] =
        serde_json::to_value(Bytes::new(canonical::canonical_json(&dag).unwrap())).unwrap();
    assert!(serde_json::from_value::<crucible::node_contract::RuntimeSnapshot>(corrupt).is_err());
    let mut dag: serde_json::Value = serde_json::from_slice(original_dag.as_slice()).unwrap();
    dag["objects"].as_array_mut().unwrap().pop();
    let mut missing = stopped_wire.clone();
    missing["original_bodies"] =
        serde_json::to_value(Bytes::new(canonical::canonical_json(&dag).unwrap())).unwrap();
    assert!(serde_json::from_value::<crucible::node_contract::RuntimeSnapshot>(missing).is_err());
    // A small repeated-reference index must not expand one retained native
    // body beyond aggregate ownership credit during the selected decoder.
    let dag: serde_json::Value = serde_json::from_slice(original_dag.as_slice()).unwrap();
    let largest = dag["objects"]
        .as_array()
        .unwrap()
        .iter()
        .max_by_key(|object| {
            object["reference"]["length"]
                .as_str()
                .unwrap()
                .parse::<usize>()
                .unwrap()
        })
        .unwrap()["reference"]
        .clone();
    let length = largest["length"]
        .as_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!(length > 0);
    let repetitions = (64 << 20) / length + 1;
    assert!(repetitions <= 65_536);
    let mut amplified = stopped_wire.clone();
    amplified["inputs"][0]["payloads"] = serde_json::Value::Array(vec![largest; repetitions]);
    assert!(serde_json::from_value::<crucible::node_contract::RuntimeSnapshot>(amplified).is_err());

    let mut changed = stopped_wire;
    changed["condition_stop"]["acknowledged"] = serde_json::json!(true);
    assert!(serde_json::from_value::<crucible::node_contract::RuntimeSnapshot>(changed).is_err());
    eprintln!(
        "condition runtime6 original snapshot: {} bytes",
        stopped_bytes.len()
    );

    // An actual distinct empty Directory store cannot prove historical roots.
    let mut absent = crate::node_observed_executor::StoredConditionResultPublisher::new(
        Arc::new(DirectoryBlobBackend::new(
            "absent",
            directory.path().join("absent-blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(
            directory.path().join("absent-refs"),
        )),
        result_name,
        32 << 20,
    )
    .unwrap();
    assert_eq!(
        runtime
            .publish_condition_result(&stop, &mut absent, 32 << 20)
            .unwrap()
            .0,
        PublicationStatus::NotCommitted
    );
    assert!(
        runtime
            .acknowledge_condition_result(&stop, &original_report)
            .is_err()
    );
    let permit = runtime
        .publish_condition_result(&stop, &mut publisher, 32 << 20)
        .unwrap()
        .1
        .unwrap();
    runtime
        .acknowledge_condition_result(&stop, &permit)
        .unwrap();
    let acknowledged = runtime
        .condition_runtime_snapshot(saved.record.cut, 8.into(), 32 << 20)
        .unwrap();
    let acknowledged: crucible::node_contract::RuntimeSnapshot =
        serde_json::from_value(serde_json::to_value(acknowledged).unwrap()).unwrap();
    let history = acknowledged.condition_stop.as_ref().unwrap();
    assert!(history.acknowledged);
    assert!(!history.resumed);
    assert_eq!(
        history.publication,
        Some(crucible::node_contract::ConditionPublicationState::Committed)
    );

    let BeginResult::Accepted(resume) = runtime
        .begin_condition_resume(&activation, id("original-resume"))
        .unwrap()
    else {
        panic!("resume refused")
    };
    let Poll::Ready(Ok(_)) = runtime.poll(&resume, &mut context) else {
        panic!("resume did not complete")
    };
    let permit = runtime
        .publish_condition_result(&resume, &mut publisher, 32 << 20)
        .unwrap()
        .1
        .unwrap();
    let resume_pending_ack = runtime
        .condition_runtime_snapshot(saved.record.cut, 9.into(), 32 << 20)
        .unwrap();
    let resume_pending_ack: crucible::node_contract::RuntimeSnapshot =
        serde_json::from_value(serde_json::to_value(resume_pending_ack).unwrap()).unwrap();
    let history = resume_pending_ack.condition_stop.as_ref().unwrap();
    assert!(history.acknowledged);
    assert!(!history.resumed);
    assert_eq!(history.resume_operation.as_ref(), Some(resume.operation()));
    assert_eq!(
        history.resume_publication,
        Some(crucible::node_contract::ConditionPublicationState::Committed)
    );

    let original_resume = runtime
        .condition_stop_checkpoint()
        .unwrap()
        .resume_receipt
        .clone();
    runtime
        .publish_condition_result(&stop, &mut publisher, 32 << 20)
        .unwrap();
    assert_eq!(
        runtime.condition_stop_checkpoint().unwrap().resume_receipt,
        original_resume
    );
    assert!(
        runtime
            .acknowledge_condition_result(&resume, &permit)
            .is_err()
    );
    let permit = runtime
        .publish_condition_result(&resume, &mut publisher, 32 << 20)
        .unwrap()
        .1
        .unwrap();
    runtime
        .acknowledge_condition_result(&resume, &permit)
        .unwrap();
    assert!(
        runtime
            .condition_hit_candidate(&activation, &id("observer"))
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .begin_condition_resume(&activation, id("duplicate-resume"))
            .is_err()
    );
    assert_eq!(
        runtime
            .condition_stop_checkpoint()
            .unwrap()
            .report
            .as_ref()
            .unwrap(),
        &report
    );
    runtime.scheduler(&graph, &activation).unwrap();
    driver
        .continue_original_after_resume(
            &mut runtime,
            &graph,
            &activation,
            &id("observer"),
            1_513_011.into(),
        )
        .unwrap();
    let suffix = runtime
        .observe_condition_inventory(&activation, &id("observer"), 32 << 20)
        .unwrap();
    audit_original_model_growth(&suffix);
    check_model_reopening(
        &suffix,
        &runtime.condition_stop_checkpoint().unwrap().record.hit,
        false,
    );
    let resumed = runtime
        .condition_runtime_snapshot(suffix.boundary, 10.into(), 32 << 20)
        .unwrap();
    let resumed_bytes =
        canonical::canonical_json(&serde_json::to_value(&resumed).unwrap()).unwrap();
    let resumed: crucible::node_contract::RuntimeSnapshot =
        serde_json::from_slice(&resumed_bytes).unwrap();
    let history = resumed.condition_stop.as_ref().unwrap();
    assert!(history.resumed);
    assert_eq!(history.record.cut, saved.record.cut);
    assert!(history.record.cut < resumed.capture_cut);
    assert_eq!(history.report.as_ref(), Some(&report));
    eprintln!(
        "condition runtime6 resumed future snapshot: {} bytes",
        resumed_bytes.len()
    );

    let disk_outputs: Vec<_> = driver
        .publications()
        .iter()
        .filter(|publication| publication.endpoint.node_id == id("disk"))
        .collect();
    assert_eq!(disk_outputs.len(), 2);
    assert_eq!(
        BlockResponse::decode(&disk_outputs[0].payload_bytes)
            .unwrap()
            .request_id,
        7
    );
    let read = BlockResponse::decode(&disk_outputs[1].payload_bytes).unwrap();
    assert_eq!(read.request_id, 9);
    assert_eq!(read.data, write);
    assert_eq!(disk_outputs[1].evaluation.unwrap().time_ps.get(), 1_513_000);
    assert!(
        runtime
            .condition_hit_candidate(&activation, &id("observer"))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .condition_stop_checkpoint()
            .unwrap()
            .report
            .as_ref()
            .unwrap(),
        &report
    );
    drop(runtime);
    reclaim(&catalog);
}

fn audit_original_model_growth(inventory: &crucible::node_contract::NativeConditionStopInventory) {
    let bodies: std::collections::BTreeMap<_, _> = inventory
        .proof_objects
        .iter()
        .map(|object| (object.reference.clone(), &object.bytes))
        .collect();
    let wrapper: serde_json::Value = serde_json::from_slice(&inventory.receipt.bytes).unwrap();
    let native: crucible_node_contract::ContentRef =
        serde_json::from_value(wrapper["native"].clone()).unwrap();
    let index: serde_json::Value = serde_json::from_slice(bodies[&native]).unwrap();
    let mut rows = Vec::new();
    for operation in index["operations"].as_array().unwrap() {
        let request: crucible_node_contract::ContentRef =
            serde_json::from_value(operation["request"].clone()).unwrap();
        let request: serde_json::Value = serde_json::from_slice(bodies[&request]).unwrap();
        if request.get("ExactRun").is_none() && request.get("BoundarySettle").is_none() {
            continue;
        }

        let outcome: crucible_node_contract::ContentRef =
            serde_json::from_value(operation["outcome"].clone()).unwrap();
        let outcome: serde_json::Value = serde_json::from_slice(bodies[&outcome]).unwrap();
        let proof: crucible_node_contract::ContentRef =
            serde_json::from_value(outcome["scheduling"]["proof_ref"].clone()).unwrap();
        for reference in operation["evidence"].as_array().unwrap() {
            let reference: crucible_node_contract::ContentRef =
                serde_json::from_value(reference.clone()).unwrap();
            if reference != proof {
                continue;
            }
            let Ok(receipt) = serde_json::from_slice::<serde_json::Value>(bodies[&reference])
            else {
                continue;
            };
            if receipt["schema_version"] != serde_json::json!(4)
                || receipt["profile"] != serde_json::json!("host/condition-inventory-v1")
            {
                continue;
            }
            let model: crucible_node_contract::ContentRef =
                serde_json::from_value(receipt["native"].clone()).unwrap();
            let mut reachable = std::collections::BTreeSet::new();
            let mut pending = vec![model];
            while let Some(reference) = pending.pop() {
                if !reachable.insert(reference.clone()) {
                    continue;
                }
                pending.extend(
                    crucible::node_adapters::condition_evidence_dependencies(bodies[&reference])
                        .map_err(|error| error.reason)
                        .unwrap(),
                );
            }
            let bytes: usize = reachable
                .iter()
                .map(|reference| bodies[reference].len())
                .sum();
            let boundary: crucible_node_contract::Position =
                serde_json::from_value(receipt["boundary"].clone()).unwrap();
            rows.push((
                boundary,
                operation["operation"].as_str().unwrap().to_owned(),
                reachable.len(),
                bytes,
            ));
        }
    }
    rows.sort();
    for (boundary, operation, objects, bytes) in rows {
        eprintln!(
            "actual condition original model growth operation={operation} cut={boundary:?} objects={objects} body_bytes={bytes}"
        );
        assert!(objects <= 4096);
        assert!(bytes < 16 << 20);
    }
    eprintln!(
        "actual condition complete stopped observer DAG objects={} body_bytes={}",
        bodies.len(),
        bodies.values().map(|bytes| bytes.len()).sum::<usize>()
    );
}

fn check_model_reopening(
    inventory: &crucible::node_contract::NativeConditionStopInventory,
    hit: &crucible::node_adapters::ConditionHitCandidate,
    awaiting_control: bool,
) {
    let definition: ConditionDebugDefinition =
        serde_json::from_slice(&condition_program()).unwrap();
    let reopen = |inventory: &crucible::node_contract::NativeConditionStopInventory,
                  definition: ConditionDebugDefinition| {
        crucible::node_adapters::reopen_condition_model(inventory, definition, 16 << 20, 4096, 4096)
    };
    let model = reopen(inventory, definition.clone())
        .map_err(|error| error.reason)
        .unwrap();
    assert_eq!(model.candidate(), Some(hit));
    assert_eq!(model.position(), inventory.boundary);
    assert_eq!(model.awaiting_control(), awaiting_control);

    // These decode-only negatives never substitute a fresh native source or
    // reevaluate a prefix. Even a declared commitment needs its original body.
    let mut missing = inventory.clone();
    missing.proof_objects.remove(0);
    assert!(reopen(&missing, definition.clone()).is_err());
    let mut corrupt = inventory.clone();
    corrupt.proof_objects[0].bytes[0] ^= 1;
    assert!(reopen(&corrupt, definition.clone()).is_err());
    let mut wrong_cut = inventory.clone();
    wrong_cut.boundary.time_ps = wrong_cut.boundary.time_ps.checked_add(1.into()).unwrap();
    assert!(reopen(&wrong_cut, definition.clone()).is_err());
    let mut foreign = definition;
    foreign.condition = id("different-condition");
    assert!(reopen(inventory, foreign).is_err());
}
