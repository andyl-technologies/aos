//! Actual original stopped-condition capture and two independent cold worlds.

#![cfg(test)]

#[path = "host_state_condition_adverse_tests.rs"]
mod adverse;

use super::*;
use crate::node_observed_executor::condition_execution::ConditionExecution;
use crate::node_observed_executor::factory::InstalledConditionDebugProfile;
use crucible::node_adapters::{
    ConditionDebugDefinition, HostSemanticDefinition, HostSemanticInput, HostSemanticInputKind,
};
use crucible::node_contract::PublicationStatus;
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
fn acknowledged_original_stop_survives_source_gone_twins_and_future_read_once() {
    exercise_source_gone_twins(false, false);
}

#[test]
#[ignore = "requires actual source-built installed catalog companion measurement"]
fn stopped_native_queued_write_payload_survives_twins_and_completes_once() {
    exercise_source_gone_twins(true, false);
}

#[test]
#[ignore = "requires actual source-built installed catalog companion measurement"]
fn oversized_original_preserves_underdeclared_and_native_capture_refusals() {
    exercise_source_gone_twins(true, true);
}

fn exercise_source_gone_twins(queued_write: bool, oversized: bool) {
    let directory = tempfile::tempdir().unwrap().keep();
    eprintln!("condition original recipe custody: {}", directory.display());
    // This authored cohort reserves its record and expanded-association credit
    // before preparing any participant. The larger negative original measured
    // 18,145,017 expanded bytes; deduplication retains association accounting.
    // Global/default/native caps are unchanged.
    let limits = StateLimits {
        maximum_record_bytes: if queued_write { 32 << 20 } else { 8 << 20 },
        maximum_content_bytes: 512 << 20,
        maximum_total_content_bytes: 1024 << 20,
        ..StateLimits::default()
    };
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.as_path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    let base = vec![0xab; 4096];
    let write_length = if queued_write && !oversized { 64 } else { 512 };
    let queued_length = if oversized { 1024 } else { 128 };
    let write = vec![0x5c; write_length];
    let mut requests = vec![ScriptedRequest {
        time_ps: 10,
        payload: BlockRequest::write(7, 0, write.clone()).encode().unwrap(),
    }];
    if queued_write {
        // This actual second request enters native Block custody before the
        // first completion triggers Stop. Its later completion stays queued.
        requests.push(ScriptedRequest {
            time_ps: 10,
            payload: BlockRequest::write(8, 0, vec![0x6d; queued_length])
                .encode()
                .unwrap(),
        });
    }
    requests.push(ScriptedRequest {
        time_ps: 1_000_000,
        payload: BlockRequest::read(9, 0, write_length.try_into().unwrap())
            .encode()
            .unwrap(),
    });
    let script = ScriptedSource::new(ScriptedRequestKind::Block, requests)
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
        let path = directory.as_path().join(name);
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
            kind: InstalledNodeKind::HostConditionDebugPreserving {
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
        directory.as_path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.as_path().join("refs")));
    let prepared = catalog
        .prepare_world(
            &selections,
            scenario.clone(),
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

    let cut = barrier.record().cut;
    assert_eq!(
        cut,
        Position::new(
            ((write_length as u64 + 1) * 1000 + 10).into(),
            3.into(),
            Phase::BoundaryControl
        )
    );
    let BeginResult::Accepted(stop) = runtime.begin_condition_stop(barrier).unwrap() else {
        panic!("genuine original Stop refused");
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        runtime.poll(&stop, &mut context),
        Poll::Ready(Ok(_))
    ));
    let mut result_publisher = crate::node_observed_executor::StoredConditionResultPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new("node-world-coordinators/condition/cold-original").unwrap(),
        32 << 20,
    )
    .unwrap();
    let (status, permit) = runtime
        .publish_condition_result(&stop, &mut result_publisher, 32 << 20)
        .unwrap();
    assert_eq!(status, PublicationStatus::Committed);
    runtime
        .acknowledge_condition_result(&stop, &permit.unwrap())
        .unwrap();
    let original = runtime.condition_stop_checkpoint().unwrap().clone();
    let original_bytes =
        canonical::canonical_json(&serde_json::to_value(&original.record).unwrap()).unwrap();
    let original_report = original.report.clone().unwrap();
    std::fs::write(directory.join("original-stop.json"), &original_bytes).unwrap();
    std::fs::write(
        directory.join("original-report.json"),
        &original_report.bytes,
    )
    .unwrap();
    eprintln!("condition original evidence: {}", directory.display());
    if oversized {
        let before = runtime.condition_stop_checkpoint().unwrap().clone();
        for underdeclared in [8 << 20, 16 << 20] {
            assert!(matches!(
                runtime.condition_runtime_snapshot(cut, 1.into(), underdeclared),
                Err(crucible::node_contract::RuntimeError::ResourceLimit)
            ));
            assert_eq!(runtime.condition_stop_checkpoint().unwrap(), &before);
        }
    }
    let archive_path = directory.as_path().join("archive");
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let factory = catalog.host_state_factory(&selections, &scenario).unwrap();
    let captured = archive.capture_condition_world(
        &graph,
        &mut runtime,
        &activation,
        cut,
        1.into(),
        id("condition-cold/capture"),
        requirements(),
        factory.as_ref(),
        factory.as_ref(),
    );
    if oversized {
        let error = captured
            .err()
            .expect("oversized original unexpectedly captured");
        assert!(
            error
                .to_string()
                .contains("host complete native capture and evidence exceed preallocation ceiling")
        );
        assert_eq!(runtime.condition_stop_checkpoint().unwrap(), &original);
        std::fs::write(
            directory.join("original-native-ceiling-refusal.txt"),
            error.to_string(),
        )
        .unwrap();
        drop(runtime);
        reclaim(&catalog);
        return;
    }
    let record = captured.unwrap_or_else(|error| panic!("condition capture: {error}"));
    adverse::verify_original_body_controls(&record, &runtime, &graph, cut);
    if queued_write {
        let source = runtime
            .condition_runtime_snapshot(cut, 1.into(), 32 << 20)
            .unwrap();
        assert!(source.inputs.iter().any(|input| {
            input.node == id("disk")
                && input.committed
                && input.acknowledgement.is_some()
                && input.payloads.iter().any(|payload| {
                    BlockRequest::decode(&payload.bytes).is_ok_and(|request| {
                        request.request_id == 8 && request.data == vec![0x6d; queued_length]
                    })
                })
        }));
    }

    let horizon = if queued_write {
        2_100_000.into()
    } else {
        1_513_011.into()
    };
    let original_prefix = driver.publications().len();
    let BeginResult::Accepted(source_resume) = runtime
        .begin_condition_resume(&activation, id("condition-cold/source-resume"))
        .unwrap()
    else {
        panic!("original source Resume refused");
    };
    assert!(matches!(
        runtime.poll(&source_resume, &mut context),
        Poll::Ready(Ok(_))
    ));
    let mut source_resume_publisher =
        crate::node_observed_executor::StoredConditionResultPublisher::new(
            blobs.clone(),
            refs.clone(),
            RefName::new("node-world-coordinators/condition/cold-source-resume").unwrap(),
            32 << 20,
        )
        .unwrap();
    let (_, permit) = runtime
        .publish_condition_result(&source_resume, &mut source_resume_publisher, 32 << 20)
        .unwrap();
    runtime
        .acknowledge_condition_result(&source_resume, &permit.unwrap())
        .unwrap();
    // An original live world cannot mint a restored suffix namespace.
    assert!(
        ConditionExecution::for_restored_resume(&mut runtime, &graph, &activation, 8192).is_err()
    );
    driver
        .continue_original_after_resume(&mut runtime, &graph, &activation, &id("observer"), horizon)
        .unwrap();
    let original_suffix: Vec<_> = driver.publications()[original_prefix..]
        .iter()
        .filter(|publication| publication.endpoint.node_id == id("disk"))
        .map(|publication| {
            (
                publication.native_sequence,
                publication.payload_bytes.clone(),
            )
        })
        .collect();
    assert_eq!(original_suffix.len(), if queued_write { 2 } else { 1 });
    std::fs::write(
        directory.join("original-native-suffix.json"),
        canonical::canonical_json(&serde_json::to_value(&original_suffix).unwrap()).unwrap(),
    )
    .unwrap();

    let artifact = record.artifact().clone();
    drop(record);
    drop(runtime);
    reclaim(&catalog);
    drop(factory);
    drop(activation);
    drop(graph);
    drop(catalog);
    drop(archive);
    for name in ["base", "script", "condition"] {
        std::fs::remove_file(directory.as_path().join(name)).unwrap();
    }

    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.as_path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    catalog
        .install_artifacts(
            references
                .iter()
                .cloned()
                .map(InstalledIoArtifact::archive_only)
                .collect(),
        )
        .unwrap();
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let (left_graph, mut left) = restore(
        &mut catalog,
        &selections,
        &scenario,
        record.clone(),
        211,
        (&blobs, &refs),
        limits,
    );
    let (right_graph, mut right) = restore(
        &mut catalog,
        &selections,
        &scenario,
        record,
        212,
        (&blobs, &refs),
        limits,
    );
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    assert_ne!(
        left_activation.record().owners,
        right_activation.record().owners
    );

    for (index, (branch, graph, activation)) in [
        (&mut left, &left_graph, &left_activation),
        (&mut right, &right_graph, &right_activation),
    ]
    .into_iter()
    .enumerate()
    {
        let runtime = branch.runtime_mut();
        let restored = runtime.condition_stop_checkpoint().unwrap();
        assert_eq!(
            canonical::canonical_json(&serde_json::to_value(&restored.record).unwrap()).unwrap(),
            original_bytes
        );
        assert_eq!(restored.report.as_ref().unwrap(), &original_report);
        assert!(restored.acknowledged && !restored.resumed);
        assert!(ConditionExecution::for_restored_resume(runtime, graph, activation, 8192).is_err());
        assert!(
            runtime
                .begin_condition_resume(activation, id("unreconciled-resume"))
                .is_err()
        );
        let stop = runtime.recover(&original.record.operation).unwrap();
        let (status, permit) = runtime
            .publish_condition_result(&stop, &mut result_publisher, 32 << 20)
            .unwrap();
        assert_eq!(status, PublicationStatus::Committed);
        assert!(permit.is_some());
        let mut resume_publisher =
            crate::node_observed_executor::StoredConditionResultPublisher::new(
                blobs.clone(),
                refs.clone(),
                RefName::new(format!(
                    "node-world-coordinators/condition/cold-branch-{index}"
                ))
                .unwrap(),
                32 << 20,
            )
            .unwrap();
        let BeginResult::Accepted(resume) = runtime
            .begin_condition_resume(activation, id("condition-cold/resume"))
            .unwrap()
        else {
            panic!("same-cut authentic Resume refused");
        };
        assert!(matches!(
            runtime.poll(&resume, &mut context),
            Poll::Ready(Ok(_))
        ));
        let (_, permit) = runtime
            .publish_condition_result(&resume, &mut resume_publisher, 32 << 20)
            .unwrap();
        runtime
            .acknowledge_condition_result(&resume, &permit.unwrap())
            .unwrap();
        let foreign = if index == 0 {
            &right_activation
        } else {
            &left_activation
        };
        assert!(ConditionExecution::for_restored_resume(runtime, graph, foreign, 8192).is_err());
        let mut suffix_driver =
            ConditionExecution::for_restored_resume(runtime, graph, activation, 8192).unwrap();
        suffix_driver
            .continue_original_after_resume(
                runtime,
                graph,
                activation,
                &id("observer"),
                if queued_write {
                    2_100_000.into()
                } else {
                    1_513_011.into()
                },
            )
            .unwrap();
        let restored_suffix: Vec<_> = suffix_driver
            .publications()
            .iter()
            .filter(|publication| publication.endpoint.node_id == id("disk"))
            .map(|publication| {
                (
                    publication.native_sequence,
                    publication.payload_bytes.clone(),
                )
            })
            .collect();
        assert_eq!(restored_suffix, original_suffix);
        let reads: Vec<_> = suffix_driver
            .publications()
            .iter()
            .filter_map(|publication| {
                if publication.endpoint.node_id != id("disk") {
                    return None;
                }
                let response = BlockResponse::decode(&publication.payload_bytes).unwrap();
                (response.request_id == 9).then_some((response, publication.native_sequence))
            })
            .collect();
        assert_eq!(reads.len(), 1);
        assert_eq!(
            reads[0].0.data,
            vec![if queued_write { 0x6d } else { 0x5c }; write_length]
        );
        assert_eq!(reads[0].1, U64::new(if queued_write { 2 } else { 1 }));
        let queued_completions: Vec<_> = suffix_driver
            .publications()
            .iter()
            .filter(|publication| publication.endpoint.node_id == id("disk"))
            .filter_map(|publication| {
                let response = BlockResponse::decode(&publication.payload_bytes).unwrap();
                (response.request_id == 8).then_some(publication.native_sequence)
            })
            .collect();
        assert_eq!(
            queued_completions,
            if queued_write {
                vec![U64::new(1)]
            } else {
                vec![]
            }
        );
        assert!(
            runtime
                .begin_condition_resume(activation, id("condition-cold/second-resume"))
                .is_err()
        );
        assert_eq!(
            runtime
                .condition_stop_checkpoint()
                .unwrap()
                .report
                .as_ref()
                .unwrap(),
            &original_report
        );
    }
    drop(left);
    drop(right);
    reclaim(&catalog);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(
        std::fs::read(directory.as_path().join("base"))
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}
