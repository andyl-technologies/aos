//! Actual public request-source execution through a retained native 9p session.

use super::*;
use crucible::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
use crucible_device::{
    FsTree,
    ninep::{codec, tree::Node},
};
use crucible_node_contract::canonical;
use std::collections::BTreeMap;

fn frame(kind: u8, tag: u16, body: Vec<u8>) -> Vec<u8> {
    let mut bytes = u32::try_from(body.len() + 7)
        .unwrap()
        .to_le_bytes()
        .to_vec();
    bytes.push(kind);
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

fn string(body: &mut Vec<u8>, value: &str) {
    body.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
    body.extend_from_slice(value.as_bytes());
}

fn requests(count: u32) -> Vec<ScriptedRequest> {
    let mut version = 4608u32.to_le_bytes().to_vec();
    string(&mut version, "9P2000.L");
    let mut attach = 1u32.to_le_bytes().to_vec();
    attach.extend_from_slice(&u32::MAX.to_le_bytes());
    string(&mut attach, "");
    string(&mut attach, "");
    attach.extend_from_slice(&0u32.to_le_bytes());
    let mut walk = 1u32.to_le_bytes().to_vec();
    walk.extend_from_slice(&2u32.to_le_bytes());
    walk.extend_from_slice(&1u16.to_le_bytes());
    string(&mut walk, "hello");
    let mut open = 2u32.to_le_bytes().to_vec();
    open.extend_from_slice(&0u32.to_le_bytes());
    let mut read = 2u32.to_le_bytes().to_vec();
    read.extend_from_slice(&0u64.to_le_bytes());
    read.extend_from_slice(&count.to_le_bytes());
    [
        (codec::TVERSION, version),
        (codec::TATTACH, attach),
        (codec::TWALK, walk),
        (codec::TLOPEN, open),
        (codec::TREAD, read),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (kind, body))| ScriptedRequest {
        time_ps: 10 + u64::try_from(index).unwrap() * 100_000,
        payload: frame(kind, u16::try_from(index + 1).unwrap(), body),
    })
    .collect()
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_scripted_ninep_session_preserves_tags_file_bytes_and_public_custody() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "ninep-observed",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        factory::measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let file = b"actual public filesystem request bytes\n".to_vec();
    let tree = FsTree::try_new(Node::Directory {
        children: BTreeMap::from([(
            "hello".into(),
            Node::File {
                content: file.clone(),
            },
        )]),
    })
    .unwrap()
    .canonical_bytes();
    let script = ScriptedSource::new(
        ScriptedRequestKind::Ninep,
        requests(u32::try_from(file.len()).unwrap()),
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let tree_ref = canonical::content_ref(&tree, "application/octet-stream").unwrap();
    let script_ref = canonical::content_ref(&script, "application/octet-stream").unwrap();
    let tree_path = temporary.path().join("tree");
    let script_path = temporary.path().join("script");
    std::fs::write(&tree_path, &tree).unwrap();
    std::fs::write(&script_path, &script).unwrap();
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(tree_path.clone(), tree_ref.clone()),
            InstalledIoArtifact::path(script_path, script_ref.clone()),
        ])
        .unwrap();
    let selected = vec![
        InstalledNodeSelection {
            node: id("filesystem"),
            owner: id("filesystem-owner"),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Ninep {
                    tree: tree_ref,
                    source_node: 9,
                    control_ns: 1.into(),
                    data_ns: 1.into(),
                    per_byte_ns: 1.into(),
                },
            },
        },
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: script_ref,
                    consumer: id("filesystem"),
                },
            },
        },
    ];
    let scenario = catalog.scenario(&selected).unwrap();
    assert_eq!(scenario.world.connections.len(), 1);
    let execution = ExecutionId::from_bytes([73; 16]).unwrap();
    let backend = catalog
        .prepare(
            &selected,
            scenario,
            NodeRunConfiguration {
                horizon_ps: 600_000.into(),
                maximum_rounds: 128.into(),
                ..configuration()
            },
            execution,
            blobs.clone(),
            refs,
        )
        .unwrap();
    let planned = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            planned.scenario(),
            planned.payload_schema(),
            planned.payload().to_vec(),
        )
        .unwrap();
    let configured = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configured.scenario(),
            configured.scenario_artifact(),
            configured.configuration(),
            configured.payload_schema(),
            configured.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    assert!(request.capabilities().roster().is_repeatable());
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();
    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    worker.submit("native-ninep", &request, &admission).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(result) => break result,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("actual 9p world quarantined: {reason}")
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(Instant::now() < deadline, "actual 9p world stayed blocked");
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let bytes = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let outgoing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut responses = Vec::new();
    let mut source_publications = Vec::new();
    for event in outgoing["events"].as_array().unwrap() {
        let outcome: crucible::node_contract::OperationOutcome =
            serde_json::from_value(event.clone()).unwrap();
        let observation = outcome.scheduling.as_ref().unwrap();
        if outcome.node == id("source") {
            for publication in &observation.publications {
                assert!(publication.causal_parents.is_empty());
                assert!(observation.external_inputs.is_empty());
                source_publications.push(publication.publication);
            }
        } else if outcome.node == id("filesystem") {
            for publication in &observation.publications {
                assert!(publication.evaluation.is_some());
                assert_eq!(publication.causal_parents.len(), 1);
                publication
                    .payload
                    .verify(&publication.payload_bytes)
                    .unwrap();
                responses.push((
                    publication.payload_bytes.clone(),
                    publication.causal_parents[0],
                ));
            }
        }
    }
    assert_eq!(responses.len(), 5);
    assert_eq!(source_publications.len(), 5);
    for (index, (response, parent)) in responses.iter().enumerate() {
        assert_eq!(
            usize::try_from(u32::from_le_bytes(response[..4].try_into().unwrap())).unwrap(),
            response.len()
        );
        assert_eq!(
            response[4],
            [
                codec::RVERSION,
                codec::RATTACH,
                codec::RWALK,
                codec::RLOPEN,
                codec::RREAD
            ][index]
        );
        assert_eq!(
            u16::from_le_bytes(response[5..7].try_into().unwrap()),
            u16::try_from(index + 1).unwrap()
        );
        let original = source_publications[index];
        assert_eq!(parent.time_ps, original.time_ps);
        assert_eq!(parent.microstep, original.microstep);
        assert_eq!(parent.phase, crucible_node_contract::Phase::Delivery);
    }
    assert_eq!(
        responses[0].0,
        codec::encode_rversion(1, 4608, "9P2000.L").unwrap()
    );
    assert_eq!(responses[4].0, codec::encode_rread(5, &file).unwrap());
    assert_eq!(std::fs::read(tree_path).unwrap(), tree);
    assert_eq!(
        worker.submit("native-ninep", &request, &admission).unwrap(),
        ObservedAttemptState::Completed(result)
    );
}
