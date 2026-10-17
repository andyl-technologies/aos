//! Signed cold preservation of an actual read-only 9p session and delayed reply.

use super::*;
use crucible_device::{
    FsTree,
    ninep::{codec, tree::Node},
};
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

fn requests(length: u32) -> Vec<ScriptedRequest> {
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
    read.extend_from_slice(&length.to_le_bytes());
    let mut suffix_read = 2u32.to_le_bytes().to_vec();
    suffix_read.extend_from_slice(&5u64.to_le_bytes());
    suffix_read.extend_from_slice(&4u32.to_le_bytes());

    [
        (codec::TVERSION, version),
        (codec::TATTACH, attach),
        (codec::TWALK, walk),
        (codec::TLOPEN, open),
        (codec::TREAD, read),
        (codec::TREAD, suffix_read),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (kind, body))| ScriptedRequest {
        time_ps: 10 + u64::try_from(index).unwrap() * 100_000,
        payload: frame(kind, u16::try_from(index + 1).unwrap(), body),
    })
    .collect()
}

fn publish_request(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    index: usize,
    prefix: &str,
) {
    let time = 10 + u64::try_from(index).unwrap() * 100_000;
    exact(
        runtime,
        graph,
        activation,
        "source",
        &format!("{prefix}/park/{index}"),
        time,
    );
    settle(
        runtime,
        graph,
        activation,
        "source",
        &format!("{prefix}/publish/{index}"),
        Position::new(time.into(), 1.into(), Phase::Delivery),
    );
}

#[test]
#[ignore = "requires the source-built CRUCIBLE_REFERENCE_DEVICE and complete installed 9p archive qualification"]
fn installed_ninep_session_and_delayed_reply_survive_source_retirement_and_cold_siblings() {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let catalog = || {
        InstalledNodeCatalog::new(
            executable.clone(),
            measure_executable(&executable).unwrap(),
            directory.path().to_owned(),
            Duration::from_secs(5),
            4,
        )
        .unwrap()
    };
    let mut original = catalog();
    let file = b"original read-only native filesystem bytes\n".to_vec();
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
    let tree_path = directory.path().join("tree");
    let script_path = directory.path().join("ninep-script");
    std::fs::write(&tree_path, tree).unwrap();
    std::fs::write(&script_path, script).unwrap();
    original
        .install_artifacts(vec![
            InstalledIoArtifact::path(tree_path.clone(), tree_ref.clone()),
            InstalledIoArtifact::path(script_path.clone(), script_ref.clone()),
        ])
        .unwrap();
    let archive_policy = vec![
        InstalledIoArtifact::archive_only(tree_ref.clone()),
        InstalledIoArtifact::archive_only(script_ref.clone()),
    ];
    let selections = vec![
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("disk-owner"),
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
                    consumer: id("disk"),
                },
            },
        },
    ];
    let scenario = original.scenario(&selections).unwrap();
    let factory = original.host_state_factory(&selections, &scenario).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "ninep-cold",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let prepared = original
        .prepare_world(
            &selections,
            scenario.clone(),
            ExecutionId::from_bytes([94; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "ninep-source"))
        .unwrap();

    // Version negotiation, fid attachment, walk and open occur through real
    // public request deliveries before the delayed original read is captured.
    for index in 0..5 {
        publish_request(&mut runtime, &graph, &activation, index, "ninep-source");
        let time = 10 + u64::try_from(index).unwrap() * 100_000;
        let horizon = if index == 4 { time + 1 } else { time + 90_000 };
        let outcome = advance_disk(
            &mut runtime,
            &graph,
            &activation,
            &format!("ninep/source/{index}"),
            horizon,
        );
        let outputs = &outcome.scheduling.as_ref().unwrap().publications;
        if index == 4 {
            assert!(outputs.is_empty());
        } else {
            assert_eq!(outputs.len(), 1);
            assert_eq!(
                u16::from_le_bytes(outputs[0].payload_bytes[5..7].try_into().unwrap()),
                u16::try_from(index + 1).unwrap()
            );
        }
    }
    assert!(pending(&mut runtime, &graph, &activation).is_empty());
    let cut = Position::new(400_011.into(), 0.into(), Phase::BoundaryControl);
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive_path = directory.path().join("archive");
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &activation,
            cut,
            30.into(),
            id("capture/ninep"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let artifact = record.artifact().clone();
    drop(record);
    drop(runtime);
    reclaim(&original);
    drop(activation);
    drop(graph);
    drop(factory);
    drop(original);
    drop(archive);
    std::fs::remove_file(tree_path).unwrap();
    std::fs::remove_file(script_path).unwrap();

    let mut restored_catalog = catalog();
    restored_catalog.install_artifacts(archive_policy).unwrap();
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let (left_graph, mut left) = restore(
        &mut restored_catalog,
        &selections,
        &scenario,
        record.clone(),
        95,
        (&blobs, &refs),
        limits,
    );
    let (right_graph, mut right) = restore(
        &mut restored_catalog,
        &selections,
        &scenario,
        record,
        96,
        (&blobs, &refs),
        limits,
    );
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    let left_reply = advance_disk(
        left.runtime_mut(),
        &left_graph,
        &left_activation,
        "ninep/left-read",
        490_000,
    );
    let right_pending = advance_disk(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        "ninep/right-delay",
        400_012,
    );
    assert!(
        right_pending
            .scheduling
            .as_ref()
            .unwrap()
            .publications
            .is_empty()
    );
    let right_reply = advance_disk(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        "ninep/right-read",
        490_000,
    );
    let left_output = &left_reply.scheduling.as_ref().unwrap().publications;
    let right_output = &right_reply.scheduling.as_ref().unwrap().publications;
    assert_eq!(left_output.len(), 1);
    assert_eq!(right_output.len(), 1);
    assert_eq!(left_output[0].payload_bytes, right_output[0].payload_bytes);
    assert_eq!(left_output[0].publication, right_output[0].publication);
    assert_eq!(
        left_output[0].causal_parents,
        right_output[0].causal_parents
    );
    assert_eq!(left_output[0].native_sequence, U64::new(4));
    assert_eq!(left_output[0].payload_bytes[4], codec::RREAD);
    assert_eq!(&left_output[0].payload_bytes[11..], file.as_slice());

    // The still-open original fid serves the untouched future script request
    // exactly once in each fresh world, without repeating session setup.
    for (branch, branch_graph, activation, name) in [
        (
            &mut left,
            &left_graph,
            &left_activation,
            "ninep/left-suffix",
        ),
        (
            &mut right,
            &right_graph,
            &right_activation,
            "ninep/right-suffix",
        ),
    ] {
        publish_request(branch.runtime_mut(), branch_graph, activation, 5, name);
        let reply = advance_disk(
            branch.runtime_mut(),
            branch_graph,
            activation,
            name,
            590_000,
        );
        let outputs = &reply.scheduling.as_ref().unwrap().publications;
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].native_sequence, U64::new(5));
        assert_eq!(outputs[0].payload_bytes[4], codec::RREAD);
        assert_eq!(
            u16::from_le_bytes(outputs[0].payload_bytes[5..7].try_into().unwrap()),
            6
        );
        assert_eq!(&outputs[0].payload_bytes[11..], &file[5..9]);
        assert!(pending(branch.runtime_mut(), branch_graph, activation).is_empty());
    }
    drop(left);
    drop(right);
    reclaim(&restored_catalog);
}
