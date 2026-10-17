//! Genuine seeded transport custody and two fresh source-gone storage branches.

use super::*;
use crate::node_observed_executor::factory::InstalledSeededLinkProfile;
use crucible::node_adapters::SeededLinkDefinition;

fn stage_and_run(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    node: &str,
    name: &str,
    horizon: u64,
) -> OperationOutcome {
    observe(runtime, graph, activation);
    let cutoff = runtime
        .scheduler(graph, activation)
        .unwrap()
        .preview_exact_input_cut(&id(node), horizon.into())
        .unwrap();
    let input = runtime
        .scheduler(graph, activation)
        .unwrap()
        .prepare_input_batch(
            &id(node),
            id(&format!("{name}/stage")),
            id(&format!("{name}/batch")),
            cutoff,
        )
        .unwrap();
    let acknowledgement = runtime.stage_inputs(input).unwrap();
    let commit = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&commit).unwrap();
    exact(
        runtime,
        graph,
        activation,
        node,
        &format!("{name}/run"),
        horizon,
    )
}

fn suffix(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    name: &str,
    horizon: u64,
) -> Vec<crucible::node_scheduling::NativePublication> {
    exact(
        runtime,
        graph,
        activation,
        "source",
        &format!("{name}/source"),
        horizon,
    );
    stage_and_run(
        runtime,
        graph,
        activation,
        "link",
        &format!("{name}/link"),
        horizon,
    );
    stage_and_run(
        runtime,
        graph,
        activation,
        "disk",
        &format!("{name}/disk"),
        horizon,
    )
    .scheduling
    .unwrap()
    .publications
}

fn native_link(
    record: &HostArchiveRecord,
    definition: &SeededLinkDefinition,
) -> crucible_device::netlink::LinkSnapshot {
    let owner = record
        .manifest()
        .owners
        .iter()
        .find(|owner| owner.capture_owner_id == id("link-owner"))
        .unwrap();
    let bytes = record
        .content_bytes(owner.state_ref.as_ref().unwrap(), 64 * 1024 * 1024)
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let native: Vec<u8> = serde_json::from_value(envelope["native"].clone()).unwrap();
    definition
        .restore(&native, 64 * 1024 * 1024)
        .unwrap()
        .snapshot()
}

#[test]
#[ignore = "requires the source-built CRUCIBLE_REFERENCE_DEVICE and complete installed seeded transport"]
fn seeded_pending_native_frame_retains_rng_and_future_draws_across_two_source_gone_branches() {
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
    let write = BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap();
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: write.clone(),
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: BlockRequest::read(102, 0, 3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let definition = SeededLinkDefinition {
        version: 1,
        seed: 77.into(),
        stream: id("storage/requests"),
        source_node: 17,
        latency_ps: 1000.into(),
        floor_ps: 1000.into(),
        jitter_ps: 5000.into(),
        reorder_ps: 3000.into(),
    };
    let program = canonical::canonical_json(&serde_json::to_value(&definition).unwrap()).unwrap();
    let artifacts = [
        ("base", base.clone()),
        ("script", script),
        ("program", program),
    ];
    let references: Vec<_> = artifacts
        .iter()
        .map(|(_, bytes)| canonical::content_ref(bytes, "application/octet-stream").unwrap())
        .collect();
    let mut paths = Vec::new();
    for ((name, bytes), reference) in artifacts.iter().zip(&references) {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        catalog
            .install_artifacts(vec![InstalledIoArtifact::path(
                path.clone(),
                reference.clone(),
            )])
            .unwrap();
        paths.push(path);
    }
    let selections = vec![
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
            node: id("link"),
            owner: id("link-owner"),
            kind: InstalledNodeKind::HostSeededLink {
                profile: InstalledSeededLinkProfile {
                    program: references[2].clone(),
                    producer: id("source"),
                    consumer: id("disk"),
                },
            },
        },
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: references[1].clone(),
                    consumer: id("link"),
                },
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let factory = catalog.host_state_factory(&selections, &scenario).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "seeded",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let prepared = catalog
        .prepare_world(
            &selections,
            scenario.clone(),
            ExecutionId::from_bytes([111; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "seeded-source"))
        .unwrap();
    for node in ["source", "link", "disk"] {
        exact(
            &mut runtime,
            &graph,
            &activation,
            node,
            &format!("initial/{node}"),
            10,
        );
    }
    let birth_cut = Position::new(10.into(), 1.into(), Phase::BoundaryControl);
    for node in ["source", "link", "disk"] {
        settle(
            &mut runtime,
            &graph,
            &activation,
            node,
            &format!("birth/{node}"),
            birth_cut,
        );
    }
    exact(
        &mut runtime,
        &graph,
        &activation,
        "source",
        "pending/source",
        12,
    );
    let link_outcome = stage_and_run(
        &mut runtime,
        &graph,
        &activation,
        "link",
        "pending/link",
        12,
    );
    assert!(link_outcome.scheduling.unwrap().publications.is_empty());
    exact(
        &mut runtime,
        &graph,
        &activation,
        "disk",
        "pending/disk",
        12,
    );
    let cut = Position::new(12.into(), 0.into(), Phase::BoundaryControl);
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
            9.into(),
            id("capture/seeded"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let before = native_link(&record, &definition);
    assert_eq!(before.rng_position, 5);
    assert_eq!(before.next_seq, 1);
    assert_eq!(before.inflight.len(), 1);
    assert_eq!(before.inflight[0].response.payload, write);
    assert!(before.inflight[0].key.delivery_icount > 12);
    assert_eq!(before.faults, definition.faults());
    let mut independently_resolved = definition.instantiate().unwrap();
    let mut rng = independently_resolved.rng(
        definition.seed.get(),
        "crucible/seeded-link-v1",
        definition.stream.as_str(),
    );
    independently_resolved
        .emit_from_rng(
            &crucible_device::netlink::Frame::new(10, 0, write.clone()),
            &mut rng,
            crucible_device::netlink::PastDeliveryPolicy::FailLoud,
        )
        .unwrap();
    assert_eq!(before, independently_resolved.snapshot());
    assert_ne!(before.inflight[0].key.delivery_icount, 1010);
    let artifact = record.artifact().clone();
    let emission_time = before.inflight[0].key.delivery_icount;
    exact(
        &mut runtime,
        &graph,
        &activation,
        "source",
        "fifo/source-park",
        emission_time,
    );
    stage_and_run(
        &mut runtime,
        &graph,
        &activation,
        "link",
        "fifo/link-park",
        emission_time,
    );
    exact(
        &mut runtime,
        &graph,
        &activation,
        "disk",
        "fifo/disk-park",
        emission_time,
    );
    let fifo_cut = Position::new(emission_time.into(), 1.into(), Phase::BoundaryControl);
    for node in ["source", "link", "disk"] {
        settle(
            &mut runtime,
            &graph,
            &activation,
            node,
            &format!("fifo/{node}-publish"),
            fifo_cut,
        );
    }
    let fifo = pending(&mut runtime, &graph, &activation);
    assert_eq!(fifo.len(), 1);
    assert_eq!(fifo[0].producer, id("link"));
    assert_eq!(fifo[0].causal_parents.len(), 1);
    assert_eq!(fifo[0].native_sequence, U64::new(0));
    fifo[0].payload.verify(&write).unwrap();
    let fifo_record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &activation,
            fifo_cut,
            15.into(),
            id("capture/seeded-fifo"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let fifo_artifact = fifo_record.artifact().clone();
    drop(fifo_record);
    // The source continues unchanged as an independent oracle before every
    // original native object, registry and artifact pathname is destroyed.
    let original_write = suffix(&mut runtime, &graph, &activation, "write", 20_000);
    let original_read = suffix(&mut runtime, &graph, &activation, "read", 100_000);
    assert_eq!(std::fs::read(&paths[0]).unwrap(), base);
    let final_record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &activation,
            Position::new(100_000.into(), 0.into(), Phase::BoundaryControl),
            20.into(),
            id("capture/original-final"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let original_final = native_link(&final_record, &definition);
    assert_eq!(original_final.rng_position, 10);
    assert_eq!(original_final.next_seq, 2);
    assert!(original_final.inflight.is_empty());
    drop(final_record);
    drop(record);
    drop(runtime);
    reclaim(&catalog);
    drop(activation);
    drop(graph);
    drop(factory);
    drop(catalog);
    drop(archive);
    for path in &paths {
        std::fs::remove_file(path).unwrap();
    }
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.path().to_owned(),
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
    let reserved_before = catalog.custody().reserved_worlds();
    let mut wrong = selections.clone();
    let InstalledNodeKind::HostSeededLink { profile } = &mut wrong[1].kind else {
        panic!("wrong fixture");
    };
    let mut wrong_seed = definition.clone();
    wrong_seed.seed = 78.into();
    let wrong_program =
        canonical::canonical_json(&serde_json::to_value(&wrong_seed).unwrap()).unwrap();
    profile.program = canonical::content_ref(&wrong_program, "application/octet-stream").unwrap();
    catalog
        .install_artifacts(vec![InstalledIoArtifact::archive_only(
            profile.program.clone(),
        )])
        .unwrap();
    assert!(
        catalog
            .host_state_factory_from_archive(&wrong, &scenario, &record)
            .is_err()
    );
    assert!(
        catalog
            .prepare_host_restore_graph(
                &wrong,
                &scenario,
                &record,
                ExecutionId::from_bytes([117; 16]).unwrap()
            )
            .is_err()
    );
    assert_eq!(catalog.custody().reserved_worlds(), reserved_before);
    let (left_graph, mut left) = restore(
        &mut catalog,
        &selections,
        &scenario,
        record.clone(),
        112,
        (&blobs, &refs),
        limits,
    );
    let (right_graph, mut right) = restore(
        &mut catalog,
        &selections,
        &scenario,
        record,
        113,
        (&blobs, &refs),
        limits,
    );
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    assert_ne!(
        left_activation.record().owners,
        right_activation.record().owners
    );
    let left_write = suffix(
        left.runtime_mut(),
        &left_graph,
        &left_activation,
        "write",
        20_000,
    );
    let right_write = suffix(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        "write",
        20_000,
    );
    assert_eq!(left_write, right_write);
    assert_eq!(left_write, original_write);
    assert_eq!(left_write.len(), 1);
    assert_eq!(
        BlockResponse::decode(&left_write[0].payload_bytes)
            .unwrap()
            .request_id,
        101
    );
    let left_read = suffix(
        left.runtime_mut(),
        &left_graph,
        &left_activation,
        "read",
        100_000,
    );
    let right_read = suffix(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        "read",
        100_000,
    );
    assert_eq!(left_read, right_read);
    assert_eq!(left_read, original_read);
    assert_eq!(left_read.len(), 1);
    assert_eq!(left_read[0].native_sequence, U64::new(1));
    let reply = BlockResponse::decode(&left_read[0].payload_bytes).unwrap();
    assert_eq!(reply.request_id, 102);
    assert_eq!(reply.data, vec![7, 8, 9]);
    for (branch, branch_graph, activation, name) in [
        (
            &mut left,
            &left_graph,
            &left_activation,
            "capture/left-final",
        ),
        (
            &mut right,
            &right_graph,
            &right_activation,
            "capture/right-final",
        ),
    ] {
        let factory = catalog
            .host_state_factory_from_archive(
                &selections,
                &scenario,
                &archive.load(&artifact).unwrap(),
            )
            .unwrap();
        let final_record = archive
            .capture_world(
                branch_graph,
                branch.runtime_mut(),
                activation,
                Position::new(100_000.into(), 0.into(), Phase::BoundaryControl),
                20.into(),
                id(name),
                requirements(),
                factory.as_ref(),
                factory.as_ref(),
            )
            .unwrap();
        assert_eq!(native_link(&final_record, &definition), original_final);
    }
    for (branch, branch_graph, activation, name) in [
        (&mut left, &left_graph, &left_activation, "left-empty"),
        (&mut right, &right_graph, &right_activation, "right-empty"),
    ] {
        assert!(
            suffix(
                branch.runtime_mut(),
                branch_graph,
                activation,
                name,
                110_000
            )
            .is_empty()
        );
    }
    assert_eq!(base, artifacts[0].1);
    drop(left);
    drop(right);
    reclaim(&catalog);
    // The later cut owns the actual link-to-disk transfer under the original
    // coordinator FIFO, including its native receipt and causal position.
    for nonce in [114, 115] {
        let fifo_record = archive.load(&fifo_artifact).unwrap();
        let (graph, mut branch) = restore(
            &mut catalog,
            &selections,
            &scenario,
            fifo_record,
            nonce,
            (&blobs, &refs),
            limits,
        );
        let activation = branch.activation().clone();
        assert_eq!(pending(branch.runtime_mut(), &graph, &activation), fifo);
        assert_eq!(
            suffix(branch.runtime_mut(), &graph, &activation, "write", 20_000),
            original_write
        );
        assert_eq!(
            suffix(branch.runtime_mut(), &graph, &activation, "read", 100_000),
            original_read
        );
        drop(branch);
        reclaim(&catalog);
    }
}
