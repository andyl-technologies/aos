//! Genuine original recorded Block cursor and two source-gone native branches.

#![cfg(test)]
// Assertions intentionally panic on changed native ownership or original bytes.
// crucible-lint: allow panic-shortcut -- This native cursor fixture must fail on any changed original inventory.
// crucible-lint: allow rust-allow -- Assertions inspect genuine captured originals and intentionally panic on changed custody or refusal predicates.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_observed_executor::factory::recorded_ingress::{
    InstalledRecordedIngressProfile, endpoint,
};
use crate::node_scenario::NodeRunConfiguration;
use crucible::node_adapters::{RecordedLogicalInput, RecordedLogicalInputSource};
use crucible::node_scheduling::InputPayload;

#[path = "host_state_recorded_adverse_tests.rs"]
mod adverse;

struct Fixture {
    directory: tempfile::TempDir,
    catalog: InstalledNodeCatalog,
    selection: Vec<InstalledNodeSelection>,
    source_path: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let directory = tempfile::Builder::new()
        .prefix("recorded-ingress-")
        .tempdir_in("/tmp")
        .unwrap();
    // This scope runs the source-built host Block implementation. It creates no
    // reference child and needs no unrelated installed simulator dependency.
    let executable = std::env::current_exe().unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.path().to_owned(),
        Duration::from_secs(3),
        2,
    )
    .unwrap();
    let node = Id::new("disk").unwrap();
    let configuration = NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: U64::new(100_000),
        maximum_rounds: U64::new(64),
    };
    let original = RecordedLogicalInputSource {
        format: "crucible.recorded-logical-input".into(),
        version: 1,
        endpoint: endpoint(&node).unwrap(),
        closed_before: Position {
            time_ps: 200_000.into(),
            microstep: 0.into(),
            phase: Phase::BoundaryControl,
        },
        inputs: [
            BlockRequest::write(101, 0, vec![1, 2, 3]),
            BlockRequest::read(102, 0, 3),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, request)| {
            let bytes = request.encode().unwrap();
            RecordedLogicalInput {
                event: Id::new(format!("original/input/{index}")).unwrap(),
                sequence: U64::new(17 + index as u64),
                publication: Position {
                    time_ps: U64::new(if index == 0 { 10 } else { 50_000 }),
                    microstep: 0.into(),
                    phase: Phase::Publication,
                },
                payload: InputPayload {
                    reference: canonical::content_ref(&bytes, "application/octet-stream").unwrap(),
                    bytes,
                },
            }
        })
        .collect(),
    };
    let bytes = canonical::canonical_json(&serde_json::to_value(original).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    let source_path = directory.path().join("original-input.json");
    std::fs::write(&source_path, &bytes).unwrap();
    let base = vec![0xab; 4096];
    let base_ref = canonical::content_ref(&base, "application/octet-stream").unwrap();
    let base_path = directory.path().join("base");
    std::fs::write(&base_path, base).unwrap();
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(source_path.clone(), reference.clone()),
            InstalledIoArtifact::path(base_path, base_ref.clone()),
        ])
        .unwrap();
    let selection = vec![InstalledNodeSelection {
        node,
        owner: Id::new("disk-owner").unwrap(),
        kind: InstalledNodeKind::HostRecordedBlockPreserving {
            profile: InstalledRecordedIngressProfile {
                source: reference,
                configuration: configuration.clone(),
                storage: InstalledHostIoProfile::Block {
                    base_image: base_ref,
                    source_node: 7,
                    read_ns: 1.into(),
                    write_ns: 1.into(),
                    flush_ns: 1.into(),
                    get_length_ns: 1.into(),
                    per_byte_ns: 1.into(),
                },
            },
        },
    }];
    Fixture {
        directory,
        catalog,
        selection,
        source_path,
    }
}

fn advance(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    name: &str,
    horizon: u64,
) -> OperationOutcome {
    observe(runtime, graph, activation);
    let cut = runtime
        .scheduler(graph, activation)
        .unwrap()
        .preview_exact_input_cut(&id("disk"), horizon.into())
        .unwrap();
    let batch = runtime
        .scheduler(graph, activation)
        .unwrap()
        .prepare_input_batch(
            &id("disk"),
            id(&format!("{name}/stage")),
            id(&format!("{name}/batch")),
            cut,
        )
        .unwrap();
    let acknowledgement = runtime.stage_inputs(batch).unwrap();
    let commit = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&commit).unwrap();
    exact(
        runtime,
        graph,
        activation,
        "disk",
        &format!("{name}/execute"),
        horizon,
    )
}

#[test]
fn recorded_block_original_cursor_survives_source_deletion_and_two_fresh_owners() {
    cold_branches(false);
}

#[test]
fn recorded_block_original_staged_suffix_survives_source_deletion_and_two_fresh_owners() {
    cold_branches(true);
}

fn cold_branches(stage_suffix: bool) {
    let mut fixture = fixture();
    let retained = fixture.directory.keep();
    eprintln!("original recorded Block cold root: {}", retained.display());
    let scenario = fixture.catalog.scenario(&fixture.selection).unwrap();
    let factory = fixture
        .catalog
        .host_state_factory(&fixture.selection, &scenario)
        .unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "recorded-cold",
        retained.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(retained.join("refs")));
    let prepared = fixture
        .catalog
        .prepare_world(
            &fixture.selection,
            scenario.clone(),
            ExecutionId::from_bytes([201; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared.realization.admit(&graph).ok().unwrap();
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "recorded-cold-source"))
        .unwrap();
    let first = advance(&mut runtime, &graph, &activation, "original/write", 10_000);
    let outputs = &first.scheduling.as_ref().unwrap().publications;
    assert_eq!(outputs.len(), 1);
    assert_eq!(
        BlockResponse::decode(&outputs[0].payload_bytes)
            .unwrap()
            .request_id,
        101
    );
    assert_eq!(
        first.scheduling.as_ref().unwrap().external_inputs[0]
            .inputs
            .len(),
        1
    );
    let before = pending(&mut runtime, &graph, &activation);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].publication_id, id("original/input/1"));
    if stage_suffix {
        observe(&mut runtime, &graph, &activation);
        let cut = runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .preview_exact_input_cut(&id("disk"), 100_000.into())
            .unwrap();
        let batch = runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .prepare_input_batch(&id("disk"), id("suffix/stage"), id("suffix/batch"), cut)
            .unwrap();
        let acknowledgement = runtime.stage_inputs(batch).unwrap();
        let commit = runtime
            .commit_input_acknowledgement(acknowledgement)
            .unwrap();
        runtime.commit_input_staging(&commit).unwrap();
        assert_eq!(pending(&mut runtime, &graph, &activation), before);
    }
    let cut = Position::new(10_000.into(), 0.into(), Phase::BoundaryControl);
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let snapshot = runtime
        .runtime_snapshot(cut, 1.into(), 16 * 1024 * 1024)
        .unwrap();
    let archive_path = retained.join("archive");
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &activation,
            cut,
            1.into(),
            id("recorded/capture"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    adverse::verify_original_data_refusals(&record, &snapshot, &graph, factory.as_ref(), limits);
    let original_native = adverse::native_body(&record);
    let artifact = record.artifact().clone();
    drop(record);
    drop(runtime);
    reclaim(&fixture.catalog);
    drop(activation);
    drop(graph);
    drop(factory);
    let executable = std::env::current_exe().unwrap();
    drop(fixture.catalog);
    drop(archive);
    std::fs::remove_file(&fixture.source_path).unwrap();
    std::fs::remove_file(retained.join("base")).unwrap();
    let InstalledNodeKind::HostRecordedBlockPreserving { profile } = &fixture.selection[0].kind
    else {
        panic!("preserving source must be selected");
    };
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        retained.clone(),
        Duration::from_secs(3),
        4,
    )
    .unwrap();
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::archive_only(profile.source.clone()),
            InstalledIoArtifact::archive_only(profile.storage.artifact().clone()),
        ])
        .unwrap();
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    adverse::verify_archive_availability(&archive, &archive_path, &artifact);
    let record = archive.load(&artifact).unwrap();
    let mut changed_selection = fixture.selection.clone();
    let InstalledNodeKind::HostRecordedBlockPreserving { profile: changed } =
        &mut changed_selection[0].kind
    else {
        panic!("preserving selection changed family");
    };
    let InstalledHostIoProfile::Block { write_ns, .. } = &mut changed.storage else {
        panic!("preserving selection changed storage");
    };
    *write_ns = U64::new(write_ns.get() + 1);
    assert!(
        catalog
            .host_state_factory_from_archive(&changed_selection, &scenario, &record,)
            .is_err()
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    let mut live_only = fixture.selection.clone();
    live_only[0].kind = InstalledNodeKind::HostRecordedBlock {
        profile: profile.clone(),
    };
    assert!(
        catalog
            .host_state_factory_from_archive(&live_only, &scenario, &record)
            .is_err()
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    let retained_original = record.clone();
    let (left_graph, mut left) = restore(
        &mut catalog,
        &fixture.selection,
        &scenario,
        record.clone(),
        202,
        (&blobs, &refs),
        limits,
    );
    let (right_graph, mut right) = restore(
        &mut catalog,
        &fixture.selection,
        &scenario,
        record,
        203,
        (&blobs, &refs),
        limits,
    );
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    assert_ne!(
        left_activation.record().owners,
        right_activation.record().owners
    );
    let mut original_suffix = None;
    for (branch, graph, activation) in [
        (&mut left, &left_graph, &left_activation),
        (&mut right, &right_graph, &right_activation),
    ] {
        let restored_snapshot = branch
            .runtime_mut()
            .runtime_snapshot(cut, 1.into(), 16 * 1024 * 1024)
            .unwrap();
        assert_original_ledgers(&snapshot, &restored_snapshot, activation);
        let fresh_factory = catalog
            .host_state_factory_from_archive(&fixture.selection, &scenario, &retained_original)
            .unwrap();
        let fresh_capture = archive
            .capture_world(
                graph,
                branch.runtime_mut(),
                activation,
                cut,
                1.into(),
                id("recorded/recapture"),
                requirements(),
                fresh_factory.as_ref(),
                fresh_factory.as_ref(),
            )
            .unwrap();
        let fresh_native = adverse::native_body(&fresh_capture);
        assert_eq!(fresh_native["native"], original_native["native"]);
        assert_eq!(fresh_native["recorded_ingress"]["consumed"], "1");
        assert_eq!(
            fresh_native["recorded_ingress"]["histories"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            fresh_native["recorded_ingress"]["histories"][0],
            original_native["recorded_ingress"]["histories"][0]
        );
        assert_eq!(adverse::native_body(&retained_original), original_native);
        drop(fresh_capture);
        drop(fresh_factory);
        let token = branch
            .runtime_mut()
            .recover(&id("original/write/execute"))
            .unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let Poll::Ready(Ok(cached)) = branch.runtime_mut().poll(&token, &mut context) else {
            panic!("original acknowledged write was not recoverable");
        };
        let mut expected = first.clone();
        expected.owners = activation.record().owners.clone();
        expected.scheduling.as_mut().unwrap().owners = activation.record().owners.clone();
        assert_eq!(cached, expected);
        let commit = branch
            .runtime_mut()
            .recover_scheduling_commit(&token)
            .unwrap();
        branch
            .runtime_mut()
            .acknowledge_scheduled(&token, &commit)
            .unwrap();
        assert_eq!(
            branch
                .runtime_mut()
                .runtime_snapshot(cut, 1.into(), 16 * 1024 * 1024)
                .unwrap(),
            restored_snapshot
        );
        assert_eq!(
            pending(branch.runtime_mut(), graph, activation),
            before.clone()
        );
        let result = if stage_suffix {
            exact(
                branch.runtime_mut(),
                graph,
                activation,
                "disk",
                "suffix/execute",
                100_000,
            )
        } else {
            advance(branch.runtime_mut(), graph, activation, "suffix", 100_000)
        };
        let outputs = &result.scheduling.as_ref().unwrap().publications;
        assert_eq!(outputs.len(), 1);
        let response = BlockResponse::decode(&outputs[0].payload_bytes).unwrap();
        assert_eq!(response.request_id, 102);
        assert_eq!(response.data, vec![1, 2, 3]);
        assert_eq!(outputs[0].native_sequence, U64::new(1));
        let semantic_suffix = (outputs[0].payload_bytes.clone(), outputs[0].native_sequence);
        if let Some(original) = &original_suffix {
            assert_eq!(&semantic_suffix, original);
        } else {
            original_suffix = Some(semantic_suffix);
        }
        assert!(
            result.scheduling.as_ref().unwrap().external_inputs[0]
                .inputs
                .is_empty()
        );
        assert!(pending(branch.runtime_mut(), graph, activation).is_empty());
        let later = exact(
            branch.runtime_mut(),
            graph,
            activation,
            "disk",
            "suffix/after",
            150_000,
        );
        assert!(later.scheduling.as_ref().unwrap().publications.is_empty());
        assert!(
            later.scheduling.as_ref().unwrap().external_inputs[0]
                .inputs
                .is_empty()
        );
        assert!(pending(branch.runtime_mut(), graph, activation).is_empty());
    }
    drop(left);
    drop(right);
    reclaim(&catalog);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

fn assert_original_ledgers(
    original: &RuntimeSnapshot,
    restored: &RuntimeSnapshot,
    activation: &WorldActivation,
) {
    use crucible::node_contract::SavedRuntimeResult;
    let mut operations = original.operations.clone();
    // Only these operational owner handles are remapped by the existing native
    // continuation verifier. Original request, bytes, receipts, IDs and ACK
    // state remain exact; no source record is rewritten by this assertion.
    for operation in &mut operations {
        operation.route.owners = activation.record().owners.clone();
        match &mut operation.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                outcome.owners = activation.record().owners.clone();
                outcome.scheduling.as_mut().unwrap().owners = activation.record().owners.clone();
            }
            _ => panic!("original write must remain acknowledged"),
        }
    }
    assert_eq!(restored.operations, operations);
    assert_eq!(restored.inputs.len(), original.inputs.len());
    for (fresh, source) in restored.inputs.iter().zip(&original.inputs) {
        assert_eq!(fresh.owners, activation.record().owners);
        assert_eq!(
            (
                &fresh.node,
                &fresh.stage_operation,
                &fresh.batch,
                &fresh.cutoff,
                &fresh.inventory
            ),
            (
                &source.node,
                &source.stage_operation,
                &source.batch,
                &source.cutoff,
                &source.inventory
            )
        );
        assert_eq!(fresh.deliveries, source.deliveries);
        assert_eq!(fresh.payloads, source.payloads);
        assert_eq!(fresh.provenance, source.provenance);
        assert_eq!(
            (&fresh.failure, fresh.committed, fresh.coordinator_committed),
            (
                &source.failure,
                source.committed,
                source.coordinator_committed
            )
        );
        let fresh_ack = fresh.acknowledgement.as_ref().unwrap();
        let source_ack = source.acknowledgement.as_ref().unwrap();
        assert_eq!(fresh_ack.owners, activation.record().owners);
        assert_eq!(
            (
                &fresh_ack.node,
                &fresh_ack.stage_operation,
                &fresh_ack.batch,
                &fresh_ack.cutoff,
                &fresh_ack.inventory
            ),
            (
                &source_ack.node,
                &source_ack.stage_operation,
                &source_ack.batch,
                &source_ack.cutoff,
                &source_ack.inventory
            )
        );
        assert_ne!(fresh_ack.proof_ref, source_ack.proof_ref);
    }
}
