//! Genuine installed state executor with selected controller capture and cold continuations.

// crucible-lint: allow rust-allow -- Actual native fixtures use panics to report failed preservation oracles.
// crucible-lint: allow panic-shortcut -- These installed controller tests deliberately fail on invalid native custody.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

use crucible::node_adapters::{
    AuthoredFaultTransition, ControlledFaultLink, ControlledFaultProgram, FaultCoefficients,
    FaultProbability, FaultedLinkDefinition, ScriptedRequest, ScriptedRequestKind, ScriptedSource,
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use crucible_device::{BlockRequest, netlink::LinkSnapshot};
use crucible_node_contract::{Phase, Position, canonical};

use crate::node_observed_executor::{
    InstalledControlledFaultProfile, InstalledHostIoProfile, InstalledIoArtifact,
    InstalledNodeSelection, InstalledScriptedSourceProfile,
};

fn probability(numerator: u64) -> FaultProbability {
    FaultProbability {
        numerator: numerator.into(),
        denominator: 1.into(),
    }
}

fn captured_link(
    record: &HostArchiveRecord,
    controller: &ControlledFaultProgram,
) -> (
    LinkSnapshot,
    Vec<crucible::node_contract::FaultMutationRecord>,
) {
    let owner = record
        .manifest()
        .owners
        .iter()
        .find(|owner| owner.capture_owner_id.as_str() == "link-owner")
        .unwrap();
    let bytes = record
        .content_bytes(owner.state_ref.as_ref().unwrap(), 64 * 1024 * 1024)
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["schema_version"], 3);
    let native: Vec<u8> = serde_json::from_value(envelope["native"].clone()).unwrap();
    let link = ControlledFaultLink::restore(controller, &native, 64 * 1024 * 1024).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&native).unwrap();
    let raw: crucible_node_contract::Bytes =
        serde_json::from_value(saved["native"].clone()).unwrap();
    (
        LinkSnapshot::from_canonical_bytes_with_limit(raw.as_slice(), 64 * 1024 * 1024).unwrap(),
        link.mutation_records().to_vec(),
    )
}

#[test]
#[ignore = "requires the actual source-built native companion"]
fn installed_state_executor_preserves_original_controller_at_selected_cut_after_source_removal() {
    installed_controller_state_route(false);
}

#[test]
#[ignore = "requires the actual source-built native companion"]
fn installed_state_executor_recovers_saved_native_mutation_before_new_grants_without_rebegin() {
    installed_controller_state_route(true);
}

fn installed_controller_state_route(held_source: bool) {
    let directory = tempfile::tempdir().unwrap();
    let device = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let device_ref =
        canonical::content_ref(&std::fs::read(&device).unwrap(), "application/octet-stream")
            .unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        device.clone(),
        device_ref.clone(),
        directory.path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    let base = vec![0xab; 4096];
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 15,
                payload: BlockRequest::write(102, 0, vec![1, 1, 1]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: BlockRequest::read(103, 0, 3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let coefficients = |loss, duplicate| FaultCoefficients {
        loss: probability(loss),
        duplicate: probability(duplicate),
        corrupt: probability(0),
    };
    let controller = ControlledFaultProgram {
        version: 1,
        initial: FaultedLinkDefinition {
            version: 1,
            seed: 77.into(),
            stream: Id::new("storage/requests").unwrap(),
            source_node: 17,
            latency_ps: 1000.into(),
            floor_ps: 1000.into(),
            loss: probability(0),
            duplicate: probability(1),
            duplicate_gap_ps: 100.into(),
            corrupt: probability(0),
            corruption_bits: 0,
        },
        transitions: vec![
            AuthoredFaultTransition {
                at: Position::new(12.into(), 0.into(), Phase::BoundaryControl),
                coefficients: coefficients(1, 0),
            },
            AuthoredFaultTransition {
                at: Position::new(20.into(), 0.into(), Phase::BoundaryControl),
                coefficients: coefficients(0, 1),
            },
        ],
    };
    let program = canonical::canonical_json(&serde_json::to_value(&controller).unwrap()).unwrap();
    let artifacts = [base, script, program];
    let references: Vec<_> = artifacts
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            canonical::content_ref(
                bytes,
                if index == 2 {
                    "application/json"
                } else {
                    "application/octet-stream"
                },
            )
            .unwrap()
        })
        .collect();
    let paths: Vec<_> = artifacts
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let path = directory.path().join(format!("installed-{index}"));
            std::fs::write(&path, bytes).unwrap();
            path
        })
        .collect();
    catalog
        .install_artifacts(
            paths
                .iter()
                .zip(&references)
                .map(|(path, expected)| InstalledIoArtifact::path(path.clone(), expected.clone()))
                .collect(),
        )
        .unwrap();
    let selected = vec![
        InstalledNodeSelection {
            node: Id::new("disk").unwrap(),
            owner: Id::new("disk-owner").unwrap(),
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
            node: Id::new("link").unwrap(),
            owner: Id::new("link-owner").unwrap(),
            kind: InstalledNodeKind::HostControlledFaultLink {
                profile: InstalledControlledFaultProfile {
                    program: references[2].clone(),
                    producer: Id::new("source").unwrap(),
                    consumer: Id::new("disk").unwrap(),
                },
            },
        },
        InstalledNodeSelection {
            node: Id::new("source").unwrap(),
            owner: Id::new("source-owner").unwrap(),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: references[1].clone(),
                    consumer: Id::new("link").unwrap(),
                },
            },
        },
    ];
    let scenario = catalog
        .scenario(&selected)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive = HostArchive::open(directory.path().join("archive"), limits).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "controller-state",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let request = NodeHostStateRequest::capture(
        "81818181818181818181818181818181".into(),
        selected.clone(),
        scenario.clone(),
        13,
    )
    .unwrap();
    let source = if held_source {
        let scenario_value = NodeScenario::from_json(&scenario).unwrap();
        let factory = catalog
            .host_state_factory(&selected, &scenario_value)
            .unwrap();
        let prepared = catalog
            .prepare_world(
                &selected,
                scenario_value,
                ExecutionId::from_bytes([0x81; 16]).unwrap(),
            )
            .unwrap();
        let graph = prepared.graph;
        let mut runtime = prepared
            .realization
            .admit(&graph)
            .unwrap_or_else(|failure| panic!("{}", failure.error));
        runtime.arm_all().unwrap();
        let mut publisher = StoredWorldActivationPublisher::new(
            Arc::clone(&blobs),
            Arc::clone(&refs),
            crucible_cas::content_store::RefName::new(
                "node-world-activations/held-controller-source",
            )
            .unwrap(),
        )
        .unwrap();
        let activation = runtime.activate(&mut publisher).unwrap();
        let (cut, ordinal) = advance(
            &mut runtime,
            &graph,
            &activation,
            request.execution(),
            12.into(),
            activation.record().boundary,
            0.into(),
        )
        .unwrap();
        let original = Id::new("controller/held-original").unwrap();
        let crucible::node_contract::BeginResult::Accepted(token) = runtime
            .begin_fault_injection(
                &graph,
                &activation,
                &Id::new("link").unwrap(),
                original.clone(),
            )
            .unwrap()
        else {
            panic!("authentic held source mutation was refused");
        };
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            runtime.poll(&token, &mut context),
            std::task::Poll::Ready(Ok(_))
        ));
        let saved = runtime
            .fault_runtime_snapshot(cut, ordinal, limits.maximum_record_bytes)
            .unwrap();
        assert!(saved.pending_acknowledgements().contains(&original));
        assert!(
            saved
                .operations
                .iter()
                .find(|operation| operation.operation == original)
                .unwrap()
                .scheduling_commit
                .is_none()
        );
        let captured = archive
            .capture_fault_world(
                &graph,
                &mut runtime,
                &activation,
                cut,
                ordinal,
                Id::new("capture/held-controller-source").unwrap(),
                requirements().unwrap(),
                factory.as_ref(),
                factory.as_ref(),
            )
            .unwrap();
        drop(runtime);
        reclaim(catalog.custody());
        captured
    } else {
        execute(&request, &mut catalog, &archive, limits, &blobs, &refs).unwrap()
    };
    let (pending, original) = captured_link(&source, &controller);
    assert_eq!(
        source.manifest().cut,
        Position::new(
            (if held_source { 12 } else { 13 }).into(),
            0.into(),
            Phase::BoundaryControl
        )
    );
    assert_eq!(pending.rng_position, 5);
    assert_eq!(pending.inflight.len(), 2);
    assert_eq!(original.len(), 1);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    let source_ref = source.artifact().clone();
    drop(source);
    drop(catalog);
    for path in &paths {
        std::fs::remove_file(path).unwrap();
    }
    let mut catalog = InstalledNodeCatalog::new(
        device,
        device_ref,
        directory.path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    catalog
        .install_artifacts(
            references
                .into_iter()
                .map(InstalledIoArtifact::archive_only)
                .collect(),
        )
        .unwrap();
    let mut first = None;
    for nonce in [
        "82828282828282828282828282828282",
        "83838383838383838383838383838383",
    ] {
        let request = NodeHostStateRequest::restore(
            nonce.into(),
            selected.clone(),
            scenario.clone(),
            source_ref.clone(),
            100_000,
        )
        .unwrap();
        let completed = execute(&request, &mut catalog, &archive, limits, &blobs, &refs).unwrap();
        let (native, journal) = captured_link(&completed, &controller);
        assert_eq!(native.rng_position, 15);
        assert_eq!(native.next_seq, 4);
        assert!(native.inflight.is_empty());
        assert_eq!(journal.len(), 2);
        assert_eq!(journal[0], original[0]);
        assert_ne!(
            journal[1].source.activation_id,
            journal[0].source.activation_id
        );
        if let Some(first) = &first {
            assert_eq!(&native, first);
        } else {
            first = Some(native);
        }
        assert_eq!(catalog.custody().reserved_worlds(), 0);
    }
}
