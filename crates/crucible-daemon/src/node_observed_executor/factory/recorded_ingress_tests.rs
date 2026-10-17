//! Actual installed Block input ownership, provenance and finite observed execution.

#![cfg(test)]
// Invalid native ownership or byte assertions deliberately fail this fixture.
// crucible-lint: allow panic-shortcut -- Recorded-ingress tests panic on violated original-custody assertions.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use crucible_campaign::{
    CampaignRepository, ExecutionId,
    observed_node_attempt::{ObservedAttemptOutcome, ObservedAttemptState, ObservedAttemptWorker},
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::{Phase, Position, U64};

use super::super::{InstalledNodeCatalog, InstalledNodeKind, measure_executable};
use super::*;

struct Fixture {
    directory: tempfile::TempDir,
    catalog: InstalledNodeCatalog,
    selection: Vec<InstalledNodeSelection>,
    configuration: NodeRunConfiguration,
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
        inputs: [BlockRequest::get_length(101), BlockRequest::read(102, 0, 3)]
            .into_iter()
            .enumerate()
            .map(|(index, request)| {
                let bytes = request.encode().unwrap();
                crucible::node_adapters::RecordedLogicalInput {
                    event: Id::new(format!("original/input/{index}")).unwrap(),
                    sequence: U64::new(17 + index as u64),
                    publication: Position {
                        time_ps: U64::new(if index == 0 { 10 } else { 50_000 }),
                        microstep: 0.into(),
                        phase: Phase::Publication,
                    },
                    payload: InputPayload {
                        reference: canonical::content_ref(&bytes, "application/octet-stream")
                            .unwrap(),
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
        kind: InstalledNodeKind::HostRecordedBlock {
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
        configuration,
        source_path,
    }
}

#[test]
fn original_fifo_executes_actual_block_requests_with_durable_complete_input_context() {
    let mut fixture = fixture();
    // Preserve actual original CAS artifacts even when this native fixture fails.
    let retained = fixture.directory.keep();
    eprintln!("original recorded-ingress root: {}", retained.display());
    let scenario = fixture.catalog.scenario(&fixture.selection).unwrap();
    let original = from_scenario(&scenario, &fixture.selection[0].node).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "recorded-ingress",
        retained.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(retained.join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let execution = ExecutionId::from_bytes([61; 16]).unwrap();
    let backend = fixture
        .catalog
        .prepare(
            &fixture.selection,
            scenario,
            fixture.configuration,
            execution,
            blobs.clone(),
            refs,
        )
        .unwrap();
    let scenario = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .unwrap();
    let configuration = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    let input_bytes = blobs
        .read(request.inputs(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let context: serde_json::Value = serde_json::from_slice(&input_bytes).unwrap();
    assert_eq!(context["version"], 2);
    assert_eq!(
        context["external_inputs"][0]["root"],
        serde_json::to_value(original.root()).unwrap()
    );
    assert_eq!(
        context["external_inputs"][0]["original_objects"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository, backend, 1).unwrap();
    worker
        .submit("recorded-original", &request, &admission)
        .unwrap();
    let result = (0..128)
        .find_map(|_| match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(result) => Some(result),
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("original recorded input quarantined: {reason}")
            }
            ObservedAttemptState::Reserved(_) => None,
        })
        .expect("finite synchronous Block run must complete");
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let outgoing = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&outgoing).unwrap();
    let outcomes: Vec<crucible::node_contract::OperationOutcome> =
        serde_json::from_value(document["events"].clone()).unwrap();
    let publications: Vec<_> = outcomes
        .iter()
        .flat_map(|outcome| outcome.scheduling.as_ref().unwrap().publications.iter())
        .collect();
    assert_eq!(publications.len(), 2);
    let responses: Vec<_> = publications
        .iter()
        .map(|publication| BlockResponse::decode(&publication.payload_bytes).unwrap())
        .collect();
    assert_eq!(responses[0].request_id, 101);
    assert_eq!(responses[0].data, 4096_u64.to_le_bytes());
    assert_eq!(responses[1].request_id, 102);
    assert_eq!(responses[1].data, vec![0xab; 3]);
}

#[test]
fn installed_source_file_and_complete_world_configuration_mismatches_refuse() {
    let mut fixture = fixture();
    let scenario = fixture.catalog.scenario(&fixture.selection).unwrap();
    let definition = from_scenario(&scenario, &fixture.selection[0].node).unwrap();
    let mut changed_configuration = fixture.configuration.clone();
    changed_configuration.maximum_rounds = U64::new(63);
    assert!(check_configuration(&changed_configuration, &definition).is_err());
    let mut changed = scenario.clone();
    let source = changed
        .content
        .iter_mut()
        .find(|object| object.reference == definition.objects()[0].reference)
        .unwrap();
    source.bytes[0] ^= 1;
    assert!(from_scenario(&changed, &fixture.selection[0].node).is_err());
    std::fs::write(&fixture.source_path, b"changed original source").unwrap();
    assert!(
        fixture
            .catalog
            .prepare_world(
                &fixture.selection,
                scenario,
                ExecutionId::from_bytes([62; 16]).unwrap()
            )
            .is_err()
    );
}

#[test]
fn no_ingress_context_preserves_literal_first_edition_and_unknown_codec_refuses() {
    let fixture = fixture();
    let selection = vec![InstalledNodeSelection {
        node: Id::new("clock").unwrap(),
        owner: Id::new("clock-owner").unwrap(),
        kind: InstalledNodeKind::HostClock,
    }];
    let scenario = fixture.catalog.scenario(&selection).unwrap();
    let actual =
        super::super::super::backend::input_context_bytes(&scenario, &fixture.configuration)
            .unwrap();
    let expected = canonical::canonical_json(&serde_json::json!({
        "format":"crucible.node-input-context","version":1,"world":scenario.world.identity().unwrap(),
        "configuration":fixture.configuration.artifact(&scenario).unwrap().id().unwrap().to_text(),
        "external_inputs":[],"faults":[],"ordering_profile":"superdense-v1",
        "clock_policy":"selected-complete-operating-contracts"
    })).unwrap();
    assert_eq!(actual, expected);
    let mut source: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.source_path).unwrap()).unwrap();
    source["physical_sampling"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RecordedLogicalInputSource>(source).is_err());
}

#[test]
fn actual_staging_retains_fifo_until_native_consumption_and_cursor_capture_refuses() {
    use crucible::node_contract::{BeginResult, InputProvenanceLimits};
    use std::task::{Context, Poll, Waker};

    let mut fixture = fixture();
    let scenario = fixture.catalog.scenario(&fixture.selection).unwrap();
    assert!(
        fixture
            .catalog
            .host_state_factory(&fixture.selection, &scenario)
            .is_err()
    );
    let world = fixture
        .catalog
        .prepare_world(
            &fixture.selection,
            scenario,
            ExecutionId::from_bytes([63; 16]).unwrap(),
        )
        .unwrap();
    // The original owner already possesses the exact record and base bytes.
    std::fs::remove_file(&fixture.source_path).unwrap();
    std::fs::remove_file(fixture.directory.path().join("base")).unwrap();
    let graph = world.graph;
    let mut runtime = world.realization.admit(&graph).ok().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "staging-ingress",
        fixture.directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(
        fixture.directory.path().join("refs"),
    ));
    let mut publisher = super::super::super::StoredWorldActivationPublisher::new(
        blobs,
        refs,
        crucible_cas::content_store::RefName::new("node-world-activations/recorded-staging")
            .unwrap(),
    )
    .unwrap();
    runtime.arm_all().unwrap();
    let activation = runtime.activate(&mut publisher).unwrap();
    let node = fixture.selection[0].node.clone();
    let before = runtime.observe_scheduling(&activation, &node).unwrap();
    assert_eq!(before.native().external_inputs[0].inputs.len(), 2);
    let complete = runtime
        .scheduling_evidence(
            &before,
            InputProvenanceLimits {
                maximum_objects: 32,
                maximum_bytes: 2 * 1024 * 1024,
            },
        )
        .unwrap();
    assert_eq!(complete.len(), 8);
    for object in complete {
        object.reference.verify(&object.bytes).unwrap();
    }
    runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .accept_boundary_observation(before)
        .unwrap();

    let cutoff = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .preview_exact_input_cut(&node, fixture.configuration.horizon_ps)
        .unwrap();
    let batch = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &node,
            Id::new("original/stage").unwrap(),
            Id::new("original/batch").unwrap(),
            cutoff,
        )
        .unwrap();
    assert_eq!(batch.deliveries().len(), 2);
    let originals = batch.deliveries().to_vec();
    assert_eq!(originals[0].publication_id.as_str(), "original/input/0");
    assert_eq!(originals[1].native_sequence, U64::new(18));
    assert_eq!(originals[0].publication.phase, Phase::Publication);
    assert_eq!(originals[0].delivery.phase, Phase::Delivery);
    assert_eq!(
        originals[0].publication.microstep,
        originals[0].delivery.microstep
    );
    let acknowledgement = runtime.stage_inputs(batch).unwrap();
    let commit = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&commit).unwrap();

    let staged = runtime.observe_scheduling(&activation, &node).unwrap();
    assert_eq!(staged.native().external_inputs[0].inputs.len(), 2);
    assert_eq!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .pending_inputs(&node)
            .unwrap()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>(),
        originals
    );
    let grant = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(
            &node,
            Id::new("original/consume").unwrap(),
            fixture.configuration.horizon_ps,
        )
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("authentic Block grant must be accepted");
    };
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
    else {
        panic!("synchronous original Block request must complete");
    };
    let observed = outcome.scheduling.as_ref().unwrap();
    assert!(observed.external_inputs[0].inputs.is_empty());
    assert_eq!(observed.input_progress.as_ref().unwrap().consumed.len(), 2);
    // Native consumption alone has not committed coordinator removal or output ACK.
    assert_eq!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .pending_inputs(&node)
            .unwrap()
            .len(),
        2
    );
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    assert!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .pending_inputs(&node)
            .unwrap()
            .is_empty()
    );
    let after = runtime.observe_scheduling(&activation, &node).unwrap();
    assert!(after.native().external_inputs[0].inputs.is_empty());
    // A formerly valid stopped observation cannot authorize current proof bytes.
    assert!(
        runtime
            .scheduling_evidence(&staged, InputProvenanceLimits::default())
            .is_err()
    );
}

#[test]
fn rehashed_source_fifo_scope_and_payload_counterfactuals_refuse_before_realization() {
    let fixture = fixture();
    let original: RecordedLogicalInputSource =
        serde_json::from_slice(&std::fs::read(&fixture.source_path).unwrap()).unwrap();
    let mut counterfactuals = Vec::new();
    let mut duplicate = original.clone();
    duplicate.inputs[1].event = duplicate.inputs[0].event.clone();
    counterfactuals.push(duplicate);
    let mut reordered = original.clone();
    reordered.inputs.swap(0, 1);
    counterfactuals.push(reordered);
    let mut nonroot = original.clone();
    nonroot.inputs[0].publication.microstep = U64::new(1);
    counterfactuals.push(nonroot);
    let mut late = original.clone();
    late.inputs[1].publication.time_ps = late.closed_before.time_ps;
    counterfactuals.push(late);
    let mut corrupt_payload = original.clone();
    corrupt_payload.inputs[0].payload.bytes[0] ^= 1;
    counterfactuals.push(corrupt_payload);
    let mut unknown = original.clone();
    unknown.version = 2;
    counterfactuals.push(unknown);
    for document in counterfactuals {
        let bytes = canonical::canonical_json(&serde_json::to_value(document).unwrap()).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        assert!(
            crucible::node_adapters::validate_recorded_input_source(&InputPayload {
                reference,
                bytes
            })
            .is_err()
        );
    }
    let bytes = canonical::canonical_json(&serde_json::to_value(original).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    assert!(
        crucible::node_adapters::validate_recorded_input_source(&InputPayload { reference, bytes })
            .is_err()
    );
}
