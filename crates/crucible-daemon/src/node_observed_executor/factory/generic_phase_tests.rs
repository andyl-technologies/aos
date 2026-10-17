//! Actual Block phase-only refusal and complete original native custody checks.
//!
//! The installed host build and artifact enrollment authenticate each actual
//! model. The direct native companion test compares complete original CoW and
//! staging state; this ordinary pipeline checks authentic common input custody.

// crucible-lint: allow panic-shortcut -- Changed original native state, responses or custody fail this single test attempt.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
#[ignore = "requires actual installed Block model and source-built companion identity"]
fn excluded_same_microstep_reaction_preserves_native_cow_and_original_batch() {
    let directory = tempfile::tempdir().unwrap();
    let (mut selections, mut artifacts) = fixture(directory.path(), 1, true);
    let observer = selections
        .iter()
        .find(|selection| selection.node == id("observer"))
        .unwrap();
    let InstalledNodeKind::HostSemantics { profile } = &observer.kind else {
        panic!("fixture changed its unrelated observer kind");
    };
    let unrelated_program = profile.program.clone();
    // This native comparison selects only the existing storage pipeline. An
    // unrelated zero-latency observer has its own strict-predecessor ceiling.
    selections.retain(|selection| selection.node != id("observer"));
    artifacts.retain(|artifact| artifact.expected != unrelated_program);
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(72, 0, vec![42]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::read(73, 0, 3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let script = artifact(
        directory.path(),
        "script",
        &script,
        "application/octet-stream",
    );
    let source = selections
        .iter_mut()
        .find(|selection| selection.node == id("source"))
        .unwrap();
    let InstalledNodeKind::HostScripted { profile } = &mut source.kind else {
        panic!("source fixture changed its original native kind");
    };
    let previous = profile.script.clone();
    profile.script = script.expected.clone();
    let original = artifacts
        .iter_mut()
        .find(|artifact| artifact.expected == previous)
        .unwrap();
    *original = script;

    let mut catalog = catalog(directory.path(), artifacts);
    let scenario = catalog.scenario(&selections).unwrap();
    let prepared = catalog
        .prepare_world(
            &selections,
            scenario,
            ExecutionId::from_bytes([121; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = match prepared.realization.admit(&graph) {
        Ok(runtime) => runtime,
        Err(failure) => panic!("{}", failure.error),
    };
    runtime.arm_all().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> =
        Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
            "block-original-phase-cut",
            directory.path().join("blobs"),
        ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(
        crucible_cas::content_store::DirectoryRefBackend::new(directory.path().join("refs")),
    );
    let mut publisher = StoredWorldActivationPublisher::new(
        blobs,
        refs,
        RefName::new("node-world-activations/block-original-phase-cut").unwrap(),
    )
    .unwrap();
    let activation = runtime.activate(&mut publisher).unwrap();
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }
    let source = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("source"), id("source/phase-original"), 11.into())
        .unwrap();
    let source = commit_native(&mut runtime, source);
    assert_eq!(source.scheduling.as_ref().unwrap().publications.len(), 2);
    let deliveries: Vec<_> = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .pending_inputs(&id("disk"))
        .unwrap()
        .into_iter()
        .cloned()
        .collect();
    assert_eq!(deliveries.len(), 2);
    assert_eq!(deliveries[0].delivery, deliveries[1].delivery);
    let reaction = Position::new(
        deliveries[0].delivery.time_ps,
        deliveries[0].delivery.microstep,
        Phase::Reaction,
    );
    assert!(
        deliveries
            .iter()
            .all(|delivery| delivery.delivery < reaction)
    );

    let batch = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &id("disk"),
            id("disk/phase-stage"),
            id("disk/phase-batch"),
            Position::new(5_000.into(), 0.into(), Phase::BoundaryControl),
        )
        .unwrap();
    assert_eq!(batch.deliveries(), deliveries);
    let acknowledgement = runtime.stage_inputs(batch).unwrap();
    let committed = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&committed).unwrap();
    let park = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("disk"), id("disk/phase-park"), reaction.time_ps)
        .unwrap();
    let parked = commit_native(&mut runtime, park);
    assert!(
        parked
            .scheduling
            .as_ref()
            .unwrap()
            .input_progress
            .as_ref()
            .unwrap()
            .consumed
            .is_empty()
    );
    let cut = Position::new(reaction.time_ps, 0.into(), Phase::BoundaryControl);
    assert_eq!(parked.scheduling.as_ref().unwrap().reached, cut);
    let source_before = runtime
        .runtime_snapshot(cut, 0.into(), 16 * 1024 * 1024)
        .unwrap();

    let excluded = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_boundary_settlement(&id("disk"), id("disk/phase-excluded"), reaction)
        .unwrap();
    let BeginResult::Refused(refusal) = runtime.begin_admitted(excluded).unwrap() else {
        panic!("excluded Block reaction did not refuse before effects");
    };
    assert!(
        refusal
            .reason
            .contains("exclusive cut excludes the original input reaction")
    );
    let source_after = runtime
        .runtime_snapshot(cut, 0.into(), 16 * 1024 * 1024)
        .unwrap();
    assert_eq!(source_before.inputs, source_after.inputs);
    let recovered = runtime
        .recover_input_staging(&activation, &id("disk/phase-stage"))
        .unwrap();
    let recovered = runtime.commit_input_acknowledgement(recovered).unwrap();
    runtime.commit_input_staging(&recovered).unwrap();
    assert_eq!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .position(&id("disk"))
            .unwrap(),
        cut
    );
    assert_eq!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .pending_inputs(&id("disk"))
            .unwrap(),
        deliveries.iter().collect::<Vec<_>>()
    );

    // The same native write and read run only when the original range includes
    // their baseline same-microstep Reaction. The read observes the actual CoW.
    let included = Position::new(
        reaction.time_ps,
        reaction.microstep.checked_add(U64::new(1)).unwrap(),
        Phase::BoundaryControl,
    );
    let allowed = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_boundary_settlement(&id("disk"), id("disk/phase-allowed"), included)
        .unwrap();
    let allowed = commit_native(&mut runtime, allowed);
    let progress = allowed
        .scheduling
        .as_ref()
        .unwrap()
        .input_progress
        .as_ref()
        .unwrap();
    assert_eq!(progress.batch, id("disk/phase-batch"));
    assert_eq!(progress.consumed.len(), 2);
    assert!(allowed.scheduling.as_ref().unwrap().publications.is_empty());
    let finish = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("disk"), id("disk/phase-finish"), 5_000.into())
        .unwrap();
    let finished = commit_native(&mut runtime, finish);
    let responses: Vec<_> = finished
        .scheduling
        .as_ref()
        .unwrap()
        .publications
        .iter()
        .map(|publication| BlockResponse::decode(&publication.payload_bytes).unwrap())
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].request_id, 72);
    assert_eq!(responses[0].status, BlockStatus::Ok);
    assert_eq!(responses[1].request_id, 73);
    assert_eq!(responses[1].status, BlockStatus::Ok);
    assert_eq!(responses[1].data, [42, 8, 9]);
    assert!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .pending_inputs(&id("disk"))
            .unwrap()
            .is_empty()
    );

    drop(runtime);
    reclaim(&catalog);
}
