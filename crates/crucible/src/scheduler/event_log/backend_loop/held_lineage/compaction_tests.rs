//! Exercises private live-origin checkpoints and long-lived actor publication.

use super::tests::prepared_peer_commit;
use super::*;

fn fill_segment(lineage: &mut HeldRunLineage, scheduler: &SingleScheduler) {
    let affected = scheduler.nodes[1].id.node.clone();
    while lineage.ensure_extension_room().is_ok() {
        lineage
            .extend_commit(scheduler, scheduler, &affected)
            .unwrap_or_else(|error| panic!("checked no-op segment transition: {error}"));
    }
}

#[test]
fn live_origin_checkpoint_preserves_original_owner_and_retires_old_segment() {
    let (scheduler, mut run, mut lineage, controller, original) = prepared_peer_commit();
    fill_segment(&mut lineage, &scheduler);
    run.canonical_lineage = Some(lineage.clone());
    let owner = run.admission.clone();
    let stale = lineage.clone();
    let old_tip = Arc::downgrade(
        lineage
            .tip
            .as_ref()
            .unwrap_or_else(|| panic!("full segment")),
    );
    let old_checkpoint = Arc::downgrade(&lineage.checkpoint);

    lineage
        .checkpoint_live_origins(&scheduler, &controller, 1, [&run, &run, &run])
        .unwrap_or_else(|error| panic!("three actual map views of one owner: {error}"));
    assert_eq!(lineage.certified_origins.len(), 1);
    assert!(lineage.tip.is_none());
    assert!(lineage.validate_context(&original, &scheduler));
    assert!(
        lineage
            .authenticate(&controller, 1, &run, &scheduler)
            .is_err()
    );
    run.canonical_lineage = Some(lineage.clone());
    lineage
        .authenticate(&controller, 1, &run, &scheduler)
        .unwrap_or_else(|error| panic!("refreshed exact RUN checkpoint: {error}"));
    assert!(owner.shares_semantic_owner(&run.admission));
    assert_eq!(owner.context(), run.admission.context());
    assert_eq!(owner.control_token(), run.admission.control_token());
    drop(stale);
    assert!(old_tip.upgrade().is_none());
    assert!(old_checkpoint.upgrade().is_none());

    // A previous checkpoint cannot authenticate even when both have no tip
    // and their complete current contexts are equal.
    let empty_stale = lineage.clone();
    fill_segment(&mut lineage, &scheduler);
    run.canonical_lineage = Some(lineage.clone());
    lineage
        .checkpoint_live_origins(&scheduler, &controller, 1, [&run])
        .unwrap_or_else(|error| panic!("second authenticated checkpoint: {error}"));
    run.canonical_lineage = Some(empty_stale);
    assert!(
        lineage
            .authenticate(&controller, 1, &run, &scheduler)
            .is_err()
    );
}

#[test]
fn checkpoint_refuses_foreign_unregistered_and_corrupt_origins_without_mutation() {
    for failure in 0..7 {
        let (scheduler, mut run, mut lineage, controller, _) = prepared_peer_commit();
        fill_segment(&mut lineage, &scheduler);
        run.canonical_lineage = Some(lineage.clone());
        match failure {
            0 => {
                run.canonical_lineage = Some(HeldRunLineage::begin(
                    HeldHostStopController::new(),
                    1,
                    &scheduler,
                ))
            }
            1 => {
                // The actual original owner remains intact, but a forged
                // history cannot certify its source by just matching the tip.
                lineage.root = Arc::new(RetainedRunContext::capture(&scheduler));
                run.canonical_lineage = Some(lineage.clone());
            }
            2 => {
                let mut tip = CanonicalExtension {
                    previous: None,
                    before: lineage.root.clone(),
                    after: lineage
                        .tip
                        .as_ref()
                        .unwrap_or_else(|| panic!("full tip"))
                        .after
                        .clone(),
                    affected_node: NodeId {
                        name: "foreign".into(),
                    },
                    generation: MAX_CANONICAL_EXTENSIONS,
                };
                tip.before = Arc::new(RetainedRunContext::capture(&scheduler));
                lineage.tip = Some(Arc::new(tip));
                run.canonical_lineage = Some(lineage.clone());
            }
            3 => run.plan.index = scheduler.nodes.len(),
            4 => {
                run.admission = {
                    let mut foreign = scheduler.clone();
                    foreign.configuration.def =
                        crate::ScenarioDef::from_canonical_material("foreign", "owner");
                    foreign
                        .prepare_host_concurrent_quantum_limited(
                            QuantumRequest {
                                configuration: foreign.configuration().clone(),
                                control: Vec::new(),
                            },
                            2,
                        )
                        .unwrap_or_else(|error| panic!("genuine foreign RUN: {error}"))
                        .runs
                        .remove(0)
                        .admission
                }
            }
            _ => {}
        }
        let checkpoint = lineage.checkpoint.clone();
        let tip = lineage.tip.clone();
        let log = scheduler.event_log_offset();
        let actual_controller = if failure == 5 {
            HeldHostStopController::new()
        } else {
            controller.clone()
        };
        let actual_generation = if failure == 6 { 2 } else { 1 };
        assert!(
            lineage
                .checkpoint_live_origins(&scheduler, &actual_controller, actual_generation, [&run])
                .is_err(),
            "failure {failure}"
        );
        assert!(Arc::ptr_eq(&checkpoint, &lineage.checkpoint));
        assert!(Arc::ptr_eq(
            tip.as_ref().unwrap_or_else(|| panic!("retained tip")),
            lineage
                .tip
                .as_ref()
                .unwrap_or_else(|| panic!("unchanged tip"))
        ));
        assert_eq!(scheduler.event_log_offset(), log);
    }
}

#[test]
fn checkpoint_drops_retired_originals_and_bounds_complete_named_inventory() {
    let (scheduler, mut old_run, mut lineage, controller, original) = prepared_peer_commit();
    fill_segment(&mut lineage, &scheduler);
    old_run.canonical_lineage = Some(lineage.clone());
    assert_eq!(
        checkpoint_interval(0).unwrap_or_else(|error| panic!("empty interval: {error}")),
        1
    );
    assert_eq!(
        checkpoint_interval(2).unwrap_or_else(|error| panic!("two-node interval: {error}")),
        6
    );
    assert_eq!(
        checkpoint_interval(342).unwrap_or_else(|error| panic!("hard interval: {error}")),
        MAX_CANONICAL_EXTENSIONS
    );
    assert!(checkpoint_interval(usize::MAX).is_err());
    let mut empty = scheduler.clone();
    empty.nodes.clear();
    let checkpoint = lineage.checkpoint.clone();
    assert!(
        lineage
            .checkpoint_live_origins(&empty, &controller, 1, [&old_run])
            .is_err()
    );
    assert!(Arc::ptr_eq(&checkpoint, &lineage.checkpoint));
    for runs in [Vec::new(), vec![&old_run; 7]] {
        let checkpoint = lineage.checkpoint.clone();
        assert!(
            lineage
                .checkpoint_live_origins(&scheduler, &controller, 1, runs)
                .is_err()
        );
        assert!(Arc::ptr_eq(&checkpoint, &lineage.checkpoint));
    }
    lineage
        .checkpoint_live_origins(&scheduler, &controller, 1, [&old_run])
        .unwrap_or_else(|error| panic!("actual old owner certificate: {error}"));
    let source = scheduler.clone();
    let mut prepared = source
        .prepare_host_concurrent_quantum_limited(
            QuantumRequest {
                configuration: source.configuration().clone(),
                control: Vec::new(),
            },
            2,
        )
        .unwrap_or_else(|error| panic!("actual fresh planner RUN: {error}"));
    let mut fresh_run = prepared.runs.remove(0);
    let affected = fresh_run.plan.node.node.clone();
    lineage
        .extend_commit(&scheduler, &prepared.next, &affected)
        .unwrap_or_else(|error| panic!("actual planner extension: {error}"));
    assert!(lineage.validate_context(fresh_run.admission.original_source(), &prepared.next));
    fill_segment(&mut lineage, &prepared.next);
    fresh_run.canonical_lineage = Some(lineage.clone());
    lineage
        .checkpoint_live_origins(&prepared.next, &controller, 1, [&fresh_run])
        .unwrap_or_else(|error| panic!("only genuine fresh owner survives: {error}"));
    assert_eq!(lineage.certified_origins.len(), 1);
    assert!(!lineage.validate_context(&original, &prepared.next));
    assert!(lineage.validate_context(fresh_run.admission.original_source(), &prepared.next));
}

#[test]
fn checkpoint_ancestry_work_is_bounded_independently_of_actor_lifetime() {
    let (scheduler, mut run, mut lineage, controller, original) = prepared_peer_commit();
    let mut measurements = Vec::new();
    for segment in 0..4 {
        fill_segment(&mut lineage, &scheduler);
        run.canonical_lineage = Some(lineage.clone());
        let mut nodes = 0;
        let mut cursor = lineage.tip.as_ref();
        while let Some(extension) = cursor {
            nodes += 1;
            cursor = extension.previous.as_ref();
        }
        assert_eq!(nodes, MAX_CANONICAL_EXTENSIONS);
        for _ in 0..128 {
            assert!(lineage.validate_context(&original, &scheduler));
        }
        lineage
            .checkpoint_live_origins(&scheduler, &controller, 1, [&run])
            .unwrap_or_else(|error| panic!("bounded actual-owner checkpoint: {error}"));
        for _ in 0..128 {
            assert!(lineage.validate_context(&original, &scheduler));
        }
        measurements.push((segment, nodes, 0_u64, lineage.certified_origins.len()));
        assert!(lineage.tip.is_none());
        assert_eq!(lineage.certified_origins.len(), 1);
    }
    println!(
        "held_lineage_bounded_ancestry (segment,before_ancestors,after_ancestors,certificates)={measurements:?}; each cut validates128 times with a fixed Schedule"
    );
}
