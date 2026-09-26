//! Native semantic equivalence across production replay, restore, and hot fork.

use std::fs;
use std::sync::Arc;

use crucible::Configuration;
use crucible::model::DagStore;
use crucible_cas::content_store::{DirectoryBlobBackend, ImmutableBlobBackend};

use super::*;
use crate::{
    ProductionBakedGenesisCheckpoint, ProductionBakedGenesisReplayCatalogFactory,
    QemuExactResumeBasis, SharedQemuAttemptHostResourceFactory, capture_production_baked_genesis,
    promote_test_checkpoint_for_resume,
};

const POST_CHOICE_QUANTA: u64 = 512;
const MAX_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const CHILD_READY_SAMPLE_COUNT: usize = 20;
const CHILD_READY_P95_LIMIT_NANOSECONDS: u64 = 100_000_000;

struct ExactResume<'a> {
    store: &'a ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    boundary: &'a Configuration,
}

#[path = "equivalence/campaign_perf.rs"]
mod campaign_perf;
#[path = "equivalence/child.rs"]
mod child;
#[path = "equivalence/evidence.rs"]
mod evidence;
#[path = "equivalence/siblings.rs"]
mod siblings;

use self::campaign_perf::measure_campaign_planner_queue_at_boundary;
use self::child::{
    NativeHotChildStart, run_hot_child, start_descendant_hot_child, start_hot_child,
};
use self::evidence::{
    BoundaryEvidence, EquivalenceTopology, assert_continuation_equivalent,
    capture_boundary_evidence, continue_from_pending, drain_exact_pending,
    drive_configuration_to_pending_boundary, drive_to_pending_boundary, prepared_world_evidence,
    select_pending_configuration,
};

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_hot_fork_matches_thin_and_exact_from_execution_and_exact_templates() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) =
        scenario::build_equivalence(&fixture, artifacts, &paths.kernel, &paths.root_image)
            .expect("build equivalence scenario");

    let input = execution_input_for_scenario(source.clone());
    let checkpoint_context = native_execution_context(&input, 0x90);
    let mut checkpoint_source = begin_fresh(
        &paths,
        "equivalence-checkpoint-source",
        6_000,
        &source,
        Arc::clone(&artifacts),
        &checkpoint_context,
    );
    let checkpoint_boundary = drive_to_pending_boundary(
        &mut checkpoint_source,
        &source,
        EquivalenceTopology::MultiNode,
    );
    let checkpoints = checkpoint_store();
    let capture = QemuFreshAttemptLifecycleOwner::capture_attempt_checkpoint(
        &mut checkpoint_source,
        &checkpoint_context,
    )
    .expect("capture pending production boundary");
    let prepared = checkpoints
        .prepare_attempt_checkpoint(&capture)
        .expect("prepare pending production checkpoint");
    let checkpoint = checkpoints
        .publish_attempt_checkpoint(&prepared)
        .expect("publish pending production checkpoint")
        .root();
    let source_reference = continue_from_pending(
        &mut checkpoint_source,
        &source,
        checkpoint_boundary.configuration.clone(),
        checkpoint_boundary.pending.clone(),
    );
    let locked_fault_replay = source_reference
        .fault_evidence
        .locked_effect_trace
        .clone()
        .expect("capture authenticated shared-fault replay trace");
    QemuFreshAttemptLifecycleOwner::shutdown(&mut checkpoint_source)
        .expect("shutdown checkpoint capture source");
    let baked = capture_replay_genesis(
        &paths,
        "equivalence-replay-genesis",
        6_025,
        &source,
        Arc::clone(&artifacts),
        &input,
        0x97,
    );

    let thin_context = native_execution_context(&input, 0x96);
    let mut thin_reference = begin_fresh_with_fault_replay(
        &paths,
        "equivalence-thin-reference",
        6_050,
        &source,
        Arc::clone(&artifacts),
        &thin_context,
        locked_fault_replay,
    );
    let thin_boundary =
        drive_to_pending_boundary(&mut thin_reference, &source, EquivalenceTopology::MultiNode);
    assert_eq!(thin_boundary, checkpoint_boundary);
    let thin = continue_from_pending(
        &mut thin_reference,
        &source,
        thin_boundary.configuration.clone(),
        thin_boundary.pending.clone(),
    );
    QemuFreshAttemptLifecycleOwner::shutdown(&mut thin_reference).expect("shutdown thin reference");

    let execution_source_context = native_execution_context(&input, 0x91);
    let mut execution_source = begin_fresh(
        &paths,
        "equivalence-execution-source",
        6_100,
        &source,
        Arc::clone(&artifacts),
        &execution_source_context,
    );
    let execution_boundary = drive_to_pending_boundary(
        &mut execution_source,
        &source,
        EquivalenceTopology::MultiNode,
    );
    assert_eq!(execution_boundary, checkpoint_boundary);
    let execution_world = execution_source
        .prepare_hot_fork_source_world()
        .expect("prepare execution-created source template");
    let execution_world_evidence =
        prepared_world_evidence(&execution_world, EquivalenceTopology::MultiNode);
    let exact_input = execution_input_for_scenario_configuration(
        source.clone(),
        checkpoint_boundary.configuration.clone(),
    );
    let (exact_checkpoints, exact_checkpoint) = promote_exact_checkpoint(
        &paths,
        "equivalence-replay-oracle-reference",
        6_275,
        &input,
        &baked,
        checkpoint,
        0x98,
    );
    let exact_context =
        native_execution_context(&exact_input, 0x92).with_resume_checkpoint(Some(exact_checkpoint));
    let mut exact_reference = begin_exact(
        &paths,
        "equivalence-exact-reference",
        6_300,
        &source,
        Arc::clone(&artifacts),
        ExactResume {
            store: &exact_checkpoints,
            checkpoint: exact_checkpoint,
            boundary: &checkpoint_boundary.configuration,
        },
        &exact_context,
    );
    let exact_pending = drain_exact_pending(&mut exact_reference);
    let exact_boundary = capture_boundary_evidence(
        &mut exact_reference,
        &source,
        checkpoint_boundary.configuration.clone(),
        exact_pending,
        EquivalenceTopology::MultiNode,
    );
    assert_eq!(exact_boundary, checkpoint_boundary);
    let exact = continue_from_pending(
        &mut exact_reference,
        &source,
        exact_boundary.configuration.clone(),
        exact_boundary.pending.clone(),
    );
    QemuFreshAttemptLifecycleOwner::shutdown(&mut exact_reference)
        .expect("shutdown exact reference");

    let (template_checkpoints, template_checkpoint) = promote_exact_checkpoint(
        &paths,
        "equivalence-replay-oracle-template",
        6_375,
        &input,
        &baked,
        checkpoint,
        0x99,
    );
    let exact_template_context = native_execution_context(&exact_input, 0x93)
        .with_resume_checkpoint(Some(template_checkpoint));
    let mut exact_template_source = begin_exact(
        &paths,
        "equivalence-exact-template-source",
        6_400,
        &source,
        artifacts,
        ExactResume {
            store: &template_checkpoints,
            checkpoint: template_checkpoint,
            boundary: &checkpoint_boundary.configuration,
        },
        &exact_template_context,
    );
    let exact_template_pending = drain_exact_pending(&mut exact_template_source);
    let exact_template_boundary = capture_boundary_evidence(
        &mut exact_template_source,
        &source,
        checkpoint_boundary.configuration.clone(),
        exact_template_pending,
        EquivalenceTopology::MultiNode,
    );
    assert_eq!(exact_template_boundary, checkpoint_boundary);
    let exact_world = exact_template_source
        .prepare_hot_fork_source_world()
        .expect("prepare exact-restore-created source template");
    let exact_world_evidence =
        prepared_world_evidence(&exact_world, EquivalenceTopology::MultiNode);
    assert_eq!(exact_world_evidence, execution_world_evidence);
    let execution_child = start_hot_child(NativeHotChildStart {
        paths: &paths,
        lane: "equivalence-execution-target",
        project_id_start: 6_200,
        source: source.clone(),
        expected_boundary: &execution_boundary,
        checkpoint: None,
        execution_byte: 0x94,
        world: execution_world,
        topology: EquivalenceTopology::MultiNode,
    });
    let exact_child = start_hot_child(NativeHotChildStart {
        paths: &paths,
        lane: "equivalence-exact-template-target",
        project_id_start: 6_500,
        source,
        expected_boundary: &checkpoint_boundary,
        checkpoint: Some(template_checkpoint),
        execution_byte: 0x95,
        world: exact_world,
        topology: EquivalenceTopology::MultiNode,
    });
    assert_eq!(execution_child.live_processes(), 3);
    assert_eq!(exact_child.live_processes(), 3);
    println!("concurrent_live_children=2");
    let execution_hot = execution_child.finish();
    let exact_hot = exact_child.finish();

    assert_continuation_equivalent("fresh source", &source_reference, &thin);
    assert_continuation_equivalent("exact restore", &exact, &thin);
    assert_continuation_equivalent("execution-created hot fork", &execution_hot, &thin);
    assert_continuation_equivalent("exact-created hot fork", &exact_hot, &thin);

    println!("hot_fork_equivalence=true");
    println!("template_origins=execution,exact-restore");
    println!("reference_tiers=thin-replay,exact-checkpoint");
    println!("child_boundary_matches_capture=true");
    println!("child_suffix_matches_exact_restore=true");
    println!("child_suffix_matches_genesis_replay=true");
    println!("locked_fault_replay_evidence_match=true");
    println!("pre_event_queue_and_volatile_cache=true");
    println!("pre_event_exact_restore=true");
    println!("shared_effect_state_transition=true");
    println!("shared_cause=network,block,node");
    println!("ninep_fault_injection=true");
    println!("application_http_status=200");
    println!("inactive_world_reactivation=true");
    println!("state=network,block,ninep,guest-choice,measurement,signal,permanent-failure");
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_single_node_hot_fork_matches_thin_and_exact() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) = scenario::build_single_node_equivalence(
        &fixture,
        artifacts,
        &paths.kernel,
        &paths.root_image,
    )
    .expect("build single-node equivalence scenario");

    let input = execution_input_for_scenario(source.clone());
    let checkpoint_context = native_execution_context(&input, 0xa0);
    let mut checkpoint_source = begin_fresh(
        &paths,
        "single-checkpoint-source",
        7_000,
        &source,
        Arc::clone(&artifacts),
        &checkpoint_context,
    );
    let checkpoint_boundary = drive_to_pending_boundary(
        &mut checkpoint_source,
        &source,
        EquivalenceTopology::SingleNode,
    );
    let checkpoints = checkpoint_store();
    let capture = QemuFreshAttemptLifecycleOwner::capture_attempt_checkpoint(
        &mut checkpoint_source,
        &checkpoint_context,
    )
    .expect("capture single-node pending boundary");
    let prepared = checkpoints
        .prepare_attempt_checkpoint(&capture)
        .expect("prepare single-node checkpoint");
    let checkpoint = checkpoints
        .publish_attempt_checkpoint(&prepared)
        .expect("publish single-node checkpoint")
        .root();
    QemuFreshAttemptLifecycleOwner::shutdown(&mut checkpoint_source)
        .expect("shutdown single-node checkpoint source");
    let baked = capture_replay_genesis(
        &paths,
        "single-replay-genesis",
        7_025,
        &source,
        Arc::clone(&artifacts),
        &input,
        0xa7,
    );

    let thin_context = native_execution_context(&input, 0xa6);
    let mut thin_reference = begin_fresh(
        &paths,
        "single-thin-reference",
        7_050,
        &source,
        Arc::clone(&artifacts),
        &thin_context,
    );
    let thin_boundary = drive_to_pending_boundary(
        &mut thin_reference,
        &source,
        EquivalenceTopology::SingleNode,
    );
    assert_eq!(thin_boundary, checkpoint_boundary);
    let thin = continue_from_pending(
        &mut thin_reference,
        &source,
        thin_boundary.configuration.clone(),
        thin_boundary.pending.clone(),
    );
    QemuFreshAttemptLifecycleOwner::shutdown(&mut thin_reference)
        .expect("shutdown single-node thin reference");

    let execution_source_context = native_execution_context(&input, 0xa1);
    let mut execution_source = begin_fresh(
        &paths,
        "single-execution-source",
        7_100,
        &source,
        Arc::clone(&artifacts),
        &execution_source_context,
    );
    let execution_boundary = drive_to_pending_boundary(
        &mut execution_source,
        &source,
        EquivalenceTopology::SingleNode,
    );
    assert_eq!(execution_boundary, checkpoint_boundary);
    let execution_world = execution_source
        .prepare_hot_fork_source_world()
        .expect("prepare single-node execution source");
    let execution_world_evidence =
        prepared_world_evidence(&execution_world, EquivalenceTopology::SingleNode);
    let execution_hot = run_hot_child(NativeHotChildStart {
        paths: &paths,
        lane: "single-execution-target",
        project_id_start: 7_200,
        source: source.clone(),
        expected_boundary: &execution_boundary,
        checkpoint: None,
        execution_byte: 0xa4,
        world: execution_world,
        topology: EquivalenceTopology::SingleNode,
    });

    let exact_input = execution_input_for_scenario_configuration(
        source.clone(),
        checkpoint_boundary.configuration.clone(),
    );
    let (exact_checkpoints, exact_checkpoint) = promote_exact_checkpoint(
        &paths,
        "single-replay-oracle-reference",
        7_275,
        &input,
        &baked,
        checkpoint,
        0xa8,
    );
    let exact_context =
        native_execution_context(&exact_input, 0xa2).with_resume_checkpoint(Some(exact_checkpoint));
    let mut exact_reference = begin_exact(
        &paths,
        "single-exact-reference",
        7_300,
        &source,
        Arc::clone(&artifacts),
        ExactResume {
            store: &exact_checkpoints,
            checkpoint: exact_checkpoint,
            boundary: &checkpoint_boundary.configuration,
        },
        &exact_context,
    );
    let exact_pending = drain_exact_pending(&mut exact_reference);
    let exact_boundary = capture_boundary_evidence(
        &mut exact_reference,
        &source,
        checkpoint_boundary.configuration.clone(),
        exact_pending,
        EquivalenceTopology::SingleNode,
    );
    assert_eq!(exact_boundary, checkpoint_boundary);
    let exact = continue_from_pending(
        &mut exact_reference,
        &source,
        exact_boundary.configuration.clone(),
        exact_boundary.pending.clone(),
    );
    QemuFreshAttemptLifecycleOwner::shutdown(&mut exact_reference)
        .expect("shutdown single-node exact reference");

    let (template_checkpoints, template_checkpoint) = promote_exact_checkpoint(
        &paths,
        "single-replay-oracle-template",
        7_375,
        &input,
        &baked,
        checkpoint,
        0xa9,
    );
    let exact_template_context = native_execution_context(&exact_input, 0xa3)
        .with_resume_checkpoint(Some(template_checkpoint));
    let mut exact_template_source = begin_exact(
        &paths,
        "single-exact-template-source",
        7_400,
        &source,
        artifacts,
        ExactResume {
            store: &template_checkpoints,
            checkpoint: template_checkpoint,
            boundary: &checkpoint_boundary.configuration,
        },
        &exact_template_context,
    );
    let exact_template_pending = drain_exact_pending(&mut exact_template_source);
    let exact_template_boundary = capture_boundary_evidence(
        &mut exact_template_source,
        &source,
        checkpoint_boundary.configuration.clone(),
        exact_template_pending,
        EquivalenceTopology::SingleNode,
    );
    assert_eq!(exact_template_boundary, checkpoint_boundary);
    let exact_world = exact_template_source
        .prepare_hot_fork_source_world()
        .expect("prepare single-node exact-restore source");
    let exact_world_evidence =
        prepared_world_evidence(&exact_world, EquivalenceTopology::SingleNode);
    assert_eq!(exact_world_evidence, execution_world_evidence);
    let exact_hot = run_hot_child(NativeHotChildStart {
        paths: &paths,
        lane: "single-exact-template-target",
        project_id_start: 7_500,
        source,
        expected_boundary: &checkpoint_boundary,
        checkpoint: Some(template_checkpoint),
        execution_byte: 0xa5,
        world: exact_world,
        topology: EquivalenceTopology::SingleNode,
    });

    assert_continuation_equivalent("single-node exact restore", &exact, &thin);
    assert_continuation_equivalent(
        "single-node execution-created hot fork",
        &execution_hot,
        &thin,
    );
    assert_continuation_equivalent("single-node exact-created hot fork", &exact_hot, &thin);

    println!("hot_fork_equivalence=true");
    println!("topology=single-node");
    println!("state=block,ninep,guest-choice,measurement");
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_single_vm_child_ready_p95_is_below_100_milliseconds() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) = scenario::build_single_node_equivalence_with_memory(
        &fixture,
        artifacts,
        64,
        &paths.kernel,
        &paths.root_image,
    )
    .expect("build 64 MiB single-VM reference scenario");
    let input = execution_input_for_scenario(source.clone());
    let source_context = native_execution_context(&input, 0xb0);
    let mut source_lifecycle = begin_fresh(
        &paths,
        "child-ready-source",
        12_000,
        &source,
        artifacts,
        &source_context,
    );
    let boundary = drive_to_pending_boundary(
        &mut source_lifecycle,
        &source,
        EquivalenceTopology::SingleNode,
    );
    let mut world = source_lifecycle
        .prepare_hot_fork_source_world()
        .expect("prepare reference hot-fork source");
    let mut samples = Vec::with_capacity(CHILD_READY_SAMPLE_COUNT);

    for _ in 0..CHILD_READY_SAMPLE_COUNT {
        let child = start_hot_child(NativeHotChildStart {
            paths: &paths,
            lane: "child-ready-target",
            project_id_start: 12_100,
            source: source.clone(),
            expected_boundary: &boundary,
            checkpoint: None,
            execution_byte: 0xb1,
            world,
            topology: EquivalenceTopology::SingleNode,
        });
        let measurement = child.measurement();
        assert_eq!(measurement.processes, 1, "reference child is one VM");
        samples.push(measurement.child_ready_nanoseconds);
        world = child.finish_without_continuation_and_recover();
    }
    world.retire().expect("retire reference source");

    let p95 = nearest_rank_p95(&samples);
    let raw_samples = samples
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    // Libtest writes the test name before the first line captured by the gate.
    println!();
    println!("child_ready_reference=single-vm-64mib-1vcpu");
    println!("child_ready_sample_count={CHILD_READY_SAMPLE_COUNT}");
    println!("child_ready_samples_ns={raw_samples}");
    println!("child_ready_p95_ns={p95}");
    println!("child_ready_p95_limit_ns={CHILD_READY_P95_LIMIT_NANOSECONDS}");
    assert!(
        p95 < CHILD_READY_P95_LIMIT_NANOSECONDS,
        "single-VM child-ready p95 is {p95} ns, limit is strictly below {CHILD_READY_P95_LIMIT_NANOSECONDS} ns"
    );
}

fn nearest_rank_p95(samples: &[u64]) -> u64 {
    assert!(!samples.is_empty(), "p95 requires measured samples");
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let rank = (ordered.len() * 95).div_ceil(100);
    ordered[rank - 1]
}

#[test]
fn nearest_rank_p95_uses_the_nineteenth_of_twenty_samples() {
    let descending = (1..=20).rev().collect::<Vec<_>>();
    assert_eq!(nearest_rank_p95(&descending), 19);
    assert_eq!(nearest_rank_p95(&[42]), 42);
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_hot_fork_scales_across_three_semantic_template_depths() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) =
        scenario::build_single_node_scaling(&fixture, artifacts, &paths.kernel, &paths.root_image)
            .expect("build scaling scenario");

    let context = native_execution_context(&execution_input_for_scenario(source.clone()), 0xc1);
    let mut lifecycle = begin_fresh(
        &paths,
        "depth-1-source",
        8_200,
        &source,
        artifacts,
        &context,
    );
    let boundary = drive_fresh_source_to_semantic_depth(&mut lifecycle, &source, 1);
    let world = lifecycle
        .prepare_hot_fork_source_world()
        .expect("prepare root semantic-depth source world");
    let mut process_generations = vec![world.continuation().nodes()[0].generation()];
    let mut source_allocated_bytes =
        allocated_tree_bytes(&paths.storage_root.join("depth-1-source"));
    let mut child = start_hot_child(NativeHotChildStart {
        paths: &paths,
        lane: "depth-1-target",
        project_id_start: 8_600,
        source: source.clone(),
        expected_boundary: &boundary,
        checkpoint: None,
        execution_byte: 0xd1,
        world,
        topology: EquivalenceTopology::SingleNode,
    });

    for depth in 1..=3 {
        let measurement = child.measurement();
        assert_eq!(measurement.processes, 1);
        println!(
            "template_depth_{depth}_ready_millis={}",
            measurement.ready_millis
        );
        println!(
            "template_depth_{depth}_private_dirty_kib={}",
            measurement.private_dirty_kib
        );
        println!(
            "template_depth_{depth}_private_rss_kib={}",
            measurement.private_rss_kib
        );
        println!(
            "template_depth_{depth}_rss_anon_kib={}",
            measurement.rss_anon_kib
        );
        println!(
            "template_depth_{depth}_allocated_bytes={}",
            measurement.allocated_bytes
        );
        println!("template_depth_{depth}_source_allocated_bytes={source_allocated_bytes}");
        if depth == 3 {
            child.finish_without_continuation();
            break;
        }

        child.advance_to_next_semantic_depth();
        let promoted = child.promote();
        assert_eq!(promoted.boundary.configuration.schedule.len(), depth + 1);
        let promoted_generation = promoted.world.continuation().nodes()[0].generation();
        let prior_generation = process_generations
            .last()
            .copied()
            .expect("descendant promotion retains its parent generation");
        assert_eq!(promoted_generation, prior_generation + 1);
        process_generations.push(promoted_generation);
        source_allocated_bytes =
            allocated_tree_bytes(&paths.storage_root.join(format!("depth-{depth}-target")));
        let next_lane = format!("depth-{}-target", depth + 1);
        child = start_descendant_hot_child(
            NativeHotChildStart {
                paths: &paths,
                lane: &next_lane,
                project_id_start: 8_600 + u32::try_from(depth).expect("depth project") * 100,
                source: promoted.source,
                expected_boundary: &promoted.boundary,
                checkpoint: None,
                execution_byte: 0xd1 + u8::try_from(depth).expect("depth byte"),
                world: promoted.world,
                topology: EquivalenceTopology::SingleNode,
            },
            promoted.lineage,
        );
    }
    assert_eq!(process_generations.len(), 3);
    println!("semantic_template_depth=3");
    println!("descendant_template_generations=3");
    println!(
        "descendant_process_generations={},{},{}",
        process_generations[0], process_generations[1], process_generations[2]
    );
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_hot_fork_scales_across_three_guest_memory_sizes() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");

    for (index, memory_mib) in [64_u32, 256, 512].into_iter().enumerate() {
        let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
        let (source, artifacts) = scenario::build_single_node_equivalence_with_memory(
            &fixture,
            artifacts,
            memory_mib,
            &paths.kernel,
            &paths.root_image,
        )
        .expect("build memory scaling scenario");
        let source_lane = format!("ram-{memory_mib}-source");
        let target_lane = format!("ram-{memory_mib}-target");
        let reference_lane = format!("ram-{memory_mib}-reference");
        let input = execution_input_for_scenario(source.clone());
        let context = native_execution_context(
            &input,
            0xb0 + u8::try_from(index).expect("memory profile byte"),
        );
        let reference_context = native_execution_context(
            &input,
            0xc0 + u8::try_from(index).expect("memory reference byte"),
        );
        let mut cold_reference = begin_fresh(
            &paths,
            &reference_lane,
            10_025 + u32::try_from(index).expect("memory profile project") * 100,
            &source,
            Arc::clone(&artifacts),
            &reference_context,
        );
        let cold_boundary = drive_to_pending_boundary(
            &mut cold_reference,
            &source,
            EquivalenceTopology::SingleNode,
        );
        let cold = continue_from_pending(
            &mut cold_reference,
            &source,
            cold_boundary.configuration.clone(),
            cold_boundary.pending.clone(),
        );
        QemuFreshAttemptLifecycleOwner::shutdown(&mut cold_reference)
            .expect("shutdown memory scaling cold reference");

        let mut lifecycle = begin_fresh(
            &paths,
            &source_lane,
            10_000 + u32::try_from(index).expect("memory profile project") * 100,
            &source,
            artifacts,
            &context,
        );
        let boundary =
            drive_to_pending_boundary(&mut lifecycle, &source, EquivalenceTopology::SingleNode);
        assert_eq!(boundary, cold_boundary);
        let mut world = lifecycle
            .prepare_hot_fork_source_world()
            .expect("prepare memory scaling source");
        let private_limit_kib = u64::from(memory_mib) * 256 + 32 * 1024;

        // Reuse the same paused source for sequential sibling counts.
        for sibling_count in 1..=4 {
            let child = start_hot_child(NativeHotChildStart {
                paths: &paths,
                lane: &target_lane,
                project_id_start: 10_050
                    + u32::try_from(index).expect("memory profile project") * 100,
                source: source.clone(),
                expected_boundary: &boundary,
                checkpoint: None,
                execution_byte: 0xb8 + u8::try_from(index).expect("memory profile byte"),
                world,
                topology: EquivalenceTopology::SingleNode,
            });
            let measurement = child.measurement();
            assert!(
                measurement.private_rss_kib <= private_limit_kib,
                "{memory_mib} MiB source, sibling {sibling_count}: private RSS exceeded limit"
            );
            println!(
                "ram_{memory_mib}_sibling_{sibling_count}_child_private_rss_kib={}",
                measurement.private_rss_kib
            );
            println!(
                "ram_{memory_mib}_sibling_{sibling_count}_child_vm_pte_kib={}",
                measurement.vm_pte_kib
            );

            if sibling_count == 4 {
                let hot = child.finish();
                assert_continuation_equivalent(&format!("{memory_mib} MiB hot child"), &hot, &cold);
                break;
            }
            world = child.finish_without_continuation_and_recover();
        }
    }
    println!("guest_memory_profiles_mib=64,256,512");
    println!("sequential_sibling_counts=1,2,4");
    println!("ram_first_quantum_cold_reference_profiles_mib=64,256,512");
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_whole_world_survives_ten_thousand_lifecycles_without_leaks() {
    const LIFECYCLES: usize = 10_000;

    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) = scenario::build_single_node_equivalence(
        &fixture,
        artifacts,
        &paths.kernel,
        &paths.root_image,
    )
    .expect("build production stress scenario");
    let input = execution_input_for_scenario(source.clone());
    let context = native_execution_context(&input, 0xa8);
    let mut lifecycle = begin_fresh(
        &paths,
        "production-stress-source",
        11_000,
        &source,
        artifacts,
        &context,
    );
    let boundary =
        drive_to_pending_boundary(&mut lifecycle, &source, EquivalenceTopology::SingleNode);
    let mut world = lifecycle
        .prepare_hot_fork_source_world()
        .expect("prepare production stress source");
    let source_cgroup = paths.cgroup_root.join("production-stress-source");
    let baseline_processes = cgroup_processes(&source_cgroup);
    let baseline_threads = process_thread_count(&baseline_processes);
    let baseline_descriptors = process_descriptor_count(&baseline_processes);
    let mut midpoint_private_dirty_kib = 0;
    let mut midpoint_source_disk_bytes = 0;
    let mut midpoint_target_disk_bytes = 0;
    let mut midpoint_run_state_bytes = 0;
    let mut midpoint_store_bytes = 0;

    for lifecycle_index in 0..LIFECYCLES {
        let child = start_hot_child(NativeHotChildStart {
            paths: &paths,
            lane: "production-stress-target",
            project_id_start: 11_100,
            source: source.clone(),
            expected_boundary: &boundary,
            checkpoint: None,
            execution_byte: 0xa9,
            world,
            topology: EquivalenceTopology::SingleNode,
        });
        world = child.finish_without_continuation_and_recover();

        let completed = lifecycle_index + 1;
        if completed % 250 == 0 || completed == LIFECYCLES / 2 || completed == LIFECYCLES {
            let processes = cgroup_processes(&source_cgroup);
            assert_eq!(process_thread_count(&processes), baseline_threads);
            assert_eq!(process_descriptor_count(&processes), baseline_descriptors);
            let private_dirty_kib = process_memory_evidence(&processes).private_dirty_kib;
            if completed == LIFECYCLES / 2 {
                midpoint_private_dirty_kib = private_dirty_kib;
                midpoint_source_disk_bytes =
                    allocated_tree_bytes(&paths.storage_root.join("production-stress-source"));
                midpoint_target_disk_bytes =
                    allocated_tree_bytes(&paths.storage_root.join("production-stress-target"));
                midpoint_run_state_bytes = allocated_tree_bytes(&paths.run_state_root);
                midpoint_store_bytes = allocated_tree_bytes(&paths.artifacts);
            }
            println!("stress_private_dirty_{completed}_kib={private_dirty_kib}");
        }
    }
    let final_processes = cgroup_processes(&source_cgroup);
    let final_private_dirty_kib = process_memory_evidence(&final_processes).private_dirty_kib;
    assert!(final_private_dirty_kib.saturating_sub(midpoint_private_dirty_kib) <= 4 * 1024);
    assert_eq!(final_processes, baseline_processes);
    assert!(cgroup_processes(&paths.cgroup_root.join("production-stress-target")).is_empty());

    // Repeating an identical child workload after warmup must not accumulate
    // attempt storage, run-state artifacts, or DAG objects with each fork.
    let final_source_disk_bytes =
        allocated_tree_bytes(&paths.storage_root.join("production-stress-source"));
    let final_target_disk_bytes =
        allocated_tree_bytes(&paths.storage_root.join("production-stress-target"));
    let final_run_state_bytes = allocated_tree_bytes(&paths.run_state_root);
    let final_store_bytes = allocated_tree_bytes(&paths.artifacts);
    assert!(final_source_disk_bytes <= midpoint_source_disk_bytes);
    assert!(final_target_disk_bytes <= midpoint_target_disk_bytes);
    assert!(final_run_state_bytes <= midpoint_run_state_bytes);
    assert!(final_store_bytes <= midpoint_store_bytes);

    world.retire().expect("retire production stress source");
    assert!(cgroup_processes(&source_cgroup).is_empty());
    println!("production_whole_world_lifecycles={LIFECYCLES}");
    println!("qemu_child_pairing=exact_source_boundary");
    println!("source_threads_leaked=0");
    println!("source_descriptors_leaked=0");
    println!("source_private_dirty_late_growth_limit_kib=4096");
    println!("stress_source_disk_midpoint_bytes={midpoint_source_disk_bytes}");
    println!("stress_source_disk_final_bytes={final_source_disk_bytes}");
    println!("stress_target_disk_midpoint_bytes={midpoint_target_disk_bytes}");
    println!("stress_target_disk_final_bytes={final_target_disk_bytes}");
    println!("stress_run_state_midpoint_bytes={midpoint_run_state_bytes}");
    println!("stress_run_state_final_bytes={final_run_state_bytes}");
    println!("stress_store_midpoint_bytes={midpoint_store_bytes}");
    println!("stress_store_final_bytes={final_store_bytes}");
    println!("stress_final_qemu_processes=0");
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_hot_fork_meets_whole_world_performance_ratchets() {
    const CORPUS_SIZE: usize = 3;
    const KNOWN_DIRTY_KIB: u64 = 1024 * 4;
    const DIRTY_OVERHEAD_KIB: u64 = 64 * 1024;

    let process_status = fs::read_to_string("/proc/self/status").expect("read guest affinity");
    let allowed_cpus = process_status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .expect("guest affinity is recorded");
    assert_eq!(
        allowed_cpus, "0",
        "reference workload must use one pinned vCPU"
    );
    println!("\ncampaign_guest_cpu_affinity={allowed_cpus}");
    println!("campaign_planner_supervisor=packaged-process");
    println!("campaign_blob_backend=sqlite-store-graph");
    println!("campaign_short_branch_boundary=two-node-pending-selectable");

    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) =
        scenario::build_equivalence(&fixture, artifacts, &paths.kernel, &paths.root_image)
            .expect("build performance scenario");
    let input = execution_input_for_scenario(source.clone());
    let checkpoint_context = native_execution_context(&input, 0xe0);
    let mut checkpoint_source = begin_fresh(
        &paths,
        "performance-checkpoint-source",
        9_000,
        &source,
        Arc::clone(&artifacts),
        &checkpoint_context,
    );
    let checkpoint_boundary = drive_to_pending_boundary(
        &mut checkpoint_source,
        &source,
        EquivalenceTopology::MultiNode,
    );
    let checkpoints = checkpoint_store();
    let capture = QemuFreshAttemptLifecycleOwner::capture_attempt_checkpoint(
        &mut checkpoint_source,
        &checkpoint_context,
    )
    .expect("capture performance checkpoint");
    let prepared = checkpoints
        .prepare_attempt_checkpoint(&capture)
        .expect("prepare performance checkpoint");
    let checkpoint = checkpoints
        .publish_attempt_checkpoint(&prepared)
        .expect("publish performance checkpoint")
        .root();
    QemuFreshAttemptLifecycleOwner::shutdown(&mut checkpoint_source)
        .expect("shutdown performance checkpoint source");
    let baked = capture_replay_genesis(
        &paths,
        "performance-replay-genesis",
        9_025,
        &source,
        Arc::clone(&artifacts),
        &input,
        0xdf,
    );

    let mut hot_setup = 0_u64;
    let mut exact_setup = 0_u64;
    let mut hot_steady = 0_u64;
    let mut exact_steady = 0_u64;
    let mut campaign_planner_queue_samples = Vec::with_capacity(CORPUS_SIZE);
    let mut hot_guest_continuation_samples = Vec::with_capacity(CORPUS_SIZE);
    for index in 0..CORPUS_SIZE {
        let source_lane = format!("performance-source-{index}");
        let hot_lane = format!("performance-hot-{index}");
        let exact_lane = format!("performance-exact-{index}");
        let replay_lane = format!("performance-replay-oracle-{index}");
        let context =
            native_execution_context(&input, 0xe1 + u8::try_from(index).expect("corpus byte"));
        let mut live_source = begin_fresh(
            &paths,
            &source_lane,
            9_100 + u32::try_from(index).expect("corpus project") * 100,
            &source,
            Arc::clone(&artifacts),
            &context,
        );
        let boundary =
            drive_to_pending_boundary(&mut live_source, &source, EquivalenceTopology::MultiNode);
        assert_eq!(boundary, checkpoint_boundary);
        let campaign_sample =
            measure_campaign_planner_queue_at_boundary(&source, &input, &boundary, index);
        campaign_planner_queue_samples.push(campaign_sample);
        println!("corpus_{index}_campaign_planner_queue_ns={campaign_sample}");
        let world = live_source
            .prepare_hot_fork_source_world()
            .expect("prepare performance source");
        let child = start_hot_child(NativeHotChildStart {
            paths: &paths,
            lane: &hot_lane,
            project_id_start: 9_200 + u32::try_from(index).expect("corpus project") * 100,
            source: source.clone(),
            expected_boundary: &boundary,
            checkpoint: None,
            execution_byte: 0xe8 + u8::try_from(index).expect("corpus byte"),
            world,
            topology: EquivalenceTopology::MultiNode,
        });
        let measurement = child.measurement();
        hot_setup = hot_setup.saturating_add(measurement.ready_nanoseconds);
        println!(
            "corpus_{index}_hot_setup_ns={}",
            measurement.ready_nanoseconds
        );
        assert_eq!(measurement.node_launch_count, 2);
        assert!(measurement.node_launch_sum_nanoseconds > measurement.node_launch_max_nanoseconds);
        assert!(
            measurement.world_launch_nanoseconds
                <= measurement
                    .node_launch_max_nanoseconds
                    .saturating_add(250_000_000),
            "whole-world launch exceeded max-node plus orchestration budget"
        );
        let (hot, elapsed, after) = child.finish_measured();
        hot_steady = hot_steady.saturating_add(elapsed);
        hot_guest_continuation_samples.push(elapsed);
        println!("corpus_{index}_hot_guest_continuation_ns={elapsed}");
        let dirty_growth = after
            .private_dirty_kib
            .saturating_sub(measurement.private_dirty_kib);
        assert!(dirty_growth >= KNOWN_DIRTY_KIB / 2);
        assert!(dirty_growth <= KNOWN_DIRTY_KIB + DIRTY_OVERHEAD_KIB);

        let exact_input = execution_input_for_scenario_configuration(
            source.clone(),
            checkpoint_boundary.configuration.clone(),
        );
        let (exact_checkpoints, exact_checkpoint) = promote_exact_checkpoint(
            &paths,
            &replay_lane,
            9_275 + u32::try_from(index).expect("corpus project") * 100,
            &input,
            &baked,
            checkpoint,
            0xd0 + u8::try_from(index).expect("corpus byte"),
        );
        let exact_context = native_execution_context(
            &exact_input,
            0xf0 + u8::try_from(index).expect("corpus byte"),
        )
        .with_resume_checkpoint(Some(exact_checkpoint));
        let exact_started = operational_monotonic_nanoseconds();
        let mut exact = begin_exact(
            &paths,
            &exact_lane,
            9_300 + u32::try_from(index).expect("corpus project") * 100,
            &source,
            Arc::clone(&artifacts),
            ExactResume {
                store: &exact_checkpoints,
                checkpoint: exact_checkpoint,
                boundary: &checkpoint_boundary.configuration,
            },
            &exact_context,
        );
        let pending = drain_exact_pending(&mut exact);
        let exact_boundary = capture_boundary_evidence(
            &mut exact,
            &source,
            checkpoint_boundary.configuration.clone(),
            pending,
            EquivalenceTopology::MultiNode,
        );
        let exact_setup_sample = operational_monotonic_nanoseconds().saturating_sub(exact_started);
        exact_setup = exact_setup.saturating_add(exact_setup_sample);
        println!("corpus_{index}_exact_setup_ns={exact_setup_sample}");
        let steady_started = operational_monotonic_nanoseconds();
        let exact_evidence = continue_from_pending(
            &mut exact,
            &source,
            exact_boundary.configuration.clone(),
            exact_boundary.pending.clone(),
        );
        let exact_steady_sample =
            operational_monotonic_nanoseconds().saturating_sub(steady_started);
        exact_steady = exact_steady.saturating_add(exact_steady_sample);
        println!("corpus_{index}_exact_guest_continuation_ns={exact_steady_sample}");
        assert_continuation_equivalent("performance exact restore", &hot, &exact_evidence);
        QemuFreshAttemptLifecycleOwner::shutdown(&mut exact).expect("shutdown exact corpus member");

        println!("corpus_{index}_vm_pte_kib={}", measurement.vm_pte_kib);
        println!("corpus_{index}_vm_data_kib={}", measurement.vm_data_kib);
        println!(
            "corpus_{index}_anon_huge_pages_kib={}",
            measurement.anon_huge_pages_kib
        );
        println!(
            "corpus_{index}_numa_resident_pages={}",
            measurement.numa_resident_pages
        );
        println!("corpus_{index}_numa_nodes={}", measurement.numa_nodes);
        println!("corpus_{index}_known_dirty_private_growth_kib={dirty_growth}");
        println!("corpus_{index}_post_dirty_vm_pte_kib={}", after.vm_pte_kib);
        println!(
            "corpus_{index}_post_dirty_vm_data_kib={}",
            after.vm_data_kib
        );
        println!(
            "corpus_{index}_post_dirty_anon_huge_pages_kib={}",
            after.anon_huge_pages_kib
        );
        println!(
            "corpus_{index}_post_dirty_numa_resident_pages={}",
            after.numa_resident_pages
        );
        println!("corpus_{index}_post_dirty_numa_nodes={}", after.numa_nodes);
        println!(
            "corpus_{index}_node_launch_sum_nanoseconds={}",
            measurement.node_launch_sum_nanoseconds
        );
        println!(
            "corpus_{index}_node_launch_max_nanoseconds={}",
            measurement.node_launch_max_nanoseconds
        );
        println!(
            "corpus_{index}_node_launch_count={}",
            measurement.node_launch_count
        );
        println!(
            "corpus_{index}_world_launch_nanoseconds={}",
            measurement.world_launch_nanoseconds
        );
    }
    assert!(
        exact_setup >= hot_setup.saturating_mul(5),
        "hot setup must be at least 5x faster"
    );
    assert!(hot_steady.saturating_mul(100) <= exact_steady.saturating_mul(110));
    assert_eq!(campaign_planner_queue_samples.len(), CORPUS_SIZE);
    assert_eq!(hot_guest_continuation_samples.len(), CORPUS_SIZE);
    let campaign_planner_queue_total = campaign_planner_queue_samples
        .iter()
        .try_fold(0_u64, |total, sample| total.checked_add(*sample))
        .expect("campaign planner/queue sample total overflow");
    let hot_guest_continuation_total = hot_guest_continuation_samples
        .iter()
        .try_fold(0_u64, |total, sample| total.checked_add(*sample))
        .expect("guest continuation sample total overflow");
    assert!(
        campaign_planner_queue_total
            .checked_mul(100)
            .expect("campaign ratio numerator overflow")
            < hot_guest_continuation_total
                .checked_mul(5)
                .expect("campaign ratio denominator overflow"),
        "campaign planner and queue exceeded 5% of the identical hot guest continuation"
    );
    println!("campaign_planner_queue_total_ns={campaign_planner_queue_total}");
    println!("hot_guest_continuation_total_ns={hot_guest_continuation_total}");
    println!("exact_restore_corpus_size={CORPUS_SIZE}");
    println!("setup_speedup_minimum=5x");
    println!("steady_execution_overhead_limit_percent=10");
    println!("known_dirty_guest_pages=1024");
    println!("memory_metrics=VmPTE,VmData,AnonHugePages,numa_maps");
    println!("multi_node_launch_model=max-plus-bounded-orchestration");
}

fn drive_fresh_source_to_semantic_depth(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    depth: usize,
) -> BoundaryEvidence {
    let mut configuration = Configuration::genesis(source.scenario_def());
    for _ in 0..depth {
        let boundary = drive_configuration_to_pending_boundary(
            lifecycle,
            source,
            configuration,
            EquivalenceTopology::SingleNode,
        );
        configuration = select_pending_configuration(
            lifecycle,
            source,
            boundary.configuration,
            &boundary.pending,
        );
    }
    drive_configuration_to_pending_boundary(
        lifecycle,
        source,
        configuration,
        EquivalenceTopology::SingleNode,
    )
}

fn begin_fresh(
    paths: &NativeGatePaths,
    lane: &str,
    project_id_start: u32,
    source: &crucible::ScenarioDefForm,
    artifacts: Arc<dyn DagStore>,
    context: &AttemptExecutionContext,
) -> crucible_api::ProductionVmLifecycleLoop {
    let host = open_host(paths, lane, project_id_start);
    let config = lifecycle_config(paths, paths.run_state_root.join(lane), artifacts);
    let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
        config,
        ComposedQemuAttemptResourceGuardFactory::new(host),
    );
    factory
        .begin_fresh(&source.scenario_def(), source, context)
        .expect("launch fresh equivalence world")
}

fn begin_fresh_with_fault_replay(
    paths: &NativeGatePaths,
    lane: &str,
    project_id_start: u32,
    source: &crucible::ScenarioDefForm,
    artifacts: Arc<dyn DagStore>,
    context: &AttemptExecutionContext,
    replay: crucible::model::ResolvedEffectTrace,
) -> crucible_api::ProductionVmLifecycleLoop {
    let host = open_host(paths, lane, project_id_start);
    let config = lifecycle_config(paths, paths.run_state_root.join(lane), artifacts)
        .with_fault_replay(replay);
    let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
        config,
        ComposedQemuAttemptResourceGuardFactory::new(host),
    );
    factory
        .begin_fresh(&source.scenario_def(), source, context)
        .expect("launch locked-replay equivalence world")
}

fn begin_exact(
    paths: &NativeGatePaths,
    lane: &str,
    project_id_start: u32,
    source: &crucible::ScenarioDefForm,
    artifacts: Arc<dyn DagStore>,
    resume: ExactResume<'_>,
    context: &AttemptExecutionContext,
) -> crucible_api::ProductionVmLifecycleLoop {
    let host = open_host(paths, lane, project_id_start);
    let config = lifecycle_config(paths, paths.run_state_root.join(lane), artifacts);
    let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
        config,
        ComposedQemuAttemptResourceGuardFactory::new(host),
    );
    factory
        .begin_resume(
            resume.store,
            resume.checkpoint,
            QemuExactResumeBasis::new(&source.scenario_def(), source, resume.boundary, None),
            context,
        )
        .expect("restore exact equivalence world")
}

fn capture_replay_genesis(
    paths: &NativeGatePaths,
    lane: &str,
    project_id_start: u32,
    source: &crucible::ScenarioDefForm,
    artifacts: Arc<dyn DagStore>,
    input: &CrucibleAttemptExecution,
    execution_byte: u8,
) -> ProductionBakedGenesisCheckpoint {
    let context = native_execution_context(input, execution_byte);
    let host = open_host(paths, lane, project_id_start);
    let config = lifecycle_config(paths, paths.run_state_root.join(lane), artifacts);
    let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
        config,
        ComposedQemuAttemptResourceGuardFactory::new(host),
    );

    capture_production_baked_genesis(&mut factory, source, &context)
        .expect("capture production baked genesis for exact replay")
}

fn promote_exact_checkpoint(
    paths: &NativeGatePaths,
    lane: &str,
    project_id_start: u32,
    source_input: &CrucibleAttemptExecution,
    baked: &ProductionBakedGenesisCheckpoint,
    raw: ExactCheckpointId,
    execution_byte: u8,
) -> (ExactCheckpointStore, ExactCheckpointId) {
    let checkpoints = checkpoint_store();
    let context = native_execution_context(source_input, execution_byte);
    let resources = ComposedQemuAttemptResourceGuardFactory::new(
        SharedQemuAttemptHostResourceFactory::new(open_host(paths, lane, project_id_start)),
    );
    let mut replay_factory =
        ProductionBakedGenesisReplayCatalogFactory::new([baked.clone()], resources)
            .expect("build production baked-genesis replay catalog");
    let promoted = promote_test_checkpoint_for_resume(
        &checkpoints,
        raw,
        source_input,
        source_input.start().configuration(),
        None,
        &paths.run_state_root.join(lane),
        &context,
        &mut replay_factory,
    );

    (checkpoints, promoted)
}

fn checkpoint_store() -> ExactCheckpointStore {
    let checkpoint_root = required_path("CRUCIBLE_ATOMIC_WORLD_CHECKPOINTS");
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "native-hot-fork-equivalence",
        checkpoint_root,
    ));
    ExactCheckpointStore::new(backend, MAX_CHECKPOINT_BYTES).expect("open exact checkpoint store")
}
