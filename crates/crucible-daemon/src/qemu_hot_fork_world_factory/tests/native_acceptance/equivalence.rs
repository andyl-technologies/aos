//! Native semantic equivalence across production replay, restore, and hot fork.

use std::fs;
use std::sync::Arc;

use crucible::Configuration;
use crucible::model::DagStore;
use crucible_cas::content_store::{DirectoryBlobBackend, ImmutableBlobBackend};

use super::*;
use crate::QemuExactResumeBasis;

const POST_CHOICE_QUANTA: u64 = 512;
const MAX_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

struct ExactResume<'a> {
    store: &'a ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    boundary: &'a Configuration,
}

#[path = "equivalence/child.rs"]
mod child;
#[path = "equivalence/evidence.rs"]
mod evidence;

use self::child::{NativeHotChildStart, run_hot_child, start_hot_child};
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
        scenario::build_equivalence(&fixture, artifacts).expect("build equivalence scenario");

    let input = execution_input_for_scenario(source.clone());
    let checkpoint_context = execution_context(&input, 0x90);
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

    let thin_context = execution_context(&input, 0x96);
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

    let execution_source_context = execution_context(&input, 0x91);
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
    let exact_context =
        execution_context(&exact_input, 0x92).with_resume_checkpoint(Some(checkpoint));
    let mut exact_reference = begin_exact(
        &paths,
        "equivalence-exact-reference",
        6_300,
        &source,
        Arc::clone(&artifacts),
        ExactResume {
            store: &checkpoints,
            checkpoint,
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

    let exact_template_context =
        execution_context(&exact_input, 0x93).with_resume_checkpoint(Some(checkpoint));
    let mut exact_template_source = begin_exact(
        &paths,
        "equivalence-exact-template-source",
        6_400,
        &source,
        artifacts,
        ExactResume {
            store: &checkpoints,
            checkpoint,
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
        checkpoint: Some(checkpoint),
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
    let (source, artifacts) = scenario::build_single_node_equivalence(&fixture, artifacts)
        .expect("build single-node equivalence scenario");

    let input = execution_input_for_scenario(source.clone());
    let checkpoint_context = execution_context(&input, 0xa0);
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

    let thin_context = execution_context(&input, 0xa6);
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

    let execution_source_context = execution_context(&input, 0xa1);
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
    let exact_context =
        execution_context(&exact_input, 0xa2).with_resume_checkpoint(Some(checkpoint));
    let mut exact_reference = begin_exact(
        &paths,
        "single-exact-reference",
        7_300,
        &source,
        Arc::clone(&artifacts),
        ExactResume {
            store: &checkpoints,
            checkpoint,
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

    let exact_template_context =
        execution_context(&exact_input, 0xa3).with_resume_checkpoint(Some(checkpoint));
    let mut exact_template_source = begin_exact(
        &paths,
        "single-exact-template-source",
        7_400,
        &source,
        artifacts,
        ExactResume {
            store: &checkpoints,
            checkpoint,
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
        checkpoint: Some(checkpoint),
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
fn production_hot_fork_scales_across_three_semantic_template_depths() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) =
        scenario::build_single_node_scaling(&fixture, artifacts).expect("build scaling scenario");

    for depth in 1..=3 {
        let source_lane = format!("depth-{depth}-source");
        let target_lane = format!("depth-{depth}-target");
        let context = execution_context(
            &execution_input_for_scenario(source.clone()),
            0xc0 + u8::try_from(depth).expect("depth byte"),
        );
        let mut lifecycle = begin_fresh(
            &paths,
            &source_lane,
            8_100 + u32::try_from(depth).expect("depth project") * 100,
            &source,
            Arc::clone(&artifacts),
            &context,
        );
        let boundary = drive_fresh_source_to_semantic_depth(&mut lifecycle, &source, depth);
        assert_eq!(boundary.configuration.schedule.len(), depth);
        let world = lifecycle
            .prepare_hot_fork_source_world()
            .expect("prepare semantic-depth source world");
        let source_allocated_bytes = allocated_tree_bytes(&paths.storage_root.join(&source_lane));
        let child = start_hot_child(NativeHotChildStart {
            paths: &paths,
            lane: &target_lane,
            project_id_start: 8_500 + u32::try_from(depth).expect("depth project") * 100,
            source: source.clone(),
            expected_boundary: &boundary,
            checkpoint: None,
            execution_byte: 0xd0 + u8::try_from(depth).expect("depth byte"),
            world,
            topology: EquivalenceTopology::SingleNode,
        });
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
        child.finish_without_continuation();
    }
    println!("semantic_template_depth=3");
    println!("nested_os_fork=forbidden-by-qemu-child-contract");
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

fn checkpoint_store() -> ExactCheckpointStore {
    let checkpoint_root = required_path("CRUCIBLE_ATOMIC_WORLD_CHECKPOINTS");
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "native-hot-fork-equivalence",
        checkpoint_root,
    ));
    ExactCheckpointStore::new(backend, MAX_CHECKPOINT_BYTES).expect("open exact checkpoint store")
}
