//! Native semantic equivalence across production replay, restore, and hot fork.

use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use crucible::model::DagStore;
use crucible::{
    Configuration, Decision, FingerprintSample, GuestMeasurementEvent, NodeId,
    ObservableEventPayload, QuantumOutcome, QuantumRequest, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SelectionDecision,
};
use crucible_api::ProductionFaultEvidenceSnapshot;
use crucible_campaign::{ChoiceValue, ConfigurationId, IntegerValue, Selection};
use crucible_cas::content_store::{DirectoryBlobBackend, ImmutableBlobBackend};

use super::*;
use crate::guest_selectable::{resolve_guest_selectable, selected_guest_reply};

const POST_CHOICE_QUANTA: u64 = 512;
const MAX_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct ContinuationEvidence {
    reply_events: Vec<SchedulerEventLogEntry>,
    outcomes: Vec<QuantumOutcome>,
    fingerprints: BTreeMap<NodeId, FingerprintSample>,
    fault_evidence: ProductionFaultEvidenceSnapshot,
}

#[derive(Debug, PartialEq, Eq)]
struct BoundaryEvidence {
    configuration: Configuration,
    pending: QemuNodeSelectablePendingRequest,
    fingerprints: BTreeMap<NodeId, FingerprintSample>,
    fault_evidence: ProductionFaultEvidenceSnapshot,
}

#[derive(Debug, PartialEq, Eq)]
struct PreparedWorldEvidence {
    scheduler: crucible::SingleSchedulerCheckpoint,
    fault_checkpoint: ContentHash,
    event_log_objects: usize,
    signal_artifact_objects: usize,
    selectable_catalogs: usize,
    node_states: Vec<(NodeId, ProductionVmHotForkNodeServiceState)>,
    io_states: Vec<(
        NodeId,
        ProductionVmHotForkIoNodeKind,
        ProductionVmHotForkNodeServiceState,
    )>,
}

#[derive(Clone, Copy)]
enum EquivalenceTopology {
    MultiNode,
    SingleNode,
}

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
        .prepare_attempt_checkpoint(capture)
        .expect("prepare pending production checkpoint");
    let checkpoint = checkpoints
        .publish_attempt_checkpoint(&prepared)
        .expect("publish pending production checkpoint")
        .root();
    QemuFreshAttemptLifecycleOwner::shutdown(&mut checkpoint_source)
        .expect("shutdown checkpoint capture source");

    let thin_context = execution_context(&input, 0x96);
    let mut thin_reference = begin_fresh(
        &paths,
        "equivalence-thin-reference",
        6_050,
        &source,
        Arc::clone(&artifacts),
        &thin_context,
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
    let execution_hot = run_hot_child(
        &paths,
        "equivalence-execution-target",
        6_200,
        source.clone(),
        &execution_boundary,
        None,
        0x94,
        execution_world,
        EquivalenceTopology::MultiNode,
    );

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
        &checkpoints,
        checkpoint,
        &checkpoint_boundary.configuration,
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
        &checkpoints,
        checkpoint,
        &checkpoint_boundary.configuration,
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
    let exact_hot = run_hot_child(
        &paths,
        "equivalence-exact-template-target",
        6_500,
        source,
        &checkpoint_boundary,
        Some(checkpoint),
        0x95,
        exact_world,
        EquivalenceTopology::MultiNode,
    );

    assert_continuation_equivalent("exact restore", &exact, &thin);
    assert_continuation_equivalent("execution-created hot fork", &execution_hot, &thin);
    assert_continuation_equivalent("exact-created hot fork", &exact_hot, &thin);

    println!("hot_fork_equivalence=true");
    println!("template_origins=execution,exact-restore");
    println!("reference_tiers=thin-replay,exact-checkpoint");
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
        .prepare_attempt_checkpoint(capture)
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
    let execution_hot = run_hot_child(
        &paths,
        "single-execution-target",
        7_200,
        source.clone(),
        &execution_boundary,
        None,
        0xa4,
        execution_world,
        EquivalenceTopology::SingleNode,
    );

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
        &checkpoints,
        checkpoint,
        &checkpoint_boundary.configuration,
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
        &checkpoints,
        checkpoint,
        &checkpoint_boundary.configuration,
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
    let exact_hot = run_hot_child(
        &paths,
        "single-exact-template-target",
        7_500,
        source,
        &checkpoint_boundary,
        Some(checkpoint),
        0xa5,
        exact_world,
        EquivalenceTopology::SingleNode,
    );

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

#[allow(clippy::too_many_arguments)]
fn begin_exact(
    paths: &NativeGatePaths,
    lane: &str,
    project_id_start: u32,
    source: &crucible::ScenarioDefForm,
    artifacts: Arc<dyn DagStore>,
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    boundary: &Configuration,
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
            checkpoints,
            checkpoint,
            &source.scenario_def(),
            source,
            boundary,
            None,
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

fn drive_to_pending_boundary(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    topology: EquivalenceTopology,
) -> BoundaryEvidence {
    let mut configuration = Configuration::genesis(source.scenario_def());
    let mut observed_http = false;
    let mut observed_block = false;
    let mut observed_ninep = false;
    let mut observed_measurement_begin = false;
    let mut pending = None;

    for _ in 0..MAX_SOURCE_QUANTA {
        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .expect("drive fresh equivalence boundary");
        observed_http |= satisfied(&outcome.event_log_entries, "curl-receives-http-200");
        observed_block |= satisfied(&outcome.event_log_entries, "curl-block-read-complete");
        observed_ninep |= satisfied(&outcome.event_log_entries, "io-probe-complete");
        observed_measurement_begin |= outcome.event_log_entries.iter().any(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMeasurement {
                    event: GuestMeasurementEvent::Begin { measurement, instance },
                    ..
                }) if measurement == "hot-fork-window" && instance == "instance-1"
            )
        });
        configuration = outcome.configuration;
        let requests = lifecycle
            .drain_pending_selectable_requests()
            .expect("inspect pending equivalence choice");
        assert!(requests.len() <= 1, "one guest choice may be pending");
        if let Some(request) = requests.into_iter().next() {
            pending = Some(request);
        }

        let permanently_failed = lifecycle
            .fault_evidence_snapshot()
            .expect("inspect equivalence fault state")
            .nodes
            .iter()
            .any(|node| node.node.name == "io-probe" && node.service_state == "permanently_failed");
        let topology_ready = match topology {
            EquivalenceTopology::MultiNode => {
                observed_http && observed_block && observed_ninep && permanently_failed
            }
            EquivalenceTopology::SingleNode => true,
        };
        if topology_ready && observed_measurement_begin && pending.is_some() {
            assert!(
                lifecycle
                    .exact_checkpoint_ready()
                    .expect("inspect exact boundary"),
                "pending choice boundary must be checkpoint ready"
            );
            return capture_boundary_evidence(
                lifecycle,
                source,
                configuration,
                pending.expect("pending choice observed"),
                topology,
            );
        }
    }
    panic!("equivalence fixture did not reach the complete pending boundary");
}

fn drain_exact_pending(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
) -> QemuNodeSelectablePendingRequest {
    let requests = lifecycle
        .drain_pending_selectable_requests()
        .expect("inspect restored pending choice");
    let [pending] = requests.as_slice() else {
        panic!("restored boundary must expose exactly one pending choice")
    };
    pending.clone()
}

fn capture_boundary_evidence(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    configuration: Configuration,
    pending: QemuNodeSelectablePendingRequest,
    topology: EquivalenceTopology,
) -> BoundaryEvidence {
    assert_eq!(pending.node().name, "curl");
    assert_eq!(
        pending.pending().request().selectable_id(),
        "hot-fork.retry-quanta"
    );
    assert_eq!(pending.pending().request().sequence(), 1);
    assert_eq!(
        pending.pending().request().instance_key(),
        "continuation/one"
    );
    assert!(pending.pending().request().narrowed_domain().is_some());
    assert!(pending.pending().request().reply_capacity() > 0);
    assert!(pending.pending().icount() > 0);
    assert_eq!(pending.pending().vcpu_index(), 0);
    assert!(pending.pending().guest_virtual_address() > 0);
    let fingerprints: BTreeMap<NodeId, FingerprintSample> = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            let sample = lifecycle
                .sample_fingerprint(node.id.clone())
                .expect("sample pending-boundary fingerprint");
            (node.id.clone(), sample)
        })
        .collect();
    let fault_evidence = normalized_fault_evidence(lifecycle);
    match topology {
        EquivalenceTopology::MultiNode => {
            assert!(fault_evidence.resolved_effect_trace.is_some());
            assert!(!fault_evidence.emitted_events.is_empty());
            assert!(!fault_evidence.network_queues.is_empty());
            assert!(
                fault_evidence
                    .block_devices
                    .iter()
                    .any(|device| device.volatile_entries > 0)
            );
            assert!(fault_evidence.nodes.iter().any(|node| {
                node.node.name == "io-probe" && node.service_state == "permanently_failed"
            }));
        }
        EquivalenceTopology::SingleNode => {
            assert_eq!(fingerprints.len(), 1);
            assert_eq!(fault_evidence.nodes.len(), 1);
            assert_eq!(fault_evidence.nodes[0].node.name, "curl");
            assert_eq!(fault_evidence.nodes[0].service_state, "running");
            assert!(fault_evidence.nodes[0].backend_owned);
            assert_eq!(fault_evidence.block_devices.len(), 1);
        }
    }

    BoundaryEvidence {
        configuration,
        pending,
        fingerprints,
        fault_evidence,
    }
}

fn prepared_world_evidence(
    world: &ProductionVmHotForkSourceWorld,
    topology: EquivalenceTopology,
) -> PreparedWorldEvidence {
    let continuation = world.continuation();
    assert_eq!(continuation.selectable_catalog_count(), 1);
    assert!(continuation.event_log_object_count() > 0);
    match topology {
        EquivalenceTopology::MultiNode => {
            assert!(continuation.signal_artifact_object_count() > 0);
            assert!(continuation.io_nodes().iter().any(|node| {
                node.kind() == ProductionVmHotForkIoNodeKind::Block
                    && node.owner_service_state() == ProductionVmHotForkNodeServiceState::Running
            }));
            assert!(continuation.io_nodes().iter().any(|node| {
                node.kind() == ProductionVmHotForkIoNodeKind::NineP
                    && node.owner_service_state()
                        == ProductionVmHotForkNodeServiceState::PermanentlyFailed
            }));
        }
        EquivalenceTopology::SingleNode => {
            assert_eq!(continuation.nodes().len(), 1);
            assert_eq!(continuation.nodes()[0].node().name, "curl");
            assert_eq!(
                continuation.nodes()[0].service_state(),
                ProductionVmHotForkNodeServiceState::Running
            );
            assert_eq!(continuation.io_nodes().len(), 2);
            for kind in [
                ProductionVmHotForkIoNodeKind::Block,
                ProductionVmHotForkIoNodeKind::NineP,
            ] {
                assert!(continuation.io_nodes().iter().any(|node| {
                    node.kind() == kind
                        && node.owner_service_state()
                            == ProductionVmHotForkNodeServiceState::Running
                }));
            }
        }
    }

    // Process generations identify operational incarnations. They intentionally
    // differ after restore and fork and are excluded from semantic comparison.
    PreparedWorldEvidence {
        scheduler: continuation.scheduler().clone(),
        fault_checkpoint: continuation.fault_checkpoint_identity(),
        event_log_objects: continuation.event_log_object_count(),
        signal_artifact_objects: continuation.signal_artifact_object_count(),
        selectable_catalogs: continuation.selectable_catalog_count(),
        node_states: continuation
            .nodes()
            .iter()
            .map(|node| (node.node().clone(), node.service_state()))
            .collect(),
        io_states: continuation
            .io_nodes()
            .iter()
            .map(|node| (node.node().clone(), node.kind(), node.owner_service_state()))
            .collect(),
    }
}

fn normalized_fault_evidence(
    lifecycle: &impl QemuFreshAttemptLifecycleOwner,
) -> ProductionFaultEvidenceSnapshot {
    let mut evidence = lifecycle
        .fault_evidence_snapshot()
        .expect("capture semantic fault evidence");
    for node in &mut evidence.nodes {
        // A restore or fork creates a new process generation. The remaining
        // fields retain scheduler activity, service state, ownership, queues,
        // device state, and complete signal/effect evidence.
        node.generation = 0;
    }
    evidence
}

fn assert_continuation_equivalent(
    label: &str,
    actual: &ContinuationEvidence,
    reference: &ContinuationEvidence,
) {
    assert_eq!(
        actual.reply_events, reference.reply_events,
        "{label} changed the selected reply boundary"
    );
    assert_eq!(
        actual.outcomes.first(),
        reference.outcomes.first(),
        "{label} changed the first completed quantum"
    );
    assert_eq!(
        actual.outcomes, reference.outcomes,
        "{label} changed the bounded continuation"
    );
    assert_eq!(
        actual.outcomes.last(),
        reference.outcomes.last(),
        "{label} changed the bounded final state"
    );
    assert_eq!(actual.fingerprints, reference.fingerprints);
    assert_eq!(actual.fault_evidence, reference.fault_evidence);
}

fn continue_from_pending(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    mut configuration: Configuration,
    pending: QemuNodeSelectablePendingRequest,
) -> ContinuationEvidence {
    let discovery = resolve_guest_selectable(
        crucible_campaign::ScenarioDefId::from_hash(crucible_campaign::CampaignHash::from_bytes(
            source.scenario_def().id().bytes,
        )),
        source,
        pending.node(),
        pending.pending(),
    )
    .expect("resolve pending equivalence choice");
    let parent = configuration.clone();
    let parent_id = ConfigurationId::from_hash(crucible_campaign::CampaignHash::from_bytes(
        parent.id().bytes,
    ));
    let selection = Selection::new_campaign_branch(
        discovery.opportunity(),
        discovery.domain(),
        ChoiceValue::Integer(IntegerValue::Unsigned(7)),
        discovery.opportunity().branch_point_id(parent_id),
    )
    .expect("select equivalence continuation");
    let decision = SelectionDecision::new(&selection);
    let selected = crucible::step(&parent, Decision::Selection(decision.clone()));
    let reply = selected_guest_reply(pending.pending(), &discovery, &selection)
        .expect("build exact equivalence reply");
    let reply_events = lifecycle
        .apply_selectable_reply(&parent, decision, &selected, &pending, &reply)
        .expect("apply exact equivalence reply");
    configuration = selected;

    let mut outcomes = Vec::new();
    let mut completed = false;
    let mut measurement_sample = false;
    let mut measurement_end = false;
    for _ in 0..POST_CHOICE_QUANTA {
        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .expect("drive selected continuation");
        completed |= satisfied(&outcome.event_log_entries, "hot-fork-continuation-complete");
        for entry in &outcome.event_log_entries {
            if let SchedulerEventLogPayload::Observable(
                ObservableEventPayload::GuestMeasurement { event, .. },
            ) = entry.payload()
            {
                measurement_sample |= matches!(
                    event,
                    GuestMeasurementEvent::Sample { measurement, metric, .. }
                        if measurement == "hot-fork-window" && metric == "selected-retry"
                );
                measurement_end |= matches!(
                    event,
                    GuestMeasurementEvent::End { measurement, instance }
                        if measurement == "hot-fork-window" && instance == "instance-1"
                );
            }
        }
        configuration = outcome.configuration.clone();
        outcomes.push(outcome);
        if completed && measurement_sample && measurement_end {
            break;
        }
    }
    assert!(completed, "selected guest continuation completed");
    assert!(
        measurement_sample,
        "selected measurement sample was retained"
    );
    assert!(measurement_end, "open measurement window closed");

    let fingerprints = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            let sample = lifecycle
                .sample_fingerprint(node.id.clone())
                .expect("sample continuation fingerprint");
            (node.id.clone(), sample)
        })
        .collect();
    let fault_evidence = normalized_fault_evidence(lifecycle);

    ContinuationEvidence {
        reply_events,
        outcomes,
        fingerprints,
        fault_evidence,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_hot_child(
    paths: &NativeGatePaths,
    lane: &str,
    project_id_start: u32,
    source: crucible::ScenarioDefForm,
    expected_boundary: &BoundaryEvidence,
    checkpoint: Option<ExactCheckpointId>,
    execution_byte: u8,
    world: ProductionVmHotForkSourceWorld,
    topology: EquivalenceTopology,
) -> ContinuationEvidence {
    let boundary = expected_boundary.configuration.clone();
    let input = execution_input_for_scenario_configuration(source.clone(), boundary.clone());
    let context = execution_context(&input, execution_byte).with_resume_checkpoint(checkpoint);
    let key = QemuHotForkSourceWorldKey::for_execution(
        &input,
        &context,
        context.runtime_basis().expect("hot child runtime basis"),
    )
    .expect("derive hot child source key");
    assert_eq!(context.resume_checkpoint(), checkpoint);
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, world);
    let target = open_host(paths, lane, project_id_start);
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ComposedQemuAttemptResourceGuardFactory::new(target),
        paths.run_state_root.join(lane),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );
    let mut lifecycle = match factory
        .try_start(&input, &context)
        .expect("start production hot child")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("prepared hot source was declined"),
    };
    let materialization = lifecycle
        .start_materialization()
        .expect("inspect hot child materialization");
    assert_eq!(materialization.restored_configuration(), Some(&boundary));
    let pending = drain_exact_pending(&mut lifecycle);
    let actual_boundary = capture_boundary_evidence(
        &mut lifecycle,
        &source,
        boundary.clone(),
        pending.clone(),
        topology,
    );
    assert_eq!(&actual_boundary, expected_boundary);
    let evidence = continue_from_pending(&mut lifecycle, &source, boundary, pending);

    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown hot child");
    reconcile_native_world(&mut lifecycle);
    assert!(factory.recover(lifecycle).is_ok());
    assert!(factory.sources().available());
    evidence
}
