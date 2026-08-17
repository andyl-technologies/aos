//! Durable content-addressed closure store for exact production checkpoints.

use super::*;
use crucible::LocalDagStore;
use crucible::model::FaultResourceLimits;
use std::collections::BTreeSet;
use std::io::Read as _;

const MANIFEST_MAGIC: &[u8] = b"crucible.production-exact-closure.v4\0";
const MANIFEST_FILE: &str = "manifest.cbor";
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES_U64: u64 = 64 * 1024 * 1024;
const ARTIFACT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const ARTIFACT_CHUNK_BYTES_U64: u64 = 4 * 1024 * 1024;
const SMALL_CONTINUATION_MAX_BYTES: u64 = 268_435_456;
const LARGE_CONTINUATION_MAX_BYTES: u64 = 1_610_612_800;

#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureManifest {
    scenario: ContentHash,
    configuration: ContentHash,
    schedule: ContentHash,
    frontier: u64,
    scheduler: ContentHash,
    event_log_segments: Vec<ContentHash>,
    signal_artifacts: Vec<ContentHash>,
    trigger_state: ContentHash,
    assertion_state: ContentHash,
    lifecycle_state: ContentHash,
    fault_checkpoint: ContentHash,
    targets: Vec<TargetManifest>,
    node_generations: Vec<(String, u64)>,
    node_service_states: Vec<(String, u8)>,
    identity: ContentHash,
}

#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetManifest {
    node: String,
    counter: u64,
    scheduler_time: u64,
    snapshot: ContentHash,
    overlay: ArtifactManifest,
    vmstate: ArtifactManifest,
    manifest_identity: ContentHash,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifest {
    identity: ContentHash,
    length: u64,
    chunks: Vec<ContentHash>,
}

struct ClosureObjects {
    schedule: Vec<u8>,
    scheduler: Vec<u8>,
    event_log_segments: BTreeMap<ContentHash, Vec<u8>>,
    signal_artifacts: BTreeMap<ContentHash, Vec<u8>>,
    trigger_state: Vec<u8>,
    assertion_state: Vec<u8>,
    lifecycle_state: Vec<u8>,
    fault_checkpoint: Vec<u8>,
    snapshots: BTreeMap<NodeId, Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleWire {
    terminal: Option<TerminalWire>,
    terminal_cause: Option<TerminalCauseWire>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<BranchWire>,
    recorded_controls: Vec<RecordedControlWire>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalWire {
    Passed,
    Failed(Vec<String>),
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalCauseWire {
    Passed,
    Failed(Vec<String>),
    BudgetExhausted,
    BackendCrash(String),
    OperatorStop,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchWire {
    base_schedule: Vec<u8>,
    frontier: u64,
    decisions: Vec<Decision>,
    seed: Option<[u8; 32]>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedControlWire {
    configuration_schedule: Vec<u8>,
    node_times: Vec<(String, u64)>,
    control: Vec<ControlOperation>,
}

pub(super) fn persist_exact_checkpoint_set(
    run_state_root: &Path,
    scenario: ContentHash,
    resource_limits: FaultResourceLimits,
    checkpoint: &mut ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    validate_checkpoint_set(scenario, checkpoint)?;
    let (mut manifest, objects) = manifest_and_objects(scenario, checkpoint)?;
    manifest.identity = closure_identity(&manifest)?;
    checkpoint.identity = manifest.identity;
    let manifest_bytes = encode_manifest(&manifest)?;
    enforce_persist_limits(
        run_state_root,
        scenario,
        resource_limits,
        &manifest,
        &objects,
        checkpoint,
        manifest_bytes.len(),
    )?;

    let closure_parent = closure_parent(run_state_root, scenario);
    let object_directory = object_parent(run_state_root, scenario);
    fs::create_dir_all(&closure_parent).map_err(|error| {
        store_error(format!(
            "create exact checkpoint closure directory {}: {error}",
            closure_parent.display()
        ))
    })?;
    fs::create_dir_all(&object_directory).map_err(|error| {
        store_error(format!(
            "create exact checkpoint object directory {}: {error}",
            object_directory.display()
        ))
    })?;
    let destination = closure_parent.join(manifest.identity.to_hex());
    if destination.exists() {
        authenticate_existing_publication(
            &destination,
            &object_directory,
            &manifest,
            &objects,
            checkpoint,
        )?;
        install_published_artifact_paths(&object_directory, &manifest, checkpoint)?;
        return Ok(());
    }
    let staging = tempfile::Builder::new()
        .prefix(".closure-")
        .tempdir_in(&closure_parent)
        .map_err(|error| {
            store_error(format!(
                "create exact checkpoint closure staging directory: {error}"
            ))
        })?;
    persist_object(&object_directory, manifest.schedule, &objects.schedule)?;
    persist_object(&object_directory, manifest.scheduler, &objects.scheduler)?;
    let checkpoint_dag = checkpoint_dag_store(run_state_root, scenario);
    for (identity, bytes) in objects
        .event_log_segments
        .iter()
        .chain(objects.signal_artifacts.iter())
    {
        persist_object(&object_directory, *identity, bytes)?;
        let stored = checkpoint_dag
            .put(bytes)
            .map_err(|error| store_error(format!("persist checkpoint DAG object: {error}")))?;
        if stored != *identity {
            return Err(store_error(
                "checkpoint DAG returned a different content identity",
            ));
        }
    }
    persist_object(
        &object_directory,
        manifest.trigger_state,
        &objects.trigger_state,
    )?;
    persist_object(
        &object_directory,
        manifest.assertion_state,
        &objects.assertion_state,
    )?;
    persist_object(
        &object_directory,
        manifest.lifecycle_state,
        &objects.lifecycle_state,
    )?;
    persist_object(
        &object_directory,
        manifest.fault_checkpoint,
        &objects.fault_checkpoint,
    )?;
    for target in &manifest.targets {
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = objects
            .snapshots
            .get(&node)
            .ok_or_else(|| store_error("closure snapshot object disappeared"))?;
        persist_object(&object_directory, target.snapshot, snapshot)?;
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        persist_chunked_artifact(&object_directory, &target.overlay, &source.overlay_artifact)?;
        persist_chunked_artifact(&object_directory, &target.vmstate, &source.vmstate_artifact)?;
    }
    sync_directory(&object_directory)?;

    persist_file_bytes(&staging.path().join(MANIFEST_FILE), &manifest_bytes)?;
    sync_directory(staging.path())?;
    fs::rename(staging.path(), &destination).map_err(|error| {
        store_error(format!(
            "publish exact checkpoint closure {}: {error}",
            destination.display()
        ))
    })?;
    if let Err(error) = enforce_published_checkpoint_count(&closure_parent, resource_limits) {
        let cleanup = fs::remove_dir_all(&destination).map_err(|cleanup| {
            store_error(format!(
                "roll back over-limit checkpoint publication {}: {cleanup}",
                destination.display()
            ))
        });
        cleanup?;
        sync_directory(&closure_parent)?;
        return Err(error);
    }
    sync_directory(&closure_parent)?;

    install_published_artifact_paths(&object_directory, &manifest, checkpoint)?;
    Ok(())
}

fn enforce_published_checkpoint_count(
    parent: &Path,
    limits: FaultResourceLimits,
) -> Result<(), SchedulerError> {
    let count = fs::read_dir(parent)
        .map_err(|error| store_error(format!("count published checkpoint closures: {error}")))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry.file_name().to_str().is_some_and(|name| {
                    name.len() == 64
                        && name
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                })
        })
        .count();
    let count = u64::try_from(count)
        .map_err(|_| store_error("published checkpoint count is not representable"))?;
    limits
        .reserve(
            "checkpoint_count",
            count.saturating_sub(1),
            u64::from(count != 0),
        )
        .map_err(|error| store_error(error.to_string()))
}

pub(super) fn load_exact_checkpoint_set(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    identity: ContentHash,
) -> Result<ProductionVmExactCheckpointSet, LifecycleApiError> {
    let root = closure_parent(run_state_root, scenario.id()).join(identity.to_hex());
    let object_directory = object_parent(run_state_root, scenario.id());
    let limits = source.plan().fault_signals().resource_limits();
    let mut budget = CheckpointReadBudget::new(limits.fat_checkpoint_bytes);
    let manifest_bytes = read_bounded_file(&root.join(MANIFEST_FILE), MAX_MANIFEST_BYTES_U64)
        .map_err(|error| {
            loop_factory_error(format!(
                "read exact checkpoint closure {}: {error}",
                identity.to_hex()
            ))
        })?;
    budget.reserve(
        u64::try_from(manifest_bytes.len())
            .map_err(|_| loop_factory_error("checkpoint manifest size is not representable"))?,
    )?;
    let manifest = decode_manifest(&manifest_bytes).map_err(|message| {
        loop_factory_error(format!("decode exact checkpoint closure: {message}"))
    })?;
    if manifest.identity != identity
        || manifest.identity
            != closure_identity(&manifest).map_err(|error| loop_factory_error(error.to_string()))?
        || manifest.scenario != scenario.id()
    {
        return Err(loop_factory_error(
            "exact checkpoint closure failed identity authentication",
        ));
    }

    let schedule = Schedule::from_compact_binary(&read_object(
        &object_directory,
        manifest.schedule,
        &mut budget,
        SMALL_CONTINUATION_MAX_BYTES,
    )?)
    .map_err(|error| loop_factory_error(format!("decode checkpoint schedule: {error}")))?;
    let configuration = Configuration {
        def: scenario.clone(),
        schedule,
    };
    if configuration.id() != manifest.configuration {
        return Err(loop_factory_error(
            "exact checkpoint closure configuration does not authenticate",
        ));
    }
    let scheduler = SingleSchedulerCheckpoint::from_canonical_bytes(&read_object(
        &object_directory,
        manifest.scheduler,
        &mut budget,
        LARGE_CONTINUATION_MAX_BYTES,
    )?)
    .map_err(|error| loop_factory_error(format!("decode scheduler continuation: {error}")))?;
    if scheduler.configuration_for(scenario).map_err(|error| {
        loop_factory_error(format!("authenticate scheduler configuration: {error}"))
    })? != configuration
        || scheduler.frontier().ticks != manifest.frontier
    {
        return Err(loop_factory_error(
            "exact checkpoint scheduler continuation does not match its manifest",
        ));
    }
    if scheduler.event_log_segment_dependencies() != manifest.event_log_segments {
        return Err(loop_factory_error(
            "exact checkpoint event-log dependencies do not match the scheduler continuation",
        ));
    }
    let mut event_log_objects = BTreeMap::new();
    for identity in &manifest.event_log_segments {
        let bytes = read_object(
            &object_directory,
            *identity,
            &mut budget,
            LARGE_CONTINUATION_MAX_BYTES,
        )?;
        if event_log_objects.insert(*identity, bytes).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint contains duplicate event-log segment identities",
            ));
        }
    }
    let mut signal_artifact_objects = BTreeMap::new();
    for identity in &manifest.signal_artifacts {
        let bytes = read_object(
            &object_directory,
            *identity,
            &mut budget,
            LARGE_CONTINUATION_MAX_BYTES,
        )?;
        if signal_artifact_objects.insert(*identity, bytes).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint contains duplicate signal artifact identities",
            ));
        }
    }
    let checkpoint_dag = checkpoint_dag_store(run_state_root, scenario.id());
    for (identity, bytes) in event_log_objects
        .iter()
        .chain(signal_artifact_objects.iter())
    {
        let stored = checkpoint_dag.put(bytes).map_err(|error| {
            loop_factory_error(format!("reconstruct checkpoint DAG object: {error}"))
        })?;
        if stored != *identity {
            return Err(loop_factory_error(
                "checkpoint DAG reconstructed a different content identity",
            ));
        }
    }
    let trigger_state = EventGraphState::from_compact_binary(&read_object(
        &object_directory,
        manifest.trigger_state,
        &mut budget,
        SMALL_CONTINUATION_MAX_BYTES,
    )?)
    .map_err(|error| loop_factory_error(format!("decode trigger continuation: {error}")))?;
    let assertion_state = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&read_object(
        &object_directory,
        manifest.assertion_state,
        &mut budget,
        SMALL_CONTINUATION_MAX_BYTES,
    )?)
    .map_err(|error| loop_factory_error(format!("decode assertion continuation: {error}")))?;
    let lifecycle = decode_lifecycle(
        &read_object(
            &object_directory,
            manifest.lifecycle_state,
            &mut budget,
            SMALL_CONTINUATION_MAX_BYTES,
        )?,
        scenario,
    )?;
    let signal_plan = source.plan().fault_signals();
    let expected_signal_artifacts =
        collect_signal_artifact_objects(signal_plan, checkpoint_dag.as_ref())?;
    if expected_signal_artifacts != signal_artifact_objects {
        return Err(loop_factory_error(
            "exact checkpoint signal-artifact closure is incomplete or contains unreferenced objects",
        ));
    }
    let fault_checkpoint = ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
        &read_object(
            &object_directory,
            manifest.fault_checkpoint,
            &mut budget,
            LARGE_CONTINUATION_MAX_BYTES,
        )?,
        signal_plan,
        scenario.id(),
    )
    .map_err(|error| loop_factory_error(format!("decode fault continuation: {error}")))?;

    let mut targets = BTreeMap::new();
    for target in &manifest.targets {
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = QemuVmSnapshot::from_canonical_bytes(&read_object(
            &object_directory,
            target.snapshot,
            &mut budget,
            SMALL_CONTINUATION_MAX_BYTES,
        )?)
        .map_err(|error| {
            loop_factory_error(format!(
                "decode QEMU snapshot for `{}`: {error}",
                target.node
            ))
        })?;
        let restored = ProductionVmExactCheckpointTarget {
            configuration: configuration.clone(),
            counter: target.counter,
            scheduler_time: VirtualTime {
                ticks: target.scheduler_time,
            },
            snapshot,
            overlay_artifact: ProductionCheckpointArtifact {
                source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.clone()),
                identity: target.overlay.identity,
                length: target.overlay.length,
                chunks: target.overlay.chunks.clone(),
            },
            vmstate_artifact: ProductionCheckpointArtifact {
                source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.clone()),
                identity: target.vmstate.identity,
                length: target.vmstate.length,
                chunks: target.vmstate.chunks.clone(),
            },
            fault_checkpoint: fault_checkpoint.clone(),
            manifest_identity: target.manifest_identity,
        };
        budget.reserve_identity_once(
            restored.overlay_artifact.identity,
            restored.overlay_artifact.length,
        )?;
        budget.reserve_identity_once(
            restored.vmstate_artifact.identity,
            restored.vmstate_artifact.length,
        )?;
        validate_exact_checkpoint_target(&node, &restored)?;
        if targets.insert(node, restored).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint closure contains duplicate node targets",
            ));
        }
    }
    let node_generations = decode_generations(&manifest.node_generations)?;
    let node_service_states = decode_service_states(&manifest.node_service_states)?;
    validate_restored_node_sets(source, &targets, &node_generations, &node_service_states)?;
    let restored = ProductionVmExactCheckpointSet {
        identity,
        configuration,
        scheduler,
        event_log_objects,
        signal_artifact_objects,
        trigger_state,
        assertion_state,
        terminal_verdict: lifecycle.terminal,
        terminal_cause: lifecycle.terminal_cause,
        initial_lifecycle_observations_pending: lifecycle.initial_lifecycle_observations_pending,
        branch: lifecycle.branch,
        recorded_controls: lifecycle.recorded_controls,
        fault_checkpoint,
        targets,
        node_generations,
        node_service_states,
    };
    validate_checkpoint_set(scenario.id(), &restored)
        .map_err(|error| loop_factory_error(error.to_string()))?;
    Ok(restored)
}

fn validate_checkpoint_set(
    scenario: ContentHash,
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    if checkpoint.configuration.def.id() != scenario
        || checkpoint
            .scheduler
            .configuration_for(&checkpoint.configuration.def)
            .map_err(|error| {
                store_error(format!("authenticate scheduler configuration: {error}"))
            })?
            != checkpoint.configuration
    {
        return Err(store_error(
            "exact checkpoint scheduler configuration does not match its scenario",
        ));
    }
    if !terminal_cause_matches_verdict(
        checkpoint.terminal_cause.as_ref(),
        checkpoint.terminal_verdict.as_ref(),
    ) {
        return Err(store_error(
            "exact checkpoint terminal cause disagrees with its trigger verdict",
        ));
    }
    if checkpoint.scheduler.event_log_segment_dependencies().len()
        != checkpoint.event_log_objects.len()
        || checkpoint
            .scheduler
            .event_log_segment_dependencies()
            .iter()
            .any(|identity| !checkpoint.event_log_objects.contains_key(identity))
    {
        return Err(store_error(
            "exact checkpoint event-log closure is incomplete or out of order",
        ));
    }
    for (identity, bytes) in &checkpoint.event_log_objects {
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(store_error(
                "exact checkpoint event-log object failed content authentication",
            ));
        }
    }
    for (identity, bytes) in &checkpoint.signal_artifact_objects {
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(store_error(
                "exact checkpoint signal artifact failed content authentication",
            ));
        }
    }
    match (
        checkpoint.scheduler.branch_frontier_cap(),
        checkpoint.branch.as_ref(),
    ) {
        (None, None) => {}
        (Some(cap), Some(branch))
            if cap == branch.frontier
                && branch.base.def.id() == scenario
                && branch.base == checkpoint.configuration => {}
        _ => {
            return Err(store_error(
                "exact checkpoint active branch disagrees with scheduler continuation",
            ));
        }
    }
    if checkpoint
        .node_generations
        .keys()
        .ne(checkpoint.node_service_states.keys())
        || checkpoint
            .node_generations
            .values()
            .any(|generation| *generation == 0)
        || checkpoint
            .targets
            .keys()
            .any(|node| !checkpoint.node_service_states.contains_key(node))
    {
        return Err(store_error(
            "exact checkpoint node generations and service states are incomplete",
        ));
    }
    for (node, state) in &checkpoint.node_service_states {
        let target = checkpoint.targets.get(node);
        if matches!(state, ProductionNodeServiceState::PermanentlyFailed) != target.is_none() {
            return Err(store_error(format!(
                "exact checkpoint target disagrees with service state for `{}`",
                node.name
            )));
        }
        if let Some(target) = target {
            if target.configuration != checkpoint.configuration
                || target.fault_checkpoint.id() != checkpoint.fault_checkpoint.id()
            {
                return Err(store_error(format!(
                    "exact checkpoint target state disagrees for `{}`",
                    node.name
                )));
            }
            validate_exact_checkpoint_target(node, target)
                .map_err(|error| store_error(error.to_string()))?;
        }
    }
    validate_recorded_controls(checkpoint)?;
    Ok(())
}

fn validate_recorded_controls(
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    let current = checkpoint.configuration.schedule.decisions();
    let mut prior_schedule_len = 0_usize;
    let mut prior_sequence = None;
    for record in &checkpoint.recorded_controls {
        let recorded = record.configuration.schedule.decisions();
        if record.configuration.def.id() != checkpoint.configuration.def.id()
            || recorded.len() < prior_schedule_len
            || !current.starts_with(recorded)
            || record.control.is_empty()
            || record
                .node_times
                .keys()
                .any(|node| !checkpoint.node_service_states.contains_key(node))
            || record
                .node_times
                .values()
                .any(|time| *time > checkpoint.scheduler.frontier())
        {
            return Err(store_error(
                "exact checkpoint recorded-control history is inconsistent with its frontier",
            ));
        }
        for control in &record.control {
            if prior_sequence.is_some_and(|sequence| control.sequence <= sequence) {
                return Err(store_error(
                    "exact checkpoint control sequences are not strictly increasing",
                ));
            }
            prior_sequence = Some(control.sequence);
        }
        prior_schedule_len = recorded.len();
    }
    Ok(())
}

fn validate_restored_node_sets(
    source: &ScenarioDefForm,
    targets: &BTreeMap<NodeId, ProductionVmExactCheckpointTarget>,
    generations: &BTreeMap<NodeId, u64>,
    service_states: &BTreeMap<NodeId, ProductionNodeServiceState>,
) -> Result<(), LifecycleApiError> {
    let expected = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let generation_nodes = generations
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let service_nodes = service_states
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let expected_targets = expected
        .iter()
        .filter(|node| {
            service_states.get(*node) != Some(&ProductionNodeServiceState::PermanentlyFailed)
        })
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let target_nodes = targets
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if generation_nodes != expected
        || service_nodes != expected
        || target_nodes != expected_targets
        || generations.values().any(|generation| *generation == 0)
    {
        return Err(loop_factory_error(
            "exact checkpoint closure has an incomplete World node set",
        ));
    }
    Ok(())
}

fn enforce_persist_limits(
    run_state_root: &Path,
    scenario: ContentHash,
    limits: FaultResourceLimits,
    manifest: &ClosureManifest,
    objects: &ClosureObjects,
    checkpoint: &ProductionVmExactCheckpointSet,
    manifest_bytes: usize,
) -> Result<(), SchedulerError> {
    let parent = closure_parent(run_state_root, scenario);
    let destination = parent.join(manifest.identity.to_hex());
    if !destination.exists() && parent.exists() {
        let count = fs::read_dir(&parent)
            .map_err(|error| store_error(format!("count exact checkpoint closures: {error}")))?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && entry.file_name().to_str().is_some_and(|name| {
                        name.len() == 64
                            && name
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    })
            })
            .count();
        limits
            .reserve(
                "checkpoint_count",
                u64::try_from(count)
                    .map_err(|_| store_error("checkpoint count is not representable"))?,
                1,
            )
            .map_err(|error| store_error(error.to_string()))?;
    }

    let mut identities = BTreeSet::new();
    let mut bytes = u64::try_from(manifest_bytes)
        .map_err(|_| store_error("checkpoint manifest size is not representable"))?;
    for (identity, size) in [
        (manifest.schedule, objects.schedule.len()),
        (manifest.scheduler, objects.scheduler.len()),
        (manifest.trigger_state, objects.trigger_state.len()),
        (manifest.assertion_state, objects.assertion_state.len()),
        (manifest.lifecycle_state, objects.lifecycle_state.len()),
        (manifest.fault_checkpoint, objects.fault_checkpoint.len()),
    ] {
        if identities.insert(identity) {
            bytes = add_checkpoint_bytes(
                bytes,
                u64::try_from(size)
                    .map_err(|_| store_error("checkpoint object size is not representable"))?,
            )?;
        }
    }
    for (identity, object) in &objects.event_log_segments {
        if identities.insert(*identity) {
            bytes = add_checkpoint_bytes(
                bytes,
                u64::try_from(object.len()).map_err(|_| {
                    store_error("event-log checkpoint object size is not representable")
                })?,
            )?;
        }
    }
    for (identity, object) in &objects.signal_artifacts {
        if identities.insert(*identity) {
            bytes = add_checkpoint_bytes(
                bytes,
                u64::try_from(object.len()).map_err(|_| {
                    store_error("signal checkpoint object size is not representable")
                })?,
            )?;
        }
    }
    for target in &manifest.targets {
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = objects
            .snapshots
            .get(&node)
            .ok_or_else(|| store_error("closure snapshot object disappeared"))?;
        if identities.insert(target.snapshot) {
            bytes = add_checkpoint_bytes(
                bytes,
                u64::try_from(snapshot.len())
                    .map_err(|_| store_error("checkpoint snapshot size is not representable"))?,
            )?;
        }
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        for (identity, size) in [
            (target.overlay.identity, source.overlay_artifact.length),
            (target.vmstate.identity, source.vmstate_artifact.length),
        ] {
            if identities.insert(identity) {
                bytes = add_checkpoint_bytes(bytes, size)?;
            }
        }
    }
    limits
        .reserve("fat_checkpoint_bytes", 0, bytes)
        .map_err(|error| store_error(error.to_string()))
}

fn add_checkpoint_bytes(current: u64, requested: u64) -> Result<u64, SchedulerError> {
    current
        .checked_add(requested)
        .ok_or_else(|| store_error("checkpoint byte accounting overflow"))
}

fn authenticate_existing_publication(
    destination: &Path,
    object_directory: &Path,
    expected: &ClosureManifest,
    objects: &ClosureObjects,
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    let bytes = read_bounded_file(&destination.join(MANIFEST_FILE), MAX_MANIFEST_BYTES_U64)
        .map_err(|error| store_error(format!("read existing checkpoint manifest: {error}")))?;
    let observed = decode_manifest(&bytes).map_err(store_error)?;
    if &observed != expected {
        return Err(store_error(
            "existing exact checkpoint publication has different authenticated content",
        ));
    }
    for (identity, bytes) in [
        (expected.schedule, objects.schedule.as_slice()),
        (expected.scheduler, objects.scheduler.as_slice()),
        (expected.trigger_state, objects.trigger_state.as_slice()),
        (expected.assertion_state, objects.assertion_state.as_slice()),
        (expected.lifecycle_state, objects.lifecycle_state.as_slice()),
        (
            expected.fault_checkpoint,
            objects.fault_checkpoint.as_slice(),
        ),
    ] {
        if ContentHash::from_bytes(bytes) != identity {
            return Err(store_error("checkpoint object changed before retry"));
        }
        validate_file_hash(&object_path(object_directory, identity), identity)?;
    }
    for identity in &expected.event_log_segments {
        let bytes = objects
            .event_log_segments
            .get(identity)
            .ok_or_else(|| store_error("event-log closure object disappeared"))?;
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(store_error(
                "event-log checkpoint object changed before retry",
            ));
        }
        validate_file_hash(&object_path(object_directory, *identity), *identity)?;
    }
    for identity in &expected.signal_artifacts {
        let bytes = objects
            .signal_artifacts
            .get(identity)
            .ok_or_else(|| store_error("signal-artifact closure object disappeared"))?;
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(store_error(
                "signal-artifact checkpoint object changed before retry",
            ));
        }
        validate_file_hash(&object_path(object_directory, *identity), *identity)?;
    }
    for target in &expected.targets {
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = objects
            .snapshots
            .get(&node)
            .ok_or_else(|| store_error("closure snapshot object disappeared"))?;
        if ContentHash::from_bytes(snapshot) != target.snapshot {
            return Err(store_error("checkpoint snapshot changed before retry"));
        }
        validate_file_hash(
            &object_path(object_directory, target.snapshot),
            target.snapshot,
        )?;
        validate_artifact_manifest(object_directory, &target.overlay)
            .map_err(|error| store_error(error.to_string()))?;
        validate_artifact_manifest(object_directory, &target.vmstate)
            .map_err(|error| store_error(error.to_string()))?;
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        validate_exact_checkpoint_artifact(&source.overlay_artifact, "root overlay")
            .map_err(|error| store_error(error.to_string()))?;
        validate_exact_checkpoint_artifact(&source.vmstate_artifact, "VMState")
            .map_err(|error| store_error(error.to_string()))?;
    }
    Ok(())
}

fn install_published_artifact_paths(
    object_directory: &Path,
    manifest: &ClosureManifest,
    checkpoint: &mut ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    for (node, target) in &mut checkpoint.targets {
        let manifest_target = manifest
            .targets
            .iter()
            .find(|candidate| candidate.node == node.name)
            .ok_or_else(|| store_error("published closure target disappeared"))?;
        target.overlay_artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.to_path_buf()),
            identity: manifest_target.overlay.identity,
            length: manifest_target.overlay.length,
            chunks: manifest_target.overlay.chunks.clone(),
        };
        target.vmstate_artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.to_path_buf()),
            identity: manifest_target.vmstate.identity,
            length: manifest_target.vmstate.length,
            chunks: manifest_target.vmstate.chunks.clone(),
        };
    }
    Ok(())
}

fn encode_lifecycle(
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<Vec<u8>, SchedulerError> {
    let wire = LifecycleWire {
        terminal: checkpoint
            .terminal_verdict
            .as_ref()
            .map(|terminal| match terminal {
                QuantumTerminalVerdict::Passed => TerminalWire::Passed,
                QuantumTerminalVerdict::Failed(failures) => TerminalWire::Failed(failures.clone()),
            }),
        terminal_cause: checkpoint.terminal_cause.as_ref().map(|cause| match cause {
            CheckpointTerminalCause::Passed => TerminalCauseWire::Passed,
            CheckpointTerminalCause::Failed(failures) => {
                TerminalCauseWire::Failed(failures.clone())
            }
            CheckpointTerminalCause::BudgetExhausted => TerminalCauseWire::BudgetExhausted,
            CheckpointTerminalCause::BackendCrash(detail) => {
                TerminalCauseWire::BackendCrash(detail.clone())
            }
            CheckpointTerminalCause::OperatorStop => TerminalCauseWire::OperatorStop,
        }),
        initial_lifecycle_observations_pending: checkpoint.initial_lifecycle_observations_pending,
        branch: checkpoint.branch.as_ref().map(|branch| BranchWire {
            base_schedule: branch.base.schedule.to_compact_binary(),
            frontier: branch.frontier.ticks,
            decisions: branch.decisions.clone(),
            seed: branch.seed.map(Seed::bytes),
        }),
        recorded_controls: checkpoint
            .recorded_controls
            .iter()
            .map(|record| RecordedControlWire {
                configuration_schedule: record.configuration.schedule.to_compact_binary(),
                node_times: record
                    .node_times
                    .iter()
                    .map(|(node, time)| (node.name.clone(), time.ticks))
                    .collect(),
                control: record.control.clone(),
            })
            .collect(),
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&wire, &mut bytes)
        .map_err(|_| store_error("encode exact lifecycle continuation"))?;
    Ok(bytes)
}

struct DecodedLifecycle {
    terminal: Option<QuantumTerminalVerdict>,
    terminal_cause: Option<CheckpointTerminalCause>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<ProductionVmBranchConfig>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
}

fn decode_lifecycle(
    bytes: &[u8],
    scenario: &ScenarioDef,
) -> Result<DecodedLifecycle, LifecycleApiError> {
    let wire: LifecycleWire = ciborium::de::from_reader(bytes)
        .map_err(|_| loop_factory_error("decode exact lifecycle continuation"))?;
    let canonical = {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&wire, &mut encoded)
            .map_err(|_| loop_factory_error("re-encode exact lifecycle continuation"))?;
        encoded
    };
    if canonical != bytes {
        return Err(loop_factory_error(
            "exact lifecycle continuation is not canonical",
        ));
    }
    let terminal = wire.terminal.map(|terminal| match terminal {
        TerminalWire::Passed => QuantumTerminalVerdict::Passed,
        TerminalWire::Failed(failures) => QuantumTerminalVerdict::Failed(failures),
    });
    let terminal_cause = wire.terminal_cause.map(|cause| match cause {
        TerminalCauseWire::Passed => CheckpointTerminalCause::Passed,
        TerminalCauseWire::Failed(failures) => CheckpointTerminalCause::Failed(failures),
        TerminalCauseWire::BudgetExhausted => CheckpointTerminalCause::BudgetExhausted,
        TerminalCauseWire::BackendCrash(detail) => CheckpointTerminalCause::BackendCrash(detail),
        TerminalCauseWire::OperatorStop => CheckpointTerminalCause::OperatorStop,
    });
    if !terminal_cause_matches_verdict(terminal_cause.as_ref(), terminal.as_ref()) {
        return Err(loop_factory_error(
            "exact lifecycle terminal cause disagrees with its trigger verdict",
        ));
    }
    let branch = wire
        .branch
        .map(
            |branch| -> Result<ProductionVmBranchConfig, LifecycleApiError> {
                let schedule =
                    Schedule::from_compact_binary(&branch.base_schedule).map_err(|error| {
                        loop_factory_error(format!("decode checkpoint branch schedule: {error}"))
                    })?;
                Ok(ProductionVmBranchConfig {
                    base: Configuration {
                        def: scenario.clone(),
                        schedule,
                    },
                    frontier: VirtualTime {
                        ticks: branch.frontier,
                    },
                    decisions: branch.decisions,
                    seed: branch.seed.map(Seed::from_bytes),
                })
            },
        )
        .transpose()?;
    let mut recorded_controls = Vec::with_capacity(wire.recorded_controls.len());
    for record in wire.recorded_controls {
        if !record
            .node_times
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        {
            return Err(loop_factory_error(
                "checkpoint recorded-control nodes are not strictly sorted",
            ));
        }
        let schedule =
            Schedule::from_compact_binary(&record.configuration_schedule).map_err(|error| {
                loop_factory_error(format!("decode recorded control schedule: {error}"))
            })?;
        recorded_controls.push(ProductionVmRecordedControl {
            configuration: Configuration {
                def: scenario.clone(),
                schedule,
            },
            node_times: record
                .node_times
                .into_iter()
                .map(|(name, ticks)| (NodeId { name }, VirtualTime { ticks }))
                .collect(),
            control: record.control,
        });
    }
    Ok(DecodedLifecycle {
        terminal,
        terminal_cause,
        initial_lifecycle_observations_pending: wire.initial_lifecycle_observations_pending,
        branch,
        recorded_controls,
    })
}

fn terminal_cause_matches_verdict(
    cause: Option<&CheckpointTerminalCause>,
    verdict: Option<&QuantumTerminalVerdict>,
) -> bool {
    match (cause, verdict) {
        (Some(CheckpointTerminalCause::Passed), Some(QuantumTerminalVerdict::Passed)) => true,
        (
            Some(CheckpointTerminalCause::Failed(cause)),
            Some(QuantumTerminalVerdict::Failed(verdict)),
        ) => cause == verdict,
        (Some(CheckpointTerminalCause::BudgetExhausted), None)
        | (Some(CheckpointTerminalCause::BackendCrash(_)), None)
        | (Some(CheckpointTerminalCause::OperatorStop), None)
        | (None, None) => true,
        _ => false,
    }
}

fn manifest_and_objects(
    scenario: ContentHash,
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<(ClosureManifest, ClosureObjects), SchedulerError> {
    let schedule = checkpoint.configuration.schedule.to_compact_binary();
    let scheduler = checkpoint
        .scheduler
        .canonical_bytes()
        .map_err(|error| store_error(format!("encode scheduler continuation: {error}")))?;
    let trigger_state = checkpoint.trigger_state.to_compact_binary();
    let assertion_state = checkpoint
        .assertion_state
        .canonical_bytes()
        .map_err(|error| store_error(format!("encode assertion continuation: {error}")))?;
    let lifecycle_state = encode_lifecycle(checkpoint)?;
    let fault_checkpoint = checkpoint
        .fault_checkpoint
        .to_canonical_bytes()
        .map_err(|error| store_error(format!("encode fault continuation: {error}")))?;
    let mut snapshots = BTreeMap::new();
    let targets = checkpoint
        .targets
        .iter()
        .map(|(node, target)| {
            let bytes = target.snapshot.to_canonical_bytes().map_err(|error| {
                store_error(format!("encode QEMU snapshot for `{}`: {error}", node.name))
            })?;
            let snapshot = ContentHash::from_bytes(&bytes);
            snapshots.insert(node.clone(), bytes);
            Ok(TargetManifest {
                node: node.name.clone(),
                counter: target.counter,
                scheduler_time: target.scheduler_time.ticks,
                snapshot,
                overlay: artifact_manifest(&target.overlay_artifact)?,
                vmstate: artifact_manifest(&target.vmstate_artifact)?,
                manifest_identity: target.manifest_identity,
            })
        })
        .collect::<Result<Vec<_>, SchedulerError>>()?;
    let manifest = ClosureManifest {
        scenario,
        configuration: checkpoint.configuration.id(),
        schedule: ContentHash::from_bytes(&schedule),
        frontier: checkpoint.scheduler.frontier().ticks,
        scheduler: ContentHash::from_bytes(&scheduler),
        event_log_segments: checkpoint
            .scheduler
            .event_log_segment_dependencies()
            .to_vec(),
        signal_artifacts: checkpoint.signal_artifact_objects.keys().copied().collect(),
        trigger_state: ContentHash::from_bytes(&trigger_state),
        assertion_state: ContentHash::from_bytes(&assertion_state),
        lifecycle_state: ContentHash::from_bytes(&lifecycle_state),
        fault_checkpoint: ContentHash::from_bytes(&fault_checkpoint),
        targets,
        node_generations: checkpoint
            .node_generations
            .iter()
            .map(|(node, generation)| (node.name.clone(), *generation))
            .collect(),
        node_service_states: checkpoint
            .node_service_states
            .iter()
            .map(|(node, state)| (node.name.clone(), service_state_tag(*state)))
            .collect(),
        identity: ContentHash::default(),
    };
    Ok((
        manifest,
        ClosureObjects {
            schedule,
            scheduler,
            event_log_segments: checkpoint.event_log_objects.clone(),
            signal_artifacts: checkpoint.signal_artifact_objects.clone(),
            trigger_state,
            assertion_state,
            lifecycle_state,
            fault_checkpoint,
            snapshots,
        },
    ))
}

fn closure_identity(manifest: &ClosureManifest) -> Result<ContentHash, SchedulerError> {
    let material = ClosureManifest {
        scenario: manifest.scenario,
        configuration: manifest.configuration,
        schedule: manifest.schedule,
        frontier: manifest.frontier,
        scheduler: manifest.scheduler,
        event_log_segments: manifest.event_log_segments.clone(),
        signal_artifacts: manifest.signal_artifacts.clone(),
        trigger_state: manifest.trigger_state,
        assertion_state: manifest.assertion_state,
        lifecycle_state: manifest.lifecycle_state,
        fault_checkpoint: manifest.fault_checkpoint,
        targets: manifest
            .targets
            .iter()
            .map(|target| TargetManifest {
                node: target.node.clone(),
                counter: target.counter,
                scheduler_time: target.scheduler_time,
                snapshot: target.snapshot,
                overlay: target.overlay.clone(),
                vmstate: target.vmstate.clone(),
                manifest_identity: target.manifest_identity,
            })
            .collect(),
        node_generations: manifest.node_generations.clone(),
        node_service_states: manifest.node_service_states.clone(),
        identity: ContentHash::default(),
    };
    let bytes = encode_manifest(&material)?;
    Ok(ContentHash::from_canonical_material(
        "crucible.production-exact-closure.v4",
        &hex_bytes(&bytes),
    ))
}

fn encode_manifest(manifest: &ClosureManifest) -> Result<Vec<u8>, SchedulerError> {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(manifest, &mut payload)
        .map_err(|_| store_error("encode exact checkpoint closure manifest"))?;
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(store_error(
            "exact checkpoint closure manifest exceeds its size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(MANIFEST_MAGIC.len() + payload.len());
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<ClosureManifest, String> {
    let payload = bytes
        .strip_prefix(MANIFEST_MAGIC)
        .ok_or_else(|| String::from("unsupported closure manifest version"))?;
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(String::from("closure manifest exceeds its size limit"));
    }
    let manifest: ClosureManifest = ciborium::de::from_reader(payload)
        .map_err(|_| String::from("malformed closure manifest"))?;
    let canonical = encode_manifest(&manifest).map_err(|error| error.to_string())?;
    if canonical != bytes {
        return Err(String::from("noncanonical closure manifest"));
    }
    validate_manifest_shape(&manifest)?;
    Ok(manifest)
}

fn validate_manifest_shape(manifest: &ClosureManifest) -> Result<(), String> {
    if !manifest
        .signal_artifacts
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        || manifest
            .event_log_segments
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != manifest.event_log_segments.len()
        || !manifest
            .targets
            .windows(2)
            .all(|pair| pair[0].node < pair[1].node)
        || !manifest
            .node_generations
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        || !manifest
            .node_service_states
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
    {
        return Err(String::from(
            "closure manifest node collections are not strictly sorted",
        ));
    }
    if manifest.targets.iter().any(|target| target.node.is_empty())
        || manifest.targets.iter().any(|target| {
            (target.overlay.length == 0) != target.overlay.chunks.is_empty()
                || (target.vmstate.length == 0) != target.vmstate.chunks.is_empty()
        })
        || manifest
            .node_generations
            .iter()
            .any(|(node, generation)| node.is_empty() || *generation == 0)
        || manifest
            .node_service_states
            .iter()
            .any(|(node, state)| node.is_empty() || !matches!(state, 1..=3))
    {
        return Err(String::from(
            "closure manifest contains an invalid node record",
        ));
    }
    let snapshot_count = manifest
        .targets
        .iter()
        .map(|target| target.snapshot)
        .collect::<BTreeSet<_>>()
        .len();
    if snapshot_count != manifest.targets.len() {
        return Err(String::from(
            "closure manifest aliases a node-specific QEMU snapshot",
        ));
    }
    for artifact in manifest
        .targets
        .iter()
        .flat_map(|target| [&target.overlay, &target.vmstate])
    {
        let chunk_count = u64::try_from(artifact.chunks.len())
            .map_err(|_| String::from("artifact chunk count is not representable"))?;
        let minimum = chunk_count
            .saturating_sub(1)
            .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
            .and_then(|bytes| bytes.checked_add(u64::from(chunk_count != 0)))
            .ok_or_else(|| String::from("artifact chunk geometry overflows"))?;
        let maximum = chunk_count
            .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
            .ok_or_else(|| String::from("artifact chunk geometry overflows"))?;
        if artifact.length < minimum || artifact.length > maximum {
            return Err(String::from(
                "closure manifest contains invalid artifact chunk geometry",
            ));
        }
    }
    Ok(())
}

fn persist_object(
    directory: &Path,
    expected: ContentHash,
    bytes: &[u8],
) -> Result<(), SchedulerError> {
    if ContentHash::from_bytes(bytes) != expected {
        return Err(store_error(
            "checkpoint object content hash mismatch before persistence",
        ));
    }
    let destination = object_path(directory, expected);
    if destination.exists() {
        return sync_existing_object(&destination, expected);
    }
    let staging_directory = destination
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    fs::create_dir_all(staging_directory)
        .map_err(|error| store_error(format!("create checkpoint object prefix: {error}")))?;
    let mut staging = tempfile::Builder::new()
        .prefix(".object-")
        .tempfile_in(staging_directory)
        .map_err(|error| store_error(format!("stage checkpoint object: {error}")))?;
    staging
        .write_all(bytes)
        .and_then(|()| staging.as_file().sync_all())
        .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => sync_directory(staging_directory),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object(&destination, expected)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {}",
            expected.to_hex(),
            error.error
        ))),
    }
}

fn persist_file_object(
    directory: &Path,
    expected: ContentHash,
    source: &Path,
) -> Result<(), SchedulerError> {
    validate_file_hash(source, expected)?;
    let destination = object_path(directory, expected);
    if destination.exists() {
        return sync_existing_object(&destination, expected);
    }
    let staging_directory = destination
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    fs::create_dir_all(staging_directory)
        .map_err(|error| store_error(format!("create checkpoint object prefix: {error}")))?;
    let staging = tempfile::Builder::new()
        .prefix(".object-")
        .tempfile_in(staging_directory)
        .map_err(|error| store_error(format!("stage checkpoint file object: {error}")))?;
    fs::copy(source, staging.path()).map_err(|error| {
        store_error(format!(
            "copy checkpoint object {} into staging: {error}",
            expected.to_hex()
        ))
    })?;
    staging
        .as_file()
        .sync_all()
        .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => {
            validate_file_hash(&destination, expected)?;
            sync_directory(staging_directory)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object(&destination, expected)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {}",
            expected.to_hex(),
            error.error
        ))),
    }
}

fn sync_existing_object(path: &Path, expected: ContentHash) -> Result<(), SchedulerError> {
    validate_file_hash(path, expected)?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| store_error(format!("flush checkpoint object: {error}")))?;
    let parent = path
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    sync_directory(parent)
}

fn artifact_manifest(
    artifact: &ProductionCheckpointArtifact,
) -> Result<ArtifactManifest, SchedulerError> {
    if !artifact.chunks.is_empty() {
        return Ok(ArtifactManifest {
            identity: artifact.identity,
            length: artifact.length,
            chunks: artifact.chunks.clone(),
        });
    }
    let ProductionCheckpointArtifactSource::File(path) = &artifact.source else {
        return Err(store_error(
            "chunk-store artifact is missing its canonical chunk sequence",
        ));
    };
    validate_file_hash(path, artifact.identity)?;
    let observed_length = fs::metadata(path)
        .map_err(|error| store_error(format!("inspect checkpoint artifact: {error}")))?
        .len();
    if observed_length != artifact.length {
        return Err(store_error(
            "checkpoint artifact length changed before persistence",
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| store_error(format!("open checkpoint artifact: {error}")))?;
    let mut buffer = vec![0_u8; ARTIFACT_CHUNK_BYTES];
    let mut chunks = Vec::new();
    loop {
        let mut filled = 0;
        while filled < buffer.len() {
            let read = file
                .read(&mut buffer[filled..])
                .map_err(|error| store_error(format!("read checkpoint artifact: {error}")))?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            break;
        }
        chunks.push(ContentHash::from_bytes(&buffer[..filled]));
        if filled < buffer.len() {
            break;
        }
    }
    Ok(ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks,
    })
}

fn persist_chunked_artifact(
    directory: &Path,
    manifest: &ArtifactManifest,
    artifact: &ProductionCheckpointArtifact,
) -> Result<(), SchedulerError> {
    match &artifact.source {
        ProductionCheckpointArtifactSource::ChunkStore(source) => {
            validate_artifact_manifest(source, manifest)
                .map_err(|error| store_error(error.to_string()))?;
            for chunk in &manifest.chunks {
                let source_path = object_path(source, *chunk);
                let destination = object_path(directory, *chunk);
                if source_path != destination && !destination.exists() {
                    persist_file_object(directory, *chunk, &source_path)?;
                }
            }
        }
        ProductionCheckpointArtifactSource::File(path) => {
            let mut file = File::open(path)
                .map_err(|error| store_error(format!("open checkpoint artifact: {error}")))?;
            let mut buffer = vec![0_u8; ARTIFACT_CHUNK_BYTES];
            for expected in &manifest.chunks {
                let mut filled = 0;
                while filled < buffer.len() {
                    let read = file.read(&mut buffer[filled..]).map_err(|error| {
                        store_error(format!("read checkpoint artifact chunk: {error}"))
                    })?;
                    if read == 0 {
                        break;
                    }
                    filled += read;
                }
                if filled == 0 || ContentHash::from_bytes(&buffer[..filled]) != *expected {
                    return Err(store_error(
                        "checkpoint artifact chunk changed before persistence",
                    ));
                }
                persist_object(directory, *expected, &buffer[..filled])?;
            }
            let mut trailing = [0_u8; 1];
            if file
                .read(&mut trailing)
                .map_err(|error| store_error(format!("finish checkpoint artifact: {error}")))?
                != 0
            {
                return Err(store_error(
                    "checkpoint artifact grew while it was being persisted",
                ));
            }
        }
    }
    validate_artifact_manifest(directory, manifest).map_err(|error| store_error(error.to_string()))
}

pub(super) fn validate_chunked_artifact(
    directory: &Path,
    artifact: &ProductionCheckpointArtifact,
) -> Result<ContentHash, LifecycleApiError> {
    let manifest = ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks: artifact.chunks.clone(),
    };
    validate_artifact_manifest(directory, &manifest)?;
    Ok(manifest.identity)
}

fn validate_artifact_manifest(
    directory: &Path,
    manifest: &ArtifactManifest,
) -> Result<(), LifecycleApiError> {
    let mut reader = ChunkSequenceReader::new(directory, &manifest.chunks)?;
    let observed = ContentHash::from_reader(&mut reader).map_err(|error| {
        loop_factory_error(format!("read chunked checkpoint artifact: {error}"))
    })?;
    if reader.bytes_read != manifest.length || observed != manifest.identity {
        return Err(loop_factory_error(
            "chunked checkpoint artifact failed length or content authentication",
        ));
    }
    Ok(())
}

pub(super) fn materialize_checkpoint_artifact(
    artifact: &ProductionCheckpointArtifact,
    destination: &Path,
    role: &str,
) -> Result<(), LifecycleApiError> {
    match &artifact.source {
        ProductionCheckpointArtifactSource::File(source) => {
            fs::copy(source, destination).map_err(|error| {
                loop_factory_error(format!(
                    "materialize exact checkpoint {role} {} as {}: {error}",
                    source.display(),
                    destination.display()
                ))
            })?;
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            let mut reader = ChunkSequenceReader::new(directory, &artifact.chunks)?;
            let mut destination_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .map_err(|error| {
                    loop_factory_error(format!(
                        "create exact checkpoint {role} {}: {error}",
                        destination.display()
                    ))
                })?;
            std::io::copy(&mut reader, &mut destination_file)
                .and_then(|_| destination_file.sync_all())
                .map_err(|error| {
                    loop_factory_error(format!(
                        "materialize exact checkpoint {role} {}: {error}",
                        destination.display()
                    ))
                })?;
        }
    }
    Ok(())
}

struct ChunkSequenceReader {
    directory: PathBuf,
    chunks: Vec<ContentHash>,
    index: usize,
    current: Option<File>,
    bytes_read: u64,
}

impl ChunkSequenceReader {
    fn new(directory: &Path, chunks: &[ContentHash]) -> Result<Self, LifecycleApiError> {
        for (index, identity) in chunks.iter().enumerate() {
            let path = object_path(directory, *identity);
            let length = fs::metadata(&path)
                .map_err(|error| {
                    loop_factory_error(format!(
                        "inspect checkpoint chunk {}: {error}",
                        path.display()
                    ))
                })?
                .len();
            let expected = if index + 1 == chunks.len() {
                1..=ARTIFACT_CHUNK_BYTES_U64
            } else {
                ARTIFACT_CHUNK_BYTES_U64..=ARTIFACT_CHUNK_BYTES_U64
            };
            if !expected.contains(&length) {
                return Err(loop_factory_error(
                    "checkpoint artifact has invalid chunk geometry",
                ));
            }
            validate_file_hash(&path, *identity)
                .map_err(|error| loop_factory_error(error.to_string()))?;
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            chunks: chunks.to_vec(),
            index: 0,
            current: None,
            bytes_read: 0,
        })
    }
}

impl std::io::Read for ChunkSequenceReader {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        loop {
            if self.current.is_none() {
                let Some(identity) = self.chunks.get(self.index).copied() else {
                    return Ok(0);
                };
                self.current = Some(File::open(object_path(&self.directory, identity))?);
            }
            let read = self
                .current
                .as_mut()
                .map_or(Ok(0), |file| file.read(buffer))?;
            if read != 0 {
                self.bytes_read = self
                    .bytes_read
                    .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                return Ok(read);
            }
            self.current = None;
            self.index = self.index.saturating_add(1);
        }
    }
}

fn persist_file_bytes(path: &Path, bytes: &[u8]) -> Result<(), SchedulerError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            store_error(format!(
                "create checkpoint object {}: {error}",
                path.display()
            ))
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            store_error(format!(
                "flush checkpoint object {}: {error}",
                path.display()
            ))
        })
}

fn read_object(
    root: &Path,
    expected: ContentHash,
    budget: &mut CheckpointReadBudget,
    role_limit: u64,
) -> Result<Vec<u8>, LifecycleApiError> {
    let path = object_path(root, expected);
    let size = fs::metadata(&path)
        .map_err(|error| {
            loop_factory_error(format!(
                "inspect checkpoint object {}: {error}",
                path.display()
            ))
        })?
        .len();
    if size > role_limit {
        return Err(loop_factory_error(format!(
            "checkpoint object {} exceeds its role-specific byte limit {}",
            expected.to_hex(),
            role_limit
        )));
    }
    if budget.identities.insert(expected) {
        budget.reserve(size)?;
    }
    let bytes = read_bounded_file(&path, size).map_err(|error| {
        loop_factory_error(format!(
            "read checkpoint object {}: {error}",
            path.display()
        ))
    })?;
    if ContentHash::from_bytes(&bytes) != expected {
        return Err(loop_factory_error(format!(
            "checkpoint object {} failed content authentication",
            expected.to_hex()
        )));
    }
    Ok(bytes)
}

struct CheckpointReadBudget {
    limit: u64,
    used: u64,
    identities: BTreeSet<ContentHash>,
}

impl CheckpointReadBudget {
    const fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            identities: BTreeSet::new(),
        }
    }

    fn reserve(&mut self, requested: u64) -> Result<(), LifecycleApiError> {
        self.used = self
            .used
            .checked_add(requested)
            .ok_or_else(|| loop_factory_error("exact checkpoint byte accounting overflow"))?;
        if self.used > self.limit {
            return Err(loop_factory_error(format!(
                "exact checkpoint closure exceeds fat_checkpoint_bytes limit {}",
                self.limit
            )));
        }
        Ok(())
    }

    fn reserve_identity_once(
        &mut self,
        identity: ContentHash,
        size: u64,
    ) -> Result<(), LifecycleApiError> {
        if !self.identities.insert(identity) {
            return Ok(());
        }
        self.reserve(size)
    }
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let capacity = usize::try_from(fs::metadata(path)?.len().min(limit)).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds its checkpoint read limit",
        ));
    }
    Ok(bytes)
}

fn validate_file_hash(path: &Path, expected: ContentHash) -> Result<(), SchedulerError> {
    let actual = hash_file(path).map_err(|error| {
        store_error(format!(
            "hash checkpoint object {}: {error}",
            path.display()
        ))
    })?;
    if actual != expected {
        return Err(store_error(format!(
            "checkpoint object {} changed before persistence",
            path.display()
        )));
    }
    Ok(())
}

fn decode_generations(
    values: &[(String, u64)],
) -> Result<BTreeMap<NodeId, u64>, LifecycleApiError> {
    let mut decoded = BTreeMap::new();
    for (node, generation) in values {
        if decoded
            .insert(NodeId { name: node.clone() }, *generation)
            .is_some()
        {
            return Err(loop_factory_error("duplicate checkpoint node generation"));
        }
    }
    Ok(decoded)
}

fn decode_service_states(
    values: &[(String, u8)],
) -> Result<BTreeMap<NodeId, ProductionNodeServiceState>, LifecycleApiError> {
    let mut decoded = BTreeMap::new();
    for (node, state) in values {
        let state = match state {
            1 => ProductionNodeServiceState::Running,
            2 => ProductionNodeServiceState::PoweredOff,
            3 => ProductionNodeServiceState::PermanentlyFailed,
            _ => return Err(loop_factory_error("invalid checkpoint node service state")),
        };
        if decoded
            .insert(NodeId { name: node.clone() }, state)
            .is_some()
        {
            return Err(loop_factory_error(
                "duplicate checkpoint node service state",
            ));
        }
    }
    Ok(decoded)
}

const fn service_state_tag(state: ProductionNodeServiceState) -> u8 {
    match state {
        ProductionNodeServiceState::Running => 1,
        ProductionNodeServiceState::PoweredOff => 2,
        ProductionNodeServiceState::PermanentlyFailed => 3,
    }
}

fn closure_parent(run_state_root: &Path, scenario: ContentHash) -> PathBuf {
    run_state_root
        .join(scenario.to_hex())
        .join("checkpoint-closures")
}

fn object_parent(run_state_root: &Path, scenario: ContentHash) -> PathBuf {
    run_state_root
        .join(scenario.to_hex())
        .join("checkpoint-objects")
}

pub(super) fn checkpoint_dag_store(
    run_state_root: &Path,
    scenario: ContentHash,
) -> Arc<dyn DagStore> {
    Arc::new(LocalDagStore::new(object_parent(run_state_root, scenario)))
}

fn object_path(root: &Path, identity: ContentHash) -> PathBuf {
    LocalDagStore::new(root).object_path(&identity)
}

fn sync_directory(path: &Path) -> Result<(), SchedulerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            store_error(format!(
                "flush checkpoint directory {}: {error}",
                path.display()
            ))
        })
}

fn store_error(message: impl Into<String>) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.into(),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn manifest() -> ClosureManifest {
        ClosureManifest {
            scenario: ContentHash::default(),
            configuration: ContentHash::default(),
            schedule: ContentHash::default(),
            frontier: 0,
            scheduler: ContentHash::default(),
            event_log_segments: Vec::new(),
            signal_artifacts: Vec::new(),
            trigger_state: ContentHash::default(),
            assertion_state: ContentHash::default(),
            lifecycle_state: ContentHash::default(),
            fault_checkpoint: ContentHash::default(),
            targets: Vec::new(),
            node_generations: Vec::new(),
            node_service_states: Vec::new(),
            identity: ContentHash::default(),
        }
    }

    fn target(node: &str) -> TargetManifest {
        let artifact = ArtifactManifest {
            identity: ContentHash::from_bytes(b"artifact"),
            length: 8,
            chunks: vec![ContentHash::from_bytes(b"artifact")],
        };
        TargetManifest {
            node: String::from(node),
            counter: 0,
            scheduler_time: 0,
            snapshot: ContentHash::from_bytes(node.as_bytes()),
            overlay: artifact.clone(),
            vmstate: artifact,
            manifest_identity: ContentHash::default(),
        }
    }

    #[test]
    fn closure_manifest_round_trip_is_canonical() {
        let mut original = manifest();
        original.targets = vec![target("a"), target("b")];
        original.node_generations = vec![(String::from("a"), 1), (String::from("b"), 2)];
        original.node_service_states = vec![(String::from("a"), 1), (String::from("b"), 2)];

        let bytes = encode_manifest(&original).expect("encode canonical closure manifest");
        let decoded = decode_manifest(&bytes).expect("decode canonical closure manifest");

        assert_eq!(
            encode_manifest(&decoded).expect("re-encode canonical closure manifest"),
            bytes
        );
    }

    #[test]
    fn closure_manifest_rejects_unsorted_or_trailing_records() {
        let mut unsorted = manifest();
        unsorted.targets = vec![target("b"), target("a")];
        let bytes = encode_manifest(&unsorted).expect("encode fixture");
        assert!(decode_manifest(&bytes).is_err());

        let mut trailing = encode_manifest(&manifest()).expect("encode fixture");
        trailing.push(0);
        assert!(decode_manifest(&trailing).is_err());
    }

    #[test]
    fn closure_identity_excludes_only_its_identity_field() {
        let mut original = manifest();
        let identity = closure_identity(&original).expect("derive closure identity");
        original.identity = ContentHash::from_bytes(b"ignored identity field");
        assert_eq!(
            closure_identity(&original).expect("derive closure identity again"),
            identity
        );
        original.frontier = 1;
        assert_ne!(
            closure_identity(&original).expect("derive changed closure identity"),
            identity
        );
    }

    #[test]
    fn content_store_deduplicates_equal_objects() {
        let directory = tempfile::tempdir().expect("create object directory");
        let bytes = b"same object";
        let identity = ContentHash::from_bytes(bytes);

        persist_object(directory.path(), identity, bytes).expect("persist first object");
        persist_object(directory.path(), identity, bytes).expect("reuse equal object");
        let dag_store = LocalDagStore::new(directory.path());
        assert_eq!(
            dag_store
                .get(&identity)
                .expect("read exact object as DAG object"),
            bytes
        );
        assert!(!directory.path().join(identity.to_hex()).exists());
    }

    #[test]
    fn concurrent_equal_object_publishers_converge_atomically() {
        let directory = std::sync::Arc::new(tempfile::tempdir().expect("create object directory"));
        let bytes = b"concurrent object".to_vec();
        let identity = ContentHash::from_bytes(&bytes);
        let publishers = (0..8)
            .map(|_| {
                let directory = std::sync::Arc::clone(&directory);
                let bytes = bytes.clone();
                std::thread::spawn(move || persist_object(directory.path(), identity, &bytes))
            })
            .collect::<Vec<_>>();

        for publisher in publishers {
            publisher
                .join()
                .expect("publisher thread should not panic")
                .expect("equal publisher should converge");
        }
        validate_file_hash(&object_path(directory.path(), identity), identity)
            .expect("published object should authenticate");
    }

    #[test]
    fn chunk_store_deduplicates_and_materializes_complete_artifacts() {
        let root = tempfile::tempdir().expect("create chunk-store fixture");
        let source = root.path().join("source");
        let restored = root.path().join("restored");
        let object_directory = root.path().join("objects");
        fs::create_dir(&object_directory).expect("create object directory");
        let mut bytes = vec![0x5a; ARTIFACT_CHUNK_BYTES];
        bytes.extend_from_slice(b"tail");
        fs::write(&source, &bytes).expect("write source artifact");
        let artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::File(source),
            identity: ContentHash::from_bytes(&bytes),
            length: u64::try_from(bytes.len()).expect("fixture length fits"),
            chunks: Vec::new(),
        };
        let manifest = artifact_manifest(&artifact).expect("derive chunk manifest");

        persist_chunked_artifact(&object_directory, &manifest, &artifact)
            .expect("persist first artifact");
        persist_chunked_artifact(&object_directory, &manifest, &artifact)
            .expect("deduplicate second artifact");
        let stored_count = fs::read_dir(&object_directory)
            .expect("read object directory")
            .map(|entry| {
                fs::read_dir(entry.expect("read object prefix entry").path())
                    .expect("read object prefix directory")
                    .count()
            })
            .sum::<usize>();
        assert_eq!(stored_count, 2);

        let chunked = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.clone()),
            identity: manifest.identity,
            length: manifest.length,
            chunks: manifest.chunks.clone(),
        };
        materialize_checkpoint_artifact(&chunked, &restored, "test")
            .expect("materialize chunked artifact");
        assert_eq!(fs::read(&restored).expect("read restored artifact"), bytes);

        let first_chunk = object_path(&object_directory, manifest.chunks[0]);
        fs::write(&first_chunk, vec![0; ARTIFACT_CHUNK_BYTES])
            .expect("corrupt first checkpoint chunk");
        fs::remove_file(&restored).expect("remove prior materialization");
        assert!(materialize_checkpoint_artifact(&chunked, &restored, "test").is_err());
        fs::write(&first_chunk, &bytes[..ARTIFACT_CHUNK_BYTES])
            .expect("restore first checkpoint chunk");

        let last_chunk = object_path(
            &object_directory,
            *manifest.chunks.last().expect("fixture has a tail chunk"),
        );
        fs::remove_file(last_chunk).expect("remove tail checkpoint chunk");
        assert!(!restored.exists());
        assert!(materialize_checkpoint_artifact(&chunked, &restored, "test").is_err());
    }

    #[test]
    fn lifecycle_wire_restores_terminal_branch_and_controls() {
        let scenario = crucible::happy_path_scenario()
            .expect("build lifecycle wire scenario")
            .scenario
            .scenario_def();
        let schedule = Schedule::empty().to_compact_binary();
        let wire = LifecycleWire {
            terminal: Some(TerminalWire::Failed(vec![String::from("failed")])),
            terminal_cause: Some(TerminalCauseWire::Failed(vec![String::from("failed")])),
            initial_lifecycle_observations_pending: false,
            branch: Some(BranchWire {
                base_schedule: schedule.clone(),
                frontier: 7,
                decisions: Vec::new(),
                seed: Some(Seed::from_u64(9).bytes()),
            }),
            recorded_controls: vec![RecordedControlWire {
                configuration_schedule: schedule,
                node_times: Vec::new(),
                control: vec![ControlOperation {
                    sequence: 1,
                    kind: crucible::ControlOperationKind::Snapshot,
                }],
            }],
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&wire, &mut bytes).expect("encode lifecycle fixture");

        let decoded = decode_lifecycle(&bytes, &scenario).expect("decode lifecycle fixture");

        assert_eq!(
            decoded.terminal,
            Some(QuantumTerminalVerdict::Failed(vec![String::from("failed")]))
        );
        assert!(!decoded.initial_lifecycle_observations_pending);
        assert_eq!(
            decoded.terminal_cause,
            Some(CheckpointTerminalCause::Failed(vec![String::from(
                "failed"
            )]))
        );
        let branch = decoded.branch.expect("branch should restore");
        assert_eq!(branch.frontier, VirtualTime { ticks: 7 });
        assert_eq!(branch.seed, Some(Seed::from_u64(9)));
        assert_eq!(decoded.recorded_controls.len(), 1);
        assert_eq!(decoded.recorded_controls[0].control[0].sequence, 1);
    }

    #[test]
    fn published_checkpoint_count_ignores_transaction_staging_directories() {
        let root = tempfile::tempdir().expect("create checkpoint count fixture");
        fs::create_dir(root.path().join(".closure-incomplete"))
            .expect("create transaction staging directory");
        fs::create_dir(root.path().join("not-a-checkpoint")).expect("create unrelated directory");
        fs::create_dir(root.path().join("0".repeat(64)))
            .expect("create one published checkpoint directory");
        let limits = FaultResourceLimits {
            checkpoint_count: 1,
            ..FaultResourceLimits::default()
        };

        enforce_published_checkpoint_count(root.path(), limits)
            .expect("only the published identity counts against the limit");

        fs::create_dir(root.path().join("1".repeat(64)))
            .expect("create a second published checkpoint directory");
        assert!(enforce_published_checkpoint_count(root.path(), limits).is_err());
    }
}
