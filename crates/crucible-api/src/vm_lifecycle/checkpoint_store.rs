//! Durable content-addressed closure store for exact production checkpoints.

use super::*;
use crucible::model::FaultResourceLimits;
use std::collections::BTreeSet;
use std::io::Read as _;

const MANIFEST_MAGIC: &[u8] = b"crucible.production-exact-closure.v1\0";
const MANIFEST_FILE: &str = "manifest.cbor";
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureManifest {
    scenario: ContentHash,
    configuration: ContentHash,
    schedule: ContentHash,
    frontier: u64,
    scheduler: ContentHash,
    trigger_state: ContentHash,
    assertion_state: ContentHash,
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
    overlay: ContentHash,
    vmstate: ContentHash,
    manifest_identity: ContentHash,
}

struct ClosureObjects {
    schedule: Vec<u8>,
    scheduler: Vec<u8>,
    trigger_state: Vec<u8>,
    assertion_state: Vec<u8>,
    fault_checkpoint: Vec<u8>,
    snapshots: BTreeMap<NodeId, Vec<u8>>,
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
    fs::create_dir_all(&closure_parent).map_err(|error| {
        store_error(format!(
            "create exact checkpoint closure directory {}: {error}",
            closure_parent.display()
        ))
    })?;
    let destination = closure_parent.join(manifest.identity.to_hex());
    if destination.exists() {
        authenticate_existing_publication(&destination, &manifest, &objects, checkpoint)?;
        install_published_artifact_paths(&destination, &manifest, checkpoint)?;
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
    let object_directory = staging.path().join("objects");
    fs::create_dir(&object_directory).map_err(|error| {
        store_error(format!(
            "create closure object directory {}: {error}",
            object_directory.display()
        ))
    })?;

    persist_object(&object_directory, manifest.schedule, &objects.schedule)?;
    persist_object(&object_directory, manifest.scheduler, &objects.scheduler)?;
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
        persist_file_object(&object_directory, target.overlay, &source.overlay_artifact)?;
        persist_file_object(&object_directory, target.vmstate, &source.vmstate_artifact)?;
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
    sync_directory(&closure_parent)?;

    install_published_artifact_paths(&destination, &manifest, checkpoint)?;
    Ok(())
}

pub(super) fn load_exact_checkpoint_set(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    identity: ContentHash,
) -> Result<ProductionVmExactCheckpointSet, LifecycleApiError> {
    let root = closure_parent(run_state_root, scenario.id()).join(identity.to_hex());
    let limits = source.plan().fault_signals().resource_limits();
    let mut budget = CheckpointReadBudget::new(limits.fat_checkpoint_bytes);
    let manifest_bytes = read_bounded_file(&root.join(MANIFEST_FILE), MAX_MANIFEST_BYTES as u64)
        .map_err(|error| {
            loop_factory_error(format!(
                "read exact checkpoint closure {}: {error}",
                identity.to_hex()
            ))
        })?;
    budget.reserve(manifest_bytes.len() as u64)?;
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

    let schedule =
        Schedule::from_compact_binary(&read_object(&root, manifest.schedule, &mut budget)?)
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
        &root,
        manifest.scheduler,
        &mut budget,
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
    let trigger_state = EventGraphState::from_compact_binary(&read_object(
        &root,
        manifest.trigger_state,
        &mut budget,
    )?)
    .map_err(|error| loop_factory_error(format!("decode trigger continuation: {error}")))?;
    let assertion_state = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&read_object(
        &root,
        manifest.assertion_state,
        &mut budget,
    )?)
    .map_err(|error| loop_factory_error(format!("decode assertion continuation: {error}")))?;
    let signal_plan = source.plan().fault_signals();
    let fault_checkpoint = ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
        &read_object(&root, manifest.fault_checkpoint, &mut budget)?,
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
            &root,
            target.snapshot,
            &mut budget,
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
            overlay_artifact: object_path(&root, target.overlay),
            overlay_hash: target.overlay,
            vmstate_artifact: object_path(&root, target.vmstate),
            vmstate_hash: target.vmstate,
            fault_checkpoint: fault_checkpoint.clone(),
            manifest_identity: target.manifest_identity,
        };
        budget.reserve_file_once(&restored.overlay_artifact, restored.overlay_hash)?;
        budget.reserve_file_once(&restored.vmstate_artifact, restored.vmstate_hash)?;
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
    Ok(ProductionVmExactCheckpointSet {
        identity,
        configuration,
        scheduler,
        trigger_state,
        assertion_state,
        fault_checkpoint,
        targets,
        node_generations,
        node_service_states,
    })
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
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
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
        (manifest.fault_checkpoint, objects.fault_checkpoint.len()),
    ] {
        if identities.insert(identity) {
            bytes = add_checkpoint_bytes(bytes, size as u64)?;
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
            bytes = add_checkpoint_bytes(bytes, snapshot.len() as u64)?;
        }
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        for (identity, path) in [
            (target.overlay, source.overlay_artifact.as_path()),
            (target.vmstate, source.vmstate_artifact.as_path()),
        ] {
            if identities.insert(identity) {
                let size = fs::metadata(path)
                    .map_err(|error| {
                        store_error(format!(
                            "inspect checkpoint artifact {}: {error}",
                            path.display()
                        ))
                    })?
                    .len();
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
    expected: &ClosureManifest,
    objects: &ClosureObjects,
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    let bytes = read_bounded_file(&destination.join(MANIFEST_FILE), MAX_MANIFEST_BYTES as u64)
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
        (
            expected.fault_checkpoint,
            objects.fault_checkpoint.as_slice(),
        ),
    ] {
        if ContentHash::from_bytes(bytes) != identity {
            return Err(store_error("checkpoint object changed before retry"));
        }
        validate_file_hash(&object_path(destination, identity), identity)?;
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
        for identity in [target.snapshot, target.overlay, target.vmstate] {
            validate_file_hash(&object_path(destination, identity), identity)?;
        }
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        validate_file_hash(&source.overlay_artifact, target.overlay)?;
        validate_file_hash(&source.vmstate_artifact, target.vmstate)?;
    }
    Ok(())
}

fn install_published_artifact_paths(
    destination: &Path,
    manifest: &ClosureManifest,
    checkpoint: &mut ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    for (node, target) in &mut checkpoint.targets {
        let manifest_target = manifest
            .targets
            .iter()
            .find(|candidate| candidate.node == node.name)
            .ok_or_else(|| store_error("published closure target disappeared"))?;
        target.overlay_artifact = object_path(destination, manifest_target.overlay);
        target.vmstate_artifact = object_path(destination, manifest_target.vmstate);
    }
    Ok(())
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
                overlay: target.overlay_hash,
                vmstate: target.vmstate_hash,
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
        trigger_state: ContentHash::from_bytes(&trigger_state),
        assertion_state: ContentHash::from_bytes(&assertion_state),
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
            trigger_state,
            assertion_state,
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
        trigger_state: manifest.trigger_state,
        assertion_state: manifest.assertion_state,
        fault_checkpoint: manifest.fault_checkpoint,
        targets: manifest
            .targets
            .iter()
            .map(|target| TargetManifest {
                node: target.node.clone(),
                counter: target.counter,
                scheduler_time: target.scheduler_time,
                snapshot: target.snapshot,
                overlay: target.overlay,
                vmstate: target.vmstate,
                manifest_identity: target.manifest_identity,
            })
            .collect(),
        node_generations: manifest.node_generations.clone(),
        node_service_states: manifest.node_service_states.clone(),
        identity: ContentHash::default(),
    };
    let bytes = encode_manifest(&material)?;
    Ok(ContentHash::from_canonical_material(
        "crucible.production-exact-closure.v1",
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
    let destination = directory.join(expected.to_hex());
    if destination.exists() {
        return validate_file_hash(&destination, expected);
    }
    persist_file_bytes(&destination, bytes)
}

fn persist_file_object(
    directory: &Path,
    expected: ContentHash,
    source: &Path,
) -> Result<(), SchedulerError> {
    validate_file_hash(source, expected)?;
    let destination = directory.join(expected.to_hex());
    if destination.exists() {
        return validate_file_hash(&destination, expected);
    }
    if fs::hard_link(source, &destination).is_err() {
        fs::copy(source, &destination).map_err(|error| {
            store_error(format!(
                "persist checkpoint object {}: {error}",
                expected.to_hex()
            ))
        })?;
    }
    File::open(&destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| store_error(format!("flush checkpoint object: {error}")))
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

    fn reserve_file_once(
        &mut self,
        path: &Path,
        identity: ContentHash,
    ) -> Result<(), LifecycleApiError> {
        if !self.identities.insert(identity) {
            return Ok(());
        }
        let size = fs::metadata(path)
            .map_err(|error| {
                loop_factory_error(format!(
                    "inspect checkpoint artifact {}: {error}",
                    path.display()
                ))
            })?
            .len();
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

fn object_path(root: &Path, identity: ContentHash) -> PathBuf {
    root.join("objects").join(identity.to_hex())
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
    use super::*;

    fn manifest() -> ClosureManifest {
        ClosureManifest {
            scenario: ContentHash::default(),
            configuration: ContentHash::default(),
            schedule: ContentHash::default(),
            frontier: 0,
            scheduler: ContentHash::default(),
            trigger_state: ContentHash::default(),
            assertion_state: ContentHash::default(),
            fault_checkpoint: ContentHash::default(),
            targets: Vec::new(),
            node_generations: Vec::new(),
            node_service_states: Vec::new(),
            identity: ContentHash::default(),
        }
    }

    fn target(node: &str) -> TargetManifest {
        TargetManifest {
            node: String::from(node),
            counter: 0,
            scheduler_time: 0,
            snapshot: ContentHash::default(),
            overlay: ContentHash::default(),
            vmstate: ContentHash::default(),
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
    }
}
