//! Durable content-addressed closure store for exact production checkpoints.

use super::*;
use crucible::LocalDagStore;
use crucible::model::FaultResourceLimits;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

mod decode;
mod io;
use io::{BoundedReadError, read_bounded_file_with_boundary};
mod paths;
use paths::{closure_parent, object_parent};
mod portable;
pub use portable::{
    ProductionExactCheckpointSource,
    authenticate_portable_exact_checkpoint_replay_oracle_promotion,
    authenticate_portable_exact_checkpoint_replay_oracle_promotion_with_boundary,
    install_exact_checkpoint_closure, install_exact_checkpoint_closure_with_boundary,
    install_exact_checkpoint_closure_with_boundary_and_admission,
};
mod publication;
pub(super) use publication::{PersistExactCheckpointError, PreparedExactCheckpointPublication};
use publication::{enforce_published_checkpoint_count, scheduler_resource_limit};
mod read_budget;
use read_budget::CheckpointReadBudget;
mod recovery;
pub(super) use recovery::{
    reconcile_indeterminate_publication, recover_published_checkpoint_catalog,
};

const MANIFEST_MAGIC: &[u8] = b"crucible.production-exact-closure.v5\0";
const LEGACY_MANIFEST_MAGIC: &[u8] = b"crucible.production-exact-closure.v4\0";
const MANIFEST_VERSION: u8 = 5;
const LEGACY_MANIFEST_VERSION: u8 = 4;
const MANIFEST_FILE: &str = "manifest.cbor";
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES_U64: u64 = 64 * 1024 * 1024;
const ARTIFACT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const ARTIFACT_CHUNK_BYTES_U64: u64 = 4 * 1024 * 1024;
const SPARSE_COPY_BUFFER_BYTES: usize = 1024 * 1024;
const CLOSURE_EXPORT_COPY_BUFFER_BYTES: usize = 1024 * 1024;
const SMALL_CONTINUATION_MAX_BYTES: u64 = 268_435_456;
const LARGE_CONTINUATION_MAX_BYTES: u64 = 1_610_612_800;

mod replay;
#[cfg(test)]
use replay::validate_replay_oracle_manifest_basis;
pub use replay::{
    PreparedProductionReplayOraclePromotion, ProductionExactCheckpointClosure,
    ProductionExactCheckpointObject, ProductionExactCheckpointReplayArtifact,
    ProductionExactCheckpointReplayCatalog, ProductionExactCheckpointReplayTarget,
    ProductionExactCheckpointReplayTargets, ProductionExactCheckpointResumeBasis,
};
use replay::{
    authenticate_replay_oracle_source_pair, read_portable_fault_checkpoint_identity,
    read_portable_snapshot,
};

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureManifest {
    #[serde(skip)]
    format_version: u8,
    scenario: ContentHash,
    configuration: ContentHash,
    schedule: ContentHash,
    frontier: u64,
    scheduler: ContentHash,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    event_log_segments: Vec<ContentHash>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    signal_artifacts: Vec<ContentHash>,
    trigger_state: ContentHash,
    assertion_state: ContentHash,
    lifecycle_state: ContentHash,
    fault_checkpoint: ContentHash,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    targets: Vec<TargetManifest>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    node_generations: Vec<(String, u64)>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    node_service_states: Vec<(String, u8)>,
    identity: ContentHash,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    #[serde(deserialize_with = "decode::deserialize_vec")]
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
    #[serde(deserialize_with = "decode::deserialize_vec")]
    recorded_controls: Vec<RecordedControlWire>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "decode::deserialize_vec"
    )]
    selectable_catalog_plans: Vec<SelectableCatalogWire>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalWire {
    Passed,
    Failed(#[serde(deserialize_with = "decode::deserialize_vec")] Vec<String>),
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalCauseWire {
    Passed,
    Failed(#[serde(deserialize_with = "decode::deserialize_vec")] Vec<String>),
    BudgetExhausted,
    BackendCrash(String),
    OperatorStop,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchWire {
    #[serde(deserialize_with = "decode::deserialize_vec")]
    base_schedule: Vec<u8>,
    frontier: u64,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    decisions: Vec<Decision>,
    seed: Option<[u8; 32]>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedControlWire {
    #[serde(deserialize_with = "decode::deserialize_vec")]
    configuration_schedule: Vec<u8>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    node_times: Vec<(String, u64)>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    control: Vec<ControlOperation>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectableCatalogWire {
    node: String,
    #[serde(deserialize_with = "decode::deserialize_selectable_catalog_plan")]
    plan: Vec<u8>,
}

#[cfg(test)]
pub(super) fn prepare_exact_checkpoint_set(
    run_state_root: &Path,
    scenario: ContentHash,
    resource_limits: FaultResourceLimits,
    checkpoint: &mut ProductionVmExactCheckpointSet,
) -> Result<PreparedExactCheckpointPublication, PersistExactCheckpointError> {
    prepare_exact_checkpoint_set_with_boundary(
        run_state_root,
        scenario,
        resource_limits,
        checkpoint,
        &mut || Ok(()),
    )
}

pub(super) fn prepare_exact_checkpoint_set_with_boundary(
    run_state_root: &Path,
    scenario: ContentHash,
    resource_limits: FaultResourceLimits,
    checkpoint: &mut ProductionVmExactCheckpointSet,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<PreparedExactCheckpointPublication, PersistExactCheckpointError> {
    boundary()?;
    validate_checkpoint_set(scenario, checkpoint)?;
    boundary()?;
    let (mut manifest, objects) =
        manifest_and_objects_with_boundary(scenario, resource_limits, checkpoint, boundary)?;
    boundary()?;
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
    boundary()?;

    let scenario_directory = run_state_root.join(scenario.to_hex());
    fs::create_dir_all(&scenario_directory).map_err(|error| {
        store_error(format!(
            "create exact checkpoint scenario directory {}: {error}",
            scenario_directory.display()
        ))
    })?;
    sync_directory(run_state_root)?;
    let closure_parent = scenario_directory.join("checkpoint-closures");
    let object_directory = scenario_directory.join("checkpoint-objects");
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
    sync_directory(&scenario_directory)?;
    let destination = closure_parent.join(manifest.identity.to_hex());
    if destination.exists() {
        boundary()?;
        authenticate_existing_publication_with_boundary(
            &destination,
            &object_directory,
            &manifest,
            &objects,
            checkpoint,
            boundary,
        )
        .map_err(|source| PersistExactCheckpointError::Indeterminate {
            identity: manifest.identity,
            source,
        })?;
        enforce_published_checkpoint_count(&closure_parent, resource_limits).map_err(|source| {
            PersistExactCheckpointError::Indeterminate {
                identity: manifest.identity,
                source,
            }
        })?;
        install_persisted_artifact_paths(&object_directory, &manifest, checkpoint).map_err(
            |source| PersistExactCheckpointError::Indeterminate {
                identity: manifest.identity,
                source,
            },
        )?;
        boundary()?;
        return Ok(PreparedExactCheckpointPublication::Existing {
            identity: manifest.identity,
            closure_parent,
        });
    }
    let staging = tempfile::Builder::new()
        .prefix(".closure-")
        .tempdir_in(&closure_parent)
        .map_err(|error| {
            store_error(format!(
                "create exact checkpoint closure staging directory: {error}"
            ))
        })?;
    persist_object_with_boundary(
        &object_directory,
        manifest.schedule,
        &objects.schedule,
        boundary,
    )?;
    persist_object_with_boundary(
        &object_directory,
        manifest.scheduler,
        &objects.scheduler,
        boundary,
    )?;
    let checkpoint_dag = checkpoint_dag_store(run_state_root, scenario);
    for (identity, bytes) in objects
        .event_log_segments
        .iter()
        .chain(objects.signal_artifacts.iter())
    {
        boundary()?;
        persist_object_with_boundary(&object_directory, *identity, bytes, boundary)?;
        let stored = checkpoint_dag
            .put(bytes)
            .map_err(|error| store_error(format!("persist checkpoint DAG object: {error}")))?;
        if stored != *identity {
            return Err(PersistExactCheckpointError::Unpublished(store_error(
                "checkpoint DAG returned a different content identity",
            )));
        }
    }
    persist_object_with_boundary(
        &object_directory,
        manifest.trigger_state,
        &objects.trigger_state,
        boundary,
    )?;
    persist_object_with_boundary(
        &object_directory,
        manifest.assertion_state,
        &objects.assertion_state,
        boundary,
    )?;
    persist_object_with_boundary(
        &object_directory,
        manifest.lifecycle_state,
        &objects.lifecycle_state,
        boundary,
    )?;
    persist_object_with_boundary(
        &object_directory,
        manifest.fault_checkpoint,
        &objects.fault_checkpoint,
        boundary,
    )?;
    for target in &manifest.targets {
        boundary()?;
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = objects
            .snapshots
            .get(&node)
            .ok_or_else(|| store_error("closure snapshot object disappeared"))?;
        persist_object_with_boundary(&object_directory, target.snapshot, snapshot, boundary)?;
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        persist_chunked_artifact_with_boundary(
            &object_directory,
            &target.overlay,
            &source.overlay_artifact,
            boundary,
        )?;
        persist_chunked_artifact_with_boundary(
            &object_directory,
            &target.vmstate,
            &source.vmstate_artifact,
            boundary,
        )?;
    }
    boundary()?;
    sync_directory(&object_directory)?;

    persist_file_bytes_with_boundary(
        &staging.path().join(MANIFEST_FILE),
        &manifest_bytes,
        boundary,
    )?;
    sync_directory(staging.path())?;
    install_persisted_artifact_paths(&object_directory, &manifest, checkpoint)?;
    Ok(PreparedExactCheckpointPublication::Staged {
        identity: manifest.identity,
        staging,
        destination,
        closure_parent,
        resource_limits: Box::new(resource_limits),
    })
}

pub(super) fn load_exact_checkpoint_set(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    identity: ContentHash,
) -> Result<ProductionVmExactCheckpointSet, LifecycleApiError> {
    load_exact_checkpoint_set_with_boundary(run_state_root, scenario, source, identity, &mut || {
        Ok(())
    })
}

fn load_exact_checkpoint_set_with_boundary(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    identity: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ProductionVmExactCheckpointSet, LifecycleApiError> {
    boundary()?;
    let root = closure_parent(run_state_root, scenario.id()).join(identity.to_hex());
    let object_directory = object_parent(run_state_root, scenario.id());
    let limits = source.plan().fault_signals().resource_limits();
    let mut budget = CheckpointReadBudget::new(limits.fat_checkpoint_bytes);
    let manifest_path = root.join(MANIFEST_FILE);
    let manifest_length = fs::metadata(&manifest_path)
        .map_err(|error| {
            loop_factory_error(format!(
                "inspect exact checkpoint closure {}: {error}",
                identity.to_hex()
            ))
        })?
        .len();
    if manifest_length > MAX_MANIFEST_BYTES_U64 {
        return Err(loop_factory_error(format!(
            "exact checkpoint manifest exceeds its role-specific byte limit {MAX_MANIFEST_BYTES_U64}"
        )));
    }
    let manifest_bytes = budget.read_admitted(manifest_length, || {
        read_bounded_file_with_boundary(&manifest_path, manifest_length, boundary)
    })?;
    boundary()?;
    let manifest = decode::decode_manifest_with_limits(&manifest_bytes, limits)?;
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
        boundary,
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
    boundary()?;
    let scheduler = SingleSchedulerCheckpoint::from_canonical_bytes(&read_object(
        &object_directory,
        manifest.scheduler,
        &mut budget,
        LARGE_CONTINUATION_MAX_BYTES,
        boundary,
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
        boundary()?;
        let bytes = read_object(
            &object_directory,
            *identity,
            &mut budget,
            LARGE_CONTINUATION_MAX_BYTES,
            boundary,
        )?;
        if event_log_objects.insert(*identity, bytes).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint contains duplicate event-log segment identities",
            ));
        }
    }
    let mut signal_artifact_objects = BTreeMap::new();
    for identity in &manifest.signal_artifacts {
        boundary()?;
        let bytes = read_object(
            &object_directory,
            *identity,
            &mut budget,
            LARGE_CONTINUATION_MAX_BYTES,
            boundary,
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
        boundary()?;
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
        boundary,
    )?)
    .map_err(|error| loop_factory_error(format!("decode trigger continuation: {error}")))?;
    let assertion_state = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&read_object(
        &object_directory,
        manifest.assertion_state,
        &mut budget,
        SMALL_CONTINUATION_MAX_BYTES,
        boundary,
    )?)
    .map_err(|error| loop_factory_error(format!("decode assertion continuation: {error}")))?;
    let lifecycle = decode_lifecycle(
        &read_object(
            &object_directory,
            manifest.lifecycle_state,
            &mut budget,
            SMALL_CONTINUATION_MAX_BYTES,
            boundary,
        )?,
        scenario,
        limits,
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
            limits.fat_checkpoint_bytes,
            boundary,
        )?,
        signal_plan,
        scenario.id(),
    )
    .map_err(|error| loop_factory_error(format!("decode fault continuation: {error}")))?;

    let mut targets = BTreeMap::new();
    for target in &manifest.targets {
        boundary()?;
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = ExactSnapshotHandle::from_canonical_bytes_with_limit(
            &read_object(
                &object_directory,
                target.snapshot,
                &mut budget,
                limits.fat_checkpoint_bytes,
                boundary,
            )?,
            limits.fat_checkpoint_bytes,
        )
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
        validate_exact_checkpoint_target(&node, &restored, fault_checkpoint.id())?;
        if targets.insert(node, restored).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint closure contains duplicate node targets",
            ));
        }
    }
    let node_generations = decode_generations(&manifest.node_generations)?;
    boundary()?;
    let node_service_states = decode_service_states(&manifest.node_service_states)?;
    validate_restored_node_sets(source, &targets, &node_generations, &node_service_states)?;
    let expected_selectable_nodes = source
        .world()
        .vm_nodes()
        .iter()
        .filter(|node| {
            node_service_states.get(&node.id)
                != Some(&ProductionNodeServiceState::PermanentlyFailed)
                && source
                    .selectables()
                    .guest_declarations(&node.id)
                    .next()
                    .is_some()
        })
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    if lifecycle
        .selectable_catalog_plans
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_selectable_nodes
    {
        return Err(loop_factory_error(
            "exact checkpoint selectable catalog node set differs from the live scenario",
        ));
    }
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
        selectable_catalog_plans: lifecycle.selectable_catalog_plans,
        fault_checkpoint: Some(fault_checkpoint),
        targets,
        node_generations,
        node_service_states,
    };
    validate_checkpoint_set(scenario.id(), &restored)
        .map_err(|error| loop_factory_error(error.to_string()))?;
    boundary()?;
    Ok(restored)
}

/// Opens one published production checkpoint as a portable read-only closure.
///
/// This operation authenticates the canonical manifest, its closure identity,
/// scenario binding, exact object names, object types, and aggregate retained
/// bytes without loading large objects into memory. Each object is
/// independently reauthenticated when streamed through
/// [`ProductionExactCheckpointClosure::copy_object_to`].
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when the closure manifest is unavailable,
/// malformed, noncanonical, over its scenario-authored bounds, names another
/// scenario or identity, or any required object is absent or not a regular
/// file.
pub fn open_exact_checkpoint_closure(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    identity: ContentHash,
) -> Result<ProductionExactCheckpointClosure, LifecycleApiError> {
    open_exact_checkpoint_closure_with_boundary(run_state_root, source, identity, &mut || Ok(()))
}

/// Opens one portable closure while observing an operational boundary.
///
/// # Errors
///
/// Returns the same errors as [`open_exact_checkpoint_closure`], including the
/// exact [`LifecycleApiError`] returned by `boundary`.
pub(super) fn open_exact_checkpoint_closure_with_boundary(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    identity: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ProductionExactCheckpointClosure, LifecycleApiError> {
    boundary()?;
    let scenario = source.scenario_def().id();
    let limits = source.plan().fault_signals().resource_limits();
    let root = closure_parent(run_state_root, scenario).join(identity.to_hex());
    let manifest_path = root.join(MANIFEST_FILE);
    let manifest =
        read_bounded_file_with_boundary(&manifest_path, MAX_MANIFEST_BYTES_U64, boundary).map_err(
            |error| match error {
                BoundedReadError::Boundary(error) => *error,
                error => loop_factory_error(format!(
                    "read portable exact checkpoint manifest {}: {error}",
                    identity.to_hex()
                )),
            },
        )?;
    boundary()?;
    let decoded = decode::decode_manifest_with_limits(&manifest, limits)?;
    if decoded.identity != identity
        || closure_identity(&decoded).map_err(|error| loop_factory_error(error.to_string()))?
            != identity
        || decoded.scenario != scenario
    {
        return Err(loop_factory_error(
            "portable exact checkpoint manifest failed identity or scenario authentication",
        ));
    }

    let object_directory = object_parent(run_state_root, scenario);
    let identities = manifest_object_identities(&decoded);
    let mut total = u64::try_from(manifest.len())
        .map_err(|_| loop_factory_error("checkpoint manifest length is not representable"))?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(identities.len())
        .map_err(|_| loop_factory_error("reserve portable checkpoint object inventory"))?;
    for object_identity in identities {
        boundary()?;
        let path = object_path(&object_directory, object_identity);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            loop_factory_error(format!(
                "inspect portable checkpoint object {}: {error}",
                object_identity.to_hex()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(loop_factory_error(format!(
                "portable checkpoint object {} is not a regular file",
                object_identity.to_hex()
            )));
        }
        let length = metadata.len();
        total = add_checkpoint_bytes(total, length)
            .map_err(|error| loop_factory_error(error.to_string()))?;
        objects.push(ProductionExactCheckpointObject {
            identity: object_identity,
            length,
        });
    }
    limits
        .reserve("fat_checkpoint_bytes", 0, total)
        .map_err(|error| match error {
            crucible::model::FaultResourceLimitError::Exceeded {
                field,
                current,
                requested,
                configured,
                hard,
            }
            | crucible::model::FaultResourceLimitError::UsageOverflow {
                field,
                current,
                requested,
                configured,
                hard,
            } => LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            }),
            error => loop_factory_error(error.to_string()),
        })?;
    boundary()?;

    Ok(ProductionExactCheckpointClosure {
        identity,
        scenario,
        configuration: decoded.configuration,
        manifest,
        run_state_root: run_state_root.to_path_buf(),
        source: source.clone(),
        object_directory,
        objects,
    })
}

fn manifest_object_identities(manifest: &ClosureManifest) -> BTreeSet<ContentHash> {
    let mut identities = BTreeSet::from([
        manifest.schedule,
        manifest.scheduler,
        manifest.trigger_state,
        manifest.assertion_state,
        manifest.lifecycle_state,
        manifest.fault_checkpoint,
    ]);
    identities.extend(manifest.event_log_segments.iter().copied());
    identities.extend(manifest.signal_artifacts.iter().copied());
    for target in &manifest.targets {
        identities.insert(target.snapshot);
        identities.extend(target.overlay.chunks.iter().copied());
        identities.extend(target.vmstate.chunks.iter().copied());
    }
    identities
}

fn validate_checkpoint_set(
    scenario: ContentHash,
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    let fault_checkpoint = checkpoint
        .fault_checkpoint
        .as_ref()
        .ok_or_else(|| store_error("exact checkpoint set has no production fault continuation"))?;
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
    if checkpoint
        .selectable_catalog_plans
        .iter()
        .any(|(node, plan)| {
            !checkpoint.targets.contains_key(node)
                || plan.declarations().is_empty()
                || plan.continuation().phase()
                    != crucible_protocol::selectable_catalog_plan::SelectablePlanPhase::Frozen
        })
    {
        return Err(store_error(
            "exact checkpoint selectable catalogs are not frozen live-node continuations",
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
            if target.configuration != checkpoint.configuration {
                return Err(store_error(format!(
                    "exact checkpoint target state disagrees for `{}`",
                    node.name
                )));
            }
            if fault_checkpoint.qemu_fingerprint(node).is_none() {
                return Err(store_error(format!(
                    "exact checkpoint target for `{}` has no paired fault-runtime fingerprint",
                    node.name
                )));
            }
            validate_exact_checkpoint_target(node, target, fault_checkpoint.id())
                .map_err(|error| store_error(error.to_string()))?;
        } else if fault_checkpoint.qemu_fingerprint(node).is_some() {
            return Err(store_error(format!(
                "permanently failed exact-checkpoint node `{}` retains a live fault-runtime fingerprint",
                node.name
            )));
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
        .map_err(scheduler_resource_limit)
}

fn add_checkpoint_bytes(current: u64, requested: u64) -> Result<u64, SchedulerError> {
    current
        .checked_add(requested)
        .ok_or_else(|| store_error("checkpoint byte accounting overflow"))
}

fn authenticate_existing_publication_with_boundary(
    destination: &Path,
    object_directory: &Path,
    expected: &ClosureManifest,
    objects: &ClosureObjects,
    checkpoint: &ProductionVmExactCheckpointSet,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    let bytes = read_bounded_file_with_scheduler_boundary(
        &destination.join(MANIFEST_FILE),
        MAX_MANIFEST_BYTES_U64,
        boundary,
    )?;
    boundary()?;
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
        if hash_bytes_with_boundary(bytes, boundary)? != identity {
            return Err(store_error("checkpoint object changed before retry"));
        }
        validate_file_hash_with_boundary(
            &object_path(object_directory, identity),
            identity,
            boundary,
        )?;
    }
    for identity in &expected.event_log_segments {
        let bytes = objects
            .event_log_segments
            .get(identity)
            .ok_or_else(|| store_error("event-log closure object disappeared"))?;
        if hash_bytes_with_boundary(bytes, boundary)? != *identity {
            return Err(store_error(
                "event-log checkpoint object changed before retry",
            ));
        }
        validate_file_hash_with_boundary(
            &object_path(object_directory, *identity),
            *identity,
            boundary,
        )?;
    }
    for identity in &expected.signal_artifacts {
        let bytes = objects
            .signal_artifacts
            .get(identity)
            .ok_or_else(|| store_error("signal-artifact closure object disappeared"))?;
        if hash_bytes_with_boundary(bytes, boundary)? != *identity {
            return Err(store_error(
                "signal-artifact checkpoint object changed before retry",
            ));
        }
        validate_file_hash_with_boundary(
            &object_path(object_directory, *identity),
            *identity,
            boundary,
        )?;
    }
    for target in &expected.targets {
        boundary()?;
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = objects
            .snapshots
            .get(&node)
            .ok_or_else(|| store_error("closure snapshot object disappeared"))?;
        if hash_bytes_with_boundary(snapshot, boundary)? != target.snapshot {
            return Err(store_error("checkpoint snapshot changed before retry"));
        }
        validate_file_hash_with_boundary(
            &object_path(object_directory, target.snapshot),
            target.snapshot,
            boundary,
        )?;
        validate_artifact_manifest_with_scheduler_boundary(
            object_directory,
            &target.overlay,
            boundary,
        )?;
        validate_artifact_manifest_with_scheduler_boundary(
            object_directory,
            &target.vmstate,
            boundary,
        )?;
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        validate_exact_checkpoint_artifact_with_boundary(&source.overlay_artifact, boundary)?;
        validate_exact_checkpoint_artifact_with_boundary(&source.vmstate_artifact, boundary)?;
    }
    Ok(())
}

fn validate_exact_checkpoint_artifact_with_boundary(
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    match &artifact.source {
        ProductionCheckpointArtifactSource::File(path) => {
            validate_file_hash_with_boundary(path, artifact.identity, boundary)?;
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            let manifest = ArtifactManifest {
                identity: artifact.identity,
                length: artifact.length,
                chunks: artifact.chunks.clone(),
            };
            validate_artifact_manifest_with_scheduler_boundary(directory, &manifest, boundary)?;
        }
    }
    boundary()?;
    Ok(())
}

fn install_persisted_artifact_paths(
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
        selectable_catalog_plans: checkpoint
            .selectable_catalog_plans
            .iter()
            .map(|(node, plan)| {
                plan.encode()
                    .map(|bytes| SelectableCatalogWire {
                        node: node.name.clone(),
                        plan: bytes,
                    })
                    .map_err(|error| {
                        store_error(format!(
                            "encode selectable catalog continuation for `{}`: {error}",
                            node.name
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
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
    selectable_catalog_plans:
        BTreeMap<NodeId, crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan>,
}

fn decode_lifecycle(
    bytes: &[u8],
    scenario: &ScenarioDef,
    limits: FaultResourceLimits,
) -> Result<DecodedLifecycle, LifecycleApiError> {
    let _budget = decode::DecodeBudgetGuard::enter(limits);
    let wire: LifecycleWire = ciborium::de::from_reader(bytes).map_err(|error| {
        decode::map_decode_resource_error(&error)
            .unwrap_or_else(|| loop_factory_error("decode exact lifecycle continuation"))
    })?;
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
    if !wire
        .selectable_catalog_plans
        .windows(2)
        .all(|pair| pair[0].node < pair[1].node)
    {
        return Err(loop_factory_error(
            "checkpoint selectable catalog nodes are not strictly sorted",
        ));
    }
    let mut selectable_catalog_plans = BTreeMap::new();
    for entry in wire.selectable_catalog_plans {
        let name = entry.node;
        let plan =
            crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan::decode(&entry.plan)
                .map_err(|error| {
                    loop_factory_error(format!(
                        "decode selectable catalog continuation for `{name}`: {error}"
                    ))
                })?;
        selectable_catalog_plans.insert(NodeId { name }, plan);
    }
    Ok(DecodedLifecycle {
        terminal,
        terminal_cause,
        initial_lifecycle_observations_pending: wire.initial_lifecycle_observations_pending,
        branch,
        recorded_controls,
        selectable_catalog_plans,
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

fn manifest_and_objects_with_boundary(
    scenario: ContentHash,
    resource_limits: FaultResourceLimits,
    checkpoint: &ProductionVmExactCheckpointSet,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(ClosureManifest, ClosureObjects), SchedulerError> {
    boundary()?;
    let schedule = checkpoint.configuration.schedule.to_compact_binary();
    boundary()?;
    let scheduler = checkpoint
        .scheduler
        .canonical_bytes()
        .map_err(|error| store_error(format!("encode scheduler continuation: {error}")))?;
    boundary()?;
    let trigger_state = checkpoint.trigger_state.to_compact_binary();
    let assertion_state = checkpoint
        .assertion_state
        .canonical_bytes()
        .map_err(|error| store_error(format!("encode assertion continuation: {error}")))?;
    let lifecycle_state = encode_lifecycle(checkpoint)?;
    let fault_checkpoint = checkpoint
        .fault_checkpoint
        .as_ref()
        .ok_or_else(|| store_error("exact checkpoint set has no production fault continuation"))?
        .to_canonical_bytes_with_limit(resource_limits.fat_checkpoint_bytes)
        .map_err(|error| store_error(format!("encode fault continuation: {error}")))?;
    boundary()?;
    let mut snapshots = BTreeMap::new();
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(checkpoint.targets.len())
        .map_err(|error| store_error(format!("reserve checkpoint target manifest: {error}")))?;
    for (node, target) in &checkpoint.targets {
        boundary()?;
        let bytes = target
            .snapshot
            .to_canonical_bytes_with_limit(resource_limits.fat_checkpoint_bytes)
            .map_err(|error| {
                store_error(format!("encode QEMU snapshot for `{}`: {error}", node.name))
            })?;
        boundary()?;
        let snapshot = hash_bytes_with_boundary(&bytes, boundary)?;
        snapshots.insert(node.clone(), bytes);
        targets.push(TargetManifest {
            node: node.name.clone(),
            counter: target.counter,
            scheduler_time: target.scheduler_time.ticks,
            snapshot,
            overlay: artifact_manifest_with_boundary(&target.overlay_artifact, boundary)?,
            vmstate: artifact_manifest_with_boundary(&target.vmstate_artifact, boundary)?,
            manifest_identity: target.manifest_identity,
        });
    }
    let manifest = ClosureManifest {
        format_version: MANIFEST_VERSION,
        scenario,
        configuration: checkpoint.configuration.id(),
        schedule: hash_bytes_with_boundary(&schedule, boundary)?,
        frontier: checkpoint.scheduler.frontier().ticks,
        scheduler: hash_bytes_with_boundary(&scheduler, boundary)?,
        event_log_segments: checkpoint
            .scheduler
            .event_log_segment_dependencies()
            .to_vec(),
        signal_artifacts: checkpoint.signal_artifact_objects.keys().copied().collect(),
        trigger_state: hash_bytes_with_boundary(&trigger_state, boundary)?,
        assertion_state: hash_bytes_with_boundary(&assertion_state, boundary)?,
        lifecycle_state: hash_bytes_with_boundary(&lifecycle_state, boundary)?,
        fault_checkpoint: hash_bytes_with_boundary(&fault_checkpoint, boundary)?,
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
        format_version: manifest.format_version,
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
    let domain = match manifest.format_version {
        LEGACY_MANIFEST_VERSION => "crucible.production-exact-closure.v4",
        MANIFEST_VERSION => "crucible.production-exact-closure.v5",
        _ => return Err(store_error("unsupported exact checkpoint manifest version")),
    };
    Ok(ContentHash::from_canonical_material(
        domain,
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
    let magic = match manifest.format_version {
        LEGACY_MANIFEST_VERSION => LEGACY_MANIFEST_MAGIC,
        MANIFEST_VERSION => MANIFEST_MAGIC,
        _ => return Err(store_error("unsupported exact checkpoint manifest version")),
    };
    let mut bytes = Vec::with_capacity(magic.len() + payload.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

// crucible-lint: allow stringly-error -- the private canonical decoder returns bounded diagnostics that the store boundary immediately wraps in CheckpointStoreError.
fn decode_manifest(bytes: &[u8]) -> Result<ClosureManifest, String> {
    let (format_version, payload) = if let Some(payload) = bytes.strip_prefix(MANIFEST_MAGIC) {
        (MANIFEST_VERSION, payload)
    } else if let Some(payload) = bytes.strip_prefix(LEGACY_MANIFEST_MAGIC) {
        (LEGACY_MANIFEST_VERSION, payload)
    } else {
        return Err(String::from("unsupported closure manifest version"));
    };
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(String::from("closure manifest exceeds its size limit"));
    }
    let mut manifest: ClosureManifest = ciborium::de::from_reader(payload)
        .map_err(|_| String::from("malformed closure manifest"))?;
    manifest.format_version = format_version;
    let canonical = encode_manifest(&manifest).map_err(|error| error.to_string())?;
    if canonical != bytes {
        return Err(String::from("noncanonical closure manifest"));
    }
    validate_manifest_shape(&manifest)?;
    Ok(manifest)
}

// crucible-lint: allow stringly-error -- the private shape validator returns bounded diagnostics that the store boundary immediately wraps in CheckpointStoreError.
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

#[cfg(test)]
fn persist_object(
    directory: &Path,
    expected: ContentHash,
    bytes: &[u8],
) -> Result<(), SchedulerError> {
    persist_object_with_boundary(directory, expected, bytes, &mut || Ok(()))
}

fn persist_object_with_boundary(
    directory: &Path,
    expected: ContentHash,
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    if hash_bytes_with_boundary(bytes, boundary)? != expected {
        return Err(store_error(
            "checkpoint object content hash mismatch before persistence",
        ));
    }
    let destination = object_path(directory, expected);
    if destination.exists() {
        return sync_existing_object_with_boundary(&destination, expected, boundary);
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
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        staging
            .write_all(chunk)
            .map_err(|error| store_error(format!("write staged checkpoint object: {error}")))?;
    }
    boundary()?;
    staging
        .as_file()
        .sync_all()
        .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => sync_directory(staging_directory),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object_with_boundary(&destination, expected, boundary)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {}",
            expected.to_hex(),
            error.error
        ))),
    }
}

fn persist_file_object_with_boundary(
    directory: &Path,
    expected: ContentHash,
    source: &Path,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(source, expected, boundary)?;
    let destination = object_path(directory, expected);
    if destination.exists() {
        return sync_existing_object_with_boundary(&destination, expected, boundary);
    }
    let staging_directory = destination
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    fs::create_dir_all(staging_directory)
        .map_err(|error| store_error(format!("create checkpoint object prefix: {error}")))?;
    let mut staging = tempfile::Builder::new()
        .prefix(".object-")
        .tempfile_in(staging_directory)
        .map_err(|error| store_error(format!("stage checkpoint file object: {error}")))?;
    let source_length = fs::metadata(source)
        .map_err(|error| store_error(format!("inspect checkpoint file object: {error}")))?
        .len();
    let source_file = File::open(source)
        .map_err(|error| store_error(format!("open checkpoint file object: {error}")))?;
    copy_sparse_authenticated_with_boundary(
        source_file,
        staging.as_file_mut(),
        source_length,
        expected,
        boundary,
    )?;
    staging
        .as_file()
        .sync_all()
        .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => {
            validate_file_hash_with_boundary(&destination, expected, boundary)?;
            sync_directory(staging_directory)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object_with_boundary(&destination, expected, boundary)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {}",
            expected.to_hex(),
            error.error
        ))),
    }
}

fn sync_existing_object_with_boundary(
    path: &Path,
    expected: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(path, expected, boundary)?;
    boundary()?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| store_error(format!("flush checkpoint object: {error}")))?;
    let parent = path
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    sync_directory(parent)
}

#[cfg(test)]
fn artifact_manifest(
    artifact: &ProductionCheckpointArtifact,
) -> Result<ArtifactManifest, SchedulerError> {
    artifact_manifest_with_boundary(artifact, &mut || Ok(()))
}

fn artifact_manifest_with_boundary(
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ArtifactManifest, SchedulerError> {
    boundary()?;
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
    validate_file_hash_with_boundary(path, artifact.identity, boundary)?;
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
        boundary()?;
        let mut filled = 0;
        while filled < buffer.len() {
            boundary()?;
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
        chunks.push(hash_bytes_with_boundary(&buffer[..filled], boundary)?);
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

#[cfg(test)]
fn persist_chunked_artifact(
    directory: &Path,
    manifest: &ArtifactManifest,
    artifact: &ProductionCheckpointArtifact,
) -> Result<(), SchedulerError> {
    persist_chunked_artifact_with_boundary(directory, manifest, artifact, &mut || Ok(()))
}

fn persist_chunked_artifact_with_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    match &artifact.source {
        ProductionCheckpointArtifactSource::ChunkStore(source) => {
            validate_artifact_manifest(source, manifest)
                .map_err(|error| store_error(error.to_string()))?;
            for chunk in &manifest.chunks {
                boundary()?;
                let source_path = object_path(source, *chunk);
                let destination = object_path(directory, *chunk);
                if source_path != destination && !destination.exists() {
                    persist_file_object_with_boundary(directory, *chunk, &source_path, boundary)?;
                }
            }
        }
        ProductionCheckpointArtifactSource::File(path) => {
            let mut file = File::open(path)
                .map_err(|error| store_error(format!("open checkpoint artifact: {error}")))?;
            let mut buffer = vec![0_u8; ARTIFACT_CHUNK_BYTES];
            for expected in &manifest.chunks {
                boundary()?;
                let mut filled = 0;
                while filled < buffer.len() {
                    boundary()?;
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
                persist_object_with_boundary(directory, *expected, &buffer[..filled], boundary)?;
            }
            let mut trailing = [0_u8; 1];
            boundary()?;
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
    boundary()?;
    validate_artifact_manifest_with_scheduler_boundary(directory, manifest, boundary)
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

fn validate_artifact_manifest_with_scheduler_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    let mut reader = ChunkSequenceReader::new(directory, &manifest.chunks)
        .map_err(|error| store_error(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    loop {
        boundary()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|error| store_error(format!("read chunked checkpoint artifact: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if reader.bytes_read != manifest.length || observed != manifest.identity {
        return Err(store_error(
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
    let parent = destination.parent().ok_or_else(|| {
        loop_factory_error(format!(
            "exact checkpoint {role} destination has no parent directory"
        ))
    })?;
    let mut staging = tempfile::Builder::new()
        .prefix(".artifact-")
        .tempfile_in(parent)
        .map_err(|error| {
            loop_factory_error(format!(
                "stage exact checkpoint {role} under {}: {error}",
                parent.display()
            ))
        })?;

    match &artifact.source {
        ProductionCheckpointArtifactSource::File(source) => {
            let source_file = File::open(source).map_err(|error| {
                loop_factory_error(format!(
                    "open exact checkpoint {role} {}: {error}",
                    source.display()
                ))
            })?;
            copy_sparse_authenticated(
                source_file,
                staging.as_file_mut(),
                artifact.length,
                artifact.identity,
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "materialize exact checkpoint {role} {} as {}: {error}",
                    source.display(),
                    destination.display()
                ))
            })?;
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            let reader = ChunkSequenceReader::new(directory, &artifact.chunks)?;
            copy_sparse_authenticated(
                reader,
                staging.as_file_mut(),
                artifact.length,
                artifact.identity,
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "materialize exact checkpoint {role} {}: {error}",
                    destination.display()
                ))
            })?;
        }
    }
    staging.as_file().sync_all().map_err(|error| {
        loop_factory_error(format!(
            "flush exact checkpoint {role} {}: {error}",
            destination.display()
        ))
    })?;
    staging.persist_noclobber(destination).map_err(|error| {
        loop_factory_error(format!(
            "publish exact checkpoint {role} {}: {}",
            destination.display(),
            error.error
        ))
    })?;
    sync_directory(parent).map_err(|error| loop_factory_error(error.to_string()))
}

pub(super) fn stream_checkpoint_artifact(
    artifact: &ProductionCheckpointArtifact,
    destination: &mut impl Write,
    role: &str,
) -> Result<(), LifecycleApiError> {
    match &artifact.source {
        ProductionCheckpointArtifactSource::File(source) => {
            let reader = File::open(source).map_err(|error| {
                loop_factory_error(format!(
                    "open exact checkpoint {role} {}: {error}",
                    source.display()
                ))
            })?;
            copy_authenticated(reader, destination, artifact.length, artifact.identity).map_err(
                |error| {
                    loop_factory_error(format!(
                        "stream exact checkpoint {role} {}: {error}",
                        source.display()
                    ))
                },
            )
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            stream_chunked_checkpoint_artifact(
                directory,
                &artifact.chunks,
                artifact.length,
                artifact.identity,
                destination,
                role,
            )
        }
    }
}

fn stream_chunked_checkpoint_artifact(
    directory: &Path,
    chunks: &[ContentHash],
    length: u64,
    identity: ContentHash,
    destination: &mut impl Write,
    role: &str,
) -> Result<(), LifecycleApiError> {
    let reader = ChunkSequenceReader::new(directory, chunks)?;
    copy_authenticated(reader, destination, length, identity).map_err(|error| {
        loop_factory_error(format!(
            "stream chunked exact checkpoint {role} from {}: {error}",
            directory.display()
        ))
    })
}

fn stream_chunked_checkpoint_artifact_with_boundary(
    directory: &Path,
    chunks: &[ContentHash],
    length: u64,
    identity: ContentHash,
    destination: &mut impl Write,
    role: &str,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    let reader = ChunkSequenceReader::new(directory, chunks)?;
    match copy_authenticated_with_boundary(reader, destination, length, identity, boundary) {
        Ok(()) => Ok(()),
        Err(AuthenticatedCopyError::Io(error)) => Err(loop_factory_error(format!(
            "stream chunked exact checkpoint {role} from {}: {error}",
            directory.display()
        ))),
        Err(AuthenticatedCopyError::Boundary(error)) => Err(error),
    }
}

enum AuthenticatedCopyError<E> {
    Io(std::io::Error),
    Boundary(E),
}

fn copy_authenticated(
    source: impl Read,
    destination: &mut impl Write,
    expected_length: u64,
    expected_identity: ContentHash,
) -> Result<(), std::io::Error> {
    let mut boundary = || Ok::<(), std::convert::Infallible>(());
    match copy_authenticated_with_boundary(
        source,
        destination,
        expected_length,
        expected_identity,
        &mut boundary,
    ) {
        Ok(()) => Ok(()),
        Err(AuthenticatedCopyError::Io(error)) => Err(error),
        Err(AuthenticatedCopyError::Boundary(never)) => match never {},
    }
}

fn copy_authenticated_with_boundary<E>(
    mut source: impl Read,
    destination: &mut impl Write,
    expected_length: u64,
    expected_identity: ContentHash,
    boundary: &mut (impl FnMut() -> Result<(), E> + ?Sized),
) -> Result<(), AuthenticatedCopyError<E>> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        boundary().map_err(AuthenticatedCopyError::Boundary)?;
        let read = source
            .read(&mut buffer)
            .map_err(AuthenticatedCopyError::Io)?;
        boundary().map_err(AuthenticatedCopyError::Boundary)?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).map_err(|_| {
            AuthenticatedCopyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length is not representable",
            ))
        })?;
        copied = copied.checked_add(read_u64).ok_or_else(|| {
            AuthenticatedCopyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length overflowed",
            ))
        })?;
        if copied > expected_length {
            return Err(AuthenticatedCopyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact exceeds its declared length",
            )));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        destination
            .write_all(bytes)
            .map_err(AuthenticatedCopyError::Io)?;
        boundary().map_err(AuthenticatedCopyError::Boundary)?;
    }
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if copied != expected_length || observed != expected_identity {
        return Err(AuthenticatedCopyError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint artifact failed length or content authentication",
        )));
    }
    boundary().map_err(AuthenticatedCopyError::Boundary)?;
    Ok(())
}

fn copy_sparse_authenticated(
    mut source: impl Read,
    destination: &mut File,
    expected_length: u64,
    expected_identity: ContentHash,
) -> Result<(), std::io::Error> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length is not representable",
            )
        })?;
        copied = copied.checked_add(read_u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length overflowed",
            )
        })?;
        if copied > expected_length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact exceeds its declared length",
            ));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            let offset = i64::try_from(read).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint sparse extent is not representable",
                )
            })?;
            destination.seek(SeekFrom::Current(offset))?;
        } else {
            destination.write_all(bytes)?;
        }
    }
    if copied != expected_length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "checkpoint artifact is shorter than its declared length",
        ));
    }
    destination.set_len(expected_length)?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if observed != expected_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint artifact failed content authentication while streaming",
        ));
    }
    Ok(())
}

fn copy_sparse_authenticated_with_boundary(
    mut source: impl Read,
    destination: &mut File,
    expected_length: u64,
    expected_identity: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        boundary()?;
        let read = source
            .read(&mut buffer)
            .map_err(|error| store_error(format!("read checkpoint sparse extent: {error}")))?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint copy length is not representable",
                )
            })
            .map_err(|error| store_error(error.to_string()))?;
        copied = copied
            .checked_add(read_u64)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint copy length overflowed",
                )
            })
            .map_err(|error| store_error(error.to_string()))?;
        if copied > expected_length {
            return Err(store_error(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint artifact exceeds its declared length",
                )
                .to_string(),
            ));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            let offset = i64::try_from(read)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "checkpoint sparse extent is not representable",
                    )
                })
                .map_err(|error| store_error(error.to_string()))?;
            destination
                .seek(SeekFrom::Current(offset))
                .map_err(|error| store_error(format!("seek sparse checkpoint extent: {error}")))?;
        } else {
            destination
                .write_all(bytes)
                .map_err(|error| store_error(format!("write checkpoint extent: {error}")))?;
        }
    }
    if copied != expected_length {
        return Err(store_error(
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "checkpoint artifact is shorter than its declared length",
            )
            .to_string(),
        ));
    }
    destination
        .set_len(expected_length)
        .map_err(|error| store_error(format!("size sparse checkpoint extent: {error}")))?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if observed != expected_identity {
        return Err(store_error(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact failed content authentication while streaming",
            )
            .to_string(),
        ));
    }
    boundary()?;
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

fn read_bounded_file_with_scheduler_boundary(
    path: &Path,
    limit: u64,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<Vec<u8>, SchedulerError> {
    boundary()?;
    let mut file =
        File::open(path).map_err(|error| store_error(format!("open checkpoint file: {error}")))?;
    let length = file
        .metadata()
        .map_err(|error| store_error(format!("inspect checkpoint file: {error}")))?
        .len();
    if length > limit {
        return Err(store_error(format!(
            "checkpoint file length {length} exceeds limit {limit}"
        )));
    }
    let length = usize::try_from(length)
        .map_err(|_| store_error("checkpoint file length is not representable"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| store_error(format!("reserve checkpoint file bytes: {error}")))?;
    bytes.resize(length, 0);
    for chunk in bytes.chunks_mut(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        file.read_exact(chunk)
            .map_err(|error| store_error(format!("read checkpoint file: {error}")))?;
    }
    boundary()?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| store_error(format!("finish checkpoint file read: {error}")))?
        != 0
    {
        return Err(store_error("checkpoint file grew while it was read"));
    }
    boundary()?;
    Ok(bytes)
}

fn persist_file_bytes_with_boundary(
    path: &Path,
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
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
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        file.write_all(chunk).map_err(|error| {
            store_error(format!(
                "write checkpoint object {}: {error}",
                path.display()
            ))
        })?;
    }
    boundary()?;
    file.sync_all().map_err(|error| {
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
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<Vec<u8>, LifecycleApiError> {
    boundary()?;
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
    let bytes = budget.read_identity(expected, size, || {
        read_bounded_file_with_boundary(&path, size, boundary)
    })?;
    boundary()?;
    if hash_bytes_with_lifecycle_boundary(&bytes, boundary)? != expected {
        return Err(loop_factory_error(format!(
            "checkpoint object {} failed content authentication",
            expected.to_hex()
        )));
    }
    Ok(bytes)
}

fn validate_file_hash(path: &Path, expected: ContentHash) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(path, expected, &mut || Ok(()))
}

fn validate_file_hash_with_boundary(
    path: &Path,
    expected: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    let mut file = File::open(path).map_err(|error| {
        store_error(format!(
            "open checkpoint object {}: {error}",
            path.display()
        ))
    })?;
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    loop {
        boundary()?;
        let read = file.read(&mut buffer).map_err(|error| {
            store_error(format!(
                "hash checkpoint object {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let actual = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if actual != expected {
        return Err(store_error(format!(
            "checkpoint object {} changed before persistence",
            path.display()
        )));
    }
    Ok(())
}

fn hash_bytes_with_boundary(
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ContentHash, SchedulerError> {
    let mut hasher = blake3::Hasher::new();
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        hasher.update(chunk);
    }
    boundary()?;
    Ok(ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
}

fn hash_bytes_with_lifecycle_boundary(
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ContentHash, LifecycleApiError> {
    let mut hasher = blake3::Hasher::new();
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        hasher.update(chunk);
    }
    boundary()?;
    Ok(ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
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
mod tests;
