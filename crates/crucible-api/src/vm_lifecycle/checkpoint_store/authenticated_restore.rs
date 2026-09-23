//! Pure reconstruction of repository-authenticated lifecycle state.
//!
//! The lower exact-checkpoint verifier owns the v9 manifest and object
//! relation. This module decodes each authenticated semantic object once into
//! the API-owned lifecycle types without installing a native closure or
//! exposing artifact identities and readers.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::sync::Arc;

use crucible::exact_checkpoint::{
    ExactCheckpointClosureBinding, ExactCheckpointSemanticObjectRole,
};
use crucible::{ContentHash, DagStore, MemoryDagStore, NodeId};

use super::*;

/// Decoded lifecycle state paired with one-shot repository target claims.
#[must_use = "authenticated checkpoint state must be consumed by lifecycle construction"]
pub struct DecodedProductionExactCheckpoint {
    pub(super) checkpoint: ProductionVmExactCheckpointSet,
    expected_snapshots: BTreeMap<NodeId, ContentHash>,
}

impl DecodedProductionExactCheckpoint {
    /// Returns the authenticated modeled configuration used to configure the lifecycle.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.checkpoint.configuration
    }

    /// Returns the complete scheduler continuation for boundary-only validation.
    #[must_use]
    pub fn scheduler(&self) -> &SingleSchedulerCheckpoint {
        &self.checkpoint.scheduler
    }

    /// Reconstructs the modeled checkpoint handle for lifecycle admission.
    ///
    /// The returned handle contains only model-visible coordinates. Native VM
    /// state remains sealed in this decoded closure and is consumed separately
    /// by the production lifecycle factory.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the authenticated schedule cannot
    /// produce its immediate modeled parent or checkpoint topology.
    pub fn modeled_checkpoint(&self) -> Result<Checkpoint, LifecycleApiError> {
        let configuration = &self.checkpoint.configuration;
        let parent = if configuration.schedule.is_empty() {
            None
        } else {
            let prefix = configuration
                .schedule
                .prefix(configuration.schedule.len().saturating_sub(1))
                .map_err(|error| loop_factory_error(error.to_string()))?;
            Some(Configuration {
                def: configuration.def.clone(),
                schedule: prefix,
            })
        };
        let node_icounts = self
            .checkpoint
            .targets
            .iter()
            .map(|(node, target)| {
                (
                    node.clone(),
                    crucible::Icount {
                        retired: target.counter,
                    },
                )
            })
            .collect();
        let mut checkpoint = Checkpoint::from_recorded_configuration(
            configuration,
            parent.as_ref(),
            self.checkpoint.scheduler.frontier(),
            node_icounts,
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .map_err(|error| loop_factory_error(error.to_string()))?;
        checkpoint.execution_closure = Some(self.checkpoint.identity);
        Ok(checkpoint)
    }

    /// Consumes the decoded closure into its one-shot node restore admissions.
    pub fn into_node_restore_admissions(self) -> ProductionVmExactNodeRestoreAdmissions {
        ProductionVmExactNodeRestoreAdmissions {
            checkpoint: self.checkpoint,
            expected_snapshots: self.expected_snapshots,
        }
    }

    pub(in crate::vm_lifecycle) fn into_checkpoint(self) -> ProductionVmExactCheckpointSet {
        self.checkpoint
    }
}

/// One-shot cursor over concretely validated exact node restore admissions.
#[must_use = "validated node restore admissions must be consumed or discarded"]
pub struct ProductionVmExactNodeRestoreAdmissions {
    checkpoint: ProductionVmExactCheckpointSet,
    expected_snapshots: BTreeMap<NodeId, ContentHash>,
}

impl ProductionVmExactNodeRestoreAdmissions {
    /// Takes the next exact node admission in canonical node order.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the decoded node has no matching
    /// one-shot structural claim or has an invalid persisted service state.
    pub fn take_next(
        &mut self,
    ) -> Result<Option<ProductionVmReplayExactNodeRestoreAdmission>, LifecycleApiError> {
        let Some((node, target)) = self.checkpoint.targets.pop_first() else {
            return Ok(None);
        };
        let service_state = self
            .checkpoint
            .node_service_states
            .get(&node)
            .copied()
            .ok_or_else(|| {
                loop_factory_error("exact restore target has no persisted service disposition")
            })?;
        let paused = restored_node_paused(service_state)?;
        let authority = self.checkpoint.repository_restore.as_mut().ok_or_else(|| {
            loop_factory_error("exact restore has no repository target authority")
        })?;
        authority
            .take_replay_node_admission(&node, target.snapshot, paused)
            .map(Some)
    }

    /// Seals one matching replay result for every consumed repository target.
    ///
    /// The returned promotion is bound to the exact repository root, closure
    /// identity, target manifest, node, and snapshot carried by each one-shot
    /// restore admission. It does not reopen an attempt-local native catalog.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when a target admission remains, the
    /// match set is incomplete, a match belongs to another exact source, or
    /// `boundary` rejects an operational boundary.
    pub fn prepare_replay_oracle_promotion_with_boundary(
        self,
        repository_root: crucible_campaign::ExactCheckpointId,
        matches: BTreeMap<NodeId, QemuReplayOracleMatch>,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<PreparedProductionReplayOraclePromotion, LifecycleApiError> {
        if !self.checkpoint.targets.is_empty() {
            return Err(loop_factory_error(
                "production replay-oracle target admissions were not completely consumed",
            ));
        }
        super::replay::prepare_production_replay_oracle_promotion_source(
            self.checkpoint.identity,
            repository_root,
            self.expected_snapshots,
            matches,
            boundary,
        )
    }
}

#[derive(Default)]
struct SemanticObjects {
    schedule: Option<Schedule>,
    scheduler: Option<SingleSchedulerCheckpoint>,
    event_log_objects: BTreeMap<usize, (ContentHash, Vec<u8>)>,
    signal_artifact_objects: BTreeMap<ContentHash, Vec<u8>>,
    trigger_state: Option<EventGraphState>,
    assertion_state: Option<HostAssertionEvaluatorCheckpoint>,
    lifecycle_state: Option<DecodedLifecycle>,
    fault_checkpoint: Option<ProductionFaultRuntimeCheckpoint>,
    targets: BTreeMap<NodeId, AuthenticatedTarget>,
    failed_host_io: BTreeMap<NodeId, ProductionFailedNodeState>,
    node_generations: BTreeMap<NodeId, u64>,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
}

struct AuthenticatedTarget {
    configuration: ContentHash,
    immutable_backing: ContentHash,
    counter: u64,
    scheduler_time: VirtualTime,
    snapshot_object: ContentHash,
    snapshot: ExactSnapshotHandle,
}

/// Decodes one repository-authenticated closure without filesystem staging.
///
/// The closure proof is consumed. Every semantic object is opened, bounded,
/// content-authenticated, and visited exactly once by the lower verifier. The
/// returned value retains one non-clone target claim for each live node.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when cancellation fires, an authenticated
/// object cannot be opened, any continuation is malformed or noncanonical, or
/// the reconstructed lifecycle disagrees with the submitted scenario.
pub fn decode_authenticated_production_exact_checkpoint(
    closure: ExactCheckpointClosureBinding,
    identity: ContentHash,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    byte_limit: u64,
    mut boundary: impl FnMut() -> io::Result<()>,
    open: Arc<dyn Fn(ContentHash) -> io::Result<Box<dyn Read + Send>> + Send + Sync>,
) -> Result<DecodedProductionExactCheckpoint, LifecycleApiError> {
    let mut objects = SemanticObjects::default();
    let semantic_open = Arc::clone(&open);
    let targets = closure
        .visit_semantic_objects(
            byte_limit,
            &mut boundary,
            move |identity| semantic_open(identity),
            |role, bytes| collect_semantic_object(&mut objects, role, bytes, scenario, source),
        )
        .map_err(|error| {
            loop_factory_error(format!(
                "authenticate exact checkpoint semantic closure: {error}"
            ))
        })?;

    let expected_snapshots = objects
        .targets
        .iter()
        .map(|(node, target)| (node.clone(), target.snapshot_object))
        .collect();
    let mut checkpoint = decode_semantic_checkpoint(identity, scenario, source, objects)?;
    checkpoint.repository_restore = Some(RepositoryExactRestoreAuthority {
        targets,
        configuration: Arc::new(checkpoint.configuration.clone()),
        scheduler: Arc::clone(&checkpoint.scheduler),
        open,
    });
    Ok(DecodedProductionExactCheckpoint {
        checkpoint,
        expected_snapshots,
    })
}

fn collect_semantic_object(
    objects: &mut SemanticObjects,
    role: ExactCheckpointSemanticObjectRole<'_>,
    bytes: &[u8],
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
) -> io::Result<Option<ContentHash>> {
    let duplicate = |role: &str| io::Error::other(format!("duplicate exact checkpoint {role}"));
    let limits = source.plan().fault_signals().resource_limits();
    match role {
        ExactCheckpointSemanticObjectRole::Schedule => {
            let value = Schedule::from_compact_binary(bytes).map_err(|error| {
                io::Error::other(format!("decode checkpoint schedule: {error}"))
            })?;
            if objects.schedule.replace(value).is_some() {
                return Err(duplicate("schedule"));
            }
        }
        ExactCheckpointSemanticObjectRole::Scheduler => {
            let value =
                SingleSchedulerCheckpoint::from_canonical_bytes(bytes).map_err(|error| {
                    io::Error::other(format!("decode scheduler continuation: {error}"))
                })?;
            if objects.scheduler.replace(value).is_some() {
                return Err(duplicate("scheduler"));
            }
        }
        ExactCheckpointSemanticObjectRole::EventLogSegment { index, identity } => {
            let value = fallible_copy(bytes, "event-log object")?;
            if objects
                .event_log_objects
                .insert(index, (identity, value))
                .is_some()
            {
                return Err(duplicate("event-log object"));
            }
        }
        ExactCheckpointSemanticObjectRole::SignalArtifact { identity, .. } => {
            let value = fallible_copy(bytes, "signal artifact")?;
            if objects
                .signal_artifact_objects
                .insert(identity, value)
                .is_some()
            {
                return Err(duplicate("signal artifact"));
            }
        }
        ExactCheckpointSemanticObjectRole::TriggerState => {
            let value = EventGraphState::from_compact_binary(bytes).map_err(|error| {
                io::Error::other(format!("decode trigger continuation: {error}"))
            })?;
            if objects.trigger_state.replace(value).is_some() {
                return Err(duplicate("trigger state"));
            }
        }
        ExactCheckpointSemanticObjectRole::AssertionState => {
            let value =
                HostAssertionEvaluatorCheckpoint::from_canonical_bytes(bytes).map_err(|error| {
                    io::Error::other(format!("decode assertion continuation: {error}"))
                })?;
            if objects.assertion_state.replace(value).is_some() {
                return Err(duplicate("assertion state"));
            }
        }
        ExactCheckpointSemanticObjectRole::LifecycleState => {
            let value = decode_lifecycle(bytes, scenario, limits)
                .map_err(|error| io::Error::other(error.to_string()))?;
            if objects.lifecycle_state.replace(value).is_some() {
                return Err(duplicate("lifecycle state"));
            }
        }
        ExactCheckpointSemanticObjectRole::FaultCheckpoint => {
            let value = ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
                bytes,
                source.plan().fault_signals(),
                scenario.id(),
            )
            .map_err(|error| io::Error::other(format!("decode fault continuation: {error}")))?;
            if objects.fault_checkpoint.replace(value).is_some() {
                return Err(duplicate("fault checkpoint"));
            }
        }
        ExactCheckpointSemanticObjectRole::TargetSnapshot {
            node,
            configuration,
            immutable_backing,
            counter,
            scheduler_time,
        } => {
            let snapshot = ExactSnapshotHandle::from_canonical_bytes_with_limit(
                bytes,
                limits.fat_checkpoint_bytes,
            )
            .map_err(|error| io::Error::other(format!("decode QEMU snapshot: {error}")))?;
            if objects
                .targets
                .insert(
                    NodeId {
                        name: node.to_owned(),
                    },
                    AuthenticatedTarget {
                        configuration,
                        immutable_backing,
                        counter,
                        scheduler_time: VirtualTime {
                            ticks: scheduler_time,
                        },
                        snapshot_object: ContentHash::from_bytes(bytes),
                        snapshot,
                    },
                )
                .is_some()
            {
                return Err(duplicate("target snapshot"));
            }
        }
        ExactCheckpointSemanticObjectRole::NodeGeneration(node, generation) => {
            if objects
                .node_generations
                .insert(
                    NodeId {
                        name: node.to_owned(),
                    },
                    generation,
                )
                .is_some()
            {
                return Err(duplicate("node generation"));
            }
        }
        ExactCheckpointSemanticObjectRole::NodeServiceState(node, state) => {
            let state = match state {
                1 => ProductionNodeServiceState::Running,
                2 => ProductionNodeServiceState::PoweredOff,
                3 => ProductionNodeServiceState::PermanentlyFailed,
                _ => return Err(io::Error::other("invalid checkpoint node service state")),
            };
            if objects
                .node_service_states
                .insert(
                    NodeId {
                        name: node.to_owned(),
                    },
                    state,
                )
                .is_some()
            {
                return Err(duplicate("node service state"));
            }
        }
        ExactCheckpointSemanticObjectRole::FailedHostIo {
            node,
            execution_binding,
            fingerprint_at,
            fingerprint,
        } => {
            let node = NodeId {
                name: node.to_owned(),
            };
            let host_io = QemuHostIoCheckpoint::from_canonical_bytes_with_limit(
                bytes,
                execution_binding,
                limits.fat_checkpoint_bytes,
            )
            .map_err(|error| io::Error::other(format!("decode failed-node host I/O: {error}")))?;
            let failed_state = ProductionFailedNodeState::new(
                &node,
                host_io,
                FingerprintSample {
                    node: node.clone(),
                    at: VirtualTime {
                        ticks: fingerprint_at,
                    },
                    fingerprint: ExecutionFingerprint { hash: fingerprint },
                },
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
            if objects.failed_host_io.insert(node, failed_state).is_some() {
                return Err(duplicate("failed-node host I/O"));
            }
        }
    }
    // The producer binds the QMP RAM target to the decoded fault identity.
    // The manifest separately binds the canonical fault object's byte hash.
    let fault_semantic_identity =
        if matches!(role, ExactCheckpointSemanticObjectRole::FaultCheckpoint) {
            objects
                .fault_checkpoint
                .as_ref()
                .map(ProductionFaultRuntimeCheckpoint::id)
        } else {
            None
        };
    Ok(fault_semantic_identity)
}

fn fallible_copy(bytes: &[u8], role: &str) -> io::Result<Vec<u8>> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| io::Error::other(format!("allocate authenticated {role}")))?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn decode_semantic_checkpoint(
    identity: ContentHash,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    mut objects: SemanticObjects,
) -> Result<ProductionVmExactCheckpointSet, LifecycleApiError> {
    let schedule = take_role(&mut objects.schedule, "schedule")?;
    let configuration = Configuration {
        def: scenario.clone(),
        schedule,
    };
    let scheduler = take_role(&mut objects.scheduler, "scheduler")?;
    if scheduler.configuration_for(scenario).map_err(|error| {
        loop_factory_error(format!("authenticate scheduler configuration: {error}"))
    })? != configuration
    {
        return Err(loop_factory_error(
            "exact checkpoint scheduler continuation does not match its configuration",
        ));
    }
    let mut event_log_objects = BTreeMap::new();
    let mut ordered_event_log_identities = Vec::new();
    ordered_event_log_identities
        .try_reserve_exact(objects.event_log_objects.len())
        .map_err(|_| loop_factory_error("allocate ordered event-log identity validation"))?;
    for (expected_index, (index, (object_identity, bytes))) in
        objects.event_log_objects.into_iter().enumerate()
    {
        if index != expected_index || event_log_objects.insert(object_identity, bytes).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint event-log indices are duplicated or noncontiguous",
            ));
        }
        ordered_event_log_identities.push(object_identity);
    }
    if scheduler.event_log_segment_dependencies() != ordered_event_log_identities {
        return Err(loop_factory_error(
            "exact checkpoint event-log dependencies do not match authenticated objects",
        ));
    }

    let signal_store = MemoryDagStore::new();
    for (object_identity, bytes) in event_log_objects
        .iter()
        .chain(objects.signal_artifact_objects.iter())
    {
        let stored = signal_store.put(bytes).map_err(|error| {
            loop_factory_error(format!("reconstruct in-memory checkpoint DAG: {error}"))
        })?;
        if stored != *object_identity {
            return Err(loop_factory_error(
                "authenticated checkpoint DAG object changed identity",
            ));
        }
    }
    let expected_signal_artifacts =
        collect_signal_artifact_objects(source.plan().fault_signals(), &signal_store)?;
    if expected_signal_artifacts != objects.signal_artifact_objects {
        return Err(loop_factory_error(
            "exact checkpoint signal-artifact closure is incomplete or contains unreferenced objects",
        ));
    }

    let trigger_state = take_role(&mut objects.trigger_state, "trigger state")?;
    let assertion_state = take_role(&mut objects.assertion_state, "assertion state")?;
    let lifecycle = take_role(&mut objects.lifecycle_state, "lifecycle state")?;
    let fault_checkpoint = take_role(&mut objects.fault_checkpoint, "fault checkpoint")?;

    let configuration = Arc::new(configuration);
    let mut targets = BTreeMap::new();
    for (node, target) in objects.targets {
        let restored = ProductionVmExactCheckpointTarget {
            configuration: Arc::clone(&configuration),
            immutable_backing: target.immutable_backing,
            counter: target.counter,
            scheduler_time: target.scheduler_time,
            snapshot: target.snapshot,
            materialization: ProductionVmExactCheckpointMaterialization::Repository,
        };
        if target.configuration != configuration.id() {
            return Err(loop_factory_error(format!(
                "exact checkpoint target for `{}` names another configuration",
                node.name
            )));
        }
        if targets.insert(node, restored).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint contains duplicate node targets",
            ));
        }
    }

    let failed_host_io = objects.failed_host_io;

    validate_restored_node_sets(
        source,
        &targets,
        &objects.node_generations,
        &objects.node_service_states,
    )?;
    validate_failed_host_io_topology(source, &objects.node_service_states, &failed_host_io)?;
    let expected_selectable_nodes = source
        .world()
        .vm_nodes()
        .iter()
        .filter(|node| {
            objects.node_service_states.get(&node.id)
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

    let checkpoint = ProductionVmExactCheckpointSet {
        identity,
        configuration: configuration.as_ref().clone(),
        scheduler: Arc::new(scheduler),
        event_log_objects: Arc::new(event_log_objects),
        signal_artifact_objects: Arc::new(objects.signal_artifact_objects),
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
        failed_host_io,
        node_generations: objects.node_generations,
        node_service_states: objects.node_service_states,
        repository_restore: None,
    };
    validate_checkpoint_set(scenario.id(), &checkpoint)
        .map_err(|error| loop_factory_error(error.to_string()))?;
    Ok(checkpoint)
}

fn take_role<T>(value: &mut Option<T>, role: &str) -> Result<T, LifecycleApiError> {
    value
        .take()
        .ok_or_else(|| loop_factory_error(format!("exact checkpoint is missing {role}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_service_disposition_controls_exact_restore_run_state() {
        assert!(matches!(
            restored_node_paused(ProductionNodeServiceState::Running),
            Ok(false)
        ));
        assert!(matches!(
            restored_node_paused(ProductionNodeServiceState::PoweredOff),
            Ok(true)
        ));
        assert!(restored_node_paused(ProductionNodeServiceState::PermanentlyFailed).is_err());
    }
}
