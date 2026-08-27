//! Transactional ownership for production exact-checkpoint capture.

use super::*;
use std::collections::BTreeMap;

/// Lifecycle-owned state of one exact-checkpoint publication attempt.
#[derive(Debug)]
pub(in crate::vm_lifecycle) enum ExactCheckpointPublicationState {
    /// Reversible capture or durable publication is still in progress.
    Preparing,
    /// The authenticated closure is durably published under this identity.
    Published(ContentHash),
    /// Snapshot deletions that must succeed before another capture attempt.
    CleanupPending(Vec<CapturedExactCheckpointTarget>),
    /// A named closure exists but its parent-directory durability is uncertain.
    PublicationIndeterminate(ContentHash),
}

/// Transaction outcome before or across durable closure publication.
pub(super) enum ExactCheckpointTransactionError<T = CapturedExactCheckpointTarget> {
    /// No authenticated closure became visible.
    Unpublished(SchedulerError),
    /// Cleanup or durability could not establish one committed outcome.
    Indeterminate {
        /// Known closure identity when the manifest rename completed.
        identity: Option<ContentHash>,
        /// Exact snapshot handles retained when live cleanup was incomplete.
        captures: Vec<T>,
        /// Primary transaction or cleanup failure.
        source: SchedulerError,
    },
}

/// Sole owner of one live QEMU snapshot during reversible capture.
#[derive(Debug)]
pub(in crate::vm_lifecycle) struct CapturedExactCheckpointTarget {
    /// World node owning the snapshot.
    pub(super) node: NodeId,
    /// Physical icount captured from the node.
    pub(super) counter: u64,
    /// Scheduler time paired with the physical counter.
    pub(super) scheduler_time: VirtualTime,
    /// Live QEMU snapshot deleted before durable publication.
    pub(super) snapshot: ExactSnapshotHandle,
    /// Staged overlay metadata once its copy authenticates.
    pub(super) overlay_artifact: Option<ProductionCheckpointArtifact>,
    /// Staged VMState metadata once its copy authenticates.
    pub(super) vmstate_artifact: Option<ProductionCheckpointArtifact>,
    /// Whether the live VMState artifact still requires deletion.
    pub(super) cleanup_pending: bool,
}

/// Allocation-owning description of one target before the first QMP save.
pub(super) struct PreparedExactCheckpointTarget {
    /// World node captured by this target.
    pub(super) node: NodeId,
    /// Physical icount paired with the exact snapshot.
    pub(super) counter: u64,
    /// Scheduler time paired with the physical counter.
    pub(super) scheduler_time: VirtualTime,
    /// Lifecycle state that selects the running or paused capture operation.
    pub(super) service_state: ProductionNodeServiceState,
    /// Fully owned temporal-graph checkpoint passed into QEMU capture.
    pub(super) checkpoint: Checkpoint,
    /// Current process-generation overlay copied after QMP save.
    pub(super) source_overlay: PathBuf,
    /// Transaction-staging destination for the overlay copy.
    pub(super) staged_overlay: PathBuf,
    /// Current process-generation VMState artifact copied after QMP save.
    pub(super) source_vmstate: PathBuf,
    /// Transaction-staging destination for the VMState copy.
    pub(super) staged_vmstate: PathBuf,
}

/// Owns every per-node checkpoint and artifact path before QMP mutation.
///
/// # Errors
///
/// Returns an error when checkpoint topology or node ownership is invalid, or
/// when the bounded destination vector cannot be reserved.
pub(super) fn prepare_exact_checkpoint_targets(
    configuration: &Configuration,
    checkpoint_virtual_time: VirtualTime,
    node_icounts: &BTreeMap<NodeId, crucible::Icount>,
    boundaries: Vec<(NodeId, u64, VirtualTime, ProductionNodeServiceState)>,
    node_indexes: &BTreeMap<NodeId, usize>,
    node_run_directories: &BTreeMap<NodeId, PathBuf>,
    staging: &Path,
) -> Result<Vec<PreparedExactCheckpointTarget>, SchedulerError> {
    let parent = if configuration.schedule.is_empty() {
        None
    } else {
        let parent_len = configuration.schedule.len().saturating_sub(1);
        let parent_schedule = configuration.schedule.prefix(parent_len).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "derive exact checkpoint parent at schedule length {parent_len}: {error}"
                ),
            }
        })?;
        Some(Configuration {
            def: configuration.def.clone(),
            schedule: parent_schedule,
        })
    };
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(boundaries.len())
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("reserve exact checkpoint prepared targets: {error}"),
        })?;

    for (node, counter, scheduler_time, service_state) in boundaries {
        let checkpoint = Checkpoint::from_recorded_configuration(
            configuration,
            parent.as_ref(),
            checkpoint_virtual_time,
            node_icounts.clone(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("materialize exact scheduler checkpoint: {error}"),
        })?;
        let index =
            node_indexes
                .get(&node)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!("exact checkpoint has no launch index for `{}`", node.name),
                })?;
        let source_directory =
            node_run_directories
                .get(&node)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "exact checkpoint has no process-generation directory for `{}`",
                        node.name
                    ),
                })?;
        prepared.push(PreparedExactCheckpointTarget {
            node,
            counter,
            scheduler_time,
            service_state,
            checkpoint,
            source_overlay: source_directory.join(PRODUCTION_ROOT_OVERLAY_FILE_NAME),
            staged_overlay: staging.join(format!("node-{index}.qcow2")),
            source_vmstate: source_directory.join(PRODUCTION_VMSTATE_FILE_NAME),
            staged_vmstate: staging.join(format!("node-{index}-vmstate.qcow2")),
        });
    }
    Ok(prepared)
}

impl CapturedExactCheckpointTarget {
    /// Consumes a complete reversible owner into the durable target shape.
    ///
    /// # Errors
    ///
    /// Returns an error when artifact staging did not complete.
    pub(super) fn into_target(
        self,
        configuration: &Configuration,
        fault_checkpoint: ContentHash,
    ) -> Result<(NodeId, ProductionVmExactCheckpointTarget), SchedulerError> {
        let overlay_artifact = self.overlay_artifact.ok_or_else(incomplete_capture)?;
        let vmstate_artifact = self.vmstate_artifact.ok_or_else(incomplete_capture)?;
        let manifest_identity = crucible::ContentHash::from_canonical_material(
            "crucible.production-vm-exact-checkpoint.v1",
            &format!(
                "configuration={}\nnode={}\ncounter={}\nscheduler_time={}\nsnapshot={}\nfault={}\noverlay={}\nvmstate={}",
                configuration.id().to_hex(),
                self.node.name,
                self.counter,
                self.scheduler_time.ticks,
                self.snapshot.id().to_hex(),
                fault_checkpoint.to_hex(),
                overlay_artifact.identity.to_hex(),
                vmstate_artifact.identity.to_hex(),
            ),
        );
        let node = self.node;
        Ok((
            node,
            ProductionVmExactCheckpointTarget {
                configuration: configuration.clone(),
                counter: self.counter,
                scheduler_time: self.scheduler_time,
                snapshot: self.snapshot,
                overlay_artifact,
                vmstate_artifact,
                manifest_identity,
            },
        ))
    }
}

impl<T> From<SchedulerError> for ExactCheckpointTransactionError<T> {
    fn from(error: SchedulerError) -> Self {
        Self::Unpublished(error)
    }
}

impl ProductionVmLifecycleLoop {
    /// Captures one exact checkpoint under a pre-owned publication slot.
    ///
    /// # Errors
    ///
    /// Returns a scheduler error when capture, cleanup, or publication fails.
    pub(super) fn capture_exact_checkpoint_set(
        &mut self,
        configuration: &Configuration,
    ) -> Result<ContentHash, SchedulerError> {
        let configuration_id = configuration.id();
        let mut pending_cleanup = None;
        let mut uncertain_publication = None;
        match self.checkpoint_targets.entry(configuration_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(ExactCheckpointPublicationState::Preparing);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let prior =
                    std::mem::replace(entry.get_mut(), ExactCheckpointPublicationState::Preparing);
                match prior {
                    ExactCheckpointPublicationState::Published(identity) => {
                        *entry.get_mut() = ExactCheckpointPublicationState::Published(identity);
                        return Ok(identity);
                    }
                    ExactCheckpointPublicationState::CleanupPending(captures) => {
                        pending_cleanup = Some(captures);
                    }
                    ExactCheckpointPublicationState::Preparing => {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "exact checkpoint {} already has a capture in progress",
                                configuration_id.to_hex()
                            ),
                        });
                    }
                    ExactCheckpointPublicationState::PublicationIndeterminate(identity) => {
                        uncertain_publication = Some(identity);
                    }
                }
            }
        }
        if let Some(mut captures) = pending_cleanup
            && let Err(error) = self.rollback_exact_captures(&mut captures)
        {
            let state = self
                .checkpoint_targets
                .get_mut(&configuration_id)
                .ok_or_else(missing_publication_owner)?;
            *state = ExactCheckpointPublicationState::CleanupPending(captures);
            return Err(error);
        }
        if let Some(identity) = uncertain_publication {
            match checkpoint_store::reconcile_indeterminate_publication(
                &self.config.run_state_root,
                &self.scenario,
                &self.source,
                identity,
            ) {
                Ok(Some(observed_configuration)) if observed_configuration == configuration_id => {
                    let state = self
                        .checkpoint_targets
                        .get_mut(&configuration_id)
                        .ok_or_else(missing_publication_owner)?;
                    *state = ExactCheckpointPublicationState::Published(identity);
                    return Ok(identity);
                }
                Ok(Some(observed_configuration)) => {
                    let state = self
                        .checkpoint_targets
                        .get_mut(&configuration_id)
                        .ok_or_else(missing_publication_owner)?;
                    *state = ExactCheckpointPublicationState::PublicationIndeterminate(identity);
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "indeterminate exact checkpoint {} authenticates configuration {} instead of {}",
                            identity.to_hex(),
                            observed_configuration.to_hex(),
                            configuration_id.to_hex()
                        ),
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    let state = self
                        .checkpoint_targets
                        .get_mut(&configuration_id)
                        .ok_or_else(missing_publication_owner)?;
                    *state = ExactCheckpointPublicationState::PublicationIndeterminate(identity);
                    return Err(error);
                }
            }
        }

        let result = self.capture_reserved_exact_checkpoint_set(configuration);
        finish_exact_checkpoint_transaction(&mut self.checkpoint_targets, configuration_id, result)
    }

    /// Deletes every captured QEMU snapshot in reverse capture order.
    ///
    /// # Errors
    ///
    /// Returns the first deletion error after attempting every snapshot.
    pub(super) fn rollback_exact_captures(
        &mut self,
        captured: &mut Vec<CapturedExactCheckpointTarget>,
    ) -> Result<(), SchedulerError> {
        cleanup_exact_captures_with(
            captured,
            |capture| {
                self.inner
                    .backend_mut()
                    .delete_exact_snapshot(&capture.node, &capture.snapshot)
                    .map_err(SchedulerError::from)
            },
            |capture| capture.cleanup_pending = false,
            |capture| capture.cleanup_pending,
        )
    }
}

fn finish_exact_checkpoint_transaction(
    publications: &mut BTreeMap<ContentHash, ExactCheckpointPublicationState>,
    configuration: ContentHash,
    result: Result<ContentHash, ExactCheckpointTransactionError>,
) -> Result<ContentHash, SchedulerError> {
    match result {
        Ok(identity) => {
            let state = publications
                .get_mut(&configuration)
                .ok_or_else(missing_publication_owner)?;
            *state = ExactCheckpointPublicationState::Published(identity);
            Ok(identity)
        }
        Err(ExactCheckpointTransactionError::Unpublished(error)) => {
            publications.remove(&configuration);
            Err(error)
        }
        Err(ExactCheckpointTransactionError::Indeterminate {
            identity,
            captures,
            source,
        }) => {
            let state = publications
                .get_mut(&configuration)
                .ok_or_else(missing_publication_owner)?;
            *state = match identity {
                Some(identity) => {
                    ExactCheckpointPublicationState::PublicationIndeterminate(identity)
                }
                None => ExactCheckpointPublicationState::CleanupPending(captures),
            };
            Err(source)
        }
    }
}

fn cleanup_exact_captures_with<T, E>(
    captured: &mut Vec<T>,
    mut delete: impl FnMut(&mut T) -> Result<(), E>,
    mut mark_complete: impl FnMut(&mut T),
    pending: impl Fn(&T) -> bool,
) -> Result<(), E> {
    let mut first_error = None;
    for capture in captured.iter_mut().rev() {
        match delete(capture) {
            Ok(()) => mark_complete(capture),
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    if first_error.is_some() {
        captured.retain(pending);
    }
    first_error.map_or(Ok(()), Err)
}

/// Resolves staged capture, live-snapshot cleanup, and durable publication.
///
/// This is the single production ordering seam after the first QMP save. It
/// always attempts every live-snapshot deletion before either publishing a
/// completed checkpoint or returning a clean unpublished error.
///
/// # Errors
///
/// Returns [`ExactCheckpointTransactionError::Unpublished`] when staging fails
/// and every snapshot is deleted, or
/// [`ExactCheckpointTransactionError::Indeterminate`] when cleanup or durable
/// publication cannot establish one outcome.
pub(super) fn resolve_exact_checkpoint_capture<T>(
    mut captured: Vec<T>,
    staged: Result<(), SchedulerError>,
    mut delete: impl FnMut(&mut T) -> Result<(), SchedulerError>,
    mut mark_complete: impl FnMut(&mut T),
    pending: impl Fn(&T) -> bool,
    publish: impl FnOnce(Vec<T>) -> Result<ContentHash, PersistExactCheckpointError>,
) -> Result<ContentHash, ExactCheckpointTransactionError<T>> {
    let cleanup = cleanup_exact_captures_with(
        &mut captured,
        |capture| delete(capture),
        |capture| mark_complete(capture),
        pending,
    );

    if let Err(cleanup) = cleanup {
        let source = match staged {
            Ok(()) => cleanup,
            Err(staging) => SchedulerError::BoundaryViolation {
                message: format!(
                    "exact checkpoint capture failed ({staging}); snapshot cleanup was indeterminate ({cleanup})"
                ),
            },
        };
        return Err(ExactCheckpointTransactionError::Indeterminate {
            identity: None,
            captures: captured,
            source,
        });
    }

    if let Err(error) = staged {
        return Err(ExactCheckpointTransactionError::Unpublished(error));
    }

    match publish(captured) {
        Ok(identity) => Ok(identity),
        Err(PersistExactCheckpointError::Unpublished(source)) => {
            Err(ExactCheckpointTransactionError::Unpublished(source))
        }
        Err(PersistExactCheckpointError::Indeterminate { identity, source }) => {
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity: Some(identity),
                captures: Vec::new(),
                source,
            })
        }
    }
}

fn missing_publication_owner() -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: String::from("exact checkpoint publication owner disappeared"),
    }
}

fn incomplete_capture() -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: String::from("exact checkpoint capture owner is incomplete"),
    }
}

#[cfg(test)]
#[path = "checkpoint_capture/tests.rs"]
mod tests;
