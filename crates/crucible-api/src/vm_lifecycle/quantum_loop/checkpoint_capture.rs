//! Transactional ownership for production exact-checkpoint capture.

use super::*;
use std::collections::BTreeMap;

pub(super) fn combine_exact_checkpoint_transaction(
    operation: Result<ContentHash, ExactCheckpointTransactionError>,
    cleanup: Result<(), SchedulerError>,
    captures: Vec<PendingExactCapture>,
) -> Result<ContentHash, ExactCheckpointTransactionError> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(identity), Err(source)) => Err(ExactCheckpointTransactionError::Indeterminate {
            identity: Some(identity),
            captures,
            source,
        }),
        (Err(ExactCheckpointTransactionError::Unpublished(error)), Err(cleanup)) => {
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity: None,
                captures,
                source: SchedulerError::BoundaryViolation {
                    message: format!(
                        "exact checkpoint failed before publication ({error}); releasing paused QEMU nodes also failed ({cleanup})"
                    ),
                },
            })
        }
        (
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity,
                captures: prior_captures,
                source,
            }),
            Err(cleanup),
        ) => {
            let captures = if captures.is_empty() {
                prior_captures
            } else {
                captures
            };
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity,
                captures,
                source: SchedulerError::BoundaryViolation {
                    message: format!(
                        "exact checkpoint publication was indeterminate ({source}); releasing paused QEMU nodes also failed ({cleanup})"
                    ),
                },
            })
        }
    }
}

pub(super) fn retained_exact_ram_parent_for_committed(
    parents: &BTreeMap<ContentHash, ProductionExactRamPublishedParent>,
    node: &NodeId,
    committed: Option<QmpCheckpointIdentity>,
) -> Result<(Option<ContentHash>, Option<ProductionExactRamCheckpoint>), SchedulerError> {
    let Some(parent_identity) = committed else {
        return Ok((None, None));
    };
    let parent = parents.get(&parent_identity.checkpoint()).ok_or_else(|| {
        SchedulerError::BoundaryViolation {
            message: format!(
                "QEMU committed parent for `{}` has no retained authenticated closure lease",
                node.name
            ),
        }
    })?;
    let checkpoint =
        parent
            .targets
            .get(node)
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "retained exact RAM parent closure has no target for `{}`",
                    node.name
                ),
            })?;
    if checkpoint.identity != parent_identity.into() {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "retained exact RAM parent for `{}` differs from QEMU's committed identity",
                node.name
            ),
        });
    }
    Ok((Some(parent.closure), Some(checkpoint)))
}

/// Selects direct capture for genesis or when the retained chain is full.
pub(super) fn exact_ram_capture_kind_for_parent(
    parent: Option<&ProductionExactRamCheckpoint>,
) -> ProductionExactRamKind {
    if parent.is_none()
        || parent.is_some_and(ProductionExactRamCheckpoint::requires_direct_compaction)
    {
        ProductionExactRamKind::Direct
    } else {
        ProductionExactRamKind::Delta
    }
}

/// Lifecycle-owned state of one exact-checkpoint publication attempt.
#[derive(Debug)]
pub(in crate::vm_lifecycle) enum ExactCheckpointPublicationState {
    /// Reversible capture or durable publication is still in progress.
    Preparing,
    /// The authenticated closure is durably published under this identity.
    Published(ContentHash),
    /// Snapshot cleanup that must finish before publication reconciliation or retry.
    CleanupPending {
        captures: Vec<PendingExactCapture>,
        publication: Option<ContentHash>,
    },
    /// A named closure exists but its parent-directory durability is uncertain.
    PublicationIndeterminate(ContentHash),
}

/// Transaction outcome before or across durable closure publication.
pub(super) enum ExactCheckpointTransactionError {
    /// No authenticated closure became visible.
    Unpublished(SchedulerError),
    /// Cleanup or durability could not establish one committed outcome.
    Indeterminate {
        /// Known closure identity when the manifest rename completed.
        identity: Option<ContentHash>,
        /// Exact snapshot handles retained when live cleanup was incomplete.
        captures: Vec<PendingExactCapture>,
        /// Primary transaction or cleanup failure.
        source: SchedulerError,
    },
}

/// Sole owner of one paused QEMU snapshot through immutable preparation.
#[derive(Debug)]
pub(in crate::vm_lifecycle) struct PendingExactCapture {
    /// World node owning the snapshot.
    pub(super) node: NodeId,
    /// Physical icount captured from the node.
    pub(super) counter: u64,
    /// Shared scheduler frontier bound to the checkpoint.
    pub(super) scheduler_time: VirtualTime,
    /// Live QEMU snapshot deleted before publication or during rollback.
    pub(super) snapshot: ExactSnapshotHandle,
    /// Pre-owned staged overlay metadata once its copy authenticates.
    pub(super) overlay_artifact: Option<ProductionCheckpointArtifact>,
    /// Direct-plus-delta RAM closure built from QEMU's capture report.
    pub(super) exact_ram: Option<ProductionExactRamCheckpoint>,
    /// QEMU-owned direct or delta candidate awaiting publication disposition.
    pub(super) exact_checkpoint: Option<PendingExactCheckpointCandidate>,
    /// Whether the live QMP snapshot still requires deletion.
    pub(super) snapshot_cleanup_pending: bool,
    /// Whether a formerly running node remains paused at the capture boundary.
    pub(super) resume_pending: bool,
}

/// QEMU epoch state paired with one paused descriptor-backed capture.
#[derive(Clone, Copy, Debug)]
pub(super) struct PendingExactCheckpointCandidate {
    /// Candidate identity that must be committed or aborted exactly once.
    pub(super) identity: crucible_qemu::QmpCheckpointIdentity,
    /// Previously committed identity that an abort must preserve.
    pub(super) parent: Option<crucible_qemu::QmpCheckpointIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExactCaptureDisposition {
    Published,
    Unpublished,
}

/// Allocation-owning description of one target before the first QMP save.
pub(super) struct PreparedExactCheckpointTarget {
    /// World node captured by this target.
    pub(super) node: NodeId,
    /// Physical icount paired with the exact snapshot.
    pub(super) counter: u64,
    /// Shared scheduler frontier bound to the checkpoint.
    pub(super) scheduler_time: VirtualTime,
    /// Lifecycle state that selects the running or paused capture operation.
    pub(super) service_state: ProductionNodeServiceState,
    /// Fully owned temporal-graph checkpoint passed into QEMU capture.
    pub(super) checkpoint: Checkpoint,
    /// Current process-generation overlay streamed after QMP save.
    pub(super) source_overlay: PathBuf,
    /// Transaction-staging directory for authenticated overlay chunks.
    pub(super) staged_overlay_chunks: PathBuf,
    /// Pre-owned descriptor-backed RAM output path.
    pub(super) ram_output: PathBuf,
    /// Pre-owned descriptor-backed device-state output path.
    pub(super) device_output: PathBuf,
    /// Transaction-staging directory for authenticated RAM chunks.
    pub(super) staged_ram_chunks: PathBuf,
    /// Transaction-staging directory for authenticated device-state chunks.
    pub(super) staged_device_chunks: PathBuf,
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
    boundaries: Vec<(NodeId, u64, ProductionNodeServiceState)>,
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

    for (node, counter, service_state) in boundaries {
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
            scheduler_time: checkpoint_virtual_time,
            service_state,
            checkpoint,
            source_overlay: source_directory.join(DEFAULT_ROOT_OVERLAY_FILE_NAME),
            staged_overlay_chunks: staging.join(format!("node-{index}-overlay-objects")),
            ram_output: staging.join(format!("node-{index}-ram.crucram")),
            device_output: staging.join(format!("node-{index}-device.vmstate")),
            staged_ram_chunks: staging.join(format!("node-{index}-ram-objects")),
            staged_device_chunks: staging.join(format!("node-{index}-device-objects")),
        });
    }
    Ok(prepared)
}

impl From<SchedulerError> for ExactCheckpointTransactionError {
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
    pub(in crate::vm_lifecycle) fn capture_exact_checkpoint_set(
        &mut self,
        configuration: &Configuration,
    ) -> Result<ContentHash, SchedulerError> {
        self.capture_exact_checkpoint_set_with_boundary(configuration, &mut || Ok(()))
    }

    /// Captures a new root when the same configuration has an earlier snapshot.
    ///
    /// A failed refresh retains the prior durable root unless publication or
    /// cleanup is indeterminate and requires reconciliation.
    ///
    /// # Errors
    ///
    /// Returns a scheduler error when the live boundary or capture fails.
    pub(in crate::vm_lifecycle) fn capture_fresh_exact_checkpoint_set_with_boundary(
        &mut self,
        configuration: &Configuration,
        boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
    ) -> Result<ContentHash, SchedulerError> {
        boundary()?;
        let configuration_id = configuration.id();
        let previous = match self.checkpoint_targets.get(&configuration_id) {
            Some(ExactCheckpointPublicationState::Published(identity)) => Some(*identity),
            _ => None,
        };
        let Some(previous) = previous else {
            return self.capture_exact_checkpoint_set_with_boundary(configuration, boundary);
        };

        // A Snapshot control may have retained this configuration before the
        // terminal event log was complete. Keep its durable root and RAM parent
        // until the fresh transaction has a definitive published outcome.
        self.retain_exact_ram_parent_from_closure(configuration_id, previous)?;
        let previous_parent = self
            .exact_ram_parents
            .get(&configuration_id)
            .filter(|parent| parent.closure == previous)
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "published exact checkpoint has no matching retained RAM parent",
                ),
            })?;
        self.checkpoint_targets.remove(&configuration_id);
        let result = self.capture_exact_checkpoint_set_with_boundary(configuration, boundary);
        if result.is_err()
            && matches!(
                self.checkpoint_targets.get(&configuration_id),
                None | Some(ExactCheckpointPublicationState::Preparing)
            )
        {
            self.checkpoint_targets.insert(
                configuration_id,
                ExactCheckpointPublicationState::Published(previous),
            );
            self.exact_ram_parents
                .insert(configuration_id, previous_parent);
        }
        result
    }

    pub(in crate::vm_lifecycle) fn capture_exact_checkpoint_set_with_boundary(
        &mut self,
        configuration: &Configuration,
        boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
    ) -> Result<ContentHash, SchedulerError> {
        boundary()?;
        // Drain every selectable delta before snapshotting scheduler and QEMU
        // state. Pending requests remain retained by the node set, while
        // registration, freeze, and completion markers update the exact plan.
        let _pending = self
            .inner
            .backend_mut()
            .drain_pending_selectable_requests()?;
        let configuration_id = configuration.id();
        let mut retry_cleanup = None;
        let mut retry_publication = None;
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
                    ExactCheckpointPublicationState::CleanupPending {
                        captures,
                        publication,
                    } => {
                        retry_cleanup = Some((captures, publication));
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
                        retry_publication = Some(identity);
                    }
                }
            }
        }
        if let Some((mut captures, publication)) = retry_cleanup {
            let disposition = if let Some(identity) = publication {
                if let Err(error) = boundary() {
                    let state = self
                        .checkpoint_targets
                        .get_mut(&configuration_id)
                        .ok_or_else(missing_publication_owner)?;
                    *state = ExactCheckpointPublicationState::CleanupPending {
                        captures,
                        publication,
                    };
                    return Err(error);
                }
                match checkpoint_store::reconcile_indeterminate_publication(
                    &self.config.run_state_root,
                    &self.scenario,
                    &self.source,
                    identity,
                ) {
                    Ok(Some(observed)) if observed == configuration_id => {
                        ExactCaptureDisposition::Published
                    }
                    Ok(Some(observed)) => {
                        let state = self
                            .checkpoint_targets
                            .get_mut(&configuration_id)
                            .ok_or_else(missing_publication_owner)?;
                        *state = ExactCheckpointPublicationState::CleanupPending {
                            captures,
                            publication,
                        };
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "indeterminate exact checkpoint {} authenticates configuration {} instead of {}",
                                identity.to_hex(),
                                observed.to_hex(),
                                configuration_id.to_hex(),
                            ),
                        });
                    }
                    Ok(None) => ExactCaptureDisposition::Unpublished,
                    Err(error) => {
                        let state = self
                            .checkpoint_targets
                            .get_mut(&configuration_id)
                            .ok_or_else(missing_publication_owner)?;
                        *state = ExactCheckpointPublicationState::CleanupPending {
                            captures,
                            publication,
                        };
                        return Err(error);
                    }
                }
            } else {
                ExactCaptureDisposition::Unpublished
            };
            match disposition {
                ExactCaptureDisposition::Published => {
                    let identity =
                        publication.ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: String::from(
                                "published exact checkpoint cleanup lost its closure identity",
                            ),
                        })?;
                    if let Err(error) =
                        self.retain_exact_ram_parent_from_closure(configuration_id, identity)
                    {
                        let state = self
                            .checkpoint_targets
                            .get_mut(&configuration_id)
                            .ok_or_else(missing_publication_owner)?;
                        *state = ExactCheckpointPublicationState::CleanupPending {
                            captures,
                            publication,
                        };
                        return Err(error);
                    }
                }
                ExactCaptureDisposition::Unpublished => {
                    self.exact_ram_parents.remove(&configuration_id);
                }
            }
            if let Err(error) = self.release_exact_captures(&mut captures, disposition) {
                let state = self
                    .checkpoint_targets
                    .get_mut(&configuration_id)
                    .ok_or_else(missing_publication_owner)?;
                *state = ExactCheckpointPublicationState::CleanupPending {
                    captures,
                    publication,
                };
                return Err(error);
            }
            if disposition == ExactCaptureDisposition::Published {
                let identity = publication.ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from(
                        "published exact checkpoint cleanup lost its closure identity",
                    ),
                })?;
                let state = self
                    .checkpoint_targets
                    .get_mut(&configuration_id)
                    .ok_or_else(missing_publication_owner)?;
                *state = ExactCheckpointPublicationState::Published(identity);
                self.exact_ram_parents
                    .retain(|candidate, _| *candidate == configuration_id);
                return Ok(identity);
            }
        }
        boundary()?;
        if let Some(identity) = retry_publication {
            match checkpoint_store::reconcile_indeterminate_publication(
                &self.config.run_state_root,
                &self.scenario,
                &self.source,
                identity,
            ) {
                Ok(Some(observed_configuration)) if observed_configuration == configuration_id => {
                    if let Err(error) =
                        self.retain_exact_ram_parent_from_closure(configuration_id, identity)
                    {
                        let state = self
                            .checkpoint_targets
                            .get_mut(&configuration_id)
                            .ok_or_else(missing_publication_owner)?;
                        *state =
                            ExactCheckpointPublicationState::PublicationIndeterminate(identity);
                        return Err(error);
                    }
                    return finish_reconciled_exact_ram_publication(
                        &mut self.checkpoint_targets,
                        &mut self.exact_ram_parents,
                        configuration_id,
                        identity,
                    );
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

        boundary()?;
        let result = self.capture_reserved_exact_checkpoint_set(configuration, boundary);
        finish_exact_checkpoint_transaction(&mut self.checkpoint_targets, configuration_id, result)
    }

    /// Deletes every snapshot and resumes each previously running node.
    ///
    /// # Errors
    ///
    /// Returns the first cleanup error after attempting every snapshot.
    pub(super) fn release_exact_captures(
        &mut self,
        captured: &mut Vec<PendingExactCapture>,
        disposition: ExactCaptureDisposition,
    ) -> Result<(), SchedulerError> {
        cleanup_exact_captures_with(
            captured,
            |capture| {
                if let Some(candidate) = capture.exact_checkpoint {
                    self.resolve_exact_checkpoint_candidate(&capture.node, candidate, disposition)?;
                    capture.exact_checkpoint = None;
                } else if capture.snapshot_cleanup_pending {
                    self.inner
                        .backend_mut()
                        .delete_exact_snapshot(&capture.node, &capture.snapshot)
                        .map_err(SchedulerError::from)?;
                    capture.snapshot_cleanup_pending = false;
                }
                if capture.resume_pending {
                    self.inner
                        .backend_mut()
                        .resume_after_exact_snapshot(&capture.node)
                        .map_err(SchedulerError::from)?;
                    capture.resume_pending = false;
                }
                Ok(())
            },
            |capture| {
                capture.exact_checkpoint.is_some()
                    || capture.snapshot_cleanup_pending
                    || capture.resume_pending
            },
        )
    }

    fn resolve_exact_checkpoint_candidate(
        &mut self,
        node: &NodeId,
        candidate: PendingExactCheckpointCandidate,
        disposition: ExactCaptureDisposition,
    ) -> Result<(), SchedulerError> {
        let state = self
            .inner
            .backend_mut()
            .query_exact_checkpoint_epoch(node)?;
        let already_resolved = match disposition {
            ExactCaptureDisposition::Published => {
                state.committed() == Some(candidate.identity) && state.candidate().is_none()
            }
            ExactCaptureDisposition::Unpublished => {
                state.committed() == candidate.parent && state.candidate().is_none()
            }
        };
        if already_resolved {
            return Ok(());
        }
        if state.committed() != candidate.parent || state.candidate() != Some(candidate.identity) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "exact checkpoint QEMU epoch for `{}` differs before {:?} disposition",
                    node.name, disposition,
                ),
            });
        }

        let resolved = match disposition {
            ExactCaptureDisposition::Published => self
                .inner
                .backend_mut()
                .commit_exact_checkpoint(node, candidate.identity)?,
            ExactCaptureDisposition::Unpublished => self
                .inner
                .backend_mut()
                .abort_exact_checkpoint(node, candidate.identity, candidate.parent)?,
        };
        let valid = match disposition {
            ExactCaptureDisposition::Published => {
                resolved.committed() == Some(candidate.identity) && resolved.candidate().is_none()
            }
            ExactCaptureDisposition::Unpublished => {
                resolved.committed() == candidate.parent && resolved.candidate().is_none()
            }
        };
        if !valid {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "exact checkpoint QEMU epoch for `{}` did not reach {:?} disposition",
                    node.name, disposition,
                ),
            });
        }
        Ok(())
    }

    fn retain_exact_ram_parent_from_closure(
        &mut self,
        configuration: ContentHash,
        closure: ContentHash,
    ) -> Result<(), SchedulerError> {
        if self.exact_ram_parents.contains_key(&configuration) {
            return Ok(());
        }
        let checkpoint = load_exact_checkpoint_set(
            &self.config.run_state_root,
            &self.scenario,
            &self.source,
            closure,
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!(
                "reload indeterminate exact RAM publication {}: {error}",
                closure.to_hex()
            ),
        })?;
        if checkpoint.configuration.id() != configuration || checkpoint.identity != closure {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "reloaded exact RAM publication differs from its transaction identity",
                ),
            });
        }
        let mut targets = BTreeMap::new();
        for (node, target) in checkpoint.targets {
            let ProductionVmExactCheckpointMaterialization::Native { exact_ram, .. } =
                target.materialization
            else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "indeterminate native checkpoint contains a repository restore target",
                    ),
                });
            };
            targets.insert(node, *exact_ram);
        }
        self.exact_ram_parents.insert(
            configuration,
            ProductionExactRamPublishedParent { closure, targets },
        );
        Ok(())
    }
}

fn cleanup_exact_captures_with<T, E>(
    captured: &mut Vec<T>,
    mut cleanup: impl FnMut(&mut T) -> Result<(), E>,
    pending: impl Fn(&T) -> bool,
) -> Result<(), E> {
    let mut first_error = None;
    for capture in captured.iter_mut().rev() {
        match cleanup(capture) {
            Ok(()) => {}
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    captured.retain(pending);
    first_error.map_or(Ok(()), Err)
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
            *state = match (captures.is_empty(), identity) {
                (true, Some(identity)) => {
                    ExactCheckpointPublicationState::PublicationIndeterminate(identity)
                }
                (_, publication) => ExactCheckpointPublicationState::CleanupPending {
                    captures,
                    publication,
                },
            };
            Err(source)
        }
    }
}

fn finish_reconciled_exact_ram_publication<T>(
    publications: &mut BTreeMap<ContentHash, ExactCheckpointPublicationState>,
    parents: &mut BTreeMap<ContentHash, T>,
    configuration: ContentHash,
    identity: ContentHash,
) -> Result<ContentHash, SchedulerError> {
    let state = publications
        .get_mut(&configuration)
        .ok_or_else(missing_publication_owner)?;
    if !parents.contains_key(&configuration) {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "reconciled exact checkpoint has no authenticated RAM parent lease",
            ),
        });
    }
    parents.retain(|candidate, _| *candidate == configuration);
    *state = ExactCheckpointPublicationState::Published(identity);
    Ok(identity)
}

fn missing_publication_owner() -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: String::from("exact checkpoint publication owner disappeared"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boundary_error(message: &str) -> SchedulerError {
        SchedulerError::BoundaryViolation {
            message: String::from(message),
        }
    }

    fn checkpoint_identity(label: &str) -> ProductionExactCheckpointIdentity {
        ProductionExactCheckpointIdentity {
            checkpoint: ContentHash::from_bytes(format!("{label} checkpoint").as_bytes()),
            target: ContentHash::from_bytes(format!("{label} target").as_bytes()),
            frontier: ContentHash::from_bytes(format!("{label} frontier").as_bytes()),
        }
    }

    fn retained_test_artifact(
        lease: &Arc<RetainedChunkStoreLease>,
        label: &str,
    ) -> ProductionCheckpointArtifact {
        ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::RetainedChunkStore(Arc::clone(lease)),
            identity: ContentHash::from_bytes(label.as_bytes()),
            length: 1,
            chunks: Vec::new(),
            sparse: false,
            extents: Vec::new(),
        }
    }

    fn staged_test_artifact(label: &str) -> ProductionCheckpointArtifact {
        ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::ChunkStore(PathBuf::from(label)),
            identity: ContentHash::from_bytes(label.as_bytes()),
            length: 1,
            chunks: Vec::new(),
            sparse: false,
            extents: Vec::new(),
        }
    }

    #[test]
    fn cleanup_attempts_every_capture_in_reverse_order() {
        #[derive(Debug, PartialEq, Eq)]
        struct Capture {
            id: u8,
            pending: bool,
        }
        let mut captures = vec![
            Capture {
                id: 1,
                pending: true,
            },
            Capture {
                id: 2,
                pending: true,
            },
            Capture {
                id: 3,
                pending: true,
            },
        ];
        let mut observed = Vec::new();
        let error = match cleanup_exact_captures_with(
            &mut captures,
            |capture| {
                observed.push(capture.id);
                if capture.id == 3 || capture.id == 1 {
                    Err(capture.id)
                } else {
                    capture.pending = false;
                    Ok(())
                }
            },
            |capture| capture.pending,
        ) {
            Ok(()) => panic!("the first reverse-order cleanup error should survive"),
            Err(error) => error,
        };

        assert_eq!(observed, [3, 2, 1]);
        assert_eq!(error, 3);
        assert_eq!(
            captures,
            [
                Capture {
                    id: 1,
                    pending: true
                },
                Capture {
                    id: 3,
                    pending: true
                }
            ]
        );
    }

    #[test]
    fn cleanup_retry_preserves_delete_before_resume_order() {
        #[derive(Debug)]
        struct Capture {
            delete_pending: bool,
            resume_pending: bool,
        }
        let mut captures = vec![Capture {
            delete_pending: true,
            resume_pending: true,
        }];
        let mut operations = Vec::new();

        let first = cleanup_exact_captures_with(
            &mut captures,
            |capture| {
                operations.push("delete-failed");
                assert!(capture.delete_pending);
                Err("delete")
            },
            |capture| capture.delete_pending || capture.resume_pending,
        );
        assert_eq!(first, Err("delete"));
        assert_eq!(captures.len(), 1);

        let second = cleanup_exact_captures_with(
            &mut captures,
            |capture| {
                if capture.delete_pending {
                    operations.push("delete");
                    capture.delete_pending = false;
                }
                operations.push("resume-failed");
                Err("resume")
            },
            |capture| capture.delete_pending || capture.resume_pending,
        );
        assert_eq!(second, Err("resume"));
        assert!(!captures[0].delete_pending);
        assert!(captures[0].resume_pending);

        cleanup_exact_captures_with(
            &mut captures,
            |capture| {
                assert!(!capture.delete_pending);
                operations.push("resume");
                capture.resume_pending = false;
                Ok::<_, &str>(())
            },
            |capture| capture.delete_pending || capture.resume_pending,
        )
        .unwrap_or_else(|error| panic!("resume retry should finish cleanup: {error}"));
        assert!(captures.is_empty());
        assert_eq!(
            operations,
            ["delete-failed", "delete", "resume-failed", "resume"]
        );
    }

    #[test]
    fn publication_registry_retains_only_durable_or_indeterminate_owners() {
        let configuration = ContentHash::from_bytes(b"configuration");
        let identity = ContentHash::from_bytes(b"checkpoint");

        let mut publications =
            BTreeMap::from([(configuration, ExactCheckpointPublicationState::Preparing)]);
        let committed = match finish_exact_checkpoint_transaction(
            &mut publications,
            configuration,
            Ok(identity),
        ) {
            Ok(committed) => committed,
            Err(error) => panic!("publication should commit: {error}"),
        };
        assert_eq!(committed, identity);
        assert!(matches!(
            publications.get(&configuration),
            Some(ExactCheckpointPublicationState::Published(observed)) if *observed == identity
        ));

        publications.insert(configuration, ExactCheckpointPublicationState::Preparing);
        assert!(
            finish_exact_checkpoint_transaction(
                &mut publications,
                configuration,
                Err(ExactCheckpointTransactionError::Unpublished(
                    boundary_error("unpublished",)
                )),
            )
            .is_err()
        );
        assert!(!publications.contains_key(&configuration));

        publications.insert(configuration, ExactCheckpointPublicationState::Preparing);
        assert!(
            finish_exact_checkpoint_transaction(
                &mut publications,
                configuration,
                Err(ExactCheckpointTransactionError::Indeterminate {
                    identity: Some(identity),
                    captures: Vec::new(),
                    source: boundary_error("indeterminate"),
                }),
            )
            .is_err()
        );
        assert!(matches!(
            publications.get(&configuration),
            Some(ExactCheckpointPublicationState::PublicationIndeterminate(observed))
                if *observed == identity
        ));

        publications.insert(configuration, ExactCheckpointPublicationState::Preparing);
        assert!(
            finish_exact_checkpoint_transaction(
                &mut publications,
                configuration,
                Err(ExactCheckpointTransactionError::Indeterminate {
                    identity: None,
                    captures: Vec::new(),
                    source: boundary_error("cleanup pending"),
                }),
            )
            .is_err()
        );
        assert!(matches!(
            publications.get(&configuration),
            Some(ExactCheckpointPublicationState::CleanupPending {
                captures,
                publication: None,
            }) if captures.is_empty()
        ));
    }

    #[test]
    fn reconciled_publication_requires_and_retires_to_its_authenticated_parent() {
        let stale_configuration = ContentHash::from_bytes(b"stale configuration");
        let configuration = ContentHash::from_bytes(b"reconciled configuration");
        let identity = ContentHash::from_bytes(b"reconciled checkpoint");
        let mut publications = BTreeMap::from([(
            configuration,
            ExactCheckpointPublicationState::PublicationIndeterminate(identity),
        )]);
        let mut parents = BTreeMap::from([(stale_configuration, "stale")]);

        assert!(
            finish_reconciled_exact_ram_publication(
                &mut publications,
                &mut parents,
                configuration,
                identity,
            )
            .is_err()
        );
        assert!(matches!(
            publications.get(&configuration),
            Some(ExactCheckpointPublicationState::PublicationIndeterminate(observed))
                if *observed == identity
        ));

        parents.insert(configuration, "authenticated");
        let committed = finish_reconciled_exact_ram_publication(
            &mut publications,
            &mut parents,
            configuration,
            identity,
        )
        .unwrap_or_else(|error| panic!("authenticated reconciliation should commit: {error}"));

        assert_eq!(committed, identity);
        assert_eq!(parents, BTreeMap::from([(configuration, "authenticated")]));
        assert!(matches!(
            publications.get(&configuration),
            Some(ExactCheckpointPublicationState::Published(observed)) if *observed == identity
        ));
    }

    #[test]
    fn ninth_capture_rebases_and_reconciled_publication_retires_ancestors() {
        let node = NodeId {
            name: String::from("vm-a"),
        };
        let topology = ContentHash::from_bytes(b"RAMBlock topology");
        let old_closure = ContentHash::from_bytes(b"eight-layer closure");
        let old_lease = Arc::new(RetainedChunkStoreLease {
            directory: PathBuf::from("old-retained-objects"),
            objects: BTreeMap::new(),
        });
        let old_lease_observer = Arc::downgrade(&old_lease);
        let mut old_layers = Vec::new();
        let mut prior_identity = None;
        for index in 0..crucible::exact_checkpoint::MAX_EXACT_CHECKPOINT_RAM_LAYERS {
            let identity = checkpoint_identity(&format!("layer-{index}"));
            old_layers.push(ProductionExactRamLayer {
                kind: if index == 0 {
                    ProductionExactRamKind::Direct
                } else {
                    ProductionExactRamKind::Delta
                },
                identity,
                parent: prior_identity,
                topology,
                ram_regions: 1,
                ram_records: 1,
                content_sha256: ContentHash::from_bytes(format!("layer-{index} sha256").as_bytes()),
                artifact: retained_test_artifact(&old_lease, &format!("layer-{index} artifact")),
            });
            prior_identity = Some(identity);
        }
        let old_identity = prior_identity.unwrap_or_else(|| panic!("test chain must be nonempty"));
        let old_checkpoint = ProductionExactRamCheckpoint::new(
            Some(old_closure),
            ContentHash::from_bytes(b"old device sha256"),
            retained_test_artifact(&old_lease, "old device artifact"),
            old_layers,
        )
        .unwrap_or_else(|error| panic!("build eight-layer parent: {error}"));
        drop(old_lease);

        let old_configuration = old_identity.checkpoint;
        let mut parents = BTreeMap::from([(
            old_configuration,
            ProductionExactRamPublishedParent {
                closure: old_closure,
                targets: BTreeMap::from([(node.clone(), old_checkpoint)]),
            },
        )]);
        let (parent_closure, parent_checkpoint) =
            retained_exact_ram_parent_for_committed(&parents, &node, Some(old_identity.into()))
                .unwrap_or_else(|error| panic!("select eight-layer parent: {error}"));
        let parent_checkpoint =
            parent_checkpoint.unwrap_or_else(|| panic!("committed parent must be retained"));

        assert_eq!(parent_closure, Some(old_closure));
        assert!(parent_checkpoint.requires_direct_compaction());
        assert_eq!(
            exact_ram_capture_kind_for_parent(Some(&parent_checkpoint)),
            ProductionExactRamKind::Direct
        );

        let new_identity = checkpoint_identity("ninth-capture");
        let compacted = ProductionExactRamCheckpoint::from_captured_layer(
            parent_closure,
            Some(parent_checkpoint),
            ProductionExactRamKind::Direct,
            ContentHash::from_bytes(b"new device sha256"),
            staged_test_artifact("new device artifact"),
            ProductionExactRamLayer {
                kind: ProductionExactRamKind::Direct,
                identity: new_identity,
                parent: None,
                topology,
                ram_regions: 1,
                ram_records: 8,
                content_sha256: ContentHash::from_bytes(b"new direct sha256"),
                artifact: staged_test_artifact("new direct artifact"),
            },
        )
        .unwrap_or_else(|error| panic!("assemble ninth direct capture: {error}"));

        assert_eq!(compacted.parent_closure, None);
        assert_eq!(compacted.identity, new_identity);
        assert_eq!(compacted.layers.len(), 1);
        assert_eq!(compacted.layers[0].kind, ProductionExactRamKind::Direct);
        assert_eq!(compacted.layers[0].parent, None);
        assert!(!compacted.requires_direct_compaction());
        compacted
            .validate()
            .unwrap_or_else(|error| panic!("compacted RAM chain must validate: {error}"));

        // The old CAS lease remains rollback authority until the replacement
        // becomes the only published parent.
        assert!(old_lease_observer.upgrade().is_some());
        let new_configuration = new_identity.checkpoint;
        let new_closure = ContentHash::from_bytes(b"ninth-capture closure");
        parents.insert(
            new_configuration,
            ProductionExactRamPublishedParent {
                closure: new_closure,
                targets: BTreeMap::from([(node.clone(), compacted)]),
            },
        );
        let mut publications = BTreeMap::from([(
            new_configuration,
            ExactCheckpointPublicationState::PublicationIndeterminate(new_closure),
        )]);
        let published = finish_reconciled_exact_ram_publication(
            &mut publications,
            &mut parents,
            new_configuration,
            new_closure,
        )
        .unwrap_or_else(|error| panic!("finish compacted publication: {error}"));

        assert_eq!(published, new_closure);
        assert!(matches!(
            publications.get(&new_configuration),
            Some(ExactCheckpointPublicationState::Published(observed))
                if *observed == new_closure
        ));
        assert!(old_lease_observer.upgrade().is_none());

        let (_, restored) =
            retained_exact_ram_parent_for_committed(&parents, &node, Some(new_identity.into()))
                .unwrap_or_else(|error| panic!("select compacted restore parent: {error}"));
        let restored = restored.unwrap_or_else(|| panic!("compacted parent must be retained"));
        assert_eq!(restored.identity, new_identity);
        assert_eq!(restored.layers.len(), 1);
        assert_eq!(restored.layers[0].kind, ProductionExactRamKind::Direct);
        assert_eq!(
            exact_ram_capture_kind_for_parent(Some(&restored)),
            ProductionExactRamKind::Delta
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn failed_terminal_capture_refreshes_same_configuration_snapshot() {
        let root = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create refresh fixture store: {error}"));
        let fixture =
            checkpoint_store::build_exact_ram_production_checkpoint_codec_fixture(root.path())
                .unwrap_or_else(|error| panic!("build refresh fixture: {error}"));
        let configuration = fixture.configuration().id();
        let previous = fixture.closure().identity();
        let mut lifecycle =
            crate::vm_lifecycle::runtime::tests::production_loop_without_backends(fixture.source());
        lifecycle.config =
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
        lifecycle.checkpoint_targets.insert(
            configuration,
            ExactCheckpointPublicationState::Published(previous),
        );

        assert_eq!(
            lifecycle.capture_exact_checkpoint_set(fixture.configuration()),
            Ok(previous)
        );
        assert!(
            lifecycle
                .capture_fresh_exact_checkpoint_set_with_boundary(
                    fixture.configuration(),
                    &mut || Ok(())
                )
                .is_err(),
            "fresh capture must reach the unavailable live backend, not reuse the snapshot"
        );
        assert!(matches!(
            lifecycle.checkpoint_targets.get(&configuration),
            Some(ExactCheckpointPublicationState::Published(identity)) if *identity == previous
        ));
        assert_eq!(
            lifecycle
                .exact_ram_parents
                .get(&configuration)
                .map(|parent| parent.closure),
            Some(previous)
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn indeterminate_v9_retry_rehydrates_the_parent_used_by_the_next_delta() {
        let root = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create reconciliation fixture store: {error}"));
        let fixture =
            checkpoint_store::build_exact_ram_production_checkpoint_codec_fixture(root.path())
                .unwrap_or_else(|error| panic!("build v9 reconciliation fixture: {error}"));
        let configuration = fixture.configuration().id();
        let identity = fixture.closure().identity();
        let node = NodeId {
            name: String::from("vm-a"),
        };
        let mut lifecycle =
            crate::vm_lifecycle::runtime::tests::production_loop_without_backends(fixture.source());
        lifecycle.config =
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
        lifecycle.checkpoint_targets = BTreeMap::from([(
            configuration,
            ExactCheckpointPublicationState::PublicationIndeterminate(identity),
        )]);
        assert!(lifecycle.exact_ram_parents.is_empty());

        let committed_closure = lifecycle
            .capture_exact_checkpoint_set(fixture.configuration())
            .unwrap_or_else(|error| panic!("retry indeterminate v9 publication: {error}"));
        assert_eq!(committed_closure, identity);
        assert!(matches!(
            lifecycle.checkpoint_targets.get(&configuration),
            Some(ExactCheckpointPublicationState::Published(observed)) if *observed == identity
        ));

        let committed = lifecycle
            .exact_ram_parents
            .get(&configuration)
            .and_then(|parent| parent.targets.get(&node))
            .map(|checkpoint| QmpCheckpointIdentity::from(checkpoint.identity))
            .unwrap_or_else(|| panic!("retry should hydrate the v9 exact RAM parent"));
        assert_eq!(committed.checkpoint(), configuration);

        let (parent_closure, parent) = retained_exact_ram_parent_for_committed(
            &lifecycle.exact_ram_parents,
            &node,
            Some(committed),
        )
        .unwrap_or_else(|error| panic!("select next delta parent: {error}"));
        assert_eq!(parent_closure, Some(identity));
        let parent = parent.unwrap_or_else(|| panic!("next capture should have a delta parent"));
        assert_eq!(parent.layers.len(), 2);
        assert!(!parent.requires_direct_compaction());
    }
}
#[cfg(test)]
#[path = "checkpoint_capture/tests.rs"]
mod preparation_tests;
