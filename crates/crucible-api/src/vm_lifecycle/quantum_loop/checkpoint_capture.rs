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
    /// Snapshot deletions that must succeed before this configuration retries.
    CleanupPending(Vec<CapturedExactCheckpointTarget>),
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
        captures: Vec<CapturedExactCheckpointTarget>,
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
    pub(super) snapshot: QemuVmSnapshot,
    /// Staged overlay metadata once its copy authenticates.
    pub(super) overlay_artifact: Option<ProductionCheckpointArtifact>,
    /// Staged VMState metadata once its copy authenticates.
    pub(super) vmstate_artifact: Option<ProductionCheckpointArtifact>,
    /// Canonical target identity once both artifacts authenticate.
    pub(super) manifest_identity: Option<ContentHash>,
    /// Whether the live VMState artifact still requires deletion.
    pub(super) cleanup_pending: bool,
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
    ) -> Result<(NodeId, ProductionVmExactCheckpointTarget), SchedulerError> {
        let overlay_artifact = self.overlay_artifact.ok_or_else(incomplete_capture)?;
        let vmstate_artifact = self.vmstate_artifact.ok_or_else(incomplete_capture)?;
        let manifest_identity = self.manifest_identity.ok_or_else(incomplete_capture)?;
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
    pub(super) fn capture_exact_checkpoint_set(
        &mut self,
        configuration: &Configuration,
    ) -> Result<ContentHash, SchedulerError> {
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
                    ExactCheckpointPublicationState::CleanupPending(captures) => {
                        retry_cleanup = Some(captures);
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
        if let Some(mut captures) = retry_cleanup
            && let Err(error) = self.rollback_exact_captures(&mut captures)
        {
            let state = self
                .checkpoint_targets
                .get_mut(&configuration_id)
                .ok_or_else(missing_publication_owner)?;
            *state = ExactCheckpointPublicationState::CleanupPending(captures);
            return Err(error);
        }
        if let Some(identity) = retry_publication {
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
mod tests {
    use super::*;

    fn boundary_error(message: &str) -> SchedulerError {
        SchedulerError::BoundaryViolation {
            message: String::from(message),
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
                    Ok(())
                }
            },
            |capture| capture.pending = false,
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
            Some(ExactCheckpointPublicationState::CleanupPending(captures))
                if captures.is_empty()
        ));
    }
}
