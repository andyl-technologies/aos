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
    /// Scheduler time paired with the physical counter.
    pub(super) scheduler_time: VirtualTime,
    /// Live QEMU snapshot deleted before publication or during rollback.
    pub(super) snapshot: ExactSnapshotHandle,
    /// Whether the live QMP snapshot still requires deletion.
    pub(super) snapshot_cleanup_pending: bool,
    /// Whether a formerly running node remains paused at the capture boundary.
    pub(super) resume_pending: bool,
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

    pub(in crate::vm_lifecycle) fn capture_exact_checkpoint_set_with_boundary(
        &mut self,
        configuration: &Configuration,
        boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
    ) -> Result<ContentHash, SchedulerError> {
        boundary()?;
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
            if let Err(error) = self.release_exact_captures(&mut captures) {
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
            retry_publication = publication;
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
    ) -> Result<(), SchedulerError> {
        cleanup_exact_captures_with(
            captured,
            |capture| {
                if capture.snapshot_cleanup_pending {
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
            |capture| capture.snapshot_cleanup_pending || capture.resume_pending,
        )
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
}
