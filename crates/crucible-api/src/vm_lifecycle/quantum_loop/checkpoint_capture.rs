//! Transactional ownership for production exact-checkpoint capture.

use super::*;
use std::collections::BTreeMap;

/// Lifecycle-owned state of one exact-checkpoint publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::vm_lifecycle) enum ExactCheckpointPublicationState {
    /// Reversible capture or durable publication is still in progress.
    Preparing,
    /// The authenticated closure is durably published under this identity.
    Published(ContentHash),
    /// Publication or cleanup crossed a boundary whose outcome is ambiguous.
    Indeterminate(Option<ContentHash>),
}

/// Transaction outcome before or across durable closure publication.
pub(super) enum ExactCheckpointTransactionError {
    /// No authenticated closure became visible.
    Unpublished(SchedulerError),
    /// Cleanup or durability could not establish one committed outcome.
    Indeterminate {
        /// Known closure identity when the manifest rename completed.
        identity: Option<ContentHash>,
        /// Primary transaction or cleanup failure.
        source: SchedulerError,
    },
}

/// Sole owner of one paused QEMU snapshot through immutable preparation.
pub(super) struct PendingExactCapture {
    /// World node owning the snapshot.
    pub(super) node: NodeId,
    /// Physical icount captured from the node.
    pub(super) counter: u64,
    /// Scheduler time paired with the physical counter.
    pub(super) scheduler_time: VirtualTime,
    /// Whether the node must resume after publication or rollback.
    pub(super) service_state: ProductionNodeServiceState,
    /// Live QEMU snapshot deleted before publication or during rollback.
    pub(super) snapshot: QemuVmSnapshot,
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
        match self.checkpoint_targets.entry(configuration_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(ExactCheckpointPublicationState::Preparing);
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "exact checkpoint {} was already captured by this lifecycle",
                        configuration_id.to_hex()
                    ),
                });
            }
        }

        let result = self.capture_reserved_exact_checkpoint_set(configuration);
        finish_exact_checkpoint_transaction(&mut self.checkpoint_targets, configuration_id, result)
    }

    /// Deletes every snapshot and resumes each previously running node.
    ///
    /// # Errors
    ///
    /// Returns the first cleanup error after attempting every snapshot.
    pub(super) fn release_exact_captures(
        &mut self,
        captured: &[PendingExactCapture],
    ) -> Result<(), SchedulerError> {
        cleanup_exact_captures_with(captured, |capture| {
            let deletion = self
                .inner
                .backend_mut()
                .delete_exact_snapshot(&capture.node, &capture.snapshot)
                .map_err(SchedulerError::from);
            let resume = if capture.service_state == ProductionNodeServiceState::Running {
                self.inner
                    .backend_mut()
                    .resume_after_exact_snapshot(&capture.node)
                    .map_err(SchedulerError::from)
            } else {
                Ok(())
            };
            match (deletion, resume) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                (Err(deletion), Err(resume)) => Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "delete paused snapshot for `{}` failed ({deletion}); resume also failed ({resume})",
                        capture.node.name
                    ),
                }),
            }
        })
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
        Err(ExactCheckpointTransactionError::Indeterminate { identity, source }) => {
            let state = publications
                .get_mut(&configuration)
                .ok_or_else(missing_publication_owner)?;
            *state = ExactCheckpointPublicationState::Indeterminate(identity);
            Err(source)
        }
    }
}

fn cleanup_exact_captures_with<T, E>(
    captured: &[T],
    mut delete: impl FnMut(&T) -> Result<(), E>,
) -> Result<(), E> {
    let mut first_error = None;
    for capture in captured.iter().rev() {
        if let Err(error) = delete(capture)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
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
        let captures = [1_u8, 2, 3];
        let mut observed = Vec::new();
        let result = cleanup_exact_captures_with(&captures, |capture| {
            observed.push(*capture);
            if *capture == 3 || *capture == 1 {
                Err(*capture)
            } else {
                Ok(())
            }
        });
        let error = match result {
            Ok(()) => panic!("cleanup should retain the first reverse-order error"),
            Err(error) => error,
        };

        assert_eq!(observed, [3, 2, 1]);
        assert_eq!(error, 3);
    }

    #[test]
    fn publication_registry_retains_only_durable_or_indeterminate_owners() {
        let configuration = ContentHash::from_bytes(b"configuration");
        let identity = ContentHash::from_bytes(b"checkpoint");

        let mut publications =
            BTreeMap::from([(configuration, ExactCheckpointPublicationState::Preparing)]);
        let published =
            finish_exact_checkpoint_transaction(&mut publications, configuration, Ok(identity))
                .unwrap_or_else(|error| panic!("publication should commit: {error}"));
        assert_eq!(published, identity);
        assert_eq!(
            publications.get(&configuration),
            Some(&ExactCheckpointPublicationState::Published(identity))
        );

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
                    source: boundary_error("indeterminate"),
                }),
            )
            .is_err()
        );
        assert_eq!(
            publications.get(&configuration),
            Some(&ExactCheckpointPublicationState::Indeterminate(Some(
                identity
            )))
        );
    }
}
