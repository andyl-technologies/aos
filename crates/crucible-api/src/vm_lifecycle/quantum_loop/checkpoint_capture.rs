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

/// Sole owner of one live QEMU snapshot during reversible capture.
pub(super) struct CapturedExactCheckpointTarget {
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

    /// Deletes every captured QEMU snapshot in reverse capture order.
    ///
    /// # Errors
    ///
    /// Returns the first deletion error after attempting every snapshot.
    pub(super) fn rollback_exact_captures(
        &mut self,
        captured: &[CapturedExactCheckpointTarget],
    ) -> Result<(), SchedulerError> {
        cleanup_exact_captures_with(captured, |capture| {
            self.inner
                .backend_mut()
                .delete_exact_snapshot(&capture.node, &capture.snapshot)
                .map_err(SchedulerError::from)
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
        let captures = [1_u8, 2, 3];
        let mut observed = Vec::new();
        let error = cleanup_exact_captures_with(&captures, |capture| {
            observed.push(*capture);
            if *capture == 3 || *capture == 1 {
                Err(*capture)
            } else {
                Ok(())
            }
        })
        .expect_err("the first reverse-order cleanup error should survive");

        assert_eq!(observed, [3, 2, 1]);
        assert_eq!(error, 3);
    }

    #[test]
    fn publication_registry_retains_only_durable_or_indeterminate_owners() {
        let configuration = ContentHash::from_bytes(b"configuration");
        let identity = ContentHash::from_bytes(b"checkpoint");

        let mut publications =
            BTreeMap::from([(configuration, ExactCheckpointPublicationState::Preparing)]);
        assert_eq!(
            finish_exact_checkpoint_transaction(&mut publications, configuration, Ok(identity),)
                .expect("publication should commit"),
            identity
        );
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
