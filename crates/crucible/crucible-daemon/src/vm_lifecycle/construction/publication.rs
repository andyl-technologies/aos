//! Publishes a failed constructor into its actual pre-reserved Main cell.

use super::custody::{FailureStorage, Phase};
use super::*;

impl ProductionVmConstructionFailure {
    /// Moves the same preallocated carrier into its original cleanup cell.
    ///
    /// This publishes custody without executing cleanup or requiring the
    /// expired Preparation to become live again. The original typed error is
    /// returned only after the actual owner is reachable from Main.
    ///
    /// # Errors
    /// Returns this same owning failure if storage, its exact reservation or
    /// the authenticated cell is unavailable. Every refused handoff retains
    /// both the returned owner and its original reservation.
    pub fn retain_in_reserved_cleanup(
        self,
    ) -> Result<
        (
            LifecycleApiError,
            Box<
                dyn crucible_control_api::ProductionVmCleanupHandoff<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                    >,
            >,
        ),
        Self,
    > {
        let Self {
            storage: FailureStorage::Preallocated(mut custody),
            additional: None,
        } = self
        else {
            return Err(self);
        };
        if custody.first.is_none() {
            return Err(Self {
                storage: FailureStorage::Preallocated(custody),
                additional: None,
            });
        }

        if custody.reservation.is_none() {
            let phase = match custody.phase.get_mut() {
                Ok(phase) => phase,
                Err(_) => {
                    return Err(Self {
                        storage: FailureStorage::Preallocated(custody),
                        additional: None,
                    });
                }
            };
            custody.reservation = match phase {
                Phase::Partial(partial) => partial
                    .node_launcher
                    .as_mut()
                    .and_then(|launcher| launcher.take_cleanup_reservation()),
                Phase::Complete(lifecycle) => lifecycle.node_launcher.take_cleanup_reservation(),
                #[cfg(target_os = "linux")]
                Phase::Source(_)
                | Phase::SourcePreparation(_)
                | Phase::SharedSource(_)
                | Phase::SourceRearmFailure(_) => None,
                Phase::Empty => None,
            };
        }
        let Some(reservation) = custody.reservation.take() else {
            return Err(Self {
                storage: FailureStorage::Preallocated(custody),
                additional: None,
            });
        };

        // The diagnostic already exists in this same carrier. Move it only
        // after authentic token extraction; every refused path retains it.
        let Some(first) = custody.first.take() else {
            custody.reservation = Some(reservation);
            return Err(Self {
                storage: FailureStorage::Preallocated(custody),
                additional: None,
            });
        };
        match reservation.retain(custody) {
            Ok(handoff) => Ok((first, handoff)),
            Err((reservation, owner)) => Err(Self {
                storage: FailureStorage::Rejected {
                    first,
                    returned: std::sync::Mutex::new(Some((reservation, owner))),
                },
                additional: None,
            }),
        }
    }

    /// Moves the original cause from an already published, empty error shell.
    ///
    /// This extracts a diagnostic only. Publication is not cleanup or physical
    /// return; its actual owner remains governed by the same cleanup receipt.
    ///
    /// # Errors
    /// Returns the same failure if it still owns a token/body, has an additional
    /// cause, or its publication state is unavailable or poisoned.
    pub fn into_published_error(mut self) -> Result<LifecycleApiError, Self> {
        if self.additional.is_some() {
            return Err(self);
        }
        let FailureStorage::Rejected { returned, .. } = &mut self.storage else {
            return Err(self);
        };
        let Ok(returned) = returned.get_mut() else {
            return Err(self);
        };
        if returned.is_some() {
            return Err(self);
        }
        match self {
            Self {
                storage: FailureStorage::Rejected { first, .. },
                additional: None,
            } => Ok(first),
            retained => Err(retained),
        }
    }

    /// Retries a refused canonical handoff while this failure remains retained.
    ///
    /// # Errors
    /// Preserves the same token and owner on poison, missing storage or repeated
    /// refusal. A successful publication transfers custody to Main; it does not
    /// attest physical cleanup or release the containing World charge.
    pub fn retry_reserved_publication(
        &mut self,
    ) -> Result<
        Option<
            Box<
                dyn crucible_control_api::ProductionVmCleanupHandoff<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                    >,
            >,
        >,
        &'static str,
    > {
        let FailureStorage::Rejected { returned, .. } = &mut self.storage else {
            return Err("construction has no returned canonical handoff");
        };
        let returned = returned
            .get_mut()
            .map_err(|_| "construction handoff is poisoned")?;
        let Some((reservation, owner)) = returned.take() else {
            return Ok(None);
        };
        // The canonical reservation publishes through its sole-writer CAS;
        // publication performs no callbacks, effects, or capacity allocation.
        match reservation.retain(owner) {
            Ok(handoff) => Ok(Some(handoff)),
            Err((reservation, owner)) => {
                *returned = Some((reservation, owner));
                Err("same construction handoff remains refused")
            }
        }
    }
}

impl ProductionVmConstructionCustody {
    /// Publishes normal lifecycle disposal without manufacturing a semantic error.
    ///
    /// The canonical Main cell retries actual physical cleanup and destroys this
    /// same body before it returns the containing World charge.
    ///
    /// # Errors
    /// Returns the same owning carrier, or the same returned token and owner,
    /// on missing or refused authenticated custody. Success proves handoff only.
    pub fn publish_for_cleanup(
        mut self: Box<Self>,
    ) -> Result<
        Box<
            dyn crucible_control_api::ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
        ProductionVmConstructionFailure,
    > {
        self.publish_cleanup_mode(false)
    }

    /// Delivers the same returned body despite a concurrent prepared borrow.
    ///
    /// This fixed custody cut does no IO or cleanup and allocates no owner.
    /// Matching poison remains Main-owned in quarantine after acceptance.
    ///
    /// # Errors
    /// Returns the same owning failure on missing original custody, a foreign
    /// epoch or occupied destination. A caller must retain that actual value.
    pub fn publish_returned_for_cleanup(
        mut self: Box<Self>,
    ) -> Result<
        Box<
            dyn crucible_control_api::ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
        ProductionVmConstructionFailure,
    > {
        self.publish_cleanup_mode(true)
    }

    fn publish_cleanup_mode(
        mut self: Box<Self>,
        returned: bool,
    ) -> Result<
        Box<
            dyn crucible_control_api::ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
        ProductionVmConstructionFailure,
    > {
        if let Some(destination) = self.return_destination.take() {
            return Ok(destination.deliver(self));
        }
        if self.reservation.is_none() {
            let phase = match self.phase.get_mut() {
                Ok(phase) => phase,
                Err(_) => {
                    return Err(
                        self.into_failure(LifecycleApiError::ConstructionCustodyUnavailable)
                    );
                }
            };
            self.reservation = match phase {
                Phase::Partial(partial) => partial
                    .node_launcher
                    .as_mut()
                    .and_then(|launcher| launcher.take_cleanup_reservation()),
                Phase::Complete(lifecycle) => lifecycle.node_launcher.take_cleanup_reservation(),
                #[cfg(target_os = "linux")]
                Phase::Source(_)
                | Phase::SourcePreparation(_)
                | Phase::SharedSource(_)
                | Phase::SourceRearmFailure(_) => None,
                Phase::Empty => None,
            };
        }
        let Some(reservation) = self.reservation.take() else {
            return Err(self.into_failure(LifecycleApiError::ConstructionCustodyUnavailable));
        };
        let publication = if returned {
            reservation.retain_returned(self)
        } else {
            reservation.retain(self)
        };
        match publication {
            Ok(handoff) => Ok(handoff),
            Err((reservation, owner)) => Err(ProductionVmConstructionFailure {
                storage: FailureStorage::Rejected {
                    first: LifecycleApiError::ConstructionCustodyUnavailable,
                    returned: std::sync::Mutex::new(Some((reservation, owner))),
                },
                additional: None,
            }),
        }
    }
}

#[cfg(test)]
mod published_error_tests {
    use super::*;

    fn empty_shell(additional: Option<LifecycleApiError>) -> ProductionVmConstructionFailure {
        // Diagnostic-only shell: no owner, reservation, Main or Source exists.
        ProductionVmConstructionFailure {
            storage: FailureStorage::Rejected {
                first: LifecycleApiError::LoopFactory {
                    message: String::from("original constructor refusal"),
                },
                returned: std::sync::Mutex::new(None),
            },
            additional,
        }
    }

    #[test]
    fn empty_publication_shell_moves_its_original_error() {
        let first = empty_shell(None).into_published_error().unwrap();
        assert!(matches!(first, LifecycleApiError::LoopFactory { message }
            if message == "original constructor refusal"));
    }

    #[test]
    fn additional_cause_keeps_complete_error_shell() {
        let retained = empty_shell(Some(LifecycleApiError::ConstructionCustodyUnavailable))
            .into_published_error()
            .unwrap_err();
        assert!(
            matches!(retained.first_error(), Some(LifecycleApiError::LoopFactory { message })
            if message == "original constructor refusal")
        );
        assert!(retained.additional.is_some());
    }
}

#[cfg(test)]
mod refused_publication_tests;
