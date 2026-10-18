//! Returns an admitted external lifecycle through its own original destination.
//!
//! Live state owns three existing values: the actual Loop, its validated empty
//! construction Box, and its exclusive original return destination. Public
//! borrowing exposes operations rather than a replaceable sized Loop. The
//! terminal move installs that same body and Box without a fallible handoff.

use super::*;
use crate::lifecycle_cleanup::SourceBodyReturn;

/// Retains a witnessed lifecycle until canonical Main custody accepts its body.
///
/// Construction moves existing owners and allocates nothing. Its destructor
/// performs fixed metadata delivery only; actual cleanup remains with the same
/// Main cell and saved authority. Delivery never claims physical completion.
#[must_use = "the actual lifecycle must return to its original Main role"]
pub struct MainSourceLifecycle {
    state: MainLifecycleState,
}

/// Preserves an unexportable actual lifecycle without allocating a carrier.
///
/// This explicit invalid-input failure owns the original body. It supplies no
/// automatic containment or cleanup proof; callers retain or return that body.
pub struct MainSourceLifecycleFailure {
    lifecycle: ProductionVmLifecycleLoop,
    refusal: MainSourceLifecycleRefusal,
}

/// Identifies the actual refused precondition of an external lifecycle export.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum MainSourceLifecycleRefusal {
    /// No genuine original destination was prepared before export.
    #[error("original lifecycle return destination is absent")]
    DestinationAbsent,
    /// The actual original carrier is missing or cannot receive its body.
    #[error("original lifecycle return carrier is unavailable")]
    CarrierUnavailable,
    /// The retained destination does not select this actual launcher role.
    #[error("original lifecycle return destination is foreign")]
    ForeignDestination,
}

impl MainSourceLifecycleFailure {
    /// Borrows the actual failed export precondition.
    pub fn refusal(&self) -> &MainSourceLifecycleRefusal {
        &self.refusal
    }

    /// Returns the same owning lifecycle for an explicit caller disposition.
    pub fn into_lifecycle(self) -> ProductionVmLifecycleLoop {
        self.lifecycle
    }
}

impl std::fmt::Debug for MainSourceLifecycleFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MainSourceLifecycleFailure")
            .field("refusal", &self.refusal)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for MainSourceLifecycleFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.refusal.fmt(formatter)
    }
}

impl std::error::Error for MainSourceLifecycleFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.refusal)
    }
}

enum MainLifecycleState {
    Live {
        lifecycle: ProductionVmLifecycleLoop,
        carrier: Box<ProductionVmConstructionCustody>,
        destination: SourceBodyReturn,
    },
    Returned,
}

impl ProductionVmLifecycleLoop {
    /// Reserves this actual Loop's return before the final committed export.
    ///
    /// The caller retains the containing Main carrier. Refusal restores the
    /// original token there, and neither slot may be discarded on an error.
    ///
    /// # Errors
    /// Refuses occupied/foreign storage or a reservation that cannot retain its
    /// original external-body destination, preserving the actual token.
    pub(crate) fn prepare_source_body_return(
        &mut self,
        reservation_slot: &mut Option<
            Box<
                dyn crucible_control_api::ProductionVmCleanupReservation<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                        ReturnDestination = SourceBodyReturn,
                    >,
            >,
        >,
        destination_slot: &mut Option<SourceBodyReturn>,
    ) -> Result<(), LifecycleApiError> {
        if !matches!(
            self.construction_custody,
            LifecycleConstructionCustody::Unissued(None)
        ) {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        if let Some(destination) = destination_slot {
            return if reservation_slot.is_none()
                && self
                    .node_launcher
                    .prepared_source_selector()
                    .as_ref()
                    .is_some_and(|selector| destination.matches_selector(selector))
            {
                Ok(())
            } else {
                Err(LifecycleApiError::ConstructionCustodyUnavailable)
            };
        }
        let reservation = reservation_slot
            .take()
            .or_else(|| self.node_launcher.take_cleanup_reservation())
            .ok_or(LifecycleApiError::ConstructionCustodyUnavailable)?;
        match reservation.prepare_return() {
            Ok(destination) => {
                *destination_slot = Some(destination);
                Ok(())
            }
            Err(reservation) => {
                *reservation_slot = Some(reservation);
                Err(LifecycleApiError::ConstructionCustodyUnavailable)
            }
        }
    }

    /// Copies only the actual launcher's original nonissuing Main selection.
    pub(crate) fn prepared_source_selector(&self) -> Option<crate::PreparedSourceSelector> {
        self.node_launcher.prepared_source_selector()
    }

    pub(in crate::vm_lifecycle) fn take_retirement_custody(
        &mut self,
    ) -> Result<
        (
            Box<ProductionVmConstructionCustody>,
            Option<SourceBodyReturn>,
        ),
        LifecycleApiError,
    > {
        let storage = std::mem::replace(
            &mut self.construction_custody,
            LifecycleConstructionCustody::Unissued(None),
        );
        match storage {
            LifecycleConstructionCustody::Main {
                mut carrier,
                destination,
            } => {
                if !carrier.has_empty_return_slot() {
                    self.construction_custody = LifecycleConstructionCustody::Main {
                        carrier,
                        destination,
                    };
                    return Err(LifecycleApiError::ConstructionCustodyUnavailable);
                }
                Ok((carrier, Some(destination)))
            }
            LifecycleConstructionCustody::Unissued(Some(mut carrier)) => {
                if !carrier.has_empty_return_slot() {
                    self.construction_custody =
                        LifecycleConstructionCustody::Unissued(Some(carrier));
                    return Err(LifecycleApiError::ConstructionCustodyUnavailable);
                }
                Ok((carrier, None))
            }
            LifecycleConstructionCustody::Unissued(None) => {
                Err(LifecycleApiError::ConstructionCustodyUnavailable)
            }
        }
    }

    pub(in crate::vm_lifecycle) fn restore_retirement_custody(
        &mut self,
        carrier: Box<ProductionVmConstructionCustody>,
        destination: Option<SourceBodyReturn>,
    ) {
        self.construction_custody = match destination {
            Some(destination) => LifecycleConstructionCustody::Main {
                carrier,
                destination,
            },
            None => LifecycleConstructionCustody::Unissued(Some(carrier)),
        };
    }

    /// Moves this witnessed body into an operation-only external return owner.
    ///
    /// # Errors
    /// Returns this same owning lifecycle when it has no actual Main pair.
    pub fn into_main_lifecycle(
        mut self,
    ) -> Result<MainSourceLifecycle, MainSourceLifecycleFailure> {
        match std::mem::replace(
            &mut self.construction_custody,
            LifecycleConstructionCustody::Unissued(None),
        ) {
            LifecycleConstructionCustody::Main {
                carrier,
                destination,
            } => Ok(MainSourceLifecycle {
                state: MainLifecycleState::Live {
                    lifecycle: self,
                    carrier,
                    destination,
                },
            }),
            unissued @ LifecycleConstructionCustody::Unissued(_) => {
                self.construction_custody = unissued;
                Err(MainSourceLifecycleFailure {
                    lifecycle: self,
                    refusal: MainSourceLifecycleRefusal::DestinationAbsent,
                })
            }
        }
    }

    pub(crate) fn has_main_return(&self) -> bool {
        matches!(
            self.construction_custody,
            LifecycleConstructionCustody::Main { .. }
        )
    }

    /// Consumes an actor-owned native body through its own required Main pair.
    ///
    /// Unissued component/custom bodies keep their ordinary disposal behavior;
    /// that route neither claims native return nor creates a destination.
    pub(crate) fn retire_owned_body(mut self) {
        match std::mem::replace(
            &mut self.construction_custody,
            LifecycleConstructionCustody::Unissued(None),
        ) {
            LifecycleConstructionCustody::Main {
                carrier,
                destination,
            } => {
                let receipt = destination.deliver(carrier.install_owned_return(self));
                drop(receipt);
            }
            unissued @ LifecycleConstructionCustody::Unissued(_) => {
                self.construction_custody = unissued;
                drop(self);
            }
        }
    }
}

impl MainSourceLifecycle {
    /// Holds an already validated actual Loop and its original return pair.
    pub(in crate::vm_lifecycle) fn from_return_pair(
        lifecycle: ProductionVmLifecycleLoop,
        carrier: Box<ProductionVmConstructionCustody>,
        destination: SourceBodyReturn,
    ) -> Self {
        Self {
            state: MainLifecycleState::Live {
                lifecycle,
                carrier,
                destination,
            },
        }
    }

    /// Borrows read-only lifecycle operations without exposing the sized body.
    pub(crate) fn lifecycle(&self) -> Option<&dyn crate::QemuFreshAttemptLifecycleOwner> {
        match &self.state {
            MainLifecycleState::Live { lifecycle, .. } => Some(lifecycle),
            MainLifecycleState::Returned => None,
        }
    }
    /// Borrows lifecycle operations without exposing an extractable sized body.
    #[must_use]
    pub fn lifecycle_mut(&mut self) -> Option<&mut dyn crate::QemuFreshAttemptLifecycleOwner> {
        match &mut self.state {
            MainLifecycleState::Live { lifecycle, .. } => Some(lifecycle),
            MainLifecycleState::Returned => None,
        }
    }

    /// Borrows the actual body for a crate-owned nonextracting operation.
    pub(crate) fn with_lifecycle<R>(
        &self,
        apply: impl FnOnce(&ProductionVmLifecycleLoop) -> R,
    ) -> Option<R> {
        match &self.state {
            MainLifecycleState::Live { lifecycle, .. } => Some(apply(lifecycle)),
            MainLifecycleState::Returned => None,
        }
    }

    /// Runs a fixed crate-owned operation without moving or replacing the body.
    pub(crate) fn with_lifecycle_mut<R>(
        &mut self,
        apply: impl FnOnce(&mut ProductionVmLifecycleLoop) -> R,
    ) -> Option<R> {
        match &mut self.state {
            MainLifecycleState::Live { lifecycle, .. } => Some(apply(lifecycle)),
            MainLifecycleState::Returned => None,
        }
    }

    /// Reattaches the original witness and carrier for an actor-owned lifetime.
    ///
    /// A returned wrapper contains no body. The actual Loop retains its own
    /// destination, so moving it never substitutes an outer cached selection.
    pub(crate) fn into_lifecycle(mut self) -> Option<ProductionVmLifecycleLoop> {
        match std::mem::replace(&mut self.state, MainLifecycleState::Returned) {
            MainLifecycleState::Live {
                mut lifecycle,
                carrier,
                destination,
            } => {
                lifecycle.construction_custody = LifecycleConstructionCustody::Main {
                    carrier,
                    destination,
                };
                Some(lifecycle)
            }
            MainLifecycleState::Returned => None,
        }
    }

    /// Delivers this actual body into its already reserved original Main cell.
    ///
    /// Delivery recovers matching poisoned control metadata into quarantine.
    /// It cannot refuse after taking the body, run cleanup or allocate another
    /// carrier. Repeated calls perform no work after the first delivery.
    pub fn return_to_main(&mut self) {
        let MainLifecycleState::Live {
            lifecycle,
            carrier,
            destination,
        } = std::mem::replace(&mut self.state, MainLifecycleState::Returned)
        else {
            return;
        };
        let carrier = carrier.install_owned_return(lifecycle);
        let receipt = destination.deliver(carrier);
        // No stage/history was extracted into this fresh receipt. Its disposal
        // returns only its report pin; the actual body and raw causes are Main's.
        drop(receipt);
    }
}

impl Drop for MainSourceLifecycle {
    fn drop(&mut self) {
        self.return_to_main();
    }
}

impl std::fmt::Debug for MainSourceLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MainSourceLifecycle")
            .field(
                "returned",
                &matches!(self.state, MainLifecycleState::Returned),
            )
            .finish_non_exhaustive()
    }
}
