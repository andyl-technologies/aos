//! Retains the distinct cold Inventory18 native progress under actual Recover.
//!
//! The enclosing authorized loan and its same C/Source/profile interval remain
//! borrowed while Security drives the common cold kernel. This field holds no
//! Journal and never claims, restores or resets an initial/J/U/C23 receiver.

pub(in crate::controller_resource_reservation) mod inventory;
pub use inventory::{OperatorRecoverInventoryLoanV1, OperatorRecoverInventoryDisposalV1,
    OperatorReconciliationInventoryLoanV2, ControllerRecoveryInventoryLoanV2};

use super::*;
use crate::{ControllerInitialBrokerSessionReceivingV1, ControllerInitialBrokerSessionShapeV1};

#[derive(Default)]
pub(super) struct OperatorRecoverStorageSessionOriginalV1 {
    receiver: Option<ControllerInitialBrokerSessionReceivingV1>,
    inventory: inventory::InventoryOriginalsV1,
    entered: bool,
    reentry: Option<ResourceReservationErrorV1>,
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    sdk_refusal: Option<ResourceReservationErrorV1>,
}

impl OperatorCreateRecoveryLoanV1<'_, '_> {
    /// Prepares the cold native receiver under this authorized Recover once.
    ///
    /// # Errors
    /// Retains repeated entry, original expiry, funding, native or currentness
    /// refusal. The whole entered native progress remains on the Recover owner.
    #[doc(hidden)]
    pub fn prepare_storage_session_once_v1(&mut self, shape: ControllerInitialBrokerSessionShapeV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.prepare_recovery_session_once_v2(shape, false)
    }

    pub(super) fn prepare_recovery_session_once_v2(&mut self, shape: ControllerInitialBrokerSessionShapeV1,
        stop_cleanup: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.owner.storage.entered {
            self.owner.storage.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.storage.entered = true;
        self.owner.storage.preparation = Some((|| {
            self.require_current_v1()?;
            let cutoff = self.original_cutoff_v1()?;
            let native = self.owner.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let bank = self.owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            self.owner.storage.receiver = Some(if stop_cleanup {
                bank.prepare_operator_recover_stop_session_v1(native, self.controller,
                    Arc::clone(&self.owner.profile), shape, Arc::clone(&self.owner.runtime), cutoff)?
            } else {
                bank.prepare_operator_recover_storage_session_v1(native, self.controller,
                    Arc::clone(&self.owner.profile), shape, Arc::clone(&self.owner.runtime), cutoff)?
            });
            if self.owner.storage.receiver.as_ref().is_some_and(|receiver| receiver.failure().is_none()) {
                Ok(())
            } else {
                Err(ResourceReservationErrorV1::Conflict)
            }
        })());
        match &self.owner.storage.preparation {
            Some(Ok(())) => Ok(()),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Moves the genuinely prepared cold receiver into its SDK capture once.
    ///
    /// # Errors
    /// Refuses an unprepared, expired, changed or already moved original. The
    /// enclosing Recover native original remains live through its owed posts.
    #[doc(hidden)]
    pub fn take_storage_session_receiver_once_v1(&mut self)
        -> Result<ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1>
    {
        self.require_current_v1()?;
        if !matches!(self.owner.storage.preparation, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.storage.receiver.take().ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Latches an external SDK refusal before independently owed C/Source posts.
    ///
    /// This negative-only diagnostic marker cannot manufacture successful
    /// capture, Inventory, acceptance or disposition.
    #[doc(hidden)]
    pub fn retain_storage_sdk_refusal_once_v1(&mut self) {
        if self.owner.storage.failure_v1().is_none() {
            self.owner.storage.sdk_refusal.get_or_insert(ResourceReservationErrorV1::Conflict);
        }
        self.owner.latch_primary_failure_v1();
    }

    /// Borrows the retained native preparation failure without releasing it.
    #[doc(hidden)]
    pub fn storage_session_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.storage.failure_v1()
    }

    /// Exclusively lends the same genuinely prepared cold receiver.
    ///
    /// # Errors
    /// Refuses failed authorization, changed C, preparation or original horizon.
    #[doc(hidden)]
    pub fn borrow_storage_session_receiver_v1(&mut self)
        -> Result<&mut ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1>
    {
        self.require_current_v1()?;
        if !matches!(self.owner.storage.preparation, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.storage.receiver.as_mut().ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl OperatorRecoverStorageSessionOriginalV1 {
    pub(super) fn require_root_inventory_data_v1(&self, journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<([u8; 16], [u8; 32]), ResourceReservationErrorV1> {
        self.inventory.require_root_inventory_data_v1(journal, outcome)
    }

    /// Borrows this owner's actual completed passive Host3 query coordinates.
    ///
    /// The existing inventory engine checks its native completion, Session,
    /// signed request/body, original cutoff and positive disposal. This lends
    /// comparison DATA only and leaves the private native owner in place.
    ///
    /// # Errors
    /// Refuses an incomplete, failed, foreign or changed completed query.
    pub(super) fn require_stop_cleanup_inventory_data_v1(&self, journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<([u8; 16], [u8; 32]), ResourceReservationErrorV1> {
        let method = aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
        self.inventory.require_completed_inventory_data_v2(journal, outcome, method, false)
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.inventory.failure_v1().or_else(|| self.receiver.as_ref().and_then(ControllerInitialBrokerSessionReceivingV1::failure))
            .or_else(|| self.preparation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
            .or_else(|| self.sdk_refusal.as_ref().map(|cause| cause as _))
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Identifies the retained external SDK marker selected before outer posts.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_sdk_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(FirstV1::Storage)) && self.storage.sdk_refusal.is_some()
    }
}
