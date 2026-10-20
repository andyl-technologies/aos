//! Owns the original image-paid Create continuation capture entrance.
//!
//! The original completed Q04 parent moves here with its genuine retained
//! child and all native results. J14 is a disjoint image subdivision: it pays
//! only the fixed entered capture and bounded profile archive. It cannot issue
//! U15, a signing challenge, a Prepare request or an Apply permission.
//!
//! A cold row, a changed recipient invocation and an abandoned attempt cannot
//! construct this owner. Native ambiguous outcomes and the original parent
//! remain resident; closure never refunds J or C.

pub(super) mod ready;
pub(super) mod history;
pub(crate) mod provisioning;

use std::sync::{Arc, Mutex};

use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::Journal;

use super::{
    ControllerResourceBankOpeningV1, ProjectPreparationReservationAttemptV1,
    ResourceReservationErrorV1, q04_intake::Q04OriginalIntakeAttemptV1,
};

/// Retains the original completed Q04 parent and one image-paid J capture.
///
/// This owner grants no Root policy, signing, Prepare or Apply permission.
/// Historical rows cannot construct it or replace its moved original parent.
#[must_use]
pub struct CreateContinuationIntakeAttemptV1 {
    parent: ProjectPreparationReservationAttemptV1,
    intake: Q04OriginalIntakeAttemptV1,
    ready_before: Option<Result<ready::CreateStorageAcceptedIdentityV1, ResourceReservationErrorV1>>,
    ready_after: Option<Result<(), ResourceReservationErrorV1>>,
    histories: history::CreateStorageOriginalHistoriesV1,
    assignment: history::assignment::AssignmentPlannedOriginalV1,
    ownership: ready::ownership::OriginalCreateStorageOwnershipV1,
    cache_capture: ready::cache_receiving::CacheCaptureOriginalV1,
    client_session: ready::client_session::ClientSessionOriginalsV1,
    inventory: ready::inventory::InventoryOriginalsV1,
    bundle: ready::bundle::BundleEncodingOriginalsV1,
    root_exchange: ready::root_exchange::RootExchangeOriginalsV1,
    storage_use: ready::use_reserved::CreateStorageUseOriginalsV1,
    ready_loan_borrowed: bool,
    provisioning_entered: bool,
}

impl CreateContinuationIntakeAttemptV1 {
    /// Moves the actual parent and original bank into a vacant capture owner.
    ///
    /// Construction performs no observation or allocation. The entered capture
    /// independently checks that these are the same original enrolled owners.
    pub fn begin(
        parent: ProjectPreparationReservationAttemptV1,
        bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    ) -> Self {
        Self {
            parent,
            intake: Q04OriginalIntakeAttemptV1::begin_create(bank),
            ready_before: None,
            ready_after: None,
            histories: history::CreateStorageOriginalHistoriesV1::default(),
            assignment: history::assignment::AssignmentPlannedOriginalV1::default(),
            ownership: ready::ownership::OriginalCreateStorageOwnershipV1::default(),
            cache_capture: ready::cache_receiving::CacheCaptureOriginalV1::default(),
            client_session: ready::client_session::ClientSessionOriginalsV1::default(),
            inventory: ready::inventory::InventoryOriginalsV1::default(),
            bundle: ready::bundle::BundleEncodingOriginalsV1::default(),
            root_exchange: ready::root_exchange::RootExchangeOriginalsV1::default(),
            storage_use: ready::use_reserved::CreateStorageUseOriginalsV1::default(),
            ready_loan_borrowed: false,
            provisioning_entered: false,
        }
    }

    /// Pays and captures the fixed original J entrance once.
    ///
    /// # Errors
    /// Retains original-parent, bank, profile, clock, native-append and independent
    /// post failures. Repeated entry cannot rearm or refund this subdivision.
    pub fn prepare_once(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.intake.prepare_create_once(controller, source, profile, &self.parent)
    }

    /// Persists the original Controller Intent and the exact new Source Held once.
    ///
    /// This prefix still supplies no complete B, Root proof, U or Prepare grant.
    /// The real writers remain resident in their existing owners; namespace 81
    /// prevents ordinary mutation while the closed continuation is pending.
    ///
    /// # Errors
    /// Retains original-parent, funding, nonce, encoding, native append/readback
    /// and independent post failures. A repeated entrance cannot renew J.
    pub fn produce_original_history_once(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.ready_before.is_some() || self.histories.production.is_some() {
            self.intake.close();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.ready_before = Some((|| {
            self.parent.require_terminal_retention()?;
            self.intake.require_retained_capture()?;
            self.parent.require_create_storage_association(controller, source, profile)?;
            self.parent.create_storage_original_identity_v1()
        })());
        let Some(accepted) = self.ready_before.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.intake.close();
            return Err(ResourceReservationErrorV1::Conflict);
        };
        self.histories.produce_once(&self.parent, &mut self.intake, controller, source, profile, accepted)
    }

    /// Checks same-operation retention without observing or renewing authority.
    ///
    /// This supports a truthful pending Create projection only. It supplies no
    /// live policy, signing challenge, broker request or future capture loan.
    ///
    /// # Errors
    /// Refuses a different accepted operation or absent/failed J native outcome.
    pub fn require_pending_retention(
        &self,
        operation: aos_sandbox_core::OperationId,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.parent.matches_create_operation(operation) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.parent.require_terminal_retention()?;
        self.intake.require_retained_capture()
    }

    /// Requires the actual completed original Create terminal for this operation.
    ///
    /// This historical completion check borrows the same committed J, positive
    /// U, both released owners, C10 and strict Root6 outcome. It performs no IO,
    /// settlement, capture renewal or construction from decoded receipts.
    ///
    /// # Errors
    /// Refuses a foreign operation, failed or incomplete original, missing final
    /// Cache/control post, absent final association seal or unobserved Root6.
    #[doc(hidden)]
    pub fn require_original_create_terminal_v1(
        &self, operation: aos_sandbox_core::OperationId,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.parent.matches_create_operation(operation) || self.failure().is_some()
            || !matches!(self.ready_after, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.parent.require_terminal_retention()?;
        self.intake.require_retained_capture()?;
        self.storage_use.require_completed_cache_terminal_v1()?;
        let handoff = self.storage_use.borrow_handoff_v1()?;
        self.root_exchange.borrow_closed_v1(&handoff)?;
        Ok(())
    }

    // The lane is comparison DATA from this actual owned parent, never a permit.
    pub(crate) fn lane(&self) -> Result<[u8; 16], ResourceReservationErrorV1> {
        self.intake.create_lane()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.parent.failure().or_else(|| self.intake.failure())
            .or_else(|| self.ready_before.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.histories.failure())
            .or_else(|| self.cache_capture.failure())
            .or_else(|| self.client_session.failure())
            .or_else(|| self.assignment.failure())
            .or_else(|| self.inventory.failure())
            .or_else(|| self.bundle.failure())
            .or_else(|| if self.root_exchange.use_tail_funding_failure_is_selected_v1() {
                self.storage_use.failure()
            } else { None })
            .or_else(|| if self.storage_use.release_funding_failure_is_selected_v1() {
                self.storage_use.failure()
            } else { None })
            .or_else(|| self.storage_use.selected_release_primary_failure_v1())
            .or_else(|| self.storage_use.selected_handoff_primary_failure_v1())
            .or_else(|| self.root_exchange.failure())
            .or_else(|| self.storage_use.failure())
            .or_else(|| self.ownership.fatal_failure())
            .or_else(|| self.ready_after.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    pub(crate) fn close(&self) {
        self.intake.close();
    }
}

#[cfg(test)]
pub(super) fn create_intake_layout_diagnostics_v1() -> [(&'static str, usize); 12] {
    use std::mem::size_of;
    println!("AOS_CREATE_ROOT_LAYOUT {:?}", ready::root_exchange::root_layout_diagnostics_v1());
    [
        ("whole", size_of::<CreateContinuationIntakeAttemptV1>()),
        ("parent", size_of::<ProjectPreparationReservationAttemptV1>()),
        ("intake", size_of::<Q04OriginalIntakeAttemptV1>()),
        ("histories", size_of::<history::CreateStorageOriginalHistoriesV1>()),
        ("assignment", size_of::<history::assignment::AssignmentPlannedOriginalV1>()),
        ("ownership", size_of::<ready::ownership::OriginalCreateStorageOwnershipV1>()),
        ("cache", size_of::<ready::cache_receiving::CacheCaptureOriginalV1>()),
        ("client", size_of::<ready::client_session::ClientSessionOriginalsV1>()),
        ("inventory", size_of::<ready::inventory::InventoryOriginalsV1>()),
        ("bundle", size_of::<ready::bundle::BundleEncodingOriginalsV1>()),
        ("root", size_of::<ready::root_exchange::RootExchangeOriginalsV1>()),
        ("use", size_of::<ready::use_reserved::CreateStorageUseOriginalsV1>()),
    ]
}
