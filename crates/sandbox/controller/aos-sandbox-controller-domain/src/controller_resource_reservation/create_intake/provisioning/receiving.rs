//! Retains the next purpose's real C receiver beside its installed issuer.
//!
//! The same original moves into and out of the private Core Journal scope.
//! Neither a Root reply nor a historical terminal record constructs this
//! receiver. Every native turn uses the original Bank, launch and profile.

mod client_session;
mod root_client;
mod runtime_layout;
mod completed_residency;
pub(crate) mod start_entry;
#[doc(hidden)]
pub use start_entry::AcceptedStartEntryOriginalV1;
mod storage_post;
#[doc(hidden)]
pub use storage_post::StorageProvisioningSessionPostShapeDataV1;
pub(in crate::controller_resource_reservation) mod storage_io;

#[doc(hidden)]
pub use storage_io::{StorageProvisioningIoDisposalV1, StorageProvisioningWorkspaceOriginalV1, StorageProvisioningSessionIoShapeDataV1, DeleteStoragePreparationIoOriginalV3, DeleteStorageApplyIoOriginalV3, DeleteNetworkApplyIoOriginalV4, DeleteMountReapIoOriginalV4};
pub(crate) mod source;
pub(crate) mod source_boundary;
pub(crate) use source_boundary::SourceAppendBoundaryV1;

#[doc(hidden)]
pub use client_session::CreateProvisioningClientSessionAssociationErrorV1;

use std::error::Error;
use std::sync::{Arc, Mutex};

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1;
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension, ResourceVector};

use super::CreateStorageCompletedIntakeOriginalV1;
use crate::controller_resource_reservation::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::Journal;

enum NativeResidenceV1 {
    Positive(Box<ControllerCreateProvisioningReceivingV1>),
    Refused(ControllerCreateProvisioningReceivingV1),
}

impl NativeResidenceV1 {
    fn original_v1(&self) -> &ControllerCreateProvisioningReceivingV1 {
        match self {
            Self::Positive(value) => value,
            Self::Refused(value) => value,
        }
    }

    fn original_mut_v1(&mut self) -> &mut ControllerCreateProvisioningReceivingV1 {
        match self {
            Self::Positive(value) => value,
            Self::Refused(value) => value,
        }
    }
}

/// Retains one original Controller provisioning purpose across staged turns.
///
/// Its negative native destination stays inline in the installed worker header,
/// whose compiled layout is paid before this purpose can be entered.
#[doc(hidden)]
#[must_use = "retain this original and finish its independently owed native post"]
pub struct CreateProvisioningOriginalsV1 {
    parent: aos_sandbox_model::OperationId,
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    runtime_layout: Result<runtime_layout::RuntimeLayoutV1, runtime_layout::RuntimeLayoutErrorV1>,
    native: Result<NativeResidenceV1, ResourceReservationErrorV1>,
    demand: Option<Result<(), ResourceReservationErrorV1>>,
    next: Option<Result<(), ResourceReservationErrorV1>>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
    root_client_entered: bool,
    completion_entered: bool,
    start_entry_entered: bool,
    storage_post: storage_post::StoragePostPreparationV1,
    io_cause_before_after: bool,
    source: source::SourceProvisioningOriginalsV1,
    storage_io: storage_io::StorageIoStagesV1,
    native_turn: u64,
    client_session: super::super::ready::client_session::ClientSessionOriginalsV1,
    unissued_storage_apply: Option<crate::reconciler::provisioning::storage_io::UnissuedStorageApplyAttemptV1>,
}

impl CreateProvisioningOriginalsV1 {
    /// Enters from the real terminal before constructing any new native body.
    pub(crate) fn begin_completed_create_v1<T: Sized>(
        completed: &CreateStorageCompletedIntakeOriginalV1<'_>,
        bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        complete: ResourceVector,
        runtime_header: &T,
    ) -> Self {
        let runtime_layout = runtime_layout::RuntimeLayoutV1::from_runtime_header_v1(
            completed.operation_v1(), runtime_header,
        );
        let native = (|| {
            let bytes = std::mem::size_of::<Self>().checked_mul(2)
                .and_then(|n| u64::try_from(n).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = complete.checked_add(ResourceVector::ZERO
                .with(ResourceDimension::MemoryBytes, bytes))?
                .checked_add(runtime_layout.as_ref()
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?
                    .receiving_demand_v1(completed.operation_v1())?)?;
            let bank = bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let native = bank.begin_create_provisioning_receiving_v1(
                completed, controller, source, profile.as_ref(), complete,
            )?;
            // A refusal may not allocate its destination after the debit failed.
            // Its whole original stays in the already-paid inline reservoir.
            Ok(if native.failure().is_some() {
                NativeResidenceV1::Refused(native)
            } else {
                NativeResidenceV1::Positive(Box::new(native))
            })
        })();
        Self { parent: completed.operation_v1(), bank, profile, runtime_layout, native, demand: None, next: None, after: None, root_client_entered: false, completion_entered: false, start_entry_entered: false, storage_post: Default::default(), io_cause_before_after: false, native_turn: 0,
            client_session: Default::default(), unissued_storage_apply: None, source: Default::default(), storage_io: Default::default() }
    }

    pub(crate) const fn native_turn_v1(&self) -> u64 {
        self.native_turn
    }

    pub(crate) fn belongs_to_operation_v1(&self,
        operation: aos_sandbox_model::OperationId,
    ) -> bool {
        self.parent == operation
    }

    pub(crate) fn has_same_profile_v1(&self,
        profile:&Arc<ProductionControllerNormalRootProfileV1>,
    )->bool {Arc::ptr_eq(&self.profile,profile)}

    /// Borrows original Root inputs only from the same completed intake.
    ///
    /// # Errors
    /// Refuses a different parent, unfinished terminal, or closed native turn.
    #[doc(hidden)]
    pub fn borrow_root_v1<'loan, 'intake>(
        &'loan mut self,
        intake: &'intake super::super::CreateContinuationIntakeAttemptV1,
        operation: aos_sandbox_model::OperationId,
        controller: &Journal,
    ) -> Result<OriginalCreateProvisioningRootLoanV1<'loan, 'intake>, ResourceReservationErrorV1> {
        let completed = intake.borrow_completed_provisioning_v1(operation)?;
        OriginalCreateProvisioningRootLoanV1::from_completed_create_v1(self, completed, controller)
    }

    pub(crate) fn require_current_v1(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.runtime_layout.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?
            .require_parent_v1(self.parent)?;
        if self.storage_post.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.after.is_some() || self.client_session.failure().is_some() || self.source.failure().is_some() || self.storage_io.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?
            .original_v1();
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_create_provisioning_current_v1(native, controller, self.profile.as_ref())
    }

    /// Rejoins the actual initial Storage receiver to this same C and profile.
    ///
    /// The actual completed Security borrower independently holds the same
    /// Session, physical Journal, cookie and authenticated transcript. This
    /// identity comparison neither borrows its old payer nor creates IO rights.
    ///
    /// # Errors
    /// Refuses another role, C original or profile, or a closed current turn.
    #[doc(hidden)]
    pub fn require_initial_storage_session_original_v1(&self,
        initial: &crate::ControllerInitialBrokerSessionReceivingV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_provisioning_initial_storage_original_v1(initial, &self.profile)
    }

    /// Charges the reached complete representation on this original C purpose.
    ///
    /// The requirement includes every co-resident owner and this turn's actual
    /// cumulative traffic. The constructor-attached Runtime header is added
    /// automatically; callers supply the additional reached representation.
    /// This cost-only port creates no Session, native scope,
    /// lease, semantic grant, readiness, or resource capacity.
    ///
    /// # Errors
    /// Retains the actual debit refusal in this same original. A failed or
    /// completed turn cannot receive another healthy debit through this port.
    #[doc(hidden)]
    pub fn require_complete_v1(&mut self, controller: &Journal, complete: ResourceVector)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.after.is_some() || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.demand = Some((|| {
            let complete = complete.checked_add(self.storage_post.receiving_demand_v1()?)?
                .checked_add(self.runtime_layout.as_ref()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?
                .receiving_demand_v1(self.parent)?)?
                .checked_add(self.storage_io.retained_demand_v1(self.native_turn)?)?;
            let native = self.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?
                .original_mut_v1();
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_create_provisioning_complete_v1(native, controller, self.profile.as_ref(), complete)
        })());
        self.demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Rejoins the same positively completed native turn without granting work.
    ///
    /// This does not prove a semantic child, Root temporal gate, Source terminal
    /// or workspace completed. Their genuine owners remain separate borrowers.
    ///
    /// # Errors
    /// Refuses an unfinished/failed turn, undisposed probes or profile controls,
    /// or a changed original C writer, baseline, profile or confirmed launch.
    #[doc(hidden)]
    pub fn require_completed_original_v1(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.failure().is_some() || self.client_session.failure().is_some() || self.source.failure().is_some() || self.storage_io.failure().is_some()
            || !matches!(self.after, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?
            .original_v1();
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_completed_provisioning_original_v1(native, controller, self.profile.as_ref())
    }

    /// Starts another turn only after this original's positive native disposal.
    ///
    /// The same baseline ledger and spent traffic remain monotone. A failed
    /// predecessor cannot be replaced or used to begin another native interval.
    ///
    /// # Errors
    /// Refuses a different intake, a failed or unfinished predecessor, or any
    /// original Bank, writer, Source, profile, and launch association failure.
    #[doc(hidden)]
    pub fn begin_next_completed_create_turn_v1(
        &mut self,
        intake: &super::super::CreateContinuationIntakeAttemptV1,
        operation: aos_sandbox_model::OperationId,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if operation != self.parent || self.completion_entered || self.failure().is_some()
            || self.client_session.failure().is_some() || self.source.active()
            || !matches!(self.after, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let completed = intake.borrow_completed_provisioning_v1(operation)?;
        let next_turn = self.native_turn.checked_add(1)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = complete.checked_add(self.storage_post.receiving_demand_v1()?)?
            .checked_add(self.runtime_layout.as_ref()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?
            .receiving_demand_v1(self.parent)?)?
            .checked_add(self.storage_io.retained_demand_v1(next_turn)?)?;
        let native = self.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?
            .original_mut_v1();
        // Once the next native entry is attempted, its owed post has a fresh
        // destination even if that entry refuses. The actual lower original
        // retains whether a new interval was reached.
        self.native_turn = next_turn;
        self.demand = None;
        self.after = None;
        self.next = Some((|| {
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .begin_next_create_provisioning_turn_v1(&completed, native, controller,
                    source, self.profile.as_ref(), complete)
        })());
        self.next.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Finishes the original native posts after every entered semantic body.
    ///
    /// # Errors
    /// Retains the actual same-writer, profile, launch, and independently owed
    /// post failures. Repeated finish is refused without replacing originals.
    #[doc(hidden)]
    pub fn finish_native_once_v1(&mut self, controller: &mut Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.after.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.io_cause_before_after = (self.storage_io.failure().is_some() || self.storage_post.failure().is_some())
            && self.native.as_ref().ok().is_some_and(|native| native.original_v1().failure().is_none());
        self.after = Some((|| {
            let native = self.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?
                .original_mut_v1();
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .finish_create_provisioning_native_once_v1(native, controller, self.profile.as_ref())
        })());
        self.after.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the earliest retained admission, debit, or native-post cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Err(cause) = &self.runtime_layout {
            return Some(cause);
        }
        if self.io_cause_before_after {
            return self.storage_io.failure().or_else(|| self.storage_post.failure());
        }
        match self.native.as_ref() {
            Err(cause) => Some(cause as _),
            Ok(native) => native.original_v1().failure(),
        }.or_else(|| self.demand.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.next.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.source.failure())
            .or_else(|| self.storage_io.failure())
            .or_else(|| self.storage_post.failure())
    }
}

/// Lends the actual original inputs during its separately paid Root turn.
#[doc(hidden)]
pub struct OriginalCreateProvisioningRootLoanV1<'loan, 'intake> {
    receiving: &'loan mut CreateProvisioningOriginalsV1,
    completed: CreateStorageCompletedIntakeOriginalV1<'intake>,
}

impl<'loan, 'intake> OriginalCreateProvisioningRootLoanV1<'loan, 'intake> {
    pub(crate) fn from_completed_create_v1(
        receiving: &'loan mut CreateProvisioningOriginalsV1,
        completed: CreateStorageCompletedIntakeOriginalV1<'intake>,
        controller: &Journal,
    ) -> Result<Self, ResourceReservationErrorV1> {
        completed.require_current_v1()?;
        if receiving.parent != completed.operation_v1() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        receiving.require_current_v1(controller)?;
        Ok(Self { receiving, completed })
    }

    /// Borrows the same actual profile retained by this intrinsic receiver.
    ///
    /// This supplies no new observation scope. An independently owed post must
    /// use its actual prepaid native destination even after financial refusal.
    #[must_use]
    pub fn profile_v1(&self) -> &ProductionControllerNormalRootProfileV1 {
        self.receiving.profile.as_ref()
    }

    /// Borrows the original cause even after this receiver has refused.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.receiving.failure()
    }

    /// Rejoins the actual same C original before another healthy Root stage.
    ///
    /// # Errors
    /// Refuses a changed, failed or already-finished original. This method must
    /// not gate the receiver's independently prepaid negative native post.
    pub fn require_current_v1(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.completed.require_current_v1()?;
        self.receiving.require_current_v1(controller)
    }

    /// Borrows the original closed Root6 receipt; this issues no new role grant.
    ///
    /// # Errors
    /// Refuses if the same retained terminal no longer passes its original gates.
    pub fn root_closed_receipt_v1(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'intake>, ResourceReservationErrorV1>
    {
        self.completed.root_closed_receipt_v1()
    }

    /// Borrows the original complete canonical public-mutation context.
    ///
    /// # Errors
    /// Refuses an inconsistent or closed original and retains its native cause.
    pub fn accepted_context_v1(&self) -> Result<&[u8], ResourceReservationErrorV1> {
        self.completed.accepted_context_v1()
    }

    /// Returns the original paired sample and unchanged absolute cutoff.
    ///
    /// # Errors
    /// Refuses an inconsistent or closed original and retains its native cause.
    pub fn original_horizon_v1(&self)
        -> Result<(RawPairedClockSample, u64), ResourceReservationErrorV1>
    {
        self.completed.original_horizon_v1()
    }

    /// Charges the reached complete representation on this same genuine receiver.
    ///
    /// # Errors
    /// Refuses an inconsistent or closed original and retains its native cause.
    pub fn require_complete_v1(&mut self, controller: &Journal, complete: ResourceVector)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.receiving.require_complete_v1(controller, complete)
    }

    /// Borrows this same C's current baseline account, never a C23 claim.
    ///
    /// # Errors
    /// Refuses a different/closed original or a changed complete bank fold.
    pub fn controller_account_head_v1<'journal>(&self, controller: &'journal Journal)
        -> Result<&'journal [u8], ResourceReservationErrorV1>
    {
        self.require_current_v1(controller)?;
        let native = self.receiving.native.as_ref()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?.original_v1();
        self.receiving.bank.lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .provisioning_controller_head_v1(native, controller, self.receiving.profile.as_ref())
    }

    /// Rejoins the exact retained Ready and actual C9 authenticated terminal.
    ///
    /// This comparison cannot mint an Apply grant or adopt another Session.
    ///
    /// # Errors
    /// Refuses another Ready frame, request/outcome packet or closed original.
    pub(crate) fn require_storage_apply_inputs_v1(&self, controller: &Journal,
        ready: &[u8], outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        self.completed.require_storage_apply_inputs_v1(ready, outcome)
    }

    pub(crate) fn storage_preparation_cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.completed.storage_preparation_cutoff_v1()
    }

    /// Borrows the same verified original lease, not a decoded replacement.
    ///
    /// # Errors
    /// Refuses an incomplete original ownership flight or changed assignment.
    pub(crate) fn ownership_lease_v1(&self)
        -> Result<&'intake aos_sandbox_ownership_protocol::SignedOwnershipLease, ResourceReservationErrorV1>
    {
        self.completed.ownership_lease_v1()
    }

    /// Borrows the real child and inclusive grant from the same Controller bank cut.
    ///
    /// # Errors
    /// Refuses an inconsistent or closed original and retains its native cause.
    pub fn resource_members_v1<'journal>(&self, controller: &'journal Journal)
        -> Result<(&'journal [u8], &'journal [u8]), ResourceReservationErrorV1>
    {
        self.completed.resource_members_v1(controller)
    }
}

impl CreateProvisioningOriginalsV1 {
    /// Borrows the actual scoped native cause for a selected IO stopping marker.
    ///
    /// Its upper chronological selector must first identify this exact IO hook;
    /// this view alone neither selects a failure nor authorizes any continuation.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_io_original_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.failure()
    }
}

impl CreateProvisioningOriginalsV1 {
    pub(crate) fn storage_io_has_entered_v1(&self) -> bool {
        self.storage_io.has_entered_v1()
    }
}

impl CreateProvisioningOriginalsV1 {
    pub(crate) fn retain_unissued_storage_apply_attempt_v1(&mut self,
        proof: crate::reconciler::provisioning::storage_io::UnissuedStorageApplyAttemptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.storage_io_has_entered_v1()
            || self.unissued_storage_apply.as_ref().is_some_and(|proof| !proof.consumed_v1()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // Only the completed pure absence proof is replaced. Native IO state,
        // original ordinal, retained errors and financial highwater stay intact.
        self.unissued_storage_apply = Some(proof);
        Ok(())
    }

    pub(crate) fn unissued_storage_apply_attempt_mut_v1(&mut self)
        -> Option<&mut crate::reconciler::provisioning::storage_io::UnissuedStorageApplyAttemptV1> {
        self.unissued_storage_apply.as_mut()
    }
}
