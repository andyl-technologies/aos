//! Keeps the whole outer Session beside the one genuine Delete query kernel.
//!
//! The native guard is first through `kernel`, before the same outer Session
//! and its Host replay tickets. Only this owning module lends the private inner
//! Session for named turns; it never unwraps or replaces the outer custody.

use super::*;
use crate::handshake::output_registration_continuation::{
    DeleteInventoryAnswerOriginalsV1, DeleteInventoryClientKernelV1,
    OutputPreparationClosedV1, StoragePreparationClientProgressV1,
};
use aos_sandbox::{DeleteInventorySecurityShapeDataV1, DeleteInventorySessionAppendOriginalV1, JournalError};

/// Owns a genuine Delete query and the same whole dormant Runtime Session.
///
/// The complete outer Session and its replay tickets remain resident through
/// every negative result. This owner adds no transport or financial purpose.
#[doc(hidden)]
#[must_use = "retain the whole query and outer Session through every owed post"]
pub struct OriginalDeleteInventoryClientV1<'turn, 'fence, 'journal, 'original, 'authorization, 'profile> {
    kernel: DeleteInventoryClientKernelV1<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>,
    session: DormantAuthenticatedBrokerSessionV1,
}

impl<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>
    OriginalDeleteInventoryClientV1<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>
{
    /// Describes the actual whole outer query before its genuine native debit.
    ///
    /// # Errors
    /// Returns checked compiled representation arithmetic refusal.
    pub fn security_shape_v1() -> Result<DeleteInventorySecurityShapeDataV1, JournalError> {
        DeleteInventoryClientKernelV1::security_shape_v1()
    }

    /// Borrows only the actual outer Session's native planning association.
    ///
    /// # Errors
    /// Refuses same-C17/Source/currentness or complete representation admission
    /// before the original Session moves or any query IO begins.
    #[doc(hidden)]
    pub fn borrow_planning_native_once_v1(
        bank: &'turn aos_sandbox::ControllerResourceBankOpeningV1,
        authorized: &'turn mut aos_sandbox::ControllerDeleteSourceAuthorizedScopeV1<'journal, 'original>,
        controller: &'turn mut aos_sandbox::Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        session: &DormantAuthenticatedBrokerSessionV1,
        upper_construction_bytes: usize,
    ) -> Result<DeleteInventorySessionAppendOriginalV1<'turn, 'turn, 'journal, 'original, 'journal, 'profile>, aos_sandbox::ResourceReservationErrorV1> {
        DeleteInventoryClientKernelV1::borrow_planning_native_once_v1(
            bank, authorized, controller, profile, &session.0, upper_construction_bytes,
        )
    }

    /// Borrows a fresh query from the same actual Pending and Root originals.
    ///
    /// This is the Preaccept entrance to the existing shared query engine. It
    /// preserves the whole outer Session through every failure and owes all
    /// existing independent native posts; no parser result creates authority.
    ///
    /// # Errors
    /// Refuses currentness, original association or representation funding
    /// before moving the Session or entering query IO.
    #[doc(hidden)]
    pub fn borrow_pending_native_once_v2(
        bank: &'turn aos_sandbox::ControllerResourceBankOpeningV1,
        pending: &'turn mut aos_sandbox::ControllerDeletePendingOriginalV2<'journal, 'original>,
        controller: &'turn mut aos_sandbox::Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        session: &DormantAuthenticatedBrokerSessionV1,
        challenge: &'turn aos_sandbox::ControllerDeletePendingRootChallengeLoanV2<'turn>,
        upper_construction_bytes: usize,
    ) -> Result<DeleteInventorySessionAppendOriginalV1<
        'turn, 'turn, 'journal, 'original, 'journal, 'profile,
    >, aos_sandbox::ResourceReservationErrorV1> {
        bank.borrow_delete_pending_inventory_once_v2(pending, controller, profile,
            session.0.pending_delete_inventory_transcript_v2(), Self::security_shape_v1()?, challenge,
            upper_construction_bytes)
    }

    /// Borrows the same idle Host Session after genuine completed Network9.
    ///
    /// # Errors
    /// Refuses incomplete native Network9 or a foreign committed Source/Root cut.
    #[doc(hidden)]
    pub fn borrow_host_confirmation_native_once_v4(
        bank: &'turn aos_sandbox::ControllerResourceBankOpeningV1,
        pending: &'turn mut aos_sandbox::ControllerDeletePendingOriginalV2<'journal, 'original>,
        client: &'turn mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'profile>,
        controller: &'turn mut aos_sandbox::Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        session: &DormantAuthenticatedBrokerSessionV1,
        network: &crate::controller_composition::DeleteNetworkApplySessionIoOriginalV4,
        upper_bytes: usize,
    ) -> Result<
        DeleteInventorySessionAppendOriginalV1<
            'turn,
            'turn,
            'journal,
            'original,
            'journal,
            'profile,
        >,
        aos_sandbox::ResourceReservationErrorV1,
    > {
        let (_, native) = network
            .require_completed_v4()
            .map_err(|_| aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        bank.borrow_delete_host_confirmation_once_v4(
            pending,
            client,
            controller,
            profile,
            session.0.pending_delete_inventory_transcript_v2(),
            Self::security_shape_v1()?,
            native,
            upper_bytes,
        )
    }

    /// Retains the same whole outer Session beside its already-paid native guard.
    pub fn retain_prepaid(
        native: DeleteInventorySessionAppendOriginalV1<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>,
        session: DormantAuthenticatedBrokerSessionV1,
    ) -> Self {
        Self { kernel: DeleteInventoryClientKernelV1::retain_prepaid(native), session }
    }

    /// Captures and commits the genuine query's fixed signed request.
    ///
    /// # Errors
    /// Retains every primary failure; the same final native post remains owed.
    pub fn prepare_once(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.kernel.prepare_once(&mut self.session.0)
    }

    /// Advances the same shared sender, receiver or readiness waiter.
    pub fn advance_once(&mut self) -> StoragePreparationClientProgressV1 {
        self.kernel.advance_once(&mut self.session.0)
    }

    /// Attempts all independently owed final native and Session posts.
    ///
    /// # Errors
    /// Retains reentry, the earlier primary, and each failed independent post.
    pub fn finish_native_once(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.kernel.finish_native_once(&mut self.session.0)
    }

    /// Attempts the independently prepaid enclosing Source/C17 after on failure.
    ///
    /// # Errors
    /// Retains the original failed outer post on the same native query owner;
    /// the whole Session, tickets and all reached kernel originals stay live.
    pub fn finish_outer_source_failure_once_v1(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.kernel.finish_outer_source_failure_once_v1()
    }

    /// Returns the same whole outer Session after real positive native disposal.
    ///
    /// Incomplete or refused disposition terminates while all originals remain
    /// resident. Neither success nor the historical answer grants a six-cut.
    pub fn finish_positive_once(mut self)
        -> (DormantAuthenticatedBrokerSessionV1, DeleteInventoryAnswerOriginalsV1)
    {
        let answer = self.kernel.finish_positive_once(&mut self.session.0);
        (self.session, answer)
    }

    /// Borrows the same kernel/Session's chronological actual primary cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kernel.failure(&self.session.0)
    }

    /// Borrows the exact C17 native cause only at its retained marker site.
    #[must_use]
    pub fn controller_failure_view_v1(&self)
        -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'_>>
    {
        self.kernel.controller_failure_view_v1()
    }
}
