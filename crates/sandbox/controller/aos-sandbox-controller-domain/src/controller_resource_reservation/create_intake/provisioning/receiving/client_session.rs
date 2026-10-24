//! Rejoins the genuine completed Preparation Session without reborrowing J.
//!
//! The completed intake retains the actual J transition's Journal link,
//! original new-socket binding and signed Preparation transcript. This adapter
//! compares those same originals under the next genuine C purpose. It does not
//! reenter any old J/Cache observation or create an Apply Session or authority.

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_model::{ResourceDimension, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

use super::{CreateProvisioningOriginalsV1, OriginalCreateProvisioningRootLoanV1};
use crate::controller_resource_reservation::ControllerResourceBankOpeningV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::controller_resource_reservation::create_intake::ready::client_session::ClientSessionAssociationErrorV1;
use crate::{ControllerInitialBrokerSessionReceivingV1, Journal};

#[derive(Debug)]
enum AssociationCauseV1 {
    Original(ResourceReservationErrorV1),
    Session(ClientSessionAssociationErrorV1),
}

/// Retains the actual initial-C join, payment, or completed Session refusal.
///
/// Its private source remains the original native error. This comparison is
/// not a lease, Session constructor, policy admission, or new financial owner.
#[doc(hidden)]
#[derive(Debug)]
pub struct CreateProvisioningClientSessionAssociationErrorV1 {
    cause: AssociationCauseV1,
    original: Option<OriginalAssociationV1>,
}

// Identity only for a diagnostic projection onto the same retained C. These
// existing Arc owners do not establish Session or physical-native custody.
struct OriginalAssociationV1 {
    parent: aos_sandbox_model::OperationId,
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
}

impl fmt::Debug for OriginalAssociationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("OriginalAssociationV1")
            .field("parent", &self.parent).finish_non_exhaustive()
    }
}

impl CreateProvisioningClientSessionAssociationErrorV1 {
    fn original(cause: ResourceReservationErrorV1, receiving: Option<&CreateProvisioningOriginalsV1>) -> Self {
        let original = receiving.map(|receiving| OriginalAssociationV1 {
            parent: receiving.parent,
            bank: Arc::clone(&receiving.bank),
            profile: Arc::clone(&receiving.profile),
        });
        Self { cause: AssociationCauseV1::Original(cause), original }
    }

    /// Borrows the selected richer cause only from this same retained original.
    ///
    /// A different C purpose, parent, Bank or profile cannot replace the actual
    /// stored marker. Earlier Session errors never select a later native post.
    #[must_use]
    pub fn failure_with_original_v1<'cause>(
        &'cause self,
        receiving: &'cause CreateProvisioningOriginalsV1,
    ) -> &'cause (dyn Error + 'static) {
        if self.original.as_ref().is_some_and(|original|
            original.parent == receiving.parent
                && Arc::ptr_eq(&original.bank, &receiving.bank)
                && Arc::ptr_eq(&original.profile, &receiving.profile))
        {
            receiving.failure().unwrap_or(self)
        } else { self }
    }
}

impl fmt::Display for CreateProvisioningClientSessionAssociationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the completed Preparation Session association refused")
    }
}

impl Error for CreateProvisioningClientSessionAssociationErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match &self.cause {
            AssociationCauseV1::Original(cause) => cause,
            AssociationCauseV1::Session(cause) => cause,
        })
    }
}

impl CreateProvisioningOriginalsV1 {
    /// Borrows this same original's retained Client primary or invoked debit.
    ///
    /// This diagnostic remains available after the independent native post.
    /// Pure geometry and native body refusals stay before later post failures.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_apply_client_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = &self.client_session.provisioning_association {
            return Some(cause.failure_with_original_v1(self));
        }
        self.client_session.failure_with_financial_v1(self.failure())
    }
}

impl OriginalCreateProvisioningRootLoanV1<'_, '_> {
    pub(in crate::controller_resource_reservation::create_intake) fn client_progress_v1(&self)
        -> &crate::controller_resource_reservation::create_intake::ready::client_session::ClientSessionOriginalsV1
    {
        &self.receiving.client_session
    }

    pub(in crate::controller_resource_reservation::create_intake) fn client_progress_mut_v1(&mut self)
        -> &mut crate::controller_resource_reservation::create_intake::ready::client_session::ClientSessionOriginalsV1
    {
        &mut self.receiving.client_session
    }

    pub(in crate::controller_resource_reservation::create_intake) fn client_association_failure_v1<'cause>(
        &'cause self,
        cause: &'cause CreateProvisioningClientSessionAssociationErrorV1,
    ) -> &'cause (dyn Error + 'static) {
        cause.failure_with_original_v1(self.receiving)
    }

    /// Returns the node from the same retained original enrollment.
    ///
    /// This comparison DATA is independent of any caller's decoded context or
    /// Root reply. It cannot construct a Session, grant, or renewed deadline.
    ///
    /// # Errors
    /// Refuses an unfinished terminal or unavailable retained original capture.
    #[doc(hidden)]
    pub fn original_node_v1(&self)
        -> Result<aos_sandbox_model::NodeId, ResourceReservationErrorV1>
    {
        self.completed.require_current_v1()?;
        self.completed.intake.intake.create_storage_node_v1()
    }

    /// Rejoins the same completed Preparation Session after same-C payment.
    ///
    /// The Security caller continuously holds the actual completed rollover,
    /// originating initial receiver and current Session. It retains this whole
    /// Result through every later native post. The complete requirement is the
    /// caller's actual co-resident and cumulative demand, never spare credit.
    /// No old J or released Cache borrower is entered by this method.
    ///
    /// # Errors
    /// Retains the initial Storage-role/C/profile join, financial refusal, or
    /// actual completed Journal/socket/transcript comparison error.
    #[doc(hidden)]
    pub fn require_completed_preparation_session_v1(
        &mut self,
        initial: &ControllerInitialBrokerSessionReceivingV1,
        controller: &Journal,
        session_journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        complete: ResourceVector,
    ) -> Result<(), CreateProvisioningClientSessionAssociationErrorV1> {
        self.require_current_v1(controller).map_err(|cause|
            CreateProvisioningClientSessionAssociationErrorV1::original(cause,
                self.receiving.failure().is_some().then_some(&*self.receiving)))?;
        self.receiving.require_initial_storage_session_original_v1(initial, controller)
            .map_err(|cause| CreateProvisioningClientSessionAssociationErrorV1::original(
                cause, self.receiving.failure().is_some().then_some(&*self.receiving)))?;

        // The returned error and its temporary are real compiled destinations.
        // The sole comparison below creates no FD, parser backing or pathname.
        let memory = std::mem::size_of::<Result<(), CreateProvisioningClientSessionAssociationErrorV1>>()
            .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| CreateProvisioningClientSessionAssociationErrorV1::original(
                ResourceReservationErrorV1::Conflict, None))?;
        let complete = complete.checked_add(ResourceVector::ZERO
            .with(ResourceDimension::MemoryBytes, memory))
            .map_err(|cause| CreateProvisioningClientSessionAssociationErrorV1::original(
                cause.into(), None))?;
        self.require_complete_v1(controller, complete).map_err(|cause|
            CreateProvisioningClientSessionAssociationErrorV1::original(cause,
                self.receiving.failure().is_some().then_some(&*self.receiving)))?;

        self.completed.intake.client_session.require_completed_association_v1(
            session_journal, socket, transcript,
        ).map_err(|cause| CreateProvisioningClientSessionAssociationErrorV1 {
            cause: AssociationCauseV1::Session(cause), original: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_socket_cause_remains_the_actual_error_source() {
        let cause = CreateProvisioningClientSessionAssociationErrorV1 {
            cause: AssociationCauseV1::Session(ClientSessionAssociationErrorV1::Closed),
            original: None,
        };
        let first = cause.source().unwrap() as *const dyn Error;

        assert!(cause.original.is_none());
        assert!(cause.source().unwrap().is::<ClientSessionAssociationErrorV1>());
        assert!(std::ptr::eq(first, cause.source().unwrap()));
    }
}
