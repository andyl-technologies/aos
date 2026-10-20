//! Lends the actual completed workspace models inside a fresh Source window.
//!
//! The opaque context requires the actual Action's captured child and same
//! C23/Root native interval. It lets Security borrow its surviving signed model
//! owners without retaining a reference into the mutable receiver itself.

use super::*;
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::ValidatedStorageInventory;
use aos_sandbox_api::aos::sandbox::local::v1::{InventoryStorageResourcesResponse, StorageResult};
use crate::StorageProvisioningWorkspaceOriginalV1;

/// Borrows the genuine child and live native window for one workspace lender.
///
/// No public constructor accepts decoded response DATA, an account or a
/// receiving amount. Historical getters are usable only after the native IO
/// original is rejoined to this exact Action and current Root/C23 interval.
#[doc(hidden)]
pub struct CreateProvisioningSourceWorkspaceContextV1<'turn> {
    original: &'turn mut CreateProvisioningOriginalsV1,
    action: &'turn OriginalPublicationActionV1,
    root: &'turn RootStorageApplyCurrentTurnV1<'turn>,
    controller: &'turn Journal,
    complete: ResourceVector,
}

impl CreateProvisioningSourceWorkspaceContextV1<'_> {
    fn receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                crate::cold_launch_publication::action::CompletedPublicationChildDataV1<'static>>()
                .checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                StorageProvisioningWorkspaceOriginalV1<'static>>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
    }

    /// Borrows the exact signed Apply and later Inventory after native rejoin.
    ///
    /// This forwards to the same finite native comparison as the IO borrower.
    /// Its model canonicalization scratch is paid on the same original before
    /// any encoder allocates it. The returned lender borrows external Session
    /// and model owners, allowing the actual receiver's later Source work.
    ///
    /// # Errors
    /// Refuses changed native currentness, another child/Session/model, any
    /// failed finite IO or unpayable full co-resident representation.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn borrow_completed_storage_workspace_v1<'models>(&mut self,
        journal: &'models Journal,
        socket: &'models SeqpacketSocket,
        transcript: &'models VerifiedBrokerSessionTranscriptV1,
        apply: &'models AuthenticatedBrokerMethodOutcomeV1,
        result: &'models StorageResult,
        inventory: &'models AuthenticatedBrokerMethodOutcomeV1,
        model: &'models (ValidatedStorageInventory, InventoryStorageResourcesResponse),
    ) -> Result<StorageProvisioningWorkspaceOriginalV1<'models>, ResourceReservationErrorV1> {
        self.root.require_action_v1(self.action, self.original, self.controller)?;
        self.action.child_for_current_source_v1(self.original, self.root, self.controller)?;
        self.original.borrow_completed_storage_workspace_for_source_v1(
            self.controller, journal, socket, transcript, apply, result, inventory, model,
            self.complete,
        )
    }
}

impl OriginalCreateProvisioningRootLoanV1<'_, '_> {
    /// Lends only the actual completed child's fresh workspace comparison turn.
    ///
    /// # Errors
    /// Refuses another Action, failed native currentness, missing captured
    /// child, substituted companion rows or insufficient same-C23 receiving.
    #[doc(hidden)]
    pub fn borrow_storage_workspace_source_context_v1<'turn>(
        &'turn mut self,
        action: &'turn OriginalPublicationActionV1,
        root: &'turn RootStorageApplyCurrentTurnV1<'turn>,
        controller: &'turn Journal,
    ) -> Result<CreateProvisioningSourceWorkspaceContextV1<'turn>, ResourceReservationErrorV1> {
        root.require_action_v1(action, self.receiving, controller)?;
        self.completed.require_current_v1()?;
        let complete = action.resident_receiving_demand_v1(controller)?
            .checked_add(root.receiving_demand_v1()?)?
            .checked_add(CreateProvisioningSourceWorkspaceContextV1::receiving_demand_v1()?)?;
        self.receiving.require_complete_v1(controller, complete)?;
        action.child_for_current_source_v1(self.receiving, root, controller)?;
        Ok(CreateProvisioningSourceWorkspaceContextV1 {
            original: self.receiving, action, root, controller, complete,
        })
    }
}
