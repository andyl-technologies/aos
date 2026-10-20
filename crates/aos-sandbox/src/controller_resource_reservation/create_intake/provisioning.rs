//! Borrows the completed original Create for its separate provisioning purpose.
//!
//! The historical Storage terminal is an association check. It grants no new
//! payment, lease, plan, or native effect; the same Controller baseline admits
//! each reached provisioning requirement through its distinct closed receiver.

pub(in crate::controller_resource_reservation) mod receiving;
pub(crate) use receiving::SourceAppendBoundaryV1;
pub(crate) use receiving::start_entry::source_origin::{StartSourceAdmissionAuthorizationV1, StartSourcePurposeV2};
pub(crate) use receiving::start_entry::{StartNativeEntryPredecessorV1, StartNativeStateV1, AcceptedStartPlanOriginalV1, StartTerminalAppendContextV2};
#[doc(hidden)]
pub use receiving::AcceptedStartEntryOriginalV1;
#[doc(hidden)]
pub use receiving::start_entry::{OriginalStartHostRootLoanV1,
    PreparedStartResourceRequestOriginalV2, PreparedStartResourceRequestClosedV2, StartHostCatalogPublicationLoanV2, StartHostCatalogIoLoanV2, StartHostCatalogNativeCompletionV2, StartHostCatalogCompletionRefusalV2, StartHostSessionRejoinOriginalV2, StartHostCatalogProjectionOriginalV2, StartHostCatalogProjectionClosedV2,
    StartResourceUpperDisposalV2, StartResourceSessionOpeningOriginalV2, StartResourceSessionOpeningLoanV2, StartResourceSessionOpeningOwnerLinkV2,
    StartResourceColdCompletionOriginalV4,
    StartResourceSessionAssociationV4, StartResourceHelloDisposalV4, StartResourceHelloDisposalErrorV4, StartResourceSessionCurrentnessErrorV4,
    StartResourceProvisioningIoLoanV2, StartResourcePreparedRequestBorrowV2, StartResourceSessionPostShapeDataV2,
    StartResourceSessionResidentShapeDataV4};
pub(crate) use receiving::source::{SourceAdmissionAuthorizationV1, SourcePurposeV1};

#[doc(hidden)]
pub use receiving::{CreateProvisioningOriginalsV1, OriginalCreateProvisioningRootLoanV1,
    StorageProvisioningIoDisposalV1, StorageProvisioningWorkspaceOriginalV1, StorageProvisioningSessionIoShapeDataV1, DeleteStoragePreparationIoOriginalV3, DeleteStorageApplyIoOriginalV3, DeleteNetworkApplyIoOriginalV4, DeleteMountReapIoOriginalV4,
    CreateProvisioningClientSessionAssociationErrorV1, StorageProvisioningSessionPostShapeDataV1};

use aos_sandbox_core::OperationId;

use super::CreateContinuationIntakeAttemptV1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;

/// Borrows the actual completed intake without reconstructing its originals.
pub(crate) struct CreateStorageCompletedIntakeOriginalV1<'held> {
    intake: &'held CreateContinuationIntakeAttemptV1,
    operation: OperationId,
}

impl<'held> CreateStorageCompletedIntakeOriginalV1<'held> {
    /// Repeats the original terminal check for this same accepted operation.
    pub(crate) fn require_current_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        self.intake.require_original_create_terminal_v1(self.operation)
    }

    /// Returns the accepted parent operation retained by the original intake.
    pub(crate) const fn operation_v1(&self) -> OperationId {
        self.operation
    }

    /// Borrows the originally admitted complete public-mutation context.
    pub(crate) fn accepted_context_v1(&self) -> Result<&[u8], ResourceReservationErrorV1> {
        self.require_current_v1()?;
        let identity = self.intake.parent.create_storage_original_identity_v1()?;
        self.intake.parent.create_storage_intent_components_v1(identity.coissuance_binding)
            .map(|original| original.accepted_context)
    }

    /// Returns the original sample and unchanged absolute request cutoff.
    pub(crate) fn original_horizon_v1(
        &self,
    ) -> Result<(aos_sandbox_core::RawPairedClockSample, u64), ResourceReservationErrorV1> {
        self.require_current_v1()?;
        let identity = self.intake.parent.create_storage_original_identity_v1()?;
        Ok((self.intake.parent.original_clock()?, identity.original_cutoff))
    }

    /// Borrows the actual fully sealed Root6 receipt from the retained turn.
    pub(crate) fn root_closed_receipt_v1(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1>
    {
        self.require_current_v1()?;
        let handoff = self.intake.storage_use.borrow_handoff_v1()?;
        self.intake.root_exchange.borrow_closed_v1(&handoff)?.receipt_v1()
    }

    /// Compares new Apply inputs with the same completed native storage owners.
    pub(crate) fn require_storage_apply_inputs_v1(&self, ready: &[u8],
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.intake.bundle.require_completed_bytes_v1(ready)?;
        self.intake.storage_use.borrow_handoff_v1()?.released_v1().committed_v1()
            .recorded_v1().require_outcome_v1(outcome)
    }

    /// Borrows the actual positive ownership flight's original verified lease.
    pub(crate) fn ownership_lease_v1(&self)
        -> Result<&'held aos_sandbox_ownership_protocol::SignedOwnershipLease, ResourceReservationErrorV1>
    {
        self.require_current_v1()?;
        let intake: &'held CreateContinuationIntakeAttemptV1 = self.intake;
        intake.ownership.verified_signing_material_v1(&intake.assignment).map(|(lease, _)| lease)
    }

    pub(crate) fn original_specification_v2(&self)
        -> Result<&'held crate::sandbox_spec_state::DurableSandboxSpecV1, ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.intake.parent.create_storage_assignment_proposal_inputs_v1().map(|(specification, _)| specification)
    }

    /// Borrows historical signed policy inputs for a separately paid Start.
    pub(crate) fn start_assignment_policy_inputs_v2(&self) -> Result<(
        &'held crate::policy_compiler::create_q04::RetainedCreatePolicySourcesDataV1,
        ((u64, &'held ed25519_dalek::VerifyingKey), (u64, &'held ed25519_dalek::VerifyingKey)),
    ), ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.intake.parent.start_assignment_policy_inputs_v2()
    }

    /// Borrows the same completed verified assignment, claim and lease.
    pub(crate) fn publication_material_v1(&self) -> Result<(
        &aos_sandbox_core::CanonicalAssignmentManifestV1,
        &aos_sandbox_ownership_protocol::OwnershipClaimV1,
        &aos_sandbox_ownership_protocol::SignedOwnershipLease,
    ), ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.intake.ownership.verified_material_v1(&self.intake.assignment)
    }

    /// Returns the original prepared response's already tightened terminal bound.
    pub(crate) fn storage_preparation_cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.intake.storage_use.borrow_handoff_v1()?.cutoff_v1()
    }

    /// Rejoins the actual parent owners before new-purpose native admission.
    pub(crate) fn require_original_owners_v1(
        &self,
        controller: &crate::Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.intake.parent.require_create_storage_association(controller, source, profile)
    }

    pub(crate) fn source_q04_identity_v1(&self)
        -> Result<&crate::policy_compiler::create_q04::Q04CutIdentityV1, ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.intake.assignment.completed_q04_identity_v1()
    }

    /// Borrows the actual child and inclusive grant from the same bank cut.
    ///
    /// The caller pays native held-name validation before this read. These
    /// bytes are resource-fact referents, not a new claim or an Apply grant.
    pub(crate) fn resource_members_v1<'journal>(
        &self,
        controller: &'journal crate::Journal,
    ) -> Result<(&'journal [u8], &'journal [u8]), ResourceReservationErrorV1> {
        use aos_sandbox_protocol::domain_ledger::resource_bank as bank;

        self.require_current_v1()?;
        let state = controller.controller_resource_state_v1()
            .map_err(ResourceReservationErrorV1::Journal)?;
        self.intake.parent.require_create_continuation_state(state)?;
        let original = self.intake.parent.create_storage_use_original_binding_v1()?;
        let (_, child) = self.intake.parent.create_storage_child_account_data_v1()?;
        let grant = original.inclusive_grant_v1();

        let child = bank::head_bytes(state, child)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let grant = bank::claim_bytes(state, grant.native_fields().id)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((child, grant))
    }
}

impl CreateContinuationIntakeAttemptV1 {
    /// Enters the separately paid continuation from this exact terminal intake.
    ///
    /// This retains the whole native refusal in the returned opaque owner. It
    /// cannot renew either earlier purpose or construct an Apply permission.
    /// The installed caller lends its whole compiled Runtime header so its
    /// resident memory is included automatically on every subsequent turn.
    ///
    /// # Errors
    /// Refuses when this original operation has not completed its actual terminal.
    #[doc(hidden)]
    pub fn begin_original_provisioning_v1<T: Sized>(
        &mut self,
        operation: OperationId,
        bank: std::sync::Arc<std::sync::Mutex<crate::ControllerResourceBankOpeningV1>>,
        profile: std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        controller: &mut crate::Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        complete: aos_sandbox_core::ResourceVector,
        runtime_header: &T,
    ) -> Result<CreateProvisioningOriginalsV1, ResourceReservationErrorV1> {
        self.require_original_create_terminal_v1(operation)?;
        if self.provisioning_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.provisioning_entered = true;
        let completed = self.borrow_completed_provisioning_v1(operation)?;
        Ok(CreateProvisioningOriginalsV1::begin_completed_create_v1(
            &completed, bank, profile, controller, source, complete, runtime_header,
        ))
    }

    /// Borrows the completed original for the separately paid next purpose.
    ///
    /// This does not reenter Ready, reset J/U, or issue an Apply permission.
    pub(crate) fn borrow_completed_provisioning_v1(
        &self,
        operation: OperationId,
    ) -> Result<CreateStorageCompletedIntakeOriginalV1<'_>, ResourceReservationErrorV1> {
        self.require_original_create_terminal_v1(operation)?;
        Ok(CreateStorageCompletedIntakeOriginalV1 { intake: self, operation })
    }
}

#[doc(hidden)]
pub use receiving::source::{CreateProvisioningSourceWorkspaceContextV1,
    CreateStoppedCompletionAttemptV1, CreateStoppedPreAckContextV1,
    CreateStoppedCompletionAssociationV1, CreateStoppedPreAckOriginalV1,
    CreateStoppedPostAckContextV1, CreateStoppedTerminalOriginalV1, CreateStoppedTerminalCustodyV1};

pub use receiving::start_entry::{OriginalStartAssignmentInputsLoanV2, StartAssignmentInputsCompletedTurnV2};

pub(crate) use receiving::start_entry::host_publication::StartHostPublicationContractV2;

pub(crate) use receiving::start_entry::host_publication::start_host_publication_operation_id_data_v2;
