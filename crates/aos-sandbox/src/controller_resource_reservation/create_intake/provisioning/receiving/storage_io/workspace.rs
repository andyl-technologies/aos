//! Borrows actual completed IO models and their continuously held Session.
//!
//! A later Source crossing rejoins the same C23 and freshly checks its actual
//! native Session association. This lender neither creates a Source authority
//! nor substitutes a historical outcome for Root's current temporal checks.

use super::*;
use aos_sandbox_protocol::{ValidatedStorageInventory, authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
}};
use aos_proto::aos::sandbox::local::v1::{StorageResult, InventoryStorageResourcesResponse};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

/// Borrows signed, typed IO and the actual surviving native Session owners.
///
/// Only the genuine C23 IO loan constructs this lender. Private Arc identities
/// let Source mutably reborrow that same receiver without a self-reference;
/// the Journal/socket/transcript references continuously retain its real native
/// backing. Historical model getters confer no write or workspace authority.
#[doc(hidden)]
pub struct StorageProvisioningWorkspaceOriginalV1<'models> {
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    journal: &'models Journal,
    socket: &'models SeqpacketSocket,
    transcript: &'models VerifiedBrokerSessionTranscriptV1,
    apply: &'models AuthenticatedBrokerMethodOutcomeV1,
    result: &'models StorageResult,
    inventory: &'models AuthenticatedBrokerMethodOutcomeV1,
    model: &'models (ValidatedStorageInventory, InventoryStorageResourcesResponse),
}

fn identities_match(stage: &IoStageV1, outcome: &AuthenticatedBrokerMethodOutcomeV1) -> bool {
    stage.phase == IoPhaseV1::Complete && stage.failure().is_none()
        && stage.terminal_identity == Some((outcome.request().signed_request_digest(),
            *blake3::hash(outcome.canonical_packet()).as_bytes()))
        && stage.binding == outcome.request().session_binding()
}

fn exact_success(outcome: &AuthenticatedBrokerMethodOutcomeV1) -> Result<&[u8], ResourceReservationErrorV1> {
    match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => Ok(exact_body),
        _ => Err(ResourceReservationErrorV1::Conflict),
    }
}

impl CreateProvisioningStorageIoLoanV1<'_> {
    /// Borrows the actual complete workspace evidence beside its same Session.
    ///
    /// # Errors
    /// Retains changed native association and refuses foreign signed terminals,
    /// a substituted typed model, unfinished IO or another actual Core attempt.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn borrow_completed_storage_workspace_v1<'models>(&mut self,
        prepared: &PreparedAuthorityEffectV1,
        journal: &'models Journal, socket: &'models SeqpacketSocket,
        transcript: &'models VerifiedBrokerSessionTranscriptV1,
        apply: &'models AuthenticatedBrokerMethodOutcomeV1, result: &'models StorageResult,
        inventory: &'models AuthenticatedBrokerMethodOutcomeV1,
        model: &'models (ValidatedStorageInventory, InventoryStorageResourcesResponse),
    ) -> Result<StorageProvisioningWorkspaceOriginalV1<'models>, ResourceReservationErrorV1> {
        self.require_storage_contract_once_v1(prepared, 3, None)?;
        if apply.request().exact_body() != prepared.attempt().body() { return Err(ResourceReservationErrorV1::Conflict); }
        let complete = self.complete_for_storage_v1(ResourceVector::ZERO)?;
        let (original, controller) = self.original_and_controller_v1();
        original.borrow_completed_storage_workspace_for_source_v1(controller, journal, socket, transcript,
            apply, result, inventory, model, complete)
    }

}

impl StorageProvisioningWorkspaceOriginalV1<'_> {
    fn require_same_original_v1(&self, original: &mut CreateProvisioningOriginalsV1, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        original.require_current_v1(controller)?;
        if !Arc::ptr_eq(&self.bank, &original.bank) || !Arc::ptr_eq(&self.profile, &original.profile)
            || !identities_match(&original.storage_io.apply, self.apply)
            || !identities_match(&original.storage_io.inventory, self.inventory) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let stage = &original.storage_io.inventory;
        let key = stage.native_key.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let expected = stage.native_position.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.journal.get(crate::RecordNamespace::BrokerSessionTraffic, key)
            .is_none_or(|raw| blake3::hash(raw).as_bytes() != expected) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // Only a whole positive zero-FD identity comparison can be replaced.
        // A prior real native refusal stays sticky with its actual raw cause.
        if original.storage_io.workspace_association.as_ref().is_some_and(Result::is_err) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.storage_io.workspace_association = Some(original.client_session
            .require_completed_provisioning_session_v1(self.journal, self.socket, self.transcript));
        if matches!(original.storage_io.workspace_association, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Borrows the exact original authenticated Apply outcome as historical DATA.
    #[must_use]
    pub const fn apply_outcome_v1(&self) -> &AuthenticatedBrokerMethodOutcomeV1 { self.apply }

    /// Borrows its exact canonical, validated Storage result as historical DATA.
    #[must_use]
    pub const fn apply_result_v1(&self) -> &StorageResult { self.result }

    /// Borrows the exact later authenticated Inventory outcome as historical DATA.
    #[must_use]
    pub const fn inventory_outcome_v1(&self) -> &AuthenticatedBrokerMethodOutcomeV1 { self.inventory }

    /// Borrows the same decoded immutable Inventory and its complete wire model.
    #[must_use]
    pub const fn inventory_model_v1(&self) -> &(ValidatedStorageInventory, InventoryStorageResourcesResponse) { self.model }
}

impl OriginalCreateProvisioningRootLoanV1<'_, '_> {
    /// Rejoins the actual completed IO lender before a fresh Source crossing.
    ///
    /// This adds no Root approval: the actual Root temporal borrower and closed
    /// accepted operation/action checks remain mandatory at their own caller.
    ///
    /// # Errors
    /// Retains native Session refusal and rejects another C23, profile or IO.
    #[doc(hidden)]
    pub fn require_storage_workspace_original_v1(&mut self,
        workspace: &StorageProvisioningWorkspaceOriginalV1<'_>, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.completed.require_current_v1()?;
        workspace.require_same_original_v1(self.receiving, controller)
    }
}

impl CreateProvisioningOriginalsV1 {
    pub(crate) fn storage_workspace_header_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        StorageProvisioningWorkspaceOriginalV1::receiving_demand_v1()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn borrow_completed_storage_workspace_for_source_v1<'models>(&mut self, controller: &Journal,
        journal: &'models Journal, socket: &'models SeqpacketSocket,
        transcript: &'models VerifiedBrokerSessionTranscriptV1,
        apply: &'models AuthenticatedBrokerMethodOutcomeV1, result: &'models StorageResult,
        inventory: &'models AuthenticatedBrokerMethodOutcomeV1,
        model: &'models (ValidatedStorageInventory, InventoryStorageResourcesResponse),
        complete_base: ResourceVector,
    ) -> Result<StorageProvisioningWorkspaceOriginalV1<'models>, ResourceReservationErrorV1> {
        let original = self;
        original.require_current_v1(controller)?;
        // A refused signed-result shape or arithmetic frontier is part of
        // this same attempted comparison, rather than a retryable preflight.
        let admitted = (|| {
            let scratch = exact_success(apply)?.len().checked_add(exact_success(inventory)?.len())
                .and_then(|n| n.checked_mul(3)).and_then(|n| u64::try_from(n).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let incoming = StorageProvisioningWorkspaceOriginalV1::receiving_demand_v1()?
                .checked_add(ResourceVector::ZERO.with(aos_sandbox_core::ResourceDimension::MemoryBytes, scratch))?;
            // Only this private fixed-purpose bridge accepts the actual already-
            // admitted Action/Root base from the sealed Source context. Its public
            // constructor exposes neither an amount nor a caller-selected payer.
            let complete = complete_base.checked_add(incoming)?;
            original.require_complete_v1(controller, complete)
        })();
        original.storage_io.workspace_admission = Some(admitted);
        if !matches!(original.storage_io.workspace_admission, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        original.storage_io.workspace_comparison = Some((|| {
        if !identities_match(&original.storage_io.apply, apply)
            || !identities_match(&original.storage_io.inventory, inventory)
            || result.encode_to_vec().as_slice() != exact_success(apply)?
            || model.0.encoded_response_digest_v1() != <[u8; 32]>::from(Sha256::digest(exact_success(inventory)?))
            || model.1.encode_to_vec().as_slice() != exact_success(inventory)? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let inventory_stage = &original.storage_io.inventory;
        let expected = inventory_stage.native_position.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let key = inventory_stage.native_key.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let raw = journal.get(crate::RecordNamespace::BrokerSessionTraffic, key).ok_or(ResourceReservationErrorV1::Conflict)?;
        if blake3::hash(raw).as_bytes() != expected { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
        })());
        if !matches!(original.storage_io.workspace_comparison, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        original.storage_io.workspace_association = Some(original.client_session
            .require_completed_provisioning_session_v1(journal, socket, transcript));
        if !matches!(original.storage_io.workspace_association, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(StorageProvisioningWorkspaceOriginalV1 { bank: Arc::clone(&original.bank),
            profile: Arc::clone(&original.profile), journal, socket, transcript,
            apply, result, inventory, model })
    }
}

impl StorageProvisioningWorkspaceOriginalV1<'_> {
    pub(crate) fn receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|n| u64::try_from(n).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(aos_sandbox_core::ResourceDimension::MemoryBytes, bytes))
    }
}
