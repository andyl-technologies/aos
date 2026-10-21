//! Retains the exact Start catalog source before publication on its Host Session.
//!
//! The private catalog loan supplies the actual pending child, Start, Source
//! and Root interval. This owner derives the existing canonical pending record
//! from the genuine Prepared projection. A pending row or sealed descriptor is
//! not a Host grant, native completion or confirmation of publication.

mod maintenance;
pub use maintenance::CatalogMaintenancePublicationStatusV2;

use super::*;
use crate::OriginalStartHostRootLoanV1;
use crate::StartHostCatalogPublicationLoanV2;
use crate::{PreparedStartResourceRequestOriginalV2, ResourceReservationErrorV1};
use aos_sandbox_model::{OperationId, ResourceVector};
use aos_linux_descriptors::credential::SealedReadOnlyCredential;
use aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateClosedV1;
use aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateOriginalsV1;
use std::error::Error;
use std::mem::size_of;
use std::sync::Arc;

const TRANSFER_NAME: &str = "aos-host-catalog";
const CLOSED: StartHostCatalogPublicationClosedV2 = StartHostCatalogPublicationClosedV2;

/// Refuses publication while the actual canonical and native originals remain held.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original Start Host catalog publication is incomplete or refused")]
#[doc(hidden)]
pub struct StartHostCatalogPublicationClosedV2;

#[derive(Clone, Copy)]
enum First {
    Reentry,
    Entry,
    Geometry,
    Funding,
    ResidentHandoff,
    History,
    ControllerState,
    Pending,
    Transaction,
    Commit,
    Readback,
    Draft,
    Seal,
    ConfirmationEntry,
    ConfirmationHistory,
    ConfirmationTransaction,
    ConfirmationCommit,
    ConfirmationReadback,
    MaintenanceEntry,
    MaintenanceProjection,
    MaintenanceExtent,
    MaintenanceOutputGeometry,
    MaintenanceOutputFunding,
}

/// Retains the same canonical pending source and sealed transfer through catalog posts.
///
/// Empty construction allocates nothing. No caller-supplied catalog, inventory
/// hash array, descriptor or resource vector can construct a positive source.
#[doc(hidden)]
#[must_use = "retain the complete source through Session, C and Root posts"]
pub struct StartHostCatalogPublicationOriginalV2 {
    maintenance_identity: Option<Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2, ResourceReservationErrorV1>>,
    maintenance_mode: Option<maintenance::MaintenanceSourceModeV2>,
    maintenance_projection: Option<Result<PreparedHostCatalogModelDataV2, HostCatalogReconciliationError>>,
    maintenance_current_catalog: Option<DurableCurrentHostCatalogV1>,
    maintenance_current_row_digest: Option<[u8; 32]>,
    maintenance_extent: Option<Result<usize, HostCatalogSnapshotError>>,
    maintenance_output_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    maintenance_output_funding: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<First>,
    identity: Option<Arc<()>>,
    parent: Option<OperationId>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    resident_handoff: Option<Result<(), ResourceReservationErrorV1>>,
    history: Option<Result<CatalogHistory, HostCatalogReconciliationError>>,
    controller_state: Option<Result<[u8; 32], crate::ResourceInventoryError>>,
    pending: Option<Result<CatalogRecord, HostCatalogReconciliationError>>,
    transaction: Option<Result<JournalTransaction, HostCatalogReconciliationError>>,
    commit: Option<Result<crate::CommitResult, JournalError>>,
    readback: Option<Result<CatalogHistory, HostCatalogReconciliationError>>,
    draft: Option<Result<HostCatalogPublicationDraftV1, HostCatalogPublicationError>>,
    sealing: SealedReadOnlyCredentialCreateOriginalsV1,
    seal: Option<Result<(), SealedReadOnlyCredentialCreateClosedV1>>,
    original_selected: bool,
    confirmation_entry: Option<Result<(), ResourceReservationErrorV1>>,
    confirmation_history: Option<Result<CatalogHistory, HostCatalogReconciliationError>>,
    confirmation_transaction: Option<Result<JournalTransaction, HostCatalogReconciliationError>>,
    confirmation_commit: Option<Result<crate::CommitResult, JournalError>>,
    confirmation_readback: Option<Result<CatalogHistory, HostCatalogReconciliationError>>,
}

impl StartHostCatalogPublicationOriginalV2 {
    /// Creates only inert inline destinations, without IO or variable backing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            maintenance_identity: None,
            maintenance_mode: None,
            maintenance_projection: None,
            maintenance_current_catalog: None,
            maintenance_current_row_digest: None,
            maintenance_extent: None,
            maintenance_output_geometry: None,
            maintenance_output_funding: None,
            first: None,
            identity: None,
            parent: None,
            entry: None,
            geometry: None,
            funding: None,
            resident_handoff: None,
            history: None,
            controller_state: None,
            pending: None,
            transaction: None,
            commit: None,
            readback: None,
            draft: None,
            sealing: SealedReadOnlyCredentialCreateOriginalsV1::new(),
            seal: None,
            original_selected: false,
            confirmation_entry: None,
            confirmation_history: None,
            confirmation_transaction: None,
            confirmation_commit: None,
            confirmation_readback: None,
        }
    }

    /// Commits and seals only the actual signed Prepared projection in catalog6.
    ///
    /// The genuine short Root loan admits the complete co-live source before
    /// decoding history or cloning the catalog. The private catalog wrapper
    /// temporarily installs the same paid append scope for the pending write,
    /// then restores the original Start native state before Session IO.
    ///
    /// # Errors
    /// Retains reentry, currentness, compiled geometry, original funding,
    /// canonical history/projection, native append/readback or sealing refusal.
    pub fn prepare_pending_once_v2(
        &mut self,
        loan: &mut StartHostCatalogPublicationLoanV2<'_>,
        controller: &mut Journal,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), StartHostCatalogPublicationClosedV2> {
        if self.entry.is_some() || self.maintenance_identity.is_some() || self.first.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.entry = Some(loan.enter_publication_source_once_v2(controller));
        if !matches!(self.entry, Some(Ok(()))) {
            self.original_selected = loan.original_failure_selected_v2();
            self.first = Some(First::Entry);
            return Err(CLOSED);
        }
        self.geometry = Some((|| {
            let original = loan.borrow_host_root_v2(controller)?;
            let projection = prepared
                .host_catalog_projection_v2(&original, controller)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let bytes = projection
                .canonical_catalog_data_v2(&original, controller)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            source_receiving_demand_v2(controller, bytes.len())
        })());
        let Some(Ok(demand)) = self.geometry.as_ref() else {
            self.original_selected = loan.original_failure_selected_v2();
            self.first = Some(First::Geometry);
            return Err(CLOSED);
        };
        self.funding = Some((|| {
            let mut original = loan.borrow_host_root_v2(controller)?;
            let returned = original.require_complete_v1(controller, *demand);
            if returned.is_ok() {
                self.identity = Some(original.retained_resource_identity_v2());
                self.parent = Some(original.parent_operation_v1());
            }
            self.original_selected = returned.is_err() && original.failure_v1().is_some();
            returned
        })());
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(CLOSED);
        }

        self.resident_handoff = Some(loan.retain_source_resident_v2(controller, self));
        if !matches!(self.resident_handoff, Some(Ok(()))) {
            self.original_selected = loan.original_failure_selected_v2();
            self.first = Some(First::ResidentHandoff);
            return Err(CLOSED);
        }

        self.history = Some(CatalogHistory::load(controller));
        if !matches!(self.history, Some(Ok(_))) {
            self.first = Some(First::History);
            return Err(CLOSED);
        }
        self.controller_state = Some(crate::resource_inventory::controller_state_digest(
            controller,
        ));
        if !matches!(self.controller_state, Some(Ok(_))) {
            self.first = Some(First::ControllerState);
            return Err(CLOSED);
        }
        self.pending = Some((|| {
            let original = loan
                .borrow_host_root_v2(controller)
                .map_err(|_| HostCatalogReconciliationError::InventoryConflict)?;
            let projection = prepared
                .host_catalog_projection_v2(&original, controller)
                .map_err(|_| HostCatalogReconciliationError::InventoryConflict)?;
            let catalog = projection
                .catalog_data_v2(&original, controller)
                .map_err(|_| HostCatalogReconciliationError::InventoryConflict)?;
            let digests = projection
                .source_comparison_data_v2(&original, controller)
                .map_err(|_| HostCatalogReconciliationError::InventoryConflict)?;
            let history = positive(&self.history)?;
            if history.pending.is_some() {
                return Err(HostCatalogReconciliationError::PendingPublication);
            }
            let expected = history
                .current
                .as_ref()
                .map_or(Some(1), |prior| prior.catalog.generation().checked_add(1))
                .ok_or(HostCatalogReconciliationError::GenerationExhausted)?;
            if catalog.generation() != expected {
                return Err(HostCatalogReconciliationError::InventoryConflict);
            }
            let digest = self
                .controller_state
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(HostCatalogReconciliationError::CorruptState)?;
            CatalogRecord::pending(
                ObjectDigest::from_bytes(digest),
                digests.map(ObjectDigest::from_bytes),
                history.current.as_ref(),
                catalog.clone(),
            )
        })());
        if !matches!(self.pending, Some(Ok(_))) {
            self.original_selected = loan.original_failure_selected_v2();
            self.first = Some(First::Pending);
            return Err(CLOSED);
        }
        self.commit_and_seal_pending_v2(controller, |controller, transaction, recipe| {
            let result = loan.commit_catalog_recipe_v2(controller, transaction, recipe);
            (result, loan.original_failure_selected_v2())
        })
    }

    fn commit_and_seal_pending_v2(
        &mut self,
        controller: &mut Journal,
        mut append: impl FnMut(
            &mut Journal,
            &JournalTransaction,
            &publication_recipe::HostCatalogCommitRecipeV2<'_>,
        ) -> (Result<crate::CommitResult, JournalError>, bool),
    ) -> Result<(), StartHostCatalogPublicationClosedV2> {
        self.transaction = Some(positive(&self.pending).and_then(CatalogRecord::transaction));
        if !matches!(self.transaction, Some(Ok(_))) {
            self.first = Some(First::Transaction);
            return Err(CLOSED);
        }
        self.commit = Some((|| {
            let record = self
                .pending
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let transaction = self
                .transaction
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let recipe = publication_recipe::HostCatalogCommitRecipeV2::from_canonical_assembly_v2(
                controller,
                transaction,
                record,
                publication_recipe::HostCatalogCommitPhaseV2::Pending,
            )
            .map_err(|_| JournalError::ProtectedBoundary)?;
            let (result, original_selected) = append(controller, transaction, &recipe);
            if result.is_err() {
                self.original_selected = original_selected;
            }
            result
        })());
        if !matches!(self.commit, Some(Ok(_))) {
            self.first = Some(First::Commit);
            return Err(CLOSED);
        }
        self.readback = Some((|| {
            let readback = CatalogHistory::load(controller)?;
            if readback.pending.as_ref() != Some(positive(&self.pending)?) {
                return Err(HostCatalogReconciliationError::CorruptState);
            }
            Ok(readback)
        })());
        if !matches!(self.readback, Some(Ok(_))) {
            self.first = Some(First::Readback);
            return Err(CLOSED);
        }
        self.seal_canonical_pending_v2()
    }

    fn seal_canonical_pending_v2(&mut self) -> Result<(), StartHostCatalogPublicationClosedV2> {
        self.draft = Some((|| {
            let pending = self
                .pending
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(HostCatalogPublicationError::InvalidDraft)?;
            let draft = HostCatalogPublicationDraftV1::new(
                pending.canonical_catalog.clone(),
                pending.catalog.generation(),
            )?;
            if draft.expected_digest().as_bytes() != &pending.catalog_digest {
                return Err(HostCatalogPublicationError::ReceiptMismatch);
            }
            Ok(draft)
        })());
        let Some(Ok(draft)) = self.draft.as_ref() else {
            self.first = Some(First::Draft);
            return Err(CLOSED);
        };
        self.seal = Some(self.sealing.create_once(
            TRANSFER_NAME,
            draft.canonical_catalog(),
            aos_sandbox_protocol::host_catalog::MAXIMUM_HOST_CATALOG_BYTES,
        ));
        if !matches!(self.seal, Some(Ok(()))) {
            self.first = Some(First::Seal);
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Confirms only the same actual native-completed publication through the paid append.
    ///
    /// The short IO borrower must have returned before this method mutably
    /// borrows the canonical source. A signed outcome alone cannot enter: the
    /// genuine Catalog6 loan rejoins its actual retained native stage/receipts.
    /// The source's original complete invoice covers all confirmation models,
    /// transaction, recipe and readback before their construction.
    ///
    /// # Errors
    /// Retains changed source/native evidence, reentry, canonical history,
    /// actual native commit or readback failure without ordinary commit fallback.
    pub fn confirm_once_v2(
        &mut self,
        loan: &mut StartHostCatalogPublicationLoanV2<'_>,
        controller: &mut Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), StartHostCatalogPublicationClosedV2> {
        if self.first.is_some() || self.confirmation_entry.is_some() {
            return Err(CLOSED);
        }
        self.confirmation_entry =
            Some(loan.require_terminal_for_confirmation_v2(self, controller, outcome));
        if !matches!(self.confirmation_entry, Some(Ok(()))) {
            self.original_selected = loan.original_failure_selected_v2();
            self.first = Some(First::ConfirmationEntry);
            return Err(CLOSED);
        }
        self.confirm_canonical_pending_v2(controller, outcome, |controller, transaction, recipe| {
            let result = loan.commit_catalog_recipe_v2(controller, transaction, recipe);
            (result, loan.original_failure_selected_v2())
        })
    }

    fn confirm_canonical_pending_v2(
        &mut self,
        controller: &mut Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        mut append: impl FnMut(
            &mut Journal,
            &JournalTransaction,
            &publication_recipe::HostCatalogCommitRecipeV2<'_>,
        ) -> (Result<crate::CommitResult, JournalError>, bool),
    ) -> Result<(), StartHostCatalogPublicationClosedV2> {
        self.confirmation_history = Some((|| {
            let history = CatalogHistory::load(controller)?;
            let pending = positive(&self.pending)?;
            if history.pending.as_ref() != Some(pending) {
                return Err(HostCatalogReconciliationError::InventoryConflict);
            }
            super::authenticated::validate_pending_outcome_binding_v2(pending, outcome)?;
            Ok(history)
        })());
        if !matches!(self.confirmation_history, Some(Ok(_))) {
            self.first = Some(First::ConfirmationHistory);
            return Err(CLOSED);
        }
        self.confirmation_transaction =
            Some(positive(&self.pending).and_then(CatalogRecord::completion_transaction));
        if !matches!(self.confirmation_transaction, Some(Ok(_))) {
            self.first = Some(First::ConfirmationTransaction);
            return Err(CLOSED);
        }
        self.confirmation_commit = Some((|| {
            let pending = self
                .pending
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let transaction = self
                .confirmation_transaction
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let recipe = publication_recipe::HostCatalogCommitRecipeV2::from_canonical_assembly_v2(
                controller,
                transaction,
                pending,
                publication_recipe::HostCatalogCommitPhaseV2::Confirmation,
            )
            .map_err(|_| JournalError::ProtectedBoundary)?;
            let (result, original_selected) = append(controller, transaction, &recipe);
            if result.is_err() {
                self.original_selected = original_selected;
            }
            result
        })());
        if !matches!(self.confirmation_commit, Some(Ok(_))) {
            self.first = Some(First::ConfirmationCommit);
            return Err(CLOSED);
        }
        self.confirmation_readback = Some((|| {
            let history = CatalogHistory::load(controller)?;
            require_confirmation_readback_v2(&history, positive(&self.pending)?)?;
            Ok(history)
        })());
        if !matches!(self.confirmation_readback, Some(Ok(_))) {
            self.first = Some(First::ConfirmationReadback);
            return Err(CLOSED);
        }
        Ok(())
    }

    // The actual native resource handoff invokes this BEFORE the first
    // history/model/append/sealer growth. Positive payment alone cannot be
    // transplanted to another Start or used as a generic supplied vector.
    pub(crate) fn require_admitted_receiving_owner_v2(
        &self,
        original: &OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        original.require_current_v1(controller)?;
        if self.first.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || self.parent != Some(original.parent_operation_v1())
            || self.identity.as_ref().is_none_or(|identity| {
                !Arc::ptr_eq(identity, &original.retained_resource_identity_v2())
            })
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    // This is an identity/history comparison on the genuine current Start
    // borrower. The separate catalog6 loan checks its pending child and Root
    // purpose before any request or native entry.
    pub(crate) fn require_same_source_v2(
        &self,
        original: &OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        original.require_current_v1(controller)?;
        self.require_native_source_v2(
            &original.retained_resource_identity_v2(),
            original.parent_operation_v1(),
            controller,
        )
    }

    pub(crate) fn require_native_source_v2(
        &self,
        identity: &Arc<()>,
        parent: OperationId,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some()
            || self.parent != Some(parent)
            || self
                .identity
                .as_ref()
                .is_none_or(|held| !Arc::ptr_eq(held, identity))
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(self.resident_handoff, Some(Ok(())))
            || !matches!(self.commit, Some(Ok(_)))
            || !matches!(self.seal, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if matches!(self.confirmation_commit, Some(Ok(_))) {
            return self.require_confirmed_native_source_v2(controller);
        }
        let transaction = self
            .transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let [record] = transaction.records() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        if record.namespace() != RecordNamespace::HostCatalogReconciliation
            || record.key() != PENDING_KEY
            || controller.get(RecordNamespace::HostCatalogReconciliation, PENDING_KEY)
                != record.value()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_confirmed_native_source_v2(
        &self,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some()
            || !matches!(self.confirmation_commit, Some(Ok(_)))
            || !matches!(self.confirmation_readback, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let transaction = self
            .confirmation_transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let current = transaction
            .records()
            .iter()
            .find(|record| {
                record.namespace() == RecordNamespace::HostCatalogReconciliation
                    && record.key() == CURRENT_KEY
            })
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if controller
            .get(RecordNamespace::HostCatalogReconciliation, PENDING_KEY)
            .is_some()
            || controller.get(RecordNamespace::HostCatalogReconciliation, CURRENT_KEY)
                != current.value()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Borrows the same paid source shape without refunding a failed prefix.
    #[must_use]
    pub fn resident_receiving_demand_v2(&self) -> Option<ResourceVector> {
        let history = self.geometry.as_ref()?.as_ref().ok().copied()?;
        match self.maintenance_output_geometry.as_ref() {
            Some(Ok(output)) => history.checked_add(*output).ok(),
            Some(Err(_)) => None,
            None => Some(history),
        }
    }

    /// Borrows the actual first failure without replacing it with a later post.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Reentry => Some(&CLOSED),
            First::MaintenanceEntry => cause(&self.maintenance_identity),
            First::MaintenanceProjection => cause(&self.maintenance_projection),
            First::MaintenanceExtent => cause(&self.maintenance_extent),
            First::MaintenanceOutputGeometry => cause(&self.maintenance_output_geometry),
            First::MaintenanceOutputFunding => cause(&self.maintenance_output_funding),
            First::Entry => cause(&self.entry),
            First::Geometry => cause(&self.geometry),
            First::Funding => cause(&self.funding),
            First::ResidentHandoff => cause(&self.resident_handoff),
            First::History => cause(&self.history),
            First::ControllerState => cause(&self.controller_state),
            First::Pending => cause(&self.pending),
            First::Transaction => cause(&self.transaction),
            First::Commit => cause(&self.commit),
            First::Readback => cause(&self.readback),
            First::Draft => cause(&self.draft),
            First::Seal => self.sealing.failure().or_else(|| cause(&self.seal)),
            First::ConfirmationEntry => cause(&self.confirmation_entry),
            First::ConfirmationHistory => cause(&self.confirmation_history),
            First::ConfirmationTransaction => cause(&self.confirmation_transaction),
            First::ConfirmationCommit => cause(&self.confirmation_commit),
            First::ConfirmationReadback => cause(&self.confirmation_readback),
        }
    }

    /// Identifies only a source gate selected before the retained local first cause.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        self.original_selected
    }

    /// Borrows the same canonical draft after the real pending append and sealing.
    ///
    /// This view is comparison DATA, not a publication or activation grant.
    ///
    /// # Errors
    /// Refuses any incomplete or failed source prefix.
    #[doc(hidden)]
    pub fn draft_v2(
        &self,
    ) -> Result<&HostCatalogPublicationDraftV1, StartHostCatalogPublicationClosedV2> {
        if self.first.is_some() || !matches!(self.seal, Some(Ok(()))) {
            return Err(CLOSED);
        }
        self.draft
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(CLOSED)
    }

    /// Borrows the same completed sealed transfer without cloning its descriptor.
    ///
    /// The actual catalog IO loan must independently associate this source
    /// before the shared sender may transfer its descriptor.
    ///
    /// # Errors
    /// Refuses incomplete pending, sealing or prior source failure.
    #[doc(hidden)]
    pub fn sealed_transfer_v2(
        &self,
    ) -> Result<&SealedReadOnlyCredential, StartHostCatalogPublicationClosedV2> {
        self.draft_v2()?;
        self.sealing.completed().ok_or(CLOSED)
    }
}

impl Default for StartHostCatalogPublicationOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

fn source_receiving_demand_v2(
    controller: &Journal,
    catalog_bytes: usize,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let inline = size_of::<StartHostCatalogPublicationOriginalV2>()
        .checked_mul(2)
        .and_then(|bytes| {
            bytes.checked_add(size_of::<crate::StartHostCatalogIoLoanV2<'static>>().checked_mul(2)?)
        })
        .and_then(|bytes| {
            bytes
                .checked_add(size_of::<crate::StartHostCatalogNativeCompletionV2>().checked_mul(2)?)
        })
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    super::source_receiving::canonical_source_receiving_demand_v2(controller, catalog_bytes, inline)
}

fn positive<T>(
    slot: &Option<Result<T, HostCatalogReconciliationError>>,
) -> Result<&T, HostCatalogReconciliationError> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(HostCatalogReconciliationError::CorruptState)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|error| error as _)
}
