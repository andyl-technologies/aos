//! Keeps Maintenance reservation selection and entropy on the actual same F.
//!
//! The shared selector authenticates current assignment/lease and real signed
//! Storage18 DATA. Existing operations remain byte-for-byte stable. A new
//! record crosses only the canonical same-owner provisioning append kernel;
//! this reservation is comparison DATA, never a Root permit or effect grant.

use super::*;
mod root_loan;
mod signing;
mod prepared;
mod storage_io;
use crate::guest_root_publication::{
    GuestRootPublicationAssemblyDataV3, GuestRootPublicationErrorV1,
    GuestRootPublicationReservationV1, GuestRootTemplatePinsV1,
};
pub(crate) use root_loan::ControllerCatalogMaintenanceRootLoanV3;
pub use signing::ControllerCatalogMaintenanceSigningBorrowV3;
pub use prepared::ControllerMaintenanceStorageRequestOriginalV3;
pub use storage_io::ControllerMaintenanceStorageIoLoanV3;
pub use storage_io::ControllerMaintenanceStorageSdkDisposalV3;

pub(super) struct CatalogMaintenanceGuestRootOriginalV3 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    entropy_bytes: [u8; 32],
    entropy: Option<Result<usize, rustix::io::Errno>>,
    entropy_selected: bool,
    selection:
        Option<Result<Option<GuestRootPublicationReservationV1>, GuestRootPublicationErrorV1>>,
    assembly: Option<GuestRootPublicationAssemblyDataV3>,
    append: Option<Result<crate::journal::CommitResult, JournalError>>,
    repeated: Option<ResourceReservationErrorV1>,
    root_total: ResourceVector,
    root_admission: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) root: Option<crate::normal_root::RootMaintenanceStorageClientOriginalV3>,
    pending_root: Option<JournalError>,
    pub(super) storage_io: storage_io::MaintenanceStorageIoOriginalV3,
}

impl CatalogMaintenanceGuestRootOriginalV3 {
    pub(super) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            entropy_bytes: [0; 32],
            entropy: None,
            entropy_selected: false,
            selection: None,
            assembly: None,
            append: None,
            repeated: None,
            root_total: ResourceVector::ZERO,
            root_admission: None,
            root: Some(crate::normal_root::RootMaintenanceStorageClientOriginalV3::new_v3()),
            pending_root: None,
            storage_io: storage_io::MaintenanceStorageIoOriginalV3::new(),
        }
    }

    pub(super) fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        // The raw entropy error is selected only at its actual boundary; an
        // independently owed later post cannot replace an earlier selector.
        if self.entropy_selected {
            if let Some(Err(cause)) = self.entropy.as_ref() {
                return Some(cause);
            }
        }
        self.geometry
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| {
                self.funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.selection
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.append.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.root_admission
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.root.as_ref().and_then(|root| root.failure_v3()))
            .or_else(|| self.storage_io.failure_v3())
            .or_else(|| self.pending_root.as_ref().map(|cause| cause as _))
            .or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }

    pub(super) fn reject_unfinished_root_body_v3(&mut self) -> bool {
        if self
            .root
            .as_ref()
            .is_some_and(|root| root.has_pending_work_v3())
        {
            self.pending_root
                .get_or_insert(JournalError::ProtectedBoundary);
            true
        } else {
            false
        }
    }
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Completes actual31/fresh18 on the original Root socket before Catalog17.
    ///
    /// # Errors
    /// Retains changed actual Session/terminal/native pair, missing fresh C
    /// snapshot, Root proof/ACK/EOF, same-F payment or independent final posts.
    #[doc(hidden)]
    pub fn complete_refresh_guest_root_root_once_v3(
        &mut self,
        receiving: &crate::ControllerInitialBrokerSessionReceivingV1,
        session: &Journal,
        initial_inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        prepared: &ControllerMaintenanceStorageRequestOriginalV3,
        resource: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        native: &[u8; 64],
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.require_completed_session_v2(receiving, session, 2)?;
        self.owner
            .guest_root
            .storage_io
            .require_outcomes_v3(resource, inventory, native)?;
        self.owner.snapshots.require_fresh_storage_snapshot_v3()?;
        let Some(mut root) = self.owner.guest_root.root.take() else {
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let returned = {
            let mut loan = root_loan::ControllerCatalogMaintenanceRootLoanV3::new_v3(
                self.owner,
                self.source,
                receiving,
                session,
                initial_inventory,
            );
            root.complete_final_ack_once_v3(
                &mut loan,
                self.controller,
                prepared,
                [
                    resource.request().canonical_packet(),
                    resource.canonical_packet(),
                    inventory.request().canonical_packet(),
                    inventory.canonical_packet(),
                ],
                native,
            )
        };
        self.owner.guest_root.root = Some(root);
        if returned.is_err() {
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        Ok(())
    }

    /// Transfers the actual all-post signed request once to its owning SDK flight.
    ///
    /// # Errors
    /// Refuses a changed same-F/native association, incomplete signing posts,
    /// missing verified lease or repeated transfer. Root custody stays held.
    #[doc(hidden)]
    pub fn take_refresh_guest_root_request_once_v3(
        &mut self,
    ) -> Result<ControllerMaintenanceStorageRequestOriginalV3, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.check_frontier_v2()?;
        let result = self
            .owner
            .guest_root
            .root
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .take_completed_request_once_v3();
        if result.is_err() {
            self.owner.first.get_or_insert(First::GuestRoot);
        }
        result.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Opens the distinct current Maintenance Root child on its actual Storage Session.
    ///
    /// The caller supplies only its already authenticated query outcome. The
    /// actual query's native disposal/packet commitment, stable C reservation,
    /// complete same-F debit and fixed Root native profile are independently
    /// rejoined before the sole bounded subject/reply transport can run.
    ///
    /// # Errors
    /// Retains changed current custody, foreign query/Session, reentry, funding,
    /// native, Root temporal, framing or independently owed post refusal.
    #[doc(hidden)]
    pub fn open_refresh_guest_root_root_once_v3(
        &mut self,
        receiving: &crate::ControllerInitialBrokerSessionReceivingV1,
        session: &Journal,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.require_completed_session_v2(receiving, session, 2)?;
        let Some(mut root) = self.owner.guest_root.root.take() else {
            self.owner
                .guest_root
                .repeated
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let returned = {
            let mut loan = root_loan::ControllerCatalogMaintenanceRootLoanV3::new_v3(
                self.owner,
                self.source,
                receiving,
                session,
                inventory,
            );
            root.begin_once_v3(&mut loan, self.controller)
        };
        self.owner.guest_root.root = Some(root);
        if returned.is_err() {
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        Ok(())
    }

    /// Reserves or resumes the real first workspace under this Maintenance F.
    ///
    /// The same completed Storage Session and native-disposed signed snapshot
    /// remain held throughout. This does not issue or sign a Storage31 request;
    /// its stable effect operation must still pass the independent Root method
    /// purpose, current ownership and final physical readback conjunction.
    ///
    /// # Errors
    /// Retains reentry, another purpose/Session, stale inventory, malformed
    /// current authority, changed pins/workspace, entropy or native append
    /// failure. No ordinary journal commit or new account is used.
    #[doc(hidden)]
    pub fn reserve_refresh_guest_root_once_v3(
        &mut self,
        receiving: &crate::ControllerInitialBrokerSessionReceivingV1,
        session_journal: &Journal,
        pins: Option<GuestRootTemplatePinsV1>,
    ) -> Result<Option<GuestRootPublicationReservationV1>, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.require_completed_session_v2(receiving, session_journal, 2)?;
        if self.owner.purpose != Some(MaintenancePurposeV2::CatalogRefresh)
            || self.owner.guest_root.geometry.is_some()
            || !self.owner.inventory[1..].iter().all(
                super::super::operator_create_recovery::storage::inventory::InventoryOriginalsV1::is_completed_query_v2)
        {
            self.owner.guest_root.repeated.get_or_insert(ResourceReservationErrorV1::Conflict);
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let node = receiving
            .expected_node_v1()
            .map(aos_sandbox_core::NodeId::from_bytes)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.owner
            .source_projection
            .require_same_projection_v2(self.source.journal_ref_v1())?;

        self.owner.guest_root.geometry = Some((|| {
            self.controller
                .create_storage_semantic_append_demand_v1()?
                .checked_add(GuestRootPublicationAssemblyDataV3::construction_demand_data_v3()?)
                .map_err(JournalError::ReceivingAccounting)
        })());
        let Some(demand) = self
            .owner
            .guest_root
            .geometry
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        self.owner.guest_root.funding = Some(self.reserve_additional_v2(demand));
        if !matches!(self.owner.guest_root.funding, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        self.owner.guest_root.selection = Some((|| {
            let snapshot = self
                .owner
                .snapshots
                .storage_snapshot_data_v2()
                .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
            let Some(selection) =
                crate::guest_root_publication::select_maintenance_guest_root_data_v3(
                    self.controller,
                    snapshot,
                    node,
                    pins,
                )?
            else {
                return Ok(None);
            };
            if let Some(reservation) = selection.existing_reservation_data_v3() {
                return Ok(Some(reservation));
            }

            // Both operation and transaction identifiers are sampled only
            // after payment and genuine selection of a new reservation.
            let original = &mut self.owner.guest_root;
            original.entropy = Some(rustix::rand::getrandom(
                &mut original.entropy_bytes,
                rustix::rand::GetRandomFlags::empty(),
            ));
            if !matches!(original.entropy, Some(Ok(32))) {
                original.entropy_selected = true;
                return Err(GuestRootPublicationErrorV1::Unavailable);
            }
            let mut operation = [0; 16];
            operation.copy_from_slice(&original.entropy_bytes[..16]);
            let mut transaction_id = [0; 16];
            transaction_id.copy_from_slice(&original.entropy_bytes[16..]);
            let assembly = selection.assemble_new_data_v3(
                aos_sandbox_core::OperationId::from_bytes(operation),
                transaction_id,
            )?;
            let reservation = assembly.reservation_data_v3();
            original.assembly = Some(assembly);
            Ok(Some(reservation))
        })());
        if !matches!(self.owner.guest_root.selection, Some(Ok(_))) {
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;

        if let Some(assembly) = self.owner.guest_root.assembly.take() {
            // The short canonical recipe borrow remains outside `owner` so
            // the same actual owner can fund and retain the native append.
            // Restore the assembly on both positive and negative completion.
            let result = self.owner.commit_append_recipe_once_v2(
                self.controller,
                self.source,
                assembly.transaction_v3(),
                super::append_recipe::CatalogMaintenanceAppendRecipeV2::GuestRootReservation(
                    &assembly,
                ),
            );
            self.owner.guest_root.assembly = Some(assembly);
            self.owner.guest_root.append = Some(result);
            if !matches!(self.owner.guest_root.append, Some(Ok(_))) {
                self.owner.first.get_or_insert(First::GuestRoot);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        self.check_frontier_v2()?;
        self.owner
            .guest_root
            .selection
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}
