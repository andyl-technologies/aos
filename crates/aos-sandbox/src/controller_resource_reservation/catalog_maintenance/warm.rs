//! Reuses the real refresh snapshots for the closed no-Storage31 schedule.
//!
//! The canonical reservation selector independently rejoins current C
//! assignment, lease, template pins and physical root proof. A required effect
//! refuses before operation generation or append. Source and every native post
//! remain owned by this same new Maintenance interval.

use super::*;
use crate::guest_root_publication::{GuestRootPublicationErrorV1, GuestRootTemplatePinsV1};

pub(super) struct CatalogMaintenanceWarmOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    inspection: Option<Result<(), GuestRootPublicationErrorV1>>,
    repeated: Option<ResourceReservationErrorV1>,
}

impl CatalogMaintenanceWarmOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            inspection: None,
            repeated: None,
        }
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
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
                self.inspection
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }

    pub(super) fn completed_v2(&self) -> bool {
        self.repeated.is_none()
            && matches!(self.geometry, Some(Ok(_)))
            && matches!(self.funding, Some(Ok(())))
            && matches!(self.inspection, Some(Ok(())))
    }
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Checks the canonical current assignment and physical proof without issuing Storage31.
    ///
    /// The snapshot is the same native-disposed signed Storage18 result already
    /// stored by this interval. Node identity comes from its genuine completed
    /// Storage receiver. Missing pins matter only when that actual inventory
    /// contains a workspace; no empty model or caller-supplied node is accepted.
    ///
    /// # Errors
    /// Retains reentry, changed purpose/Session, incomplete snapshots, payment,
    /// source currentness, assignment/lease/proof disagreement or required31.
    #[doc(hidden)]
    pub fn require_refresh_no_guest_root_effect_once_v2(
        &mut self,
        receiving: &crate::ControllerInitialBrokerSessionReceivingV1,
        session_journal: &Journal,
        pins: Option<GuestRootTemplatePinsV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.require_completed_session_v2(receiving, session_journal, 2)?;
        if self.owner.purpose != Some(MaintenancePurposeV2::CatalogRefresh)
            || self.owner.warm.geometry.is_some()
            || !self.owner.inventory[1..].iter().all(
                super::super::operator_create_recovery::storage::inventory::InventoryOriginalsV1::is_completed_query_v2,
            )
        {
            self.owner.warm.repeated.get_or_insert(ResourceReservationErrorV1::Conflict);
            self.owner.first.get_or_insert(First::Warm);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let node = receiving
            .expected_node_v1()
            .map(aos_sandbox_core::NodeId::from_bytes)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.owner
            .source_projection
            .require_same_projection_v2(self.source.journal_ref_v1())?;

        // The canonical full-C supplier covers the selector's reservation set,
        // current assignment/lease/template decoders and their construction
        // backing. The retained snapshot/model were paid by their own query.
        self.owner.warm.geometry = Some(self.controller.create_storage_semantic_append_demand_v1());
        let Some(demand) = self
            .owner
            .warm
            .geometry
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            self.owner.first.get_or_insert(First::Warm);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        self.owner.warm.funding = Some(self.reserve_additional_v2(demand));
        if !matches!(self.owner.warm.funding, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::Warm);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        self.owner.warm.inspection = Some((|| {
            let snapshot = self
                .owner
                .snapshots
                .storage_snapshot_data_v2()
                .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
            crate::guest_root_publication::require_no_guest_root_publication_v2(
                self.controller,
                snapshot,
                node,
                pins,
            )
        })());
        if !matches!(self.owner.warm.inspection, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::Warm);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        Ok(())
    }
}

/// Borrows this interval's completed refresh and actual native posts.
///
/// This comparison cannot authorize a guest-root effect, claim cold absence or
/// replace the SDK's independently retained query/model/disposal conjunction.
#[doc(hidden)]
pub struct CatalogMaintenanceRefreshCompletedNativeBorrowV2<'completed> {
    _owner: &'completed CatalogMaintenanceOriginalV2,
}

impl CatalogMaintenanceOriginalV2 {
    /// Rejoins genuine final physical inspection, canonical catalog and all posts.
    ///
    /// # Errors
    /// Refuses another purpose, required31, changed current catalog, incomplete
    /// query/Source/native posts, failed SDK disposal or a retained first cause.
    #[doc(hidden)]
    pub fn completed_refresh_native_v2<'completed>(
        &'completed self,
        controller: &Journal,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
    ) -> Result<
        CatalogMaintenanceRefreshCompletedNativeBorrowV2<'completed>,
        ResourceReservationErrorV1,
    > {
        self.require_completed_posts_v2(controller)?;
        if self.purpose != Some(MaintenancePurposeV2::CatalogRefresh) || !self.warm.completed_v2() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.guest_root.root.as_ref().is_some_and(|root| root.has_pending_work_v3())
            || (self.guest_root.storage_io.entered && !self.guest_root.storage_io.disposed)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = self
            .native
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        source.require_completed_maintenance_source_data_v2(native, controller)?;
        if self.catalog_io_entered {
            self.catalog_io.require_disposed_v2()?;
        }
        Ok(CatalogMaintenanceRefreshCompletedNativeBorrowV2 { _owner: self })
    }
}
