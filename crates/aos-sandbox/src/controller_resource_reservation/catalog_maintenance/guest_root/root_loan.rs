//! Lends the genuine Maintenance original to the common finite Root transport.
//!
//! Its private constructor receives the same held Source, completed Storage
//! Session and signed18 outcome. The Root transport's cumulative demand is
//! converted to monotone increments on that same F, preserving SDK and append
//! contributions incurred between the unsigned and final Root exchanges.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::semantics::CanonicalStorageGuestRootArgumentsV1;

pub(crate) struct ControllerCatalogMaintenanceRootLoanV3<'owner, 'session> {
    pub(super) owner: &'owner mut CatalogMaintenanceOriginalV2,
    source: &'session ProtectedSourceDomainJournalOwnerV1,
    receiving: &'session crate::ControllerInitialBrokerSessionReceivingV1,
    session: &'session Journal,
    inventory: &'session AuthenticatedBrokerMethodOutcomeV1,
}

impl<'owner, 'session> ControllerCatalogMaintenanceRootLoanV3<'owner, 'session> {
    pub(super) fn new_v3(
        owner: &'owner mut CatalogMaintenanceOriginalV2,
        source: &'session ProtectedSourceDomainJournalOwnerV1,
        receiving: &'session crate::ControllerInitialBrokerSessionReceivingV1,
        session: &'session Journal,
        inventory: &'session AuthenticatedBrokerMethodOutcomeV1,
    ) -> Self {
        Self {
            owner,
            source,
            receiving,
            session,
            inventory,
        }
    }

    pub(crate) fn require_current_v3(
        &mut self,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner.require_current_v2(controller, self.source)?;
        self.owner.require_completed_session_data_v3(
            controller,
            self.receiving,
            self.session,
            2,
        )?;
        if self.owner.purpose != Some(MaintenancePurposeV2::CatalogRefresh) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.reservation_data_v3()?;
        self.owner.check_frontier_v2()?;
        Ok(())
    }

    pub(crate) fn require_initial_inventory_v3(
        &mut self,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v3(controller)?;
        self.owner.inventory[2].require_completed_inventory_data_v2(
            self.session, self.inventory,
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            false,
        )
        .map(|_| ())
    }

    pub(crate) fn require_complete_v3(
        &mut self,
        controller: &Journal,
        demand: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v3(controller)?;
        let result = (|| {
            let additional = demand.checked_sub(self.owner.guest_root.root_total)?;
            self.owner
                .reserve_additional_v2(controller, self.source, additional)?;
            self.owner.guest_root.root_total = demand;
            Ok(())
        })();
        self.owner.guest_root.root_admission = Some(result);
        if !matches!(self.owner.guest_root.root_admission, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn completion_positions_demand_v3(
        &self,
        controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        crate::journal::StartResourceNativePositionsOriginalV2::receiving_demand_v2(
            controller,
            self.source.journal_ref_v1(),
        )
        .map_err(Into::into)
    }

    pub(crate) fn observe_completion_positions_once_v3(
        &mut self,
        controller: &Journal,
        positions: &mut crate::journal::StartResourceNativePositionsOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v3(controller)?;
        positions
            .observe_once_v2(controller, self.source.journal_ref_v1())
            .map_err(Into::into)
    }

    pub(crate) fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.failure_v2()
    }

    pub(crate) fn horizon_data_v3(
        &self,
    ) -> Result<(RawPairedClockSample, u64), ResourceReservationErrorV1> {
        Ok((
            self.owner.clock.original_sample_data_v2()?,
            self.owner.clock.cutoff_data_v2()?,
        ))
    }

    pub(crate) fn retained_profile_v3(
        &self,
    ) -> Result<Arc<ProductionControllerNormalRootProfileV1>, ResourceReservationErrorV1> {
        self.owner
            .profile
            .as_ref()
            .map(Arc::clone)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn reservation_data_v3(
        &self,
    ) -> Result<GuestRootPublicationReservationV1, ResourceReservationErrorV1> {
        self.owner
            .guest_root
            .selection
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .flatten()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn reservation_record_data_v3<'controller>(
        &self,
        controller: &'controller Journal,
    ) -> Result<&'controller [u8], ResourceReservationErrorV1> {
        let reservation = self.reservation_data_v3()?;
        let encoded = controller
            .get(
                crate::RecordNamespace::GuestRootPublication,
                &reservation.workspace_handle(),
            )
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if crate::guest_root_publication::current_guest_root_reservation_data_v2(
            controller, encoded,
        )
        .map_err(|_| ResourceReservationErrorV1::Conflict)?
            != reservation
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(encoded)
    }

    pub(crate) fn canonical_arguments_data_v3(
        &self,
        controller: &Journal,
    ) -> Result<CanonicalStorageGuestRootArgumentsV1, Box<dyn Error + Send + Sync>> {
        let reservation = self.reservation_data_v3()?;
        let current = crate::publication::current_readonly_v2(controller, reservation.sandbox())?
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let inventory = self.owner.snapshots.storage_snapshot_data_v2()?;
        let node = self
            .receiving
            .expected_node_v1()
            .map(aos_sandbox_core::NodeId::from_bytes)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let selected = crate::guest_root_publication::reserved_guest_root_workspace_data_v2(
            controller,
            current.manifest(),
            inventory.inventory(),
            self.reservation_record_data_v3(controller)?,
            node,
        )?;
        Ok(*selected.arguments_v2())
    }

    pub(crate) fn current_assignment_data_v3(
        &mut self,
        controller: &Journal,
    ) -> Result<crate::policy_compiler::provisioning_current::current_cleanup_assignment::CurrentCleanupAssignmentDataV2,
        Box<dyn Error + Send + Sync>> {
        self.require_current_v3(controller)?;
        let reservation = self.reservation_data_v3()?;
        let selected = controller.current_delete_resource_assignment_data_v2(reservation.sandbox())?;
        let manifest = selected.binding.manifest();
        let assignment = manifest.broker_assignment()?;
        let (incarnation, epoch, generation, digest) = reservation.assignment_fence();
        if assignment.incarnation().as_bytes() != &incarnation
            || assignment.epoch().get() != epoch
            || assignment.desired_generation().get() != generation
            || assignment.digest().as_bytes() != &digest
            || manifest.manifest().node().as_bytes() != &self.receiving.expected_node_v1()?
        {
            return Err(ResourceReservationErrorV1::Conflict.into());
        }
        Ok(selected)
    }

    pub(crate) fn controller_account_data_v3<'controller>(
        &self,
        controller: &'controller Journal,
    ) -> Result<&'controller [u8], ResourceReservationErrorV1> {
        self.owner
            .bank
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .catalog_maintenance_controller_head_v3(
                self.owner
                    .native
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
                controller,
                self.owner
                    .profile
                    .as_ref()
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
            )
    }

    pub(crate) fn inventory_packets_data_v3(&self) -> (&[u8], &[u8]) {
        (
            self.inventory.request().canonical_packet(),
            self.inventory.canonical_packet(),
        )
    }

    pub(crate) fn narrow_returned_authority_v3(
        &mut self,
        controller: &Journal,
        policy_expires: i64,
        lease_expires: i64,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.require_current_v3(controller)?;
        let reservation = self.reservation_data_v3()?;
        let current = crate::publication::current_readonly_v2(controller, reservation.sandbox())?
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if current.lease().lease().authority_expires_seconds() != lease_expires {
            return Err(ResourceReservationErrorV1::Conflict.into());
        }
        self.owner
            .clock
            .narrow_authority_expiry_v2(policy_expires.min(lease_expires))?;
        self.owner.check_frontier_v2()?;
        Ok(())
    }

    /// Captures only these two actual held fixed names through the common engine.
    pub(crate) fn capture_source_session_native_once_v3(
        &mut self,
        controller: &Journal,
        source: &mut crate::journal::CreateStorageWriterPositionOriginalV1,
        session: &mut crate::journal::CreateStorageWriterPositionOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v3(controller)?;
        source.capture_once(
            self.source.journal_ref_v1(),
            crate::controller_resource_reservation::HistoryRoleV1::Source,
        );
        source.position()?;
        session.capture_controller_storage_client_once(self.session, controller);
        session.position()?;
        self.owner.check_frontier_v2()?;
        Ok(())
    }
}
