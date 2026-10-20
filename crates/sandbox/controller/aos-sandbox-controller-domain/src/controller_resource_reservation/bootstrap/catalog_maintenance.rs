//! Joins a new catalog maintenance interval to the same actual C and Source.
//!
//! The closed lower purpose checks the real current recipient and fixed
//! profile. This adapter never claims initial B again, casts read-only Recover,
//! imports an old deadline or selects a caller account.

use super::*;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceReceivingV2;
use aos_sandbox_broker::source_receiving::SourceCatalogMaintenanceCurrentnessOriginalV2;
use aos_sandbox_model::ResourceVector;

impl ControllerResourceBankOpeningV1 {
    /// Borrows the same baseline C head after this genuine Maintenance join.
    pub(crate) fn catalog_maintenance_controller_head_v3<'journal>(
        &self,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &'journal Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<&'journal [u8], ResourceReservationErrorV1> {
        self.require_catalog_maintenance_current_v2(receiving, controller, profile)?;
        self.baseline_controller_head_data_v3(controller)
    }

    pub(crate) fn begin_catalog_maintenance_native_v2(
        &self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<ControllerCatalogMaintenanceReceivingV2, ResourceReservationErrorV1> {
        if self.failure().is_some()
            || !self.native_opened()
            || self.original.is_closed()
            || !profile
                .lower_original_v1()
                .has_same_baseline_original(&self.original)
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = controller.controller_coordinator_for_bank_v1()?;
        writer.require_same_original_v1(&self.original)?;
        Ok(writer.begin_catalog_maintenance_receiving_v2(
            launch,
            profile.lower_original_v1(),
            complete,
        ))
    }

    pub(crate) fn require_catalog_maintenance_current_v2(
        &self,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving
            .require_current_v2(
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
            )
            .map_err(Into::into)
    }

    pub(crate) fn require_catalog_maintenance_complete_v2(
        &self,
        receiving: &mut ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving
            .require_complete_representation_v2(
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
                complete,
            )
            .map_err(Into::into)
    }

    pub(crate) fn begin_source_catalog_maintenance_v2(
        &self,
        receiving: &mut ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<SourceCatalogMaintenanceCurrentnessOriginalV2, ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.journal().begin_source_catalog_maintenance_native_v2(
            receiving,
            controller.controller_coordinator_for_bank_read_v1()?,
            launch,
            profile.lower_original_v1(),
            complete,
        )
    }

    pub(crate) fn require_source_catalog_maintenance_current_v2(
        &self,
        original: &mut SourceCatalogMaintenanceCurrentnessOriginalV2,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source
            .journal_ref_v1()
            .require_source_catalog_maintenance_current_v2(
                original,
                receiving,
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
            )
    }

    // This independent destination deliberately has no healthy-primary guard.
    pub(crate) fn finish_catalog_maintenance_native_once_v2(
        &self,
        receiving: &mut ControllerCatalogMaintenanceReceivingV2,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving
            .finish_native_once_v2(
                controller.controller_coordinator_for_bank_v1()?,
                launch,
                profile.lower_original_v1(),
            )
            .map_err(Into::into)
    }

    pub(crate) fn dispose_source_catalog_maintenance_v2(
        &self,
        original: &mut SourceCatalogMaintenanceCurrentnessOriginalV2,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source
            .journal()
            .dispose_source_catalog_maintenance_native_v2(
                original,
                receiving,
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
            )
    }
    pub(crate) fn require_completed_catalog_maintenance_session_v2(
        &self,
        maintenance: &ControllerCatalogMaintenanceReceivingV2,
        receiving: &aos_sandbox_broker::controller_receiving::ControllerInitialSessionReceivingOriginalV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        role: super::super::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        maintenance
            .require_completed_session_original_v2(
                receiving,
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
                role,
            )
            .map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn catalog_maintenance_identity_current_v2(
        &self,
        native: &ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2, ResourceReservationErrorV1>{
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native
            .identity_current_v2(
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
            )
            .map_err(Into::into)
    }

    pub(crate) fn require_catalog_maintenance_identity_current_v2(
        &self,
        native: &ControllerCatalogMaintenanceReceivingV2,
        identity: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native
            .require_identity_current_v2(
                identity,
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
            )
            .map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    // The closed maintenance borrower keeps the launch private; this supplies
    // only its next prepaid native destination, including a failed prearm.
    pub(crate) fn begin_catalog_maintenance_append_post_v2(
        &self,
        receiving: &mut ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<
        aos_sandbox_broker::controller_receiving::bank_launch::ControllerNativePostOriginalV1,
        ResourceReservationErrorV1,
    > {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving
            .begin_append_post_once_v2(
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
            )
            .map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn require_catalog_maintenance_completed_v2(
        &self,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving
            .require_completed_original_v2(
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
            )
            .map_err(Into::into)
    }
}
