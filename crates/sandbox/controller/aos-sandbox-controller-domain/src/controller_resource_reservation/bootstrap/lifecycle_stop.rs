//! Selects the closed Stop native continuation without a Create/Start issuer.

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn arm_stop_cleanup_source_turn_v1(&self,
        native: &mut ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native.arm_stop_cleanup_source_turn_once_v1(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn capture_stop_cleanup_source_affinity_v1(&self,
        native: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSourceAffinityV1,
        ResourceReservationErrorV1> {
        self.require_lifecycle_stop_native_current_v4(native, controller, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native.capture_stop_cleanup_source_affinity_v1(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn require_stop_cleanup_source_affinity_v1(&self,
        native: &ControllerCreateProvisioningReceivingV1,
        affinity: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSourceAffinityV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_lifecycle_stop_native_current_v4(native, controller, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native.require_stop_cleanup_source_affinity_v1(affinity,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1())
            .map_err(Into::into)
    }

    pub(crate) fn prepare_stop_cleanup_source_session_v1(
        &self, native: &mut ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: std::sync::Arc<ProductionControllerNormalRootProfileV1>,
        shape: super::super::ControllerInitialBrokerSessionShapeV1, cutoff: u64,
    ) -> Result<super::super::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        self.require_lifecycle_stop_native_current_v4(native, controller, profile.as_ref())?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let role = super::super::ControllerInitialBrokerSessionRoleV1::Host;
        let fixed = super::super::ControllerInitialBrokerSessionReceivingV1::fixed_demand(role, shape)?;
        let receiving = native.begin_host_stop_cleanup_source_session_once_v1(
            controller.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1(), fixed)?;
        let mut session = super::super::ControllerInitialBrokerSessionReceivingV1::new(
            std::sync::Arc::clone(&self.original), profile, role);
        session.prepare_recover_once_v1(shape, receiving, cutoff);
        if session.failure().is_none() { let _entered = session.begin_capture_once_v1(); }
        Ok(session)
    }

    pub(crate) fn complete_stop_cleanup_native_after_disposal_v1(
        &self, native: &mut ControllerCreateProvisioningReceivingV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native.complete_stop_cleanup_native_after_disposal_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile.lower_original_v1())
            .map_err(Into::into)
    }

    // Financial entry only: the same completed kind2 native original is
    // required by the lower issuer. Root456 and actual Host/Source evidence
    // remain separate, and no ordinary enrollment is manufactured here.
    pub(crate) fn begin_host_stop_cleanup_native_v1(
        &self,
        completed: &crate::OperatorStopCleanupRecoveryCompletedHandoffV1<'_>,
        association: aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<ControllerCreateProvisioningReceivingV1, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened() || self.original.is_closed()
            || !profile.lower_original_v1().has_same_baseline_original(&self.original)
        { return Err(ResourceReservationErrorV1::EnrollmentUnavailable); }
        let original = completed.completed_native_original_v1()?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let native = ControllerCreateProvisioningReceivingV1::recovered_stop_receiving_demand_v3(profile.lower_original_v1())?;
        let writer = controller.controller_coordinator_for_bank_v1()?;
        let intake = writer.fund_recovered_host_stop_cleanup_seed_v1(
            launch, profile.lower_original_v1(), original, association,
            super::super::operation_intake::ControllerOperationIntakeDemandDataV1::from_demand_v1(
                complete.checked_add(native)?,
            ),
        )?;
        Ok(writer.begin_recovered_lifecycle_stop_receiving_v3(
            launch, profile.lower_original_v1(), intake, complete))
    }

    pub(crate) fn begin_lifecycle_stop_native_v4(&self, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1, complete: aos_sandbox_model::ResourceVector,
    ) -> Result<ControllerCreateProvisioningReceivingV1, ResourceReservationErrorV1> {
        self.require_operation_intake_entry_v1(controller, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(controller.controller_coordinator_for_bank_v1()?
            .begin_lifecycle_stop_receiving_v4(launch, profile.lower_original_v1(), complete))
    }

    pub(crate) fn require_lifecycle_stop_native_current_v4(&self,
        original: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if let Some(intake) = original.recovered_stop_intake_v3() {
            self.require_funded_operation_intake_entry_v2(intake, controller, profile)?;
        }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.require_lifecycle_stop_current_v4(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn require_lifecycle_stop_native_completed_v5(&self,
        original: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if let Some(intake) = original.recovered_stop_intake_v3() {
            self.require_funded_operation_intake_entry_v2(intake, controller, profile)?;
        }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.require_lifecycle_stop_completed_v4(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn finish_lifecycle_stop_native_once_v4(&self,
        original: &mut ControllerCreateProvisioningReceivingV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        // Already armed afters remain owed even when semantic Stop selection or
        // currentness refused. They never supply a replacement effect grant.
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.finish_native_once(controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn begin_next_lifecycle_stop_native_v4(
        &self,
        original: &mut ControllerCreateProvisioningReceivingV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_model::ResourceVector,
        entered: &mut bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if let Some(intake) = original.recovered_stop_intake_v3() {
            self.require_funded_operation_intake_entry_v2(intake, controller, profile)?;
        }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.require_lifecycle_stop_completed_v4(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1())?;
        let writer = controller.controller_coordinator_for_bank_v1()?;
        if *entered { return Err(ResourceReservationErrorV1::Conflict); }
        *entered = true;
        original.begin_next_native_turn_v1(writer,
            launch, profile.lower_original_v1(), complete).map_err(Into::into)
    }

    pub(crate) fn require_lifecycle_stop_complete_v4(
        &self,
        original: &mut ControllerCreateProvisioningReceivingV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if let Some(intake) = original.recovered_stop_intake_v3() {
            self.require_funded_operation_intake_entry_v2(intake, controller, profile)?;
        }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = controller.controller_coordinator_for_bank_read_v1()?;
        original.require_lifecycle_stop_current_v4(writer, launch, profile.lower_original_v1())?;
        original.require_complete_representation_v1(writer, launch, profile.lower_original_v1(), complete)
            .map_err(Into::into)
    }

    pub(crate) fn current_lifecycle_stop_node_v4(
        &self,
        original: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox_model::NodeId, ResourceReservationErrorV1> {
        self.require_lifecycle_stop_native_current_v4(original, controller, profile)?;
        let enrollment = self.observed.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(aos_sandbox_model::NodeId::from_bytes(enrollment.identity.native_fields().node))
    }

}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn lifecycle_stop_requires_recovered_seed_v3(&self) -> bool {
        !self.initial_first_use_owner()
    }

    pub(crate) fn begin_recovered_lifecycle_stop_native_v3(&self,
        enrolled: &crate::OperatorFirstLocalOrdinaryEnrollmentOriginalV2,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<ControllerCreateProvisioningReceivingV1, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened() || self.original.is_closed()
            || !profile.lower_original_v1().has_same_baseline_original(&self.original)
        { return Err(ResourceReservationErrorV1::EnrollmentUnavailable); }
        let completed = enrolled.completed_lifecycle_stop_enrollment_v3(self, controller, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let native = ControllerCreateProvisioningReceivingV1::recovered_stop_receiving_demand_v3(profile.lower_original_v1())?;
        let writer = controller.controller_coordinator_for_bank_v1()?;
        let intake = writer.fund_recovered_lifecycle_stop_seed_v3(launch, profile.lower_original_v1(), completed,
            super::super::operation_intake::ControllerOperationIntakeDemandDataV1::from_demand_v1(
                complete.checked_add(native)?,
            ))?;
        Ok(writer.begin_recovered_lifecycle_stop_receiving_v3(launch, profile.lower_original_v1(), intake, complete))
    }

    pub(crate) fn publish_recovered_lifecycle_stop_seed_v3(&self,
        native: &mut ControllerCreateProvisioningReceivingV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native.publish_recovered_stop_seed_once_v3(controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn require_recovered_lifecycle_stop_seed_v3(&self,
        native: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let intake = native.recovered_stop_intake_v3().ok_or(ResourceReservationErrorV1::Conflict)?;
        self.require_funded_operation_intake_entry_v2(intake, controller, profile)
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn begin_retained_recovered_lifecycle_stop_native_v3(&self,
        intake: super::super::operation_intake::ControllerOperationIntakeOriginalV1,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_model::ResourceVector,
    ) -> std::result::Result<ControllerCreateProvisioningReceivingV1,
        (super::super::operation_intake::ControllerOperationIntakeOriginalV1, ResourceReservationErrorV1)> {
        let Some(launch) = self.launch.as_ref() else {
            return Err((intake, ResourceReservationErrorV1::EnrollmentUnavailable));
        };
        let writer = match controller.controller_coordinator_for_bank_v1() {
            Ok(writer) => writer,
            Err(cause) => return Err((intake, cause.into())),
        };
        Ok(writer.begin_retained_recovered_lifecycle_stop_receiving_v3(
            launch, profile.lower_original_v1(), intake, complete))
    }

    pub(crate) fn require_retained_lifecycle_stop_entry_v3(&self,
        intake: &super::super::operation_intake::ControllerOperationIntakeOriginalV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_funded_operation_intake_entry_v2(intake, controller, profile)
    }

    pub(crate) fn take_completed_recovered_stop_intake_v3(&self,
        native: &mut ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<super::super::operation_intake::ControllerOperationIntakeOriginalV1>, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native.take_completed_recovered_stop_intake_v3(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn require_lifecycle_stop_seed_publication_complete_v3(&self,
        native: &mut ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !native.requires_recovered_stop_seed_publication_v3() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        native.require_recovered_stop_seed_publication_complete_v3(
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1(), complete,
        ).map_err(Into::into)
    }
}
