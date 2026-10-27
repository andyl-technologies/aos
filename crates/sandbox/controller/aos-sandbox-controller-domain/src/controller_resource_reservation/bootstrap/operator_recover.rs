//! Joins a genuinely replaced Controller to a separate Recover native purpose.
//!
//! The authenticated PID1 successor and exact complete predecessor bank remain
//! with this actual startup owner. Recovery never reenrolls a bank, reopens a
//! spent P/I/Q/J interval, adopts an interrupted C23 or releases uncertain
//! claims. Capability/timefloor/target/inventory semantics remain with the
//! closed upper Recover owner and are not established by these native methods.

use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerOperatorRecoverReceivingV1, ControllerReconciliationInventoryRoleV2,
};
use aos_sandbox_model::ResourceVector;
use std::sync::Arc;

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredEnrollmentReceivingV2 as RecoveredEnrollment;
use aos_sandbox_broker::source_receiving::SourceRecoveredEnrollmentCurrentnessOriginalV2 as RecoveredEnrollmentSource;

use super::super::ResourceReservationErrorV1;
use super::ControllerResourceBankOpeningV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::Journal;

#[derive(Clone, Copy)]
enum RecoverySessionPurposeV2 {
    Storage,
    StopCleanup,
    Reconciliation(ControllerReconciliationInventoryRoleV2),
}

impl RecoverySessionPurposeV2 {
    fn role(self) -> super::super::ControllerInitialBrokerSessionRoleV1 {
        match self {
            Self::Storage => super::super::ControllerInitialBrokerSessionRoleV1::Storage,
            Self::StopCleanup => super::super::ControllerInitialBrokerSessionRoleV1::Host,
            Self::Reconciliation(role) => role.broker_role_data_v2(),
        }
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn prepare_execution_cleanup_session_v2(
        &self, source: &mut super::super::ControllerExecutionSourceScopeV1<'_, '_>,
        controller: &Journal, profile: Arc<ProductionControllerNormalRootProfileV1>,
        shape: super::super::ControllerInitialBrokerSessionShapeV1, cutoff: u64,
    ) -> Result<super::super::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened() || self.original.is_closed()
            || !profile.lower_original_v1().has_same_baseline_original(&self.original)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let role = super::super::ControllerInitialBrokerSessionRoleV1::Host;
        let fixed = super::super::ControllerInitialBrokerSessionReceivingV1::fixed_demand(role, shape)?;
        let writer = controller.controller_coordinator_for_bank_read_v1()?;
        writer.require_same_original_v1(&self.original)?;
        launch.require_current_controller_v1(writer)?;
        let receiving = source.begin_execution_cold_session_v2(writer, launch, profile.lower_original_v1(), fixed)?;
        let mut session = super::super::ControllerInitialBrokerSessionReceivingV1::new(
            Arc::clone(&self.original), profile, role,
        );
        session.prepare_recover_once_v1(shape, receiving, cutoff);
        if session.failure().is_none() { let _entered = session.begin_capture_once_v1(); }
        Ok(session)
    }

    pub(crate) fn bind_recovered_operation_intake_once_v2(
        &self,
        intake: &mut super::super::operation_intake::ControllerOperationIntakeOriginalV1,
        receiving: &RecoveredEnrollment,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        intake.bind_recovered_enrollment_once_v2(
            receiving,
            controller.controller_coordinator_for_bank_read_v1()?,
            launch,
            profile.lower_original_v1(),
        ).map_err(Into::into)
    }

    pub(crate) fn publish_recovered_intake_pair_once_v2(
        &self,
        receiving: &mut RecoveredEnrollment,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.publish_funded_intake_pair_once_v1(
            controller.controller_coordinator_for_bank_v1()?,
            launch,
            profile.lower_original_v1(),
        ).map_err(Into::into)
    }

    pub(crate) fn require_source_recovered_enrollment_current_v2(
        &self,
        source_original: &mut RecoveredEnrollmentSource,
        receiving: &RecoveredEnrollment,
        controller: &Journal, source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.journal_ref_v1().require_source_recovered_enrollment_current_v2(source_original, receiving,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1())
    }

    pub(crate) fn begin_recovered_enrollment_receiving_once_v2(
        &self, controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        completed: &ControllerOperatorRecoverReceivingV1, complete: ResourceVector,
    ) -> Result<RecoveredEnrollment,
        ResourceReservationErrorV1> {
        self.require_operator_recover_entry_v1(controller, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(controller.controller_coordinator_for_bank_v1()?
            .begin_recovered_enrollment_receiving_once_v2(launch, profile.lower_original_v1(), completed, complete))
    }

    pub(crate) fn begin_source_recovered_enrollment_v2(
        &self,
        receiving: &mut RecoveredEnrollment,
        controller: &Journal, source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1, complete: ResourceVector,
    ) -> Result<RecoveredEnrollmentSource,
        ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.journal().begin_source_recovered_enrollment_native_v2(receiving,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1(), complete)
    }

    pub(crate) fn finish_recovered_enrollment_native_once_v2(
        &self,
        receiving: &mut RecoveredEnrollment,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.finish_native_once_v2(controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn require_recovered_enrollment_completed_v2(
        &self,
        receiving: &RecoveredEnrollment,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.require_completed_original_v2(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn dispose_source_recovered_enrollment_v2(
        &self,
        source_original: &mut RecoveredEnrollmentSource,
        receiving: &RecoveredEnrollment,
        controller: &Journal, source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.journal().dispose_source_recovered_enrollment_native_v2(source_original, receiving,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1())
    }

    pub(crate) fn fund_recovered_delete_intake_once_v2(
        &self, controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        completed: &ControllerOperatorRecoverReceivingV1,
        resident: super::super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::super::operation_intake::ControllerOperationIntakeOriginalV1, ResourceReservationErrorV1> {
        self.require_operator_recover_entry_v1(controller, profile)?;
        let declared = self.original.observed_enrollment_data_v1()?.policy
            .bootstrap_provisions().delete_operation_intake
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let capacity = super::super::operation_intake::ControllerOperationIntakeDemandDataV1::
            from_declared_delete_remaining_v1(declared, resident, profile.lower_original_v1())?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        controller.controller_coordinator_for_bank_v1()?
            .fund_recovered_delete_operation_intake_once_v2(launch, profile.lower_original_v1(),
                completed, resident, capacity).map_err(Into::into)
    }

    pub(crate) fn fund_recovered_execution_intake_once_v2(
        &self, controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        completed: &ControllerOperatorRecoverReceivingV1,
        resident: super::super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::super::operation_intake::ControllerOperationIntakeOriginalV1, ResourceReservationErrorV1> {
        self.require_operator_recover_entry_v1(controller, profile)?;
        let declared = self.original.observed_enrollment_data_v1()?.policy
            .bootstrap_provisions().execution_operation_intake
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let capacity = super::super::operation_intake::ControllerOperationIntakeDemandDataV1::
            from_declared_remaining_v1(declared, resident, profile.lower_original_v1())?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        controller.controller_coordinator_for_bank_v1()?
            .fund_recovered_execution_operation_intake_once_v2(launch, profile.lower_original_v1(),
                completed, resident, capacity).map_err(Into::into)
    }

    /// Starts the successor's distinct paid Recover observation interval.
    ///
    /// This purpose does not use `initial_first_use_owner`: its real PID1
    /// successor retains the complete previous bank graph instead. All actual
    /// files, profile affinity, returned recipient CAS and ACK/Confirm are
    /// required. No input DATA can construct that original conjunction.
    pub(crate) fn begin_operator_recover_receiving_v1(
        &self, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1, complete: ResourceVector,
    ) -> Result<ControllerOperatorRecoverReceivingV1, ResourceReservationErrorV1> {
        self.require_operator_recover_entry_v1(controller, profile)?;
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(controller.controller_coordinator_for_bank_v1()?
            .begin_operator_recover_receiving_v1(launch, profile.lower_original_v1(), complete))
    }

    fn require_operator_recover_entry_v1(
        &self, controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened() || self.original.is_closed()
            || !profile.lower_original_v1().has_same_baseline_original(&self.original) {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = controller.controller_coordinator_for_bank_read_v1()?;
        writer.require_same_original_v1(&self.original)?;
        launch.require_current_controller_v1(writer)?;
        Ok(())
    }

    pub(crate) fn require_operator_recover_current_v1(
        &self, receiving: &ControllerOperatorRecoverReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.require_current_v1(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn require_operator_recover_complete_v1(
        &self, receiving: &mut ControllerOperatorRecoverReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.require_complete_representation_v1(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1(), complete).map_err(Into::into)
    }

    pub(crate) fn finish_operator_recover_native_once_v1(
        &self, receiving: &mut ControllerOperatorRecoverReceivingV1,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        // These destinations were armed by actual entry. Earlier authorization,
        // model, funding or native refusal cannot require a fresh healthy turn.
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.finish_native_once(controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn require_operator_recover_disposed_v1(
        &self, receiving: &ControllerOperatorRecoverReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.require_completed_original_v1(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn begin_source_operator_recover_v1(
        &self, receiving: &mut ControllerOperatorRecoverReceivingV1,
        controller: &Journal, source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1, complete: ResourceVector,
    ) -> Result<aos_sandbox_broker::source_receiving::SourceOperatorRecoverCurrentnessOriginalV1,
        ResourceReservationErrorV1> {
        self.require_operator_recover_current_v1(receiving, controller, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.journal().begin_source_operator_recover_native_v1(receiving,
            controller.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1(), complete)
    }

    pub(crate) fn dispose_source_operator_recover_v1(
        &self, source_original: &mut aos_sandbox_broker::source_receiving::SourceOperatorRecoverCurrentnessOriginalV1,
        receiving: &ControllerOperatorRecoverReceivingV1, controller: &Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.journal().dispose_source_operator_recover_native_v1(source_original, receiving,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1())
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn prepare_operator_recover_storage_session_v1(
        &self, native: &mut ControllerOperatorRecoverReceivingV1, controller: &Journal,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        shape: super::super::ControllerInitialBrokerSessionShapeV1,
        runtime: Arc<tokio::runtime::Runtime>, cutoff: u64,
    ) -> Result<super::super::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        self.prepare_operator_recovery_session_v2(native, controller, profile,
            RecoverySessionPurposeV2::Storage, shape, runtime, cutoff)
    }

    /// Prepares one actual paid read-only endpoint for successor reconciliation.
    ///
    /// The genuine upper owner retains the completed recovery seed, Source cut,
    /// original horizon and whole prior residency. Initial claims stay untouched.
    ///
    /// # Errors
    /// Refuses foreign/inactive originals, reentry, unavailable native geometry
    /// or insufficient complete residual payment before any Session growth.
    pub(crate) fn prepare_operator_reconciliation_inventory_session_v2(
        &self, native: &mut ControllerOperatorRecoverReceivingV1, controller: &Journal,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        role: ControllerReconciliationInventoryRoleV2,
        shape: super::super::ControllerInitialBrokerSessionShapeV1,
        runtime: Arc<tokio::runtime::Runtime>, cutoff: u64,
    ) -> Result<super::super::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        self.prepare_operator_recovery_session_v2(native, controller, profile,
            RecoverySessionPurposeV2::Reconciliation(role), shape, runtime, cutoff)
    }

    pub(crate) fn prepare_operator_recover_stop_session_v1(
        &self, native: &mut ControllerOperatorRecoverReceivingV1, controller: &Journal,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        shape: super::super::ControllerInitialBrokerSessionShapeV1,
        runtime: Arc<tokio::runtime::Runtime>, cutoff: u64,
    ) -> Result<super::super::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        self.prepare_operator_recovery_session_v2(native, controller, profile,
            RecoverySessionPurposeV2::StopCleanup, shape, runtime, cutoff)
    }

    fn prepare_operator_recovery_session_v2(
        &self, native: &mut ControllerOperatorRecoverReceivingV1, controller: &Journal,
        profile: Arc<ProductionControllerNormalRootProfileV1>, purpose: RecoverySessionPurposeV2,
        shape: super::super::ControllerInitialBrokerSessionShapeV1,
        runtime: Arc<tokio::runtime::Runtime>, cutoff: u64,
    ) -> Result<super::super::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        self.require_operator_recover_current_v1(native, controller, &profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let role = purpose.role();
        let fixed = super::super::ControllerInitialBrokerSessionReceivingV1::fixed_demand(
            role, shape,
        )?;
        let writer = controller.controller_coordinator_for_bank_read_v1()?;
        let receiving = match purpose {
            RecoverySessionPurposeV2::StopCleanup => native.begin_host_stop_cleanup_session_once_v1(
                writer, launch, profile.lower_original_v1(), fixed)?,
            RecoverySessionPurposeV2::Storage => native.begin_storage_session_receiving_once_v1(
                writer, launch, profile.lower_original_v1(), fixed)?,
            RecoverySessionPurposeV2::Reconciliation(role) =>
                native.begin_reconciliation_inventory_session_once_v2(
                    writer, launch, profile.lower_original_v1(), role, fixed)?,
        };
        let mut session = super::super::ControllerInitialBrokerSessionReceivingV1::new(
            Arc::clone(&self.original), profile, role,
        );
        session.prepare_recover_once_v1(shape, receiving, cutoff);
        // The entered owner, including either refusal, is returned intact.
        // No fallible projection may drop a partially prepared native capsule.
        if role == super::super::ControllerInitialBrokerSessionRoleV1::Storage {
            let _runtime = session.retain_runtime_mechanics_once_v1(runtime);
        }
        if session.failure().is_none() { let _entered = session.begin_capture_once_v1(); }
        Ok(session)
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn operator_recover_node_v1(&self, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox_model::NodeId, ResourceReservationErrorV1> {
        self.require_operator_recover_entry_v1(controller, profile)?;
        let identity = self.require_enrolled(controller, profile)?;
        Ok(aos_sandbox_model::NodeId::from_bytes(identity.native_fields().node))
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn completed_operator_recover_resident_demand_v1(
        &self,
        receiving: &ControllerOperatorRecoverReceivingV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.completed_resident_receiving_demand_v1(
            controller.controller_coordinator_for_bank_read_v1()?,
            launch,
            profile.lower_original_v1(),
        ).map_err(Into::into)
    }
}
