//! Forwards catalog maintenance to the sole retained Source native engine.
//!
//! These methods require the genuine new finite B original. They do not adopt
//! a Source snapshot, lend a generic writer or authorize any Source append.

use super::*;
use crate::ResourceReservationErrorV1;
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchOriginalV1, ControllerCatalogMaintenanceReceivingV2,
    ControllerCoordinatorWriterV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use aos_sandbox_broker::source_receiving::SourceCatalogMaintenanceCurrentnessOriginalV2;
use aos_sandbox_core::ResourceVector;

#[cfg(test)]
mod tests;

impl Journal {
    pub(crate) fn begin_source_catalog_maintenance_native_v2<C>(
        &mut self,
        receiving: &mut ControllerCatalogMaintenanceReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<SourceCatalogMaintenanceCurrentnessOriginalV2, ResourceReservationErrorV1> {
        match &mut self.native {
            native_backing::JournalNativeBackingV1::Source(source) => source
                .begin_catalog_maintenance_currentness_once_v2(
                    receiving, controller, launch, profile, complete,
                )
                .map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn require_source_catalog_maintenance_current_v2<C>(
        &self,
        original: &mut SourceCatalogMaintenanceCurrentnessOriginalV2,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        match &self.native {
            native_backing::JournalNativeBackingV1::Source(source) => source
                .require_catalog_maintenance_readonly_current_v2(
                    original, receiving, controller, launch, profile,
                )
                .map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn finish_source_catalog_maintenance_native_v2(
        &self,
        original: &mut SourceCatalogMaintenanceCurrentnessOriginalV2,
    ) -> Result<(), JournalError> {
        match &self.native {
            native_backing::JournalNativeBackingV1::Source(source) => source
                .finish_catalog_maintenance_currentness_once_v2(original)
                .map_err(JournalError::SourceNative),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn dispose_source_catalog_maintenance_native_v2<C>(
        &mut self,
        original: &mut SourceCatalogMaintenanceCurrentnessOriginalV2,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        match &mut self.native {
            native_backing::JournalNativeBackingV1::Source(source) => source
                .dispose_catalog_maintenance_currentness_after_posts_v2(
                    original, receiving, controller, launch, profile,
                )
                .map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }
}

impl Journal {
    // Reads only the actual retained completed Recover original. The caller
    // prepays full C/Source replay under the new maintenance before this fold;
    // this historical comparison neither invokes nor renews the old R clock.
    pub(crate) fn catalog_maintenance_source_family_data_v2(
        &self,
    ) -> Result<Option<(aos_sandbox_core::OperationId, [u8; 32])>, JournalError> {
        use crate::controller_resource_reservation::operator_create_recovery::OperatorRecoverCustodyV2;
        use aos_sandbox_protocol::domain_ledger::resource_bank as bank;
        let state = self.historical_read_view_v1().materialized_state_v1();
        let enrollment = bank::validate(state)
            .map_err(|_| JournalError::ProtectedBoundary)?
            .ok_or(JournalError::ProtectedBoundary)?;
        let recipient = bank::recipient_incarnation(state, enrollment)
            .map_err(|_| JournalError::ProtectedBoundary)?
            .ok_or(JournalError::ProtectedBoundary)?;
        match recipient.generation() {
            0 if self.operator_recovery.is_none() => Ok(None),
            // A later ordinal is comparison DATA only. The completed owner
            // below must rejoin its actual disposed native Recover, current
            // writer/launch and same image-bound recipient/range/history.
            ordinal if ordinal > 0 => match self.operator_recovery.as_ref() {
                Some(OperatorRecoverCustodyV2::Entered(original)) => original
                    .completed_source_family_for_maintenance_data_v2(self)
                    .map(Some),
                _ => Err(JournalError::ProtectedBoundary),
            },
            _ => Err(JournalError::ProtectedBoundary),
        }
    }
}

impl Journal {
    pub(crate) fn require_cold_controller_family_for_maintenance_data_v2(
        &self,
    ) -> Result<(), JournalError> {
        use crate::controller_resource_reservation::operator_create_recovery::OperatorRecoverCustodyV2;
        match self.catalog_maintenance_source_family_data_v2()? {
            Some(_) => match self.operator_recovery.as_ref() {
                Some(OperatorRecoverCustodyV2::Entered(original)) => original
                    .require_cold_controller_family_for_maintenance_data_v2(self)
                    .map_err(|_| JournalError::ProtectedBoundary),
                _ => Err(JournalError::ProtectedBoundary),
            },
            None => {
                // The first-local generation-zero namespace contains no effect
                // or resource family. Administrative/account and comparison
                // rows are retained and are never fresh physical proof.
                for (namespace, key, _) in self.all_records() {
                    match namespace {
                        RecordNamespace::DesiredState
                            if !key.starts_with(
                                aos_sandbox_protocol::public_api::projection::PROJECTION_KEY_PREFIX,
                            ) => {}
                        RecordNamespace::Idempotency
                        | RecordNamespace::OwnershipGate
                        | RecordNamespace::AuthorityPublication
                        | RecordNamespace::PublisherAuthority
                        | RecordNamespace::PublisherPolicy
                        | RecordNamespace::PublisherIngress
                        | RecordNamespace::RuntimeAuthority
                        | RecordNamespace::SandboxSpec
                        | RecordNamespace::ControllerIdentity
                        | RecordNamespace::GlobalCapacityReservation
                        | RecordNamespace::BrokerSessionTraffic
                        | RecordNamespace::CliAuthorizationTime
                        | RecordNamespace::OperatorRecovery
                        | RecordNamespace::PublicOperationAuthorization
                        | RecordNamespace::PublicCapabilityBootstrap
                        | RecordNamespace::ControllerResourceReservation
                        | RecordNamespace::CreateStorageHistory
                        | RecordNamespace::ControllerPolicyHold
                        | RecordNamespace::SourceDomainPolicyHold
                        | RecordNamespace::StorageResourceInventory
                        | RecordNamespace::NetworkResourceInventory
                        | RecordNamespace::HostCatalogReconciliation => {}
                        _ => return Err(JournalError::ProtectedBoundary),
                    }
                }
                Ok(())
            }
        }
    }

    pub(crate) fn require_cold_storage_for_maintenance_data_v2(
        &self,
        inventory: &aos_sandbox_protocol::ValidatedStorageInventory,
    ) -> Result<(), JournalError> {
        use crate::controller_resource_reservation::operator_create_recovery::OperatorRecoverCustodyV2;
        match self.catalog_maintenance_source_family_data_v2()? {
            Some(_) => match self.operator_recovery.as_ref() {
                Some(OperatorRecoverCustodyV2::Entered(original)) => original
                    .require_cold_storage_for_maintenance_data_v2(self, inventory)
                    .map_err(|_| JournalError::ProtectedBoundary),
                _ => Err(JournalError::ProtectedBoundary),
            },
            None if inventory.workspaces().is_empty()
                && inventory.operator_repair_commits().is_empty() =>
            {
                Ok(())
            }
            None => Err(JournalError::ProtectedBoundary),
        }
    }
}
