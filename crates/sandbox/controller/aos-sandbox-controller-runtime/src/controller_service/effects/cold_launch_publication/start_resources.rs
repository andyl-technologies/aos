//! Sequences Network, held Storage, Mount and Host on one accepted Start.
//!
//! Every child is retained on the same executor. Actual Network disposition
//! precedes held-Storage31/18, and actual Storage disposition precedes Mount62/16.
//! The original shared Session guard stays held throughout each Storage step;
//! no historical completion reconstructs a Session or releases its writer.

use super::*;
use super::start_network::OriginalStartResourceV2;

pub(in crate::controller_service::effects) struct OriginalStartResourcesV2 {
    network: OriginalStartResourceV2,
    storage: OriginalStartResourceV2,
    mount: OriginalStartResourceV2,
    host: OriginalStartResourceV2,
    storage_guard: Option<Result<(), ResourceReservationErrorV1>>,
}

impl OriginalStartResourcesV2 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            OriginalStartResourceV2::inactive_receiving_bytes_v1()?.checked_mul(4),
        ])
    }

    pub(in crate::controller_service::effects) fn new() -> Self {
        Self {
            network: OriginalStartResourceV2::new(),
            storage: OriginalStartResourceV2::storage_guest_root_v2(),
            mount: OriginalStartResourceV2::mount_namespace_v2(),
            host: OriginalStartResourceV2::host_launch_v2(),
            storage_guard: None,
        }
    }

    pub(in crate::controller_service::effects) fn progress_once_v2(
        &mut self,
        entry: &mut aos_sandbox_controller_domain::AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        driver: &super::super::super::inventory::OriginalCreateStorageDriverV1,
        create: &OriginalCreateProvisioningIssuerV1,
        signer: &ControllerBrokerPlanSignerV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        sessions: &super::super::super::SharedControllerBrokerSessions,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure_with_entry_v2(entry).is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.network.completed_resource_v2().is_err() {
            return self.network.progress_preparation_once_v2(
                entry, intake, driver, create, signer, controller, source,
            );
        }

        if self.storage.completed_resource_v2().is_err() {
            let predecessor = self.network.completed_resource_v2()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let mut held = match sessions.lock() {
                Ok(held) => held,
                Err(_) => {
                    self.storage_guard = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
                    return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
                }
            };
            let session = match held.storage.as_mut() {
                Some(session) => session,
                None => {
                    self.storage_guard = Some(Err(ResourceReservationErrorV1::Conflict));
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            };
            self.storage_guard = Some(Ok(()));
            return self.storage.progress_storage_preparation_once_v2(
                entry, intake, driver, create, signer, controller, source,
                session, predecessor,
            );
        }

        if self.mount.completed_resource_v2().is_err() {
            let predecessor = self.storage.completed_resource_v2()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            return self.mount.progress_mount_preparation_once_v2(
                entry, intake, driver, create, signer, controller, source, predecessor,
            );
        }

        let models = [self.network.completed_models_v2(), self.storage.completed_models_v2(),
            self.mount.completed_models_v2()];
        let [Ok(network), Ok(storage), Ok(mount)] = models else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        self.host.progress_host_preparation_once_v2(entry, intake, driver, create, signer,
            controller, source, [network, storage, mount])
    }

    pub(in crate::controller_service::effects) fn completed_host_v2(&self)
        -> Result<&aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2,
            aos_sandbox_controller_domain::normal_root::RootHostLaunchClientClosedV1> {
        self.host.completed_resource_v2()
    }

    pub(in crate::controller_service::effects) fn completed_mount_v2(&self)
        -> Result<&aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2,
            aos_sandbox_controller_domain::normal_root::RootHostLaunchClientClosedV1> {
        self.mount.completed_resource_v2()
    }

    /// Lends historical completed models; each payload still requires the new
    /// genuine Host loan before its sole-decoded values can be borrowed.
    pub(in crate::controller_service::effects) fn completed_models_v2(
        &self,
    ) -> Result<
        [(
            &aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2,
            &aos_sandbox_broker_session_security::controller_composition::StartResourceCompletedModelsOriginalV2,
        ); 3],
        aos_sandbox_controller_domain::normal_root::RootHostLaunchClientClosedV1,
    > {
        Ok([
            self.network.completed_models_v2()?,
            self.storage.completed_models_v2()?,
            self.mount.completed_models_v2()?,
        ])
    }

    pub(in crate::controller_service::effects) fn failure_with_entry_v2<'held>(
        &'held self, entry: &'held aos_sandbox_controller_domain::AcceptedStartEntryOriginalV1,
    ) -> Option<&'held (dyn Error + 'static)> {
        self.network
            .failure_with_entry_v2(entry)
            .or_else(|| self.storage.failure_with_entry_v2(entry))
            .or_else(|| {
                self.storage_guard.as_ref()?.as_ref().err().map(|cause| cause as _)
            })
            .or_else(|| self.mount.failure_with_entry_v2(entry))
            .or_else(|| self.host.failure_with_entry_v2(entry))
    }

    pub(in crate::controller_service::effects) fn fmt_failure_with_entry_v2(
        &self, entry: &aos_sandbox_controller_domain::AcceptedStartEntryOriginalV1,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        for child in [&self.network, &self.storage] {
            if child.failure_with_entry_v2(entry).is_some() {
                return child.fmt_failure_with_entry_v2(entry, formatter);
            }
        }
        if let Some(Err(cause)) = &self.storage_guard {
            return std::fmt::Display::fmt(cause, formatter);
        }
        if self.mount.failure_with_entry_v2(entry).is_some() {
            return self.mount.fmt_failure_with_entry_v2(entry, formatter);
        }
        self.host.fmt_failure_with_entry_v2(entry, formatter)
    }
}
