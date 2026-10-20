//! Selects Mount62 only after this same client's actual cleanup receipt sent.
//!
//! The retained Host outcome is compared to the sent native/request/packet
//! coordinates before its canonical stopped scope is borrowed. This passive
//! projection reconstructs no Host owner. Root independently verifies the same
//! native history before issuing its distinct Mount draft.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    decode_host_runtime_inventory_data_v2,
    outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1,
};
use aos_sandbox_protocol::domain_ledger::delete_root::{
    cleanup_current::{DeleteRootCleanupCurrentDataV4, cleanup_approval_commitment_data_v4},
    final_inventory::DeleteRootPreparatoryApprovalDataV3,
};
use aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4;

#[derive(Clone, Copy)]
pub(in crate::normal_root::client::delete) struct DeleteMountResourceBindingDataV4 {
    pub(in crate::normal_root::client::delete) current: DeleteRootCleanupCurrentDataV4,
    pub(in crate::normal_root::client::delete) approved9: DeleteRootPreparatoryApprovalDataV3,
    pub(in crate::normal_root::client::delete) stopped: HostStoppedNamespaceDataV4,
    pub(in crate::normal_root::client::delete) before: RawPairedClockSample,
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn begin_mount_reap_interval_once_v4(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::MountReap62)
            .map_err(|_| self.closed)?;
        self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))
            .map_err(|_| self.closed)?;
        self.begin_storage_interval_inner_v3(fence, controller, launch, accepted, DeleteResourcePurposeV3::MountReap62)
    }

    pub(crate) fn require_mount_reap_before_v4(
        &mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))?;
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::MountReap62)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.require_storage_before_inner_v3(fence, controller, launch, accepted, DeleteResourcePurposeV3::MountReap62)
    }

    pub(crate) fn require_mount_reap_after_v4(
        &self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        latest: RawPairedClockSample,
    ) -> Result<(), Cause> {
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::MountReap62)?;
        self.require_storage_after_inner_v3(fence, controller, accepted, latest, DeleteResourcePurposeV3::MountReap62)
    }

    pub(crate) fn retire_mount_reap_interval_once_v4(
        &mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), Cause> {
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::MountReap62)?;
        // Only the genuine upper calls this after the native Session window
        // retired and its authenticated Reap response passed every post.
        self.retire_storage_interval_inner_v3(fence, controller, accepted, DeleteResourcePurposeV3::MountReap62)?;
        self.source_admission.as_mut().ok_or(JournalError::ProtectedBoundary)?.mount_retired = true;
        self.resource_purpose = DeleteResourcePurposeV3::Apply7;
        Ok(())
    }

    pub(crate) fn mount_request_bound_v4(&self) -> Option<usize> {
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::MountReap62).ok()?;
        self.storage_request_bound_inner_v3(DeleteResourcePurposeV3::MountReap62)
    }

    pub(crate) fn mount_request_envelope_v4(
        &self,
    ) -> Result<aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope, Cause> {
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::MountReap62)?;
        self.storage_request_envelope_inner_v3(DeleteResourcePurposeV3::MountReap62)
    }

    pub(crate) fn require_mount_inventory_v4(
        &self,
        cut: aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>,
    ) -> Result<(), Cause> {
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::MountReap62)?;
        let approved = self.resource_draft_complete[3].as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if cut.role != 2 || cut.owner_cut_data_v2()? != approved.frame.owners[1] {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        Ok(())
    }

    pub(crate) fn begin_mount_resource_exchange_once_v4(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        host: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
    ) -> Result<(), RootDeleteClientClosedV1> {
        if self.first.is_some()
            || self.terminal_complete
            || self.turn.is_some()
            || self.resource_purpose != DeleteResourcePurposeV3::Network9
            || self.mount_activation_admission.is_some()
            || self.mount_activation.is_some()
        {
            self.first.get_or_insert(super::super::First::Reentry);
            return Err(self.closed);
        }
        self.mount_activation_admission = Some((|| {
            self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))?;
            self.require_network_resource_approval_v4()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let demand = AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
                aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
                host.1.canonical_packet().len()).ok_or(JournalError::JournalTooLarge)?;
            let memory = std::mem::size_of::<DeleteMountResourceBindingDataV4>()
                .checked_mul(3)
                .and_then(|bytes| {
                    bytes.checked_add(3 * std::mem::size_of::<aos_sandbox_protocol::host_stopped_namespace::HostStoppedInventoryDataV1>())
                })
                .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<blake3::Hasher>()))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            fence.reserve_preaccept_additional_v1(
                controller,
                launch,
                self.profile.lower_original_v1(),
                demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory))?,
            )
        })());
        if !matches!(self.mount_activation_admission, Some(Ok(()))) {
            self.first
                .get_or_insert(super::super::First::MountActivationAdmission);
            return Err(self.closed);
        }
        self.mount_activation = Some((|| {
            let state = self
                .source_admission
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?;
            let (current, before) = state.cleanup.completed_frame_v4(state)?;
            let approved9 = self.preparatory_approval_complete[2]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?
                .approval;
            if current.approved9 != cleanup_approval_commitment_data_v4(approved9)?
                || current.host.native != *host.0
                || current.host.request != host.1.request().signed_request_digest()
                || current.host.outcome != *blake3::hash(host.1.canonical_packet()).as_bytes()
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = host.1.result()
            else {
                return Err(JournalError::ProtectedBoundary.into());
            };
            let inventory =
                decode_host_runtime_inventory_data_v2(exact_body, host.1.request().request_id())?;
            let challenge = self
                .challenge
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            if !inventory.runtimes.is_empty()
                || !inventory.native_absence_v5.is_empty()
                || host.1.request().deadline_boottime_nanoseconds() > challenge.source.cutoff
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            use aos_sandbox_protocol::host_stopped_namespace::HostStoppedInventoryDataV1;
            let evidence = HostStoppedInventoryDataV1::from_inventory_v1(&inventory)?
                .ok_or(JournalError::StaleAuthoritySnapshot)?;
            if let HostStoppedInventoryDataV1::Cleanup(lineage) = &evidence {
                // The ordinary Host model/fold was prepaid above. Only this
                // genuinely selected family grows additional Source history.
                // A financial refusal is retained before any new model exists.
                self.mount_history_admission = Some((|| {
                    let source_rows = fence.completed_stop_source_rows_v5()?;
                    let controller_rows = controller.historical_read_view_v1().rows_data_v2();
                    let history = crate::lifecycle::completed_stop::CompletedStopHistoryOriginalV1::receiving_demand_v1(
                        controller_rows, source_rows,
                    ).ok_or(JournalError::JournalTooLarge)?;
                    let replay = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(
                        source_rows.all_records(),
                    ).ok_or(JournalError::JournalTooLarge)?;
                    let source_carrier = crate::lifecycle::LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1()
                        .and_then(|bytes| u64::try_from(bytes).ok())
                        .ok_or(JournalError::JournalTooLarge)?;
                    let history = history.checked_add(replay)?
                        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, source_carrier))?;

                    fence.reserve_preaccept_additional_v1(
                        controller, launch, self.profile.lower_original_v1(), history,
                    )
                })());
                if !matches!(self.mount_history_admission, Some(Ok(()))) {
                    self.first.get_or_insert(super::super::First::MountHistoryAdmission);
                    return Err(JournalError::ProtectedBoundary.into());
                }

                let rows = fence.completed_stop_source_rows_v5()?;
                self.mount_stop_source = Some(crate::lifecycle::LifecycleHistoricalReadOriginalV1::new());
                let source = self.mount_stop_source.as_mut().ok_or(JournalError::ProtectedBoundary)?;
                source.observe_rows_projection_once_v3(rows)?;
                self.mount_stop_history = Some(crate::lifecycle::completed_stop::CompletedStopHistoryOriginalV1::new());
                let history = self.mount_stop_history.as_mut().ok_or(JournalError::ProtectedBoundary)?;
                let controller_rows = controller.historical_read_view_v1().rows_data_v2();
                history.observe_once_v1(controller_rows, source)?;
                history.require_same_v1(controller_rows, source)?;
                let completed = history.require_scope_v1(evidence.historical_scope_v1())?;
                completed.require_cleanup_v1(lineage)?;
                if completed.project_v1() != fence.authorization().project() {
                    return Err(JournalError::StaleAuthoritySnapshot.into());
                }
            }
            let stopped = *evidence.require_completed_v1(
                host.1.request().request_id(), challenge.source.boot,
                approved9.clock.boottime_nanoseconds(), before.boottime_nanoseconds(),
                host.1.request().deadline_boottime_nanoseconds(),
            )?;
            if host.1.request().request_id() == stopped.launch_v4().0
                || host.1.request().request_id() == stopped.stop_v4().0
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            Ok(DeleteMountResourceBindingDataV4 {
                current,
                approved9,
                stopped,
                before,
            })
        })());
        if !matches!(self.mount_activation, Some(Ok(_))) {
            self.first
                .get_or_insert(super::super::First::MountActivation);
            return Err(self.closed);
        }
        self.resource_purpose = DeleteResourcePurposeV3::MountReap62;
        Ok(())
    }

    pub(super) fn require_mount_predecessor_v4(&self) -> Result<(), JournalError> {
        let binding = self
            .mount_activation
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let (current, _) = state.cleanup.completed_frame_v4(state)?;
        let approved9 = self.preparatory_approval_complete[2]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if current != binding.current || approved9.approval != binding.approved9 {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}
