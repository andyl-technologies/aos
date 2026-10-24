//! Keeps real completed physical SDK owners through final Source settlement.

use super::*;

impl ControllerDeletePlanningCollectionV2<'_, '_, '_> {
    pub(in crate::controller_service) fn dispose_completed_once_v4(
        self,
        pending: &mut aos_sandbox_controller_domain::ControllerDeletePendingOriginalV2<'_, '_>,
        client: aos_sandbox_controller_domain::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) {
        if !matches!(self.source_completion, Some(Ok(_))) {
            // No positive owner is discarded on a terminal refusal.
            let _whole = (self, client);
            std::process::abort();
        }
        let token = match bank
            .prepare_retained_delete_final_disposal_v4(pending, client, controller, profile)
        {
            Ok(token) => token,
            Err((client, cause)) => {
                let _whole = (self, client, cause);
                std::process::abort();
            }
        };
        // This drops the exclusive Session bundle, Cache and every completed
        // query/physical model before the same Source/C17 claim is settled.
        drop(self);
        token.complete_after_upper_disposal_v4();
    }

    pub(super) fn complete_source_cleanup_once_v4(
        &mut self,
        pending: &mut aos_sandbox_controller_domain::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox_controller_domain::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.source_completion.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.source_completion = Some((|| {
            self.network_apply.completed_sdk_v4()?;
            self.host_confirmation.completed_current_answer_v4()?;
            let mount = self.mount_reap.completed_sdk_v4()?;
            let (mount_outcome, mount_native) = mount
                .require_completed_v4()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let storage = self.storage_apply.completed_sdk_v4()?;
            let (storage_outcome, storage_native) = storage
                .require_completed_v3()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let frame = bank.complete_retained_delete_source_cleanup_once_v4(
                pending,
                client,
                controller,
                profile,
                (mount_native, mount_outcome),
                (storage_native, storage_outcome),
            )?;
            bank.finish_retained_delete_root_once_v4(pending, client, controller, profile)?;
            Ok(frame)
        })());
        if matches!(self.source_completion, Some(Ok(_))) {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}
