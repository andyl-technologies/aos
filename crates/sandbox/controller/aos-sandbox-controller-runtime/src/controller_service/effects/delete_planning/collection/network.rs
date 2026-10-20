//! Uses actual retained Network Inventory and strict7 before Root's exact9 flight.

use super::*;

impl ControllerDeletePlanningCollectionV2<'_, '_, '_> {
    pub(super) fn prepare_network_resources_once_v4(&mut self,
        pending: &mut aos_sandbox_controller_domain::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox_controller_domain::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.network_resource_exchange.is_some() || self.network_approval.is_some()
            || !matches!(self.apply_approval, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.network_resource_exchange = Some(bank.exchange_retained_delete_network_resource_draft_once_v4(
            pending, client, controller, profile));
        if !matches!(self.network_resource_exchange, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let session = session_preimage_from_originals_v2(&self.fresh_sessions, &self.fresh_models, 3)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let model = self.fresh_models[3].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.network_resource_signing.sign_network_once_v4(bank, pending, client,
            controller, profile, local, model, session)?;
        self.network_approval = Some(bank.receive_retained_delete_network_approval_once_v4(
            pending, client, controller, profile));
        if matches!(self.network_approval, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}
