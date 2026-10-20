//! Lends only the actual idle Host Session to the same C17 Inventory engine.
//!
//! Publication, execution, attach, output and accepted-execution originals stay
//! in their same Host shell throughout the query. The actual Session returns
//! only from the shared Security positive disposition; no raw getter escapes.

use super::*;
use aos_sandbox_controller_domain::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};
use crate::controller_service::inventory::delete_queries::ControllerDeleteInventorySourceV2;
use aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1;
use aos_sandbox_broker_session_security::controller_composition::{
    DeleteInventoryAnswerOriginalsV1,
};

impl ControllerHostPublication {
    pub(in crate::controller_service) fn query_delete_host_confirmation_once_v4<
        'scope,
        'original,
        'profile,
    >(
        &mut self,
        pending: &mut aos_sandbox_controller_domain::ControllerDeletePendingOriginalV2<'scope, 'original>,
        client: &mut aos_sandbox_controller_domain::ControllerDeletePendingRootClientOriginalV2<'profile>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        network: &aos_sandbox_broker_session_security::controller_composition::DeleteNetworkApplySessionIoOriginalV4,
    ) -> Result<DeleteInventoryAnswerOriginalsV1, ResourceReservationErrorV1> {
        if !self.lifecycle_runtime_ready() || self.requires_reconnect() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let session = self
            .session
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let native = aos_sandbox_broker_session_security::controller_composition::OriginalDeleteInventoryClientV1::borrow_host_confirmation_native_once_v4(
            bank, pending, client, controller, profile, session, network, bytes)?;
        // No Session move precedes the full actual Source/native debit.
        let session = match self.session.take() {
            Some(session) => session,
            None => std::process::abort(),
        };
        let (session, answer) =
            super::super::inventory::delete_queries::complete_query_once_v1(native, session);
        self.session = Some(session);
        Ok(answer)
    }

    pub(in crate::controller_service) fn query_delete_from_source_once_v2(
        &mut self,
        source: &mut ControllerDeleteInventorySourceV2<'_, '_, '_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<DeleteInventoryAnswerOriginalsV1, ResourceReservationErrorV1> {
        if !self.lifecycle_runtime_ready() || self.requires_reconnect() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let session = self.session.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let native = source.borrow_native_once_v2(bank, controller, profile, session, bytes)?;
        let session = match self.session.take() {
            Some(session) => session,
            None => std::process::abort(),
        };
        let (session, answer) = super::super::inventory::delete_queries::complete_query_once_v1(
            native, session,
        );
        self.session = Some(session);
        Ok(answer)
    }
}
