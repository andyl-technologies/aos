//! Drives the authorized Recover observation on the same Source and cold owner.
//!
//! Cold authentication and signed Inventory18 remain observations. The distinct
//! fixed Root exchange and its exact newly authorized metadata-only CAS are
//! retained beside those originals until all independent outer posts finish.

use super::*;
mod execution_no_apply;
mod stop_cleanup;
mod stop_cleanup_observation;
use aos_sandbox_controller_domain::{OperatorCreateRecoveryClosedV1 as Closed,
    OperatorCreateRecoveryOriginalV1};
use aos_sandbox_broker_session_security::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    OperatorRecoverStorageSessionOpenV1,
};
use aos_sandbox_broker_session_security::controller_composition::{
    OperatorRecoverStorageInventoryOriginalV1, OutputPreparationClosedV1 as InventoryClosed,
    Pid1LaunchImageV1,
};

#[derive(Default)]
pub(super) struct OperatorRecoverObservationsV1 {
    stop_cleanup_recovery: Box<stop_cleanup::StopCleanupRecoveryOriginalV1>,
    stop_cleanup: Box<stop_cleanup_observation::StopCleanupObservationRuntimeOriginalV1>,
    execution_no_apply: Box<execution_no_apply::ExecutionNoApplyRecoveryOriginalV2>,
    entered: bool,
    image: Option<Result<Pid1LaunchImageV1, Closed>>,
    cold: Box<OperatorRecoverStorageSessionOpenV1>,
    opened: Option<Result<(), BrokerSessionSecurityError>>,
    session: Option<Box<DormantAuthenticatedBrokerSessionV1>>,
    inventory: Box<OperatorRecoverStorageInventoryOriginalV1>,
    inventoried: Option<Result<(), InventoryClosed>>,
    body: Option<Result<(), Closed>>,
    root: Option<aos_sandbox_controller_domain::normal_root::RootFinalityRecoverClientOriginalV1>,
    root_result: Option<Result<(), aos_sandbox_controller_domain::normal_root::RootFinalityRecoverClientClosedV1>>,
    metadata: Option<Result<(), Closed>>,
}

impl OperatorRecoverObservationsV1 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<stop_cleanup::StopCleanupRecoveryOriginalV1>(),
            boxed_bytes::<stop_cleanup_observation::StopCleanupObservationRuntimeOriginalV1>(),
            boxed_bytes::<execution_no_apply::ExecutionNoApplyRecoveryOriginalV2>(),
            boxed_bytes::<OperatorRecoverStorageSessionOpenV1>(),
            boxed_bytes::<OperatorRecoverStorageInventoryOriginalV1>(),
            boxed_bytes::<DormantAuthenticatedBrokerSessionV1>(),
            stop_cleanup::StopCleanupRecoveryOriginalV1::inactive_receiving_bytes_v1(),
            execution_no_apply::ExecutionNoApplyRecoveryOriginalV2::inactive_receiving_bytes_v1(),
            stop_cleanup_observation::StopCleanupObservationRuntimeOriginalV1::inactive_receiving_bytes_v1(),
        ])
    }

    /// Borrows the same completed Runtime/SDK/Source conjunction for new entry.
    ///
    /// This lends no Ready, ordinary Session, intake or execution authority.
    /// The new residual enrollment must independently complete its actual
    /// physical reconciliation and native disposal before normal service.
    ///
    /// # Errors
    /// Refuses any incomplete original, retained failure or a state outside
    /// the first-local stopped subset. No alternate owner is constructed.
    pub(in crate::controller_service) fn borrow_first_local_stopped_predecessor_v1<'completed>(
        &'completed self, original: &'completed OperatorCreateRecoveryOriginalV1,
        controller: &Journal,
        source: &aos_sandbox_controller_domain::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<aos_sandbox_controller_domain::OperatorRecoveredStoppedCreateSeedV1<'completed>, Closed> {
        if !self.entered || !matches!(self.opened, Some(Ok(())))
            || !matches!(self.inventoried, Some(Ok(())))
            || !matches!(self.root_result, Some(Ok(())))
            || !matches!(self.metadata, Some(Ok(()))) || !matches!(self.body, Some(Ok(()))) {
            return Err(Closed);
        }
        let session = self.session.as_ref().ok_or(Closed)?;
        self.inventory.borrow_first_local_stopped_predecessor_v1(original, controller, source, session)
    }
}

impl ProductionEffectExecutor {
    pub(super) fn observe_recover_sources_once_v1(&mut self, controller: &mut Journal,
        original: &mut OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), Closed> {
        if self.operator_recover.entered { return Err(Closed); }
        self.operator_recover.entered = true;

        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1;
        let purpose = original.recovery_purpose_data_v1(controller).map_err(|_| Closed)?;
        if purpose == PublicRecoveryKindV1::ExecutionNoApply {
            // No Root or Host Session starts under the soon-to-finish Recover
            // interval. The new actual cleanup owner mints its own nonce and
            // pays acquisition after the completed financial handoff.
            self.operator_recover.body = Some(original.observe_no_apply_source_once_v2(
                controller, &mut self.source_domains).map_err(|_| Closed));
            original.finish_source_after_once_v1(&mut self.source_domains);
            return self.operator_recover.body.as_ref().copied().unwrap_or(Err(Closed));
        }
        if purpose == PublicRecoveryKindV1::StopCleanup {
            self.operator_recover.body = Some(
                self.observe_stop_cleanup_passive_once_v1(controller, original));
            original.finish_source_after_once_v1(&mut self.source_domains);
            return self.operator_recover.body.as_ref().copied().unwrap_or(Err(Closed));
        }
        if purpose != PublicRecoveryKindV1::MetadataComplete {
            // The actual Stop client/456 driver must enter its own finite
            // branch; no cleanup purpose may fall through to Storage18.
            return Err(Closed);
        }

        // The SDK capsule's fixed backing is already in the startup invoice.
        // Its preparation still debits the actual dynamic cold prefix.
        self.operator_recover.body = Some((|| {
            let mut loan = original.borrow_storage_v1(controller).map_err(|_| Closed)?;
            loan.observe_source_once_v1(&mut self.source_domains).map_err(|_| Closed)?;
            self.operator_recover.image = Some((|| {
                let sessions = self.sessions.lock().map_err(|_| Closed)?;
                sessions.launch_image.clone().ok_or(Closed)
            })());
            let image = self.operator_recover.image.as_ref()
                .and_then(|image| image.as_ref().ok()).cloned().ok_or(Closed)?;
            self.operator_recover.opened = Some(self.operator_recover.cold
                .open_once_v1(&mut loan, image));
            if !matches!(self.operator_recover.opened, Some(Ok(()))) {
                loan.retain_storage_sdk_refusal_once_v1();
                return Err(Closed);
            }
            self.operator_recover.session = self.operator_recover.cold.take_completed_once_v1().map(Box::new);
            let Some(session) = self.operator_recover.session.as_mut() else {
                loan.retain_storage_sdk_refusal_once_v1();
                return Err(Closed);
            };
            self.operator_recover.inventoried = Some(self.operator_recover.inventory
                .observe_once_v1(&mut loan, &self.operator_recover.cold, session));
            if !matches!(self.operator_recover.inventoried, Some(Ok(())))
                || self.operator_recover.inventory.inventory_v1().is_none() {
                loan.retain_storage_sdk_refusal_once_v1();
                return Err(Closed);
            }
            // This whole inert destination is already in the admitted Runtime
            // header. Its own entry pays both Root posts and the final C CAS
            // before opening the fixed Root socket.
            self.operator_recover.root = Some(Default::default());
            self.operator_recover.root_result = Some(self.operator_recover.inventory
                .observe_root_finality_once_v1(&mut loan, controller, session,
                    self.operator_recover.root.as_mut().ok_or(Closed)?));
            // The short loan ends before the exact same C is mutably borrowed
            // by the closed native metadata append. Every Root outcome moves
            // into the actual Recover owner first, including entry refusal.
            drop(loan);
            let root = self.operator_recover.root.take().ok_or(Closed)?;
            self.operator_recover.metadata = Some(original.complete_metadata_after_root_once_v1(controller, root));
            if !matches!(self.operator_recover.root_result, Some(Ok(())))
                || !matches!(self.operator_recover.metadata, Some(Ok(()))) { return Err(Closed); }
            Ok(())
        })());

        // An entered Source pair remains owed after either query outcome. The
        // actual C after and Source disposition run through separate hooks.
        original.finish_source_after_once_v1(&mut self.source_domains);
        self.operator_recover.body.as_ref().copied().unwrap_or(Err(Closed))
    }

    pub(super) fn finish_recover_source_after_native_v1(&mut self, controller: &Journal,
        original: &mut OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), Closed> {
        original.dispose_source_after_native_posts_v1(controller, &mut self.source_domains);
        original.require_source_disposed_v1()
    }

    pub(super) fn complete_recover_cleanup_after_native_v2(&mut self,
        controller: &mut Journal, original: &mut OperatorCreateRecoveryOriginalV1,
        purpose: aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1,
    ) -> Result<aos_sandbox_controller_domain::OperatorCleanupRecoveryCompletionV2, Closed> {
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1;
        match purpose {
            PublicRecoveryKindV1::ExecutionNoApply => self.complete_execution_no_apply_recovery_v2(controller, original),
            PublicRecoveryKindV1::StopCleanup => self.complete_stop_cleanup_recovery_v1(controller, original)
                .map(|(response, completion)| aos_sandbox_controller_domain::OperatorCleanupRecoveryCompletionV2::Stop {
                    response, completion,
                }),
            _ => Err(Closed),
        }
    }
}
