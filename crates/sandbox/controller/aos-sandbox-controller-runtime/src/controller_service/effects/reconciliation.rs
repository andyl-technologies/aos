//! Retains ordered fresh physical observations after completed metadata recovery.
//!
//! These owners remain in admitted worker custody. Successful metadata recovery
//! remains a historical public result; these additional observations grant no
//! ordinary enrollment or Ready event.

use super::*;
use aos_sandbox_controller_domain::{
    ControllerReconciliationInventoryRoleV2 as Role,
    OperatorCreateRecoveryClosedV1 as Closed,
    OperatorCreateRecoveryOriginalV1,
    OperatorRecoveredStoppedCreateSeedV1 as Seed,
    OperatorReconciliationObservationCustodyV2 as Custody,
    OperatorReconciliationObservationOriginalV2 as Native,
    OperatorFirstLocalReconciliationCompleteV2 as Complete,
};
use aos_sandbox_broker_session_security::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
};
use aos_sandbox_broker_session_security::controller_composition::{
    OperatorReconciliationSessionOpenV2, OperatorReconciliationInventoryOriginalV2,
    OutputPreparationClosedV1 as QueryClosed, Pid1LaunchImageV1,
};

#[derive(Default)]
struct RoleObservationV2 {
    custody: Option<Custody>,
    cold: Box<OperatorReconciliationSessionOpenV2>,
    opened: Option<Result<(), BrokerSessionSecurityError>>,
    session: Option<Box<DormantAuthenticatedBrokerSessionV1>>,
    queries: [Box<OperatorReconciliationInventoryOriginalV2>; 1],
    queried: [Option<Result<(), QueryClosed>>; 1],
    body: Option<Result<(), Closed>>,
}

impl RoleObservationV2 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<OperatorReconciliationSessionOpenV2>(),
            boxed_bytes::<OperatorReconciliationInventoryOriginalV2>(),
            boxed_bytes::<DormantAuthenticatedBrokerSessionV1>(),
        ])
    }

    fn native(&self) -> Result<&Native, Closed> {
        match self.custody.as_ref() {
            Some(Custody::Entered(native)) => Ok(native),
            _ => Err(Closed),
        }
    }

    fn observe_once(&mut self, seed: &Seed<'_>, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1, previous: Option<&Native>,
        role: Role, image: Pid1LaunchImageV1,
    ) -> Result<(), Closed> {
        if self.custody.is_some() { return Err(Closed); }
        self.custody = Some(seed.begin_physical_observation_v2(
            controller, source, previous, role));
        let Some(Custody::Entered(native)) = self.custody.as_mut() else {
            return Err(Closed);
        };
        self.body = Some((|| {
            let mut loan = native.borrow_once_v2(seed, controller, source).map_err(|_| Closed)?;
            loan.observe_source_once_v2(source).map_err(|_| Closed)?;
            self.opened = Some(self.cold.open_once_v2(&mut loan, image));
            if !matches!(self.opened, Some(Ok(()))) {
                loan.retain_sdk_refusal_once_v2();
                return Err(Closed);
            }
            self.session = self.cold.take_completed_once_v2().map(Box::new);
            let Some(session) = self.session.as_mut() else {
                loan.retain_sdk_refusal_once_v2();
                return Err(Closed);
            };
            let count = 1;
            for index in 0..count {
                self.queried[index] = Some(self.queries[index]
                    .observe_once_v2(&mut loan, &self.cold, session, index));
                if !matches!(self.queried[index], Some(Ok(()))) {
                    loan.retain_sdk_refusal_once_v2();
                    return Err(Closed);
                }
            }
            Ok(())
        })());
        if !matches!(self.body, Some(Ok(()))) { native.retain_body_refusal_once_v2(); }
        // The short loan has ended. Both native afters and the separately paid
        // final clock remain owed after every entered Source/cold/query refusal.
        native.finish_native_once_v2(controller, source);
        if matches!(self.body, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.custody.as_ref()? {
            Custody::EntryRefused(refusal) => refusal.failure_v2(),
            Custody::Entered(native) => {
                if native.sdk_failure_is_selected_v2(0) {
                    if let Some(cause) = self.cold.failure_v2() { return Some(cause); }
                }
                if let Some(session) = self.session.as_ref() {
                    for (index, query) in self.queries.iter().enumerate() {
                        if native.sdk_failure_is_selected_v2(index) {
                            if let Some(cause) = query.failure_v2(session) { return Some(cause); }
                        }
                    }
                }
                native.failure_v2().or_else(||
                    self.body.as_ref().and_then(|body| body.as_ref().err())
                        .map(|cause| cause as _))
            }
        }
    }
}

/// Keeps all endpoint, signed-query and native owners resident in startup custody.
#[derive(Default)]
pub(super) struct FirstLocalReconciliationV2 {
    entered: bool,
    predecessor: Option<Result<(), Closed>>,
    image: Option<Result<Pid1LaunchImageV1, Closed>>,
    host: RoleObservationV2,
    mount: RoleObservationV2,
    network: RoleObservationV2,
    result: Option<Result<(), Closed>>,
}

impl FirstLocalReconciliationV2 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            RoleObservationV2::inactive_receiving_bytes_v1()?.checked_mul(3),
        ])
    }

    pub(super) fn borrow_complete<'held, 'completed>(&'held self,
        seed: &'held Seed<'completed>, controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<Complete<'held, 'completed>, Closed> {
        if !matches!(self.result, Some(Ok(()))) { return Err(Closed); }
        let proof = |role: &'held RoleObservationV2, index: usize| {
            role.queries[index].borrow_completed_inventory_v2(
                role.native()?, seed, controller, source,
                role.session.as_ref().ok_or(Closed)?, index)
        };
        Complete::require_first_local_v2(seed, controller, source,
            proof(&self.host, 0)?,
            proof(&self.mount, 0)?,
            proof(&self.network, 0)?)
    }

    fn observe_once(&mut self, seed: &Seed<'_>, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        image: Result<Pid1LaunchImageV1, Closed>,
    ) -> Result<(), Closed> {
        if self.entered { return Err(Closed); }
        self.entered = true;
        self.image = Some(image);
        self.result = Some((|| {
            let image = self.image.as_ref().and_then(|image| image.as_ref().ok())
                .cloned().ok_or(Closed)?;
            self.host.observe_once(seed, controller, source, None, Role::Host, image.clone())?;
            self.mount.observe_once(seed, controller, source,
                Some(self.host.native()?), Role::Mount, image.clone())?;
            self.network.observe_once(seed, controller, source,
                Some(self.mount.native()?), Role::Network, image)?;
            Ok(())
        })());
        self.result.as_ref().copied().unwrap_or(Err(Closed))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.predecessor.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.image.as_ref().and_then(|image| image.as_ref().err())
            .map(|cause| cause as _)
            )
            .or_else(|| self.host.failure())
            .or_else(|| self.mount.failure())
            .or_else(|| self.network.failure())
    }
}

impl ProductionEffectExecutor {
    pub(super) fn reconcile_first_local_after_recover_once_v2(&mut self,
        controller: &mut Journal, original: &OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), Closed> {
        let predecessor = self.operator_recover.borrow_first_local_stopped_predecessor_v1(
            original, controller, &self.source_domains);
        self.first_local_reconciliation.predecessor = Some(predecessor.as_ref()
            .map(|_| ()).map_err(|_| Closed));
        let seed = predecessor?;
        let image = self.sessions.lock().map_err(|_| Closed)
            .and_then(|sessions| sessions.launch_image.clone().ok_or(Closed));
        self.first_local_reconciliation.observe_once(
            &seed, controller, &mut self.source_domains, image)?;
        let complete = self.first_local_reconciliation.borrow_complete(
            &seed, controller, &self.source_domains)?;
        let resident = super::super::execution_output_effect::ControllerExecutionOriginalV1::resident_demand_v1()
            .map_err(|_| Closed)?;
        let bank = self.resource_bank.as_ref().ok_or(Closed)?;
        let bank = bank.lock().map_err(|_| Closed)?;
        self.first_local_enrollment.enroll_once_v2(&complete, &bank, controller,
            &mut self.source_domains, resident).map_err(|_| Closed)?;
        if self.delete_original.is_some() || self.execution_original.is_some() {
            return Err(Closed);
        }
        let (delete, execution) = self.first_local_enrollment
            .completed_operation_originals_v2().ok_or(Closed)?;
        let profile = self.execution_profile.as_deref().ok_or(Closed)?;
        delete.require_unentered_recovered_runtime_placement_v2(&bank, controller, profile)
            .map_err(|_| Closed)?;
        execution.require_unentered_recovered_runtime_placement_v2(&bank, controller, profile)
            .map_err(|_| Closed)?;

        // All fallible placement checks precede the consuming pair move. The
        // same executor owns both destinations and keeps the completed Recover,
        // all read-only Sessions and new enrollment resident beside them.
        let (delete, execution) = self.first_local_enrollment
            .take_completed_operation_originals_once_v2().ok_or(Closed)?;
        self.delete_original = Some(delete);
        self.execution_original = Some(
            super::super::execution_output_effect::ControllerExecutionOriginalV1::from_funded_original_v2(execution),
        );
        // The actual full upper enrollment and same C/Launch/profile issue
        // this owning four-role context. A returned failed context remains in
        // this executor; only the named consuming port can move a healthy one.
        self.recovered_sessions = Some(bank.begin_recovered_ordinary_sessions_once_v2(
            &self.first_local_enrollment, controller, profile));
        match self.recovered_sessions.as_ref() {
            Some(Ok(context)) if context.failure_v2().is_none() => Ok(()),
            _ => Err(Closed),
        }
    }
}
