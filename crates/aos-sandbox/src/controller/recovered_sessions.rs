//! Borrows the same Controller Journal for fresh recovered Session stages.
//!
//! The worker holds the genuine context and returned cold receivers. These
//! named entrances expose no Journal, raw writer, account or replacement
//! initial claim; all native work stays with the existing Bank engines.

use super::*;
use crate::{
    ControllerInitialBrokerSessionReceivingV1 as Session,
    ControllerInitialBrokerSessionRoleV1 as Role, ControllerInitialBrokerSessionShapeV1 as Shape,
};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2 as Context;
use std::sync::Arc;

impl<C: ActivatedOperationCompiler, E: SingleNodeEffectExecutor> NodeController<C, E> {
    /// Moves the same actual fresh context from the retained effect executor.
    ///
    /// Failed originals remain in their executor. This consuming handoff grants
    /// no readiness, cold reconciliation, or Session from historical records.
    #[doc(hidden)]
    pub fn take_recovered_ordinary_sessions_once_v2(&mut self) -> Option<Context> {
        self.reconciler.take_recovered_ordinary_sessions_once_v2()
    }

    /// Receives one actual new ordinary role on its same recovered bank.
    ///
    /// The returned whole receiver retains preparation refusals. Every entered
    /// context turn still owes its separate native after before later work.
    ///
    /// # Errors
    /// Refuses missing affinity, repeated roles or insufficient complete demand.
    #[doc(hidden)]
    pub fn prepare_recovered_ordinary_session_once_v2(
        &mut self,
        bank: &crate::ControllerResourceBankOpeningV1,
        context: &mut Context,
        profile: Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        runtime: Arc<tokio::runtime::Runtime>,
        role: Role,
        shape: Shape,
    ) -> Result<Session, crate::ResourceReservationErrorV1> {
        bank.prepare_recovered_ordinary_session_once_v2(
            context,
            self.reconciler.journal_mut(),
            profile,
            runtime,
            role,
            shape,
        )
    }

    /// Attempts the prearmed recovered role's native after without a new debit.
    ///
    /// # Errors
    /// Retains missing original affinity, native/profile or positive-disposal
    /// refusals; earlier cold acquisition errors never suppress this entrance.
    #[doc(hidden)]
    pub fn finish_recovered_ordinary_session_native_once_v2(
        &mut self,
        bank: &crate::ControllerResourceBankOpeningV1,
        context: &mut Context,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        role: Role,
    ) -> Result<(), crate::ResourceReservationErrorV1> {
        bank.finish_recovered_ordinary_session_native_once_v2(
            context,
            self.reconciler.journal_mut(),
            profile,
            role,
        )
    }
}
