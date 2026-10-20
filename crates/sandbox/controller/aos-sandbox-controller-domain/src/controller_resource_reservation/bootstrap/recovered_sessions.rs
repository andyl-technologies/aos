//! Rejoins fresh ordinary Session receivers to the completed recovered bank.
//!
//! These named bridges borrow the same Journal and confirmed Launch. The
//! initial claim path remains separate. The lower context retains every role's
//! entered native prefix and independently owed after, including refusals.

use std::sync::Arc;

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2 as Context;
use aos_sandbox_broker::controller_receiving::ControllerInitialSessionReceivingOriginalV1 as Receiving;

use super::super::initial_session::{
    ControllerInitialBrokerSessionReceivingV1 as Session,
    ControllerInitialBrokerSessionRoleV1 as Role, ControllerInitialBrokerSessionShapeV1 as Shape,
};
use super::super::{OperatorFirstLocalOrdinaryEnrollmentOriginalV2, ResourceReservationErrorV1};
use super::ControllerResourceBankOpeningV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1 as Profile;
use crate::Journal;

impl ControllerResourceBankOpeningV1 {
    /// Creates the actual four-role context after complete upper enrollment.
    ///
    /// A returned failed context remains owned by its caller. No old initial
    /// claims, inventory Sessions or successful comparison DATA enter here.
    ///
    /// # Errors
    /// Refuses incomplete upper enrollment or missing same C/Launch custody.
    #[doc(hidden)]
    pub fn begin_recovered_ordinary_sessions_once_v2(
        &self,
        enrollment: &OperatorFirstLocalOrdinaryEnrollmentOriginalV2,
        controller: &Journal,
        profile: &Profile,
    ) -> Result<Context, ResourceReservationErrorV1> {
        let completed =
            enrollment.completed_native_for_ordinary_sessions_v2(self, controller, profile)?;
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(controller
            .controller_coordinator_for_bank_read_v1()?
            .begin_recovered_ordinary_sessions_once_v2(
                completed,
                launch,
                profile.lower_original_v1(),
            ))
    }

    pub(crate) fn prepare_recovered_ordinary_session_once_v2(
        &self,
        context: &mut Context,
        controller: &mut Journal,
        profile: Arc<Profile>,
        runtime: Arc<tokio::runtime::Runtime>,
        role: Role,
        shape: Shape,
    ) -> Result<Session, ResourceReservationErrorV1> {
        let fixed = Session::fixed_demand(role, shape)?;
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let receiving = context.begin_session_receiving_once_v2(
            controller.controller_coordinator_for_bank_v1()?,
            launch,
            profile.lower_original_v1(),
            role,
            fixed,
        )?;
        let mut session = Session::new(Arc::clone(&self.original), profile, role);
        session.prepare_recovered_ordinary_once_v2(shape, receiving);
        if role == Role::Storage {
            let _runtime = session.retain_runtime_mechanics_once_v1(runtime);
        }
        // Return the whole owner even after preparation refusal. Its caller
        // must keep it and finish the context's already-entered native after.
        Ok(session)
    }

    pub(crate) fn finish_recovered_ordinary_session_native_once_v2(
        &self,
        context: &mut Context,
        controller: &mut Journal,
        profile: &Profile,
        role: Role,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        context
            .finish_session_native_once_v2(
                controller.controller_coordinator_for_bank_v1()?,
                launch,
                profile.lower_original_v1(),
                role,
            )
            .map_err(Into::into)
    }

    pub(crate) fn require_completed_recovered_ordinary_session_v2(
        &self,
        context: &Context,
        receiving: &Receiving,
        controller: &Journal,
        profile: &Profile,
        role: Role,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        context
            .require_completed_session_original_v2(
                receiving,
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile.lower_original_v1(),
                role,
            )
            .map_err(Into::into)
    }
}
