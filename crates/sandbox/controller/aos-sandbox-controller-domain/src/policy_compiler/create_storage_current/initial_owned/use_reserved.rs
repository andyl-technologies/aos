//! Receives the exact Reserved cut and runs its distinct genuine Controller read.
//!
//! Actual native frame and reader owners stay resident across each short real
//! Initial/L/U interval. The same shared Controller programme performs all later
//! named/native/semantic/captured/replay steps; no decoded frame issues a phase.

use super::{Action, Error, First, RootOwnedInitialCurrentAttemptV1, Stage};
use crate::normal_root::ProductionNormalRootStartupV1;
use aos_sandbox_policy::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    pub(super) fn receive_use_reserved_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::ReservedFrameFixed, 78)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .construct_use_reserved_frame_once_v1()
            .map_err(Action::Reserved);
        self.record_v1(79, returned)?;
        // Both arms precede the old receiving body. Either refusal exits before
        // an after scope is owed, preserving partial retained arm custody.
        self.drive_v1(startup, Stage::ReservedFrameBefore, 80)?;
        self.drive_v1(startup, Stage::ReservedFrameAfter, 81)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .receive_use_reserved_frame_once_v1()
            .map_err(Action::Reserved);
        self.record_v1(82, returned)?;
        self.drive_v1(startup, Stage::ReservedControllerFixed, 83)?;
        let body = self.receive_reserved_controller_body_v1(startup, data);
        self.latch_native_v1();
        if matches!(self.actions[86], Some(Err(_))) {
            self.first.get_or_insert(First::Action(86));
        }
        if let Some(native) = &mut self.native {
            native.observe_use_reserved_controller_native_posts_once_v1();
        }
        self.latch_native_v1();
        if let Some(native) = &mut self.native {
            native.observe_use_reserved_controller_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_use_reserved_complete_v1()
            .map_err(Action::Reserved);
        self.record_v1(96, returned)
    }

    fn receive_reserved_controller_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .enter_use_reserved_controller_body_once_v1()
            .map_err(Action::Reserved);
        self.record_v1(84, returned)?;
        let armed = self.drive_v1(startup, Stage::ReservedControllerBodyArm, 85);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_use_reserved_controller_body_arm_once_v1();
            }
            return armed;
        }
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut prepared = match native.borrow_use_reserved_controller_once_v1(data) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.actions[86] = Some(Err(Action::Reserved(error)));
                return Err(Error::Open);
            }
        };
        self.actions[86] = Some(Ok(()));
        super::controller::receive_controller_prepared_v1::<87>(
            startup,
            &mut prepared,
            &mut self.actions,
            &mut self.first,
        )
    }
}
