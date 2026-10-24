//! Runs the same real Signed input, C7 reader and Root4 append/send programme.
//!
//! Every receiving arm uses the same Initial/L/U finisher. Outside those short
//! intervals, opaque native loans retain the exact stream and current frame.
//! Entered input, Controller and append scopes always finish their own posts.

use aos_sandbox_policy::native::RootSignedInputBorrowV1;
use aos_sandbox_policy::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

use super::{Action, Actions, Error, First, RootOwnedInitialCurrentAttemptV1, Stage, frame};
use crate::normal_root::ProductionNormalRootStartupV1;

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    pub(super) fn receive_signed_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::SignedFixed, 119)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .construct_signed_once_v1()
            .map_err(Action::Signed);
        self.record_v1(120, returned)?;
        // The old outer arm precedes input arms and its entire entered body.
        // Refusal here creates no append-post observation duty.
        self.drive_v1(startup, Stage::SignedAppend, 121)?;
        let body = self.receive_signed_body_v1(startup, data);
        self.latch_native_v1();
        if let Some(native) = &mut self.native {
            native.observe_signed_append_posts_once_v1();
        }
        self.latch_native_v1();
        body?;
        if self.first.is_some() {
            return Err(Error::Open);
        }
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .frame_signed_once_v1()
            .map_err(Action::Signed);
        self.record_v1(158, returned)?;
        self.drive_v1(startup, Stage::SignedSend, 159)?;
        // The native sender parks partial IO before all original send posts,
        // opened-only readback, metadata and live/interval checks.
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .send_signed_once_v1()
            .map_err(Action::Signed);
        self.record_v1(160, returned)?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_signed_complete_v1()
            .map_err(Action::Signed);
        self.record_v1(161, returned)
    }

    fn receive_signed_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        self.receive_signed_input_once_v1(startup)?;
        self.receive_signed_controller_once_v1(startup, data)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .prepare_signed_once_v1()
            .map_err(Action::Signed);
        self.record_v1(155, returned)?;
        self.drive_v1(startup, Stage::SignedCrossing, 156)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .append_signed_once_v1()
            .map_err(Action::Signed);
        self.record_v1(157, returned)
    }

    fn receive_signed_input_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        // Both real input arms precede the old receive/after scope. A refused
        // before or after arm keeps its native original but owes no body post.
        self.drive_v1(startup, Stage::SignedInputBefore, 122)?;
        self.drive_v1(startup, Stage::SignedInputAfter, 123)?;
        let body = self.receive_signed_input_body_v1(startup);
        self.latch_native_v1();
        for slot in [125, 130] {
            if matches!(self.actions[slot], Some(Err(_))) {
                self.first.get_or_insert(First::Action(slot));
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_signed_input_after_once_v1();
        }
        self.latch_native_v1();
        body?;
        if self.first.is_some() {
            return Err(Error::Open);
        }
        Ok(())
    }

    fn receive_signed_input_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .begin_signed_input_once_v1()
            .map_err(Action::Signed);
        self.record_v1(124, returned)?;
        self.receive_signed_index_once_v1(startup)?;
        // The actual index is decoded before its real variable admission;
        // raw allocation and decoding cannot precede that same live stage.
        self.drive_v1(startup, Stage::SignedVariable, 129)?;
        self.receive_signed_chunks_once_v1(startup)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .verify_signed_input_once_v1()
            .map_err(Action::Signed);
        self.record_v1(141, returned)
    }

    fn receive_signed_index_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut input = match native.borrow_signed_index_once_v1() {
            Ok(input) => input,
            Err(error) => {
                self.actions[125] = Some(Err(Action::Signed(error)));
                return Err(Error::Open);
            }
        };
        self.actions[125] = Some(Ok(()));
        receive_signed_index_v1(
            startup,
            &mut input,
            &mut self.actions,
            &mut self.first,
            &mut self.frame,
        )
    }

    fn receive_signed_chunks_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut input = match native.borrow_signed_chunks_once_v1() {
            Ok(input) => input,
            Err(error) => {
                self.actions[130] = Some(Err(Action::Signed(error)));
                return Err(Error::Open);
            }
        };
        self.actions[130] = Some(Ok(()));
        receive_signed_chunks_v1(
            startup,
            &mut input,
            &mut self.actions,
            &mut self.first,
            &mut self.frame,
        )
    }

    fn receive_signed_controller_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::SignedController, 142)?;
        let body = self.receive_signed_controller_body_v1(startup, data);
        self.latch_native_v1();
        if matches!(self.actions[145], Some(Err(_))) {
            self.first.get_or_insert(First::Action(145));
        }
        if let Some(native) = &mut self.native {
            native.observe_signed_controller_native_posts_once_v1();
        }
        self.latch_native_v1();
        if let Some(native) = &mut self.native {
            native.observe_signed_controller_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        if self.first.is_some() {
            return Err(Error::Open);
        }
        Ok(())
    }

    fn receive_signed_controller_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .construct_signed_controller_once_v1()
            .map_err(Action::Signed);
        self.record_v1(143, returned)?;
        let armed = self.drive_v1(startup, Stage::SignedControllerBodyArm, 144);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_signed_controller_body_arm_once_v1();
            }
            return armed;
        }
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut prepared = match native.borrow_signed_controller_once_v1(data) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.actions[145] = Some(Err(Action::Signed(error)));
                return Err(Error::Open);
            }
        };
        self.actions[145] = Some(Ok(()));
        super::controller::receive_controller_prepared_v1::<146>(
            startup,
            &mut prepared,
            &mut self.actions,
            &mut self.first,
        )
    }
}

// This lexical adapter moves a real returned input error into the same upper
// reservoir before any post or later upper exclusion. The native partial is
// borrowed throughout and cannot be discarded by a `?` on a fresh constructor.
macro_rules! input_value {
    ($input:ident, $actions:ident, $first:ident, $slot:expr, $expression:expr) => {{
        match $expression {
            Ok(value) => {
                $actions[$slot] = Some(Ok(()));
                value
            }
            Err(error) => {
                $actions[$slot] = Some(Err(Action::SignedInput(error)));
                $first.get_or_insert(if $input.failure_v1().is_some() {
                    First::Native
                } else {
                    First::Action($slot)
                });
                return Err(Error::Ready);
            }
        }
    }};
}

fn receive_signed_index_v1(
    startup: &ProductionNormalRootStartupV1,
    input: &mut RootSignedInputBorrowV1<'_, '_>,
    actions: &mut Actions,
    first: &mut Option<First>,
    frame_trace: &mut frame::FrameTrace,
) -> Result<(), Error> {
    input_value!(input, actions, first, 126, input.prepare_index_once_v1());
    let received = match input.borrow_index_frame_v1() {
        Ok(mut subject) => frame::receive_frame_v1(startup, &mut subject, frame_trace, first),
        Err(error) => {
            actions[127] = Some(Err(Action::SignedInput(error)));
            Err(Error::Ready)
        }
    };
    if received.is_err() {
        first.get_or_insert(if input.failure_v1().is_some() {
            First::Native
        } else {
            First::Action(127)
        });
        return received;
    }
    actions[127] = Some(Ok(()));
    input_value!(input, actions, first, 128, input.decode_index_once_v1());
    Ok(())
}

fn receive_signed_chunks_v1(
    startup: &ProductionNormalRootStartupV1,
    input: &mut RootSignedInputBorrowV1<'_, '_>,
    actions: &mut Actions,
    first: &mut Option<First>,
    frame_trace: &mut frame::FrameTrace,
) -> Result<(), Error> {
    // The old first-sequence preparation is after Variable and before extent.
    input_value!(input, actions, first, 131, input.begin_chunks_once_v1());
    macro_rules! indexed_stage {
        (extent, $total:ident) => {
            let $total = input_value!(input, actions, first, 132, input.prepare_extent_once_v1());
        };
        (allocate, $total:ident) => {
            // Only the native scope's own retained extent is used to allocate.
            // The returned usize remains comparison/control DATA in this frame.
            let _ = $total;
            input_value!(input, actions, first, 133, input.allocate_once_v1());
        };
        (has_next) => {
            input_value!(input, actions, first, 134, input.has_next_v1())
        };
        (prepare_frame, $current_frame:ident) => {
            input_value!(input, actions, first, 135, input.prepare_frame_once_v1());
        };
        (receive_frame, $current_frame:ident) => {
            let received = match input.borrow_chunk_frame_v1() {
                Ok(mut subject) => {
                    frame::receive_frame_v1(startup, &mut subject, frame_trace, first)
                }
                Err(error) => {
                    actions[136] = Some(Err(Action::SignedInput(error)));
                    Err(Error::Ready)
                }
            };
            if received.is_err() {
                first.get_or_insert(if input.failure_v1().is_some() {
                    First::Native
                } else {
                    First::Action(136)
                });
                return received;
            }
            actions[136] = Some(Ok(()));
        };
        (bind_copy, $current_frame:ident, $total:ident) => {
            input_value!(input, actions, first, 137, input.bind_copy_frame_once_v1());
        };
        (dispose_frame, $current_frame:ident) => {
            input_value!(input, actions, first, 138, input.dispose_frame_once_v1());
        };
        (digest, $total:ident) => {
            input_value!(input, actions, first, 139, input.digest_once_v1());
        };
    }
    aos_sandbox_broker::root_indexed_transfer_receive_v1!(indexed_stage);
    input_value!(input, actions, first, 140, input.decode_bundle_once_v1());
    Ok(())
}
