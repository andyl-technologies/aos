//! Runs the original Controller admission, reader and independent post schedule.
//!
//! The body peer is prearmed before native preparation. Resident prepared and
//! nested replay loans survive only their original short receiving intervals;
//! no whole programme reborrow, replacement reader or completed DATA enters them.

use std::error::Error as StdError;

use aos_sandbox_policy::native::RootInitialControllerReadonlyPreparedBorrowV1;
use aos_sandbox_policy::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

use super::{Action, Actions, Error, First, RootOwnedInitialCurrentAttemptV1, Stage};
use crate::normal_root::ProductionNormalRootStartupV1;

/// Names only the original three prepared-Controller receiving intervals.
#[derive(Clone, Copy)]
pub(crate) enum RootOwnedControllerPreparedStageV1 {
    /// Rechecks the fixed original before named file opening, without a debit.
    Named,
    /// Pays captured native/Audit work before expected-copy allocation.
    Native,
    /// Pays the actual audited semantic/model/compiler/Storage work.
    Semantic,
}

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    /// Reads the actual Controller purpose and always finishes entered owed posts.
    ///
    /// # Errors
    /// Retains genuine receiving, reader/Audit/model, compilation or independent
    /// writer/archive/mount/Storage/metadata/prearmed-peer/late-clock refusal.
    pub(super) fn receive_controller_readonly_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::ControllerFixed, 53)?;
        let body = self.receive_controller_body_v1(startup, data);
        self.latch_native_v1();
        if matches!(self.actions[56], Some(Err(_))) {
            self.first.get_or_insert(First::Action(56));
        }
        // Attempted body scope owns the independent native posts. Their native
        // predicates preserve partial opening and mount entry on every refusal.
        if let Some(native) = &mut self.native {
            native.observe_initial_controller_readonly_native_posts_once_v1();
        }
        self.latch_native_v1();
        if let Some(native) = &mut self.native {
            native.observe_initial_controller_readonly_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_controller_readonly_complete_v1()
            .map_err(Action::Controller);
        self.record_v1(66, returned)
    }

    fn receive_controller_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .enter_initial_controller_readonly_body_once_v1()
            .map_err(Action::Controller);
        self.record_v1(54, returned)?;
        let armed = self.drive_v1(startup, Stage::ControllerBodyArm, 55);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_controller_readonly_body_arm_once_v1();
            }
            return armed;
        }
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut prepared = match native.borrow_initial_controller_readonly_once_v1(data) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.actions[56] = Some(Err(Action::Controller(error)));
                return Err(Error::Open);
            }
        };
        receive_controller_prepared_v1::<57>(
            startup,
            &mut prepared,
            &mut self.actions,
            &mut self.first,
        )
    }
}

pub(super) fn receive_controller_prepared_v1<const BASE: usize>(
    startup: &ProductionNormalRootStartupV1,
    prepared: &mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
    actions: &mut Actions,
    first: &mut Option<First>,
) -> Result<(), Error> {
    let returned = startup
        .drive_owned_controller_prepared_v1(prepared, RootOwnedControllerPreparedStageV1::Named);
    let admitted =
        retain_controller_action_v1(actions, first, BASE + 0, returned, prepared.failure_v1());
    if admitted.is_err() {
        prepared.refuse_named_entry_once_v1();
        return admitted;
    }
    let returned = prepared.prepare_files_once_v1().map_err(Action::Controller);
    retain_controller_action_v1(actions, first, BASE + 1, returned, prepared.failure_v1())?;
    let returned = startup
        .drive_owned_controller_prepared_v1(prepared, RootOwnedControllerPreparedStageV1::Native);
    retain_controller_action_v1(actions, first, BASE + 2, returned, prepared.failure_v1())?;
    let returned = prepared.audit_native_once_v1().map_err(Action::Controller);
    retain_controller_action_v1(actions, first, BASE + 3, returned, prepared.failure_v1())?;
    let returned = startup
        .drive_owned_controller_prepared_v1(prepared, RootOwnedControllerPreparedStageV1::Semantic);
    retain_controller_action_v1(actions, first, BASE + 4, returned, prepared.failure_v1())?;

    let entered = receive_controller_replay_v1::<BASE>(startup, prepared, actions, first);
    if entered.is_err() {
        if matches!(actions[BASE + 5], Some(Err(_))) {
            first.get_or_insert(if prepared.failure_v1().is_some() {
                First::Native
            } else {
                First::Action(BASE + 5)
            });
        }
        return entered;
    }
    // A constructed replay owes late materialization and its initial names
    // even when captured admission or the replay itself has returned Err.
    let returned = prepared
        .finish_replay_and_models_once_v1()
        .map_err(Action::Controller);
    let finished =
        retain_controller_action_v1(actions, first, BASE + 8, returned, prepared.failure_v1());
    if matches!(actions[BASE + 6], Some(Err(_))) || matches!(actions[BASE + 7], Some(Err(_))) {
        return Err(Error::Open);
    }
    finished
}

fn receive_controller_replay_v1<const BASE: usize>(
    startup: &ProductionNormalRootStartupV1,
    prepared: &mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
    actions: &mut Actions,
    first: &mut Option<First>,
) -> Result<(), Error> {
    let mut replay = match prepared.borrow_replay_once_v1() {
        Ok(replay) => replay,
        Err(error) => {
            actions[BASE + 5] = Some(Err(Action::Controller(error)));
            return Err(Error::Open);
        }
    };
    let returned = startup.admit_owned_controller_captured_v1(&mut replay);
    let admitted =
        retain_controller_action_v1(actions, first, BASE + 6, returned, replay.failure_v1());
    if admitted.is_err() {
        replay.refuse_captured_entry_once_v1();
    }
    // The entered reader always owes its prefix and tail, even after the real
    // captured-end live gate or its upper lock refused. No skip token is used.
    let returned = replay.replay_once_v1().map_err(Action::Controller);
    let _replayed =
        retain_controller_action_v1(actions, first, BASE + 7, returned, replay.failure_v1());
    // This reports only construction of the entered replay scope. Both actual
    // outcomes remain parked; the caller finishes models before returning them.
    Ok(())
}

fn retain_controller_action_v1(
    actions: &mut Actions,
    first: &mut Option<First>,
    slot: usize,
    returned: Result<(), Action>,
    retained: Option<&(dyn StdError + 'static)>,
) -> Result<(), Error> {
    if slot >= actions.len() || matches!(actions[slot], Some(Err(_))) {
        std::process::abort();
    }
    actions[slot] = Some(returned);
    if matches!(actions[slot], Some(Err(_))) {
        first.get_or_insert(if retained.is_some() {
            First::Native
        } else {
            First::Action(slot)
        });
        return Err(Error::Open);
    }
    Ok(())
}
